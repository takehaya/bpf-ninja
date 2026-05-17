// Package program dynamically builds and attaches a single fentry or fexit tracing program.
// When a filter is specified, a cbpfc-compiled eBPF filter is embedded.
package program

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cloudflare/cbpfc"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/takehaya/xdp-ninja/pkg/kunai"
	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
	tchost "github.com/takehaya/xdp-ninja/pkg/kunai/host/tc"
	xdphost "github.com/takehaya/xdp-ninja/pkg/kunai/host/xdp"
	"github.com/takehaya/xdp-ninja/internal/filter"
	"golang.org/x/net/bpf"
)

// Probe は fentry または fexit の1つのトレーシングポイント。
type Probe struct {
	EventsMap *ebpf.Map
	InnerMaps []*ebpf.Map // non-nil only in per-CPU sharded mode
	IsFexit   bool
	Warnings  []string // resolver / codegen non-fatal notices; CLI prints to stderr
	maps      []*ebpf.Map
	prog      *ebpf.Program
	link      link.Link
}

// Program returns the underlying tracing program. Exposed so that
// benchmarks (E2 / B2) can call Program.Test() to measure the per-
// packet runtime cost of the filter via BPF_PROG_TEST_RUN. Not
// intended for general callers — production code should manipulate
// the probe through Close() / EventsMap.
func (p *Probe) Program() *ebpf.Program {
	return p.prog
}

func (p *Probe) Close() error {
	var errs []error
	if p.link != nil {
		if err := p.link.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.prog != nil {
		if err := p.prog.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, m := range p.maps {
		if err := m.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// LoadEntry は fentry (前段) probe を作成してアタッチする。
// useDSL=true のとき filterExpr は xdp-ninja DSL として解釈される。
func LoadEntry(targetProg *ebpf.Program, funcName string, filterExpr string, argFilters []filter.ArgFilter, useDSL bool) (*Probe, error) {
	return loadProbe(targetProg, funcName, filterExpr, argFilters, false, useDSL)
}

// LoadExit は fexit (後段) probe を作成してアタッチする。
// useDSL=true のとき filterExpr は xdp-ninja DSL として解釈される。
func LoadExit(targetProg *ebpf.Program, funcName string, filterExpr string, argFilters []filter.ArgFilter, useDSL bool) (*Probe, error) {
	return loadProbe(targetProg, funcName, filterExpr, argFilters, true, useDSL)
}

func loadProbe(targetProg *ebpf.Program, funcName string, filterExpr string, argFilters []filter.ArgFilter, isFexit, useDSL bool) (*Probe, error) {
	info, err := targetProg.Info()
	if err != nil {
		return nil, fmt.Errorf("reading target program info: %w", err)
	}
	progType := info.Type
	if progType != ebpf.XDP && progType != ebpf.SchedCLS && progType != ebpf.SchedACT {
		return nil, fmt.Errorf("target program type %s is not supported (need XDP, SchedCLS, or SchedACT)", progType)
	}

	filterOut, err := compileFilter(filterExpr, useDSL, isFexit, progType)
	if err != nil {
		return nil, err
	}
	if SnaplenOverride > 0 {
		filterOut.Capture.MaxCapLen = SnaplenOverride
	}

	label := "entry"
	attachType := ebpf.AttachTraceFEntry
	if isFexit {
		label = "exit"
		attachType = ebpf.AttachTraceFExit
	}

	outerMap, innerMaps, err := createShardedRingbuf(label)
	if err != nil {
		return nil, err
	}

	probe := &Probe{
		EventsMap: outerMap, InnerMaps: innerMaps, IsFexit: isFexit,
		Warnings: filterOut.Warnings,
		maps:     append([]*ebpf.Map{outerMap}, innerMaps...),
	}

	// Filter scratch buffer: kunai/cBPF eval cannot read xdp_buff packet
	// memory as a scalar region, so runFilter copies a 256-byte prefix
	// into PTR_TO_MAP_VALUE first. Output staging is no longer needed
	// here — the bpf_ringbuf_reserve+submit path writes the metadata +
	// packet bytes directly into the reserved ring slot.
	scratchFD := 0
	if len(filterOut.Main) > 0 {
		scratchMap, err := ebpf.NewMap(&ebpf.MapSpec{
			Name: fmt.Sprintf("ninja_%s_sc", label), Type: ebpf.PerCPUArray,
			KeySize: 4, ValueSize: scratchBufSize, MaxEntries: 1,
		})
		if err != nil {
			_ = probe.Close()
			return nil, fmt.Errorf("creating scratch map: %w", err)
		}
		probe.maps = append(probe.maps, scratchMap)
		scratchFD = scratchMap.FD()
	}

	insns, err := buildTracingInsns(filterOut, argFilters, outerMap.FD(), scratchFD, isFexit, progType)
	if err != nil {
		_ = probe.Close()
		return nil, err
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: fmt.Sprintf("xdp_ninja_%s", label), Type: ebpf.Tracing, AttachType: attachType,
		AttachTo: funcName, AttachTarget: targetProg,
		Instructions: insns, License: "GPL",
	})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("loading %s program: %w", label, err)
	}
	probe.prog = prog

	l, err := link.AttachTracing(link.TracingOptions{Program: prog, AttachType: attachType})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("attaching %s: %w", label, err)
	}
	probe.link = l

	return probe, nil
}

// --- Filter compilation ---
//
// Two paths share the runFilter contract (R0=scratch start, R1=scratch
// end, filter sets R2 and ends at "filter_result"):
//
//   useDSL=false: tcpdump expression → cBPF → eBPF via cbpfc (default)
//   useDSL=true:  xdp-ninja DSL → eBPF via kunai.Compile
//
// See docs/ja/dsl-overview.md for the DSL doc index. The codegen
// ABI this wrapper plugs into is documented in
// pkg/kunai/codegen/codegen.go (KunaiStackTop and the package doc).

func compileFilter(expr string, useDSL, isFexit bool, progType ebpf.ProgramType) (codegen.Output, error) {
	// Empty expression == capture everything: no filter to compile,
	// callers wrap the zero Output with their own prologue/epilogue.
	// Centralised here so attach modes (entry/exit/xdp/tc-*) don't
	// each reimplement the empty-filter policy and drift apart.
	if expr == "" {
		return codegen.Output{}, nil
	}
	if useDSL {
		// fexit attaches see the host retval at args[1] (XDP action
		// or TC verdict, ABI shared); fentry has no action value yet
		// so disable action atoms by passing zero Capabilities. The
		// xdp-ninja host wrapper saves the tracing args ptr at
		// stack[-48] in either case, which is exactly the ABI both
		// FexitFetcher implementations expect.
		var caps codegen.Capabilities
		if isFexit {
			switch progType {
			case ebpf.XDP:
				caps = xdphost.FexitCapabilities()
			case ebpf.SchedCLS, ebpf.SchedACT:
				caps = tchost.FexitCapabilities()
			}
		}
		out, err := kunai.Compile(expr, caps)
		if err != nil {
			return out, fmt.Errorf("DSL filter compile failed: %w\n\nhint: %s",
				err, dslHintFor(expr))
		}
		return out, nil
	}
	rawInsns, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, expr)
	if err != nil {
		return codegen.Output{}, fmt.Errorf("compiling filter %q: %w", expr, err)
	}

	bpfInsns := make([]bpf.Instruction, len(rawInsns))
	for i, insn := range rawInsns {
		bpfInsns[i] = bpf.RawInstruction{Op: insn.Code, Jt: insn.Jt, Jf: insn.Jf, K: insn.K}.Disassemble()
	}

	cbpfcInsns, err := cbpfc.ToEBPF(bpfInsns, cbpfc.EBPFOpts{
		PacketStart: asm.R0, PacketEnd: asm.R1, Result: asm.R2,
		ResultLabel: "filter_result",
		Working:     [4]asm.Register{asm.R2, asm.R3, asm.R4, asm.R5},
		LabelPrefix: "filter",
	})
	if err != nil {
		return codegen.Output{}, err
	}
	return codegen.Output{Main: cbpfcInsns}, nil
}

// --- eBPF program generation ---
//
// レジスタ割り当て (callee-saved):
//   R6 = xdp_buff ポインタ (trusted, bpf_xdp_output に渡す)
//   R7 = xdp->data (パケット先頭)
//   R8 = xdp->data_end (パケット末尾)
//   R9 = パケット長
//
// スタックレイアウト (R10 からの負オフセット):
//   -8:  metadata: u32 action
//   -12: metadata: u8 mode + u8 _pad[3]
//   -16: map lookup の key
//   -24: scratch buffer ポインタ (フィルタ時のみ)
//   -48: tracing args ポインタの退避
//
// bpf_xdp_output を使うことで:
//   - パケットデータはカーネルが xdp_buff から直接コピー (bpf_probe_read_kernel 不要)
//   - per-CPU event buffer map が不要
//   - メタデータ (action, mode) だけスタック上に構築
//
// perf event のデータフォーマット (ユーザーランドで受け取る):
//   [metadata (8B)] [パケットデータ (カーネルが自動付加)]
//   metadata: u32 action + u8 mode + u8 _pad[3]

// scratchBufSize is an alias for codegen.ScratchBufSize so this file's
// existing references (map size, runFilter caps) keep their concise
// names without losing the single-source-of-truth.
const scratchBufSize = codegen.ScratchBufSize

// DefaultCapLen is the packet prefix length captured when no DSL
// capture clause narrowed the request and no --snaplen override was
// passed. Matches libpcap's default snaplen for tcpdump.
const DefaultCapLen = 1500

// SnaplenOverride, when > 0, forces the per-packet capture length
// regardless of any DSL capture clause or default. Set once by the
// CLI's --snaplen flag before calling LoadEntry / LoadExit /
// LoadXDPNative; zero means "use the per-filter MaxCapLen, falling
// back to DefaultCapLen". Process-global because the kunai/codegen
// compile chain has no callsite-level cap-override hook today.
var SnaplenOverride int

// BPF_RB_NO_WAKEUP skips the eventfd write that wakes a poll'ing
// consumer on every bpf_ringbuf_submit. Safe only when the consumer
// polls periodically; required when the producer rate is very high
// to avoid wasted eventfd traffic.
const BPF_RB_NO_WAKEUP uint32 = 1

// RingbufSubmitFlags is the flags argument passed to bpf_ringbuf_submit
// in every emit path (XDP-native captureXDPNative + tracing
// captureWithRingbuf). Set via --no-wakeup at startup; safe only with
// --fast-reader since the cilium/ebpf slow path would block on the
// missing wakeup.
var RingbufSubmitFlags uint32

// HWTimestampKfuncID, when non-zero, makes captureXDPNative emit a
// call to bpf_xdp_metadata_rx_timestamp(ctx, &ts) for the per-packet
// timestamp instead of bpf_ktime_get_ns(). Populated by
// ResolveHWTimestampKfunc when --rx-hwts is set.
var HWTimestampKfuncID uint32

// emitKfuncCall assembles a BPF call instruction targeting the kfunc
// with the given BTF type ID. cilium/ebpf v0.21.0 does not expose a
// public helper for this (asm.PseudoKfuncCall is the wire constant
// but no asm.Func.Kfunc(id) wrapper exists), so we hand-build the
// instruction with the kfunc-call wire encoding.
func emitKfuncCall(kfuncID uint32) asm.Instruction {
	return asm.Instruction{
		OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call),
		Src:      asm.PseudoKfuncCall,
		Constant: int64(kfuncID),
	}
}

// resolveKfuncID looks up a BTF type ID for the named kfunc in the
// running kernel's BTF dump. Returns the ID and nil on success, or
// 0 plus a descriptive error when the kernel doesn't expose the
// kfunc. All ResolveXxxKfunc public wrappers share this body.
func resolveKfuncID(name string) (uint32, error) {
	ks, err := btf.LoadKernelSpec()
	if err != nil {
		return 0, fmt.Errorf("loading kernel BTF: %w", err)
	}
	var fn *btf.Func
	if err := ks.TypeByName(name, &fn); err != nil {
		return 0, fmt.Errorf("kfunc %s not in kernel BTF: %w", name, err)
	}
	id, err := ks.TypeID(fn)
	if err != nil {
		return 0, fmt.Errorf("resolving kfunc %s BTF ID: %w", name, err)
	}
	return uint32(id), nil
}

// ResolveHWTimestampKfunc resolves bpf_xdp_metadata_rx_timestamp.
// Available on ice + Linux 6.8+; callers should fall back to
// bpf_ktime_get_ns when the resolve fails.
func ResolveHWTimestampKfunc() error {
	id, err := resolveKfuncID("bpf_xdp_metadata_rx_timestamp")
	if err != nil {
		return err
	}
	HWTimestampKfuncID = id
	return nil
}

// RingbufSize is the byte capacity of the BPF ringbuf events map.
// Must be a power of two and a multiple of PAGE_SIZE. Larger rings
// absorb more burst at the cost of memory (multiplied by per-CPU
// shard count). Set via --ringbuf-size at startup.
var RingbufSize uint32 = 64 * 1024 * 1024

const (
	defaultCapLen = DefaultCapLen
	// Must stay in sync with capture.MetadataSize; asserted by
	// TestMetadataSizeMatchesCapture in metadata_size_test.go.
	metadataSize = 16
)

func buildTracingInsns(filterOut codegen.Output, argFilters []filter.ArgFilter, eventsFD, scratchFD int, isFexit bool, progType ebpf.ProgramType) (asm.Instructions, error) {
	var insns asm.Instructions
	prelude, err := loadPacketPointers(progType)
	if err != nil {
		return nil, err
	}
	insns = append(insns, prelude...)
	insns = append(insns, buildArgFilter(argFilters)...)
	insns = append(insns, runFilter(filterOut.Main, scratchFD, filterScanLen(filterOut))...)
	insns = append(insns, captureWithRingbuf(eventsFD, isFexit, filterOut.Capture.MaxCapLen)...)
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	// bpf2bpf subprograms (currently only DSL bpf_loop chain
	// callbacks) live after the tracing body so they sit past the
	// program's final Return. The kernel also needs BTF func_info
	// for the outer program in that case — tag the first tracing
	// insn with codegen's canonical func proto.
	if len(filterOut.Callbacks) > 0 {
		insns[0] = btf.WithFuncMetadata(insns[0], codegen.MainFilterFuncBTF("xdp_ninja_filter"))
		insns = append(insns, filterOut.Callbacks...)
	}
	return insns, nil
}

// loadPacketPointers は tracing args の args[0] (= host-specific
// packet ctx) から packet 先頭・末尾・長さを host 別に読み出す。
// trusted pointer (BTF 型付き) として trampoline が保証してくれる。
//
// 終了時: R6=ctx, R7=data, R8=data_end, R9=pkt_len, stack[-48]=args
func loadPacketPointers(progType ebpf.ProgramType) (asm.Instructions, error) {
	prelude := asm.Instructions{
		asm.StoreMem(asm.R10, -48, asm.R1, asm.DWord),
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
	}
	switch progType {
	case ebpf.XDP:
		// args[0] は kernel struct xdp_buff *。 data @ +0, data_end
		// @ +8 (どちらも 8B pointer、 ABI 安定なので hardcode)。
		return append(prelude,
			asm.LoadMem(asm.R7, asm.R6, 0, asm.DWord),
			asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),
			asm.Mov.Reg(asm.R9, asm.R8),
			asm.Sub.Reg(asm.R9, asm.R7),
		), nil
	case ebpf.SchedCLS, ebpf.SchedACT:
		// args[0] は kernel struct sk_buff * (BPF が見せる
		// __sk_buff のラッパ rewrite は fexit context で発火しない)。
		// member offset は kernel version で動くので runtime BTF
		// resolve が必要。 data_end は sk_buff にないので
		// data + len で計算。
		dataOff, lenOff, err := skBuffPacketOffsets()
		if err != nil {
			return nil, fmt.Errorf("resolving struct sk_buff offsets via BTF: %w", err)
		}
		return append(prelude,
			asm.LoadMem(asm.R7, asm.R6, int16(dataOff), asm.DWord), // R7 = skb->data
			asm.LoadMem(asm.R9, asm.R6, int16(lenOff), asm.Word),   // R9 = skb->len
			asm.Mov.Reg(asm.R8, asm.R7),
			asm.Add.Reg(asm.R8, asm.R9), // R8 = data + len
		), nil
	}
	return nil, fmt.Errorf("unsupported program type %s", progType)
}

// ObserverPrefetch, when true, makes runFilter always probe_read the
// full scratchBufSize (512 B) regardless of the chain-specific
// FilterMinPrefix kunai computes. Sacrifices filter-eval CPU time
// (the R32-fix 20× → 1× win) in exchange for warming the ice driver
// L1 dcache, which R12 (docs/ja/r12-fentry-prefetch-finding.md)
// showed accelerates production XDP_TX programs by ≈ 70 %. The
// trade-off is visible to operators; default off because the
// production-XDP-vs-observer-throughput Pareto curve preferences
// vary by deployment.
var ObserverPrefetch bool

// filterScanLen picks the bpf_probe_read_kernel size for runFilter:
// the kunai-computed FilterMinPrefix when available (clamped to
// [1, scratchBufSize]), otherwise the conservative scratchBufSize.
// Zero from codegen means "analyser bailed" — fall back to the full
// scratch read so the verifier doesn't reject the filter for accessing
// past R1. ObserverPrefetch=true bypasses the dynamic sizing.
func filterScanLen(out codegen.Output) int {
	if ObserverPrefetch {
		return scratchBufSize
	}
	n := out.Capture.FilterMinPrefix
	if n <= 0 || n > scratchBufSize {
		return scratchBufSize
	}
	return n
}

// runFilter は scratch buffer にヘッダをコピーして cbpfc フィルタを実行する。
// scanLen is the number of packet bytes bpf_probe_read_kernel copies in
// and the upper bound exposed to the filter via R1; sized per-chain
// from codegen.Output.Capture.FilterMinPrefix to avoid copying 512 B
// when the filter only needs (e.g.) 54 B.
func runFilter(filter asm.Instructions, scratchFD, scanLen int) asm.Instructions {
	if len(filter) == 0 {
		return nil
	}
	if scanLen <= 0 || scanLen > scratchBufSize {
		scanLen = scratchBufSize
	}

	insns := asm.Instructions{
		// scratch buffer を取得
		asm.LoadMapPtr(asm.R1, scratchFD),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.StoreMem(asm.R10, -24, asm.R0, asm.DWord),

		// ヘッダコピー: bpf_probe_read_kernel(scratch, scanLen, data)
		asm.Mov.Reg(asm.R1, asm.R0),
		asm.Mov.Imm(asm.R2, int32(scanLen)),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.FnProbeReadKernel.Call(),

		// R0 = scratch 先頭, R1 = scratch + min(pkt_len, scanLen)
		asm.LoadMem(asm.R0, asm.R10, -24, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.JLE.Imm(asm.R1, int32(scanLen), "len_ok"),
		asm.Mov.Imm(asm.R1, int32(scanLen)),
		asm.Add.Reg(asm.R1, asm.R0).WithSymbol("len_ok"),
	}
	insns = append(insns, filter...)
	insns = append(insns, asm.JEq.Imm(asm.R2, 0, "exit").WithSymbol("filter_result"))
	return insns
}

// captureWithRingbuf is the tracing-mode capture epilogue: reserve a
// fixed-size slot in the BPF ringbuf, write metadata + copy packet
// bytes directly into the slot, then submit. This is the
// reserve+submit shape (one fewer memcpy than bpf_ringbuf_output, which
// internally memcpy's the data buffer into the reserved slot before
// commit).
//
// On-wire RawSample is the full reservation (metadataSize + maxCapLen
// bytes); the caplen field in the metadata header tells userspace how
// many of the trailing payload bytes are real (the producer always
// writes 8 + caplen useful bytes; the rest of the slot is unwritten
// memory but the ringbuf submit makes the entire reservation visible
// regardless).
//
// Stack layout assumptions on entry:
//
//	R6 = ctx (xdp_buff* or sk_buff*)
//	R7 = data start
//	R8 = data_end
//	R9 = pkt_len
//	stack[-48] = saved tracing args ptr (for fexit action lookup)
//
// Local stack slots used here:
//
//	stack[-32] = reserved-slot ptr (PTR_TO_MEM, mem_size = metadataSize + maxCapLen)
//	stack[-40] = u32 saved copy_size (preserved across the
//	             bpf_probe_read_kernel call, which clobbers R0..R5)
//
// Verifier acceptance hinges on the reserve size being a known
// compile-time constant — we always pass int32(metadataSize+maxCapLen)
// as an immediate, never a register-derived value. See
// docs/paper/PLAN_bpf_ringbuf risk register entry "Verifier rejects
// bpf_ringbuf_reserve with non-constant size".
func captureWithRingbuf(eventsFD int, isFexit bool, maxCapLen int) asm.Instructions {
	if maxCapLen <= 0 {
		maxCapLen = defaultCapLen
	}
	reserveSize := int32(metadataSize + maxCapLen)

	insns := asm.Instructions{
		// --- kernel_ts_ns = bpf_ktime_get_ns() ---
		// Saved on stack before any other helper call so the R0
		// return from bpf_ringbuf_reserve doesn't clobber it.
		// stack[-56] is below the args[] slot at -48 used by fexit
		// for arg fetching.
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R10, -56, asm.R0, asm.DWord),

		// cpu_id at stack[-16] overwrites the filter scratch lookup
		// key (line above) — both are u32 and the key is dead after
		// the filter_result label.
		asm.FnGetSmpProcessorId.Call(),
		asm.StoreMem(asm.R10, -16, asm.R0, asm.Word),
	}
	insns = append(insns, emitShardedRBReserve(eventsFD, reserveSize)...)
	insns = append(insns,
		// --- Write kernel_ts_ns into slot[0..8] ---
		asm.LoadMem(asm.R1, asm.R10, -56, asm.DWord),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
	)

	// --- Write action+mode metadata at slot[8..14] ---
	if isFexit {
		insns = append(insns,
			asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord),
			asm.LoadMem(asm.R2, asm.R2, 8, asm.DWord), // args[1] = XDP action
			asm.StoreMem(asm.R0, 8, asm.R2, asm.Word),
			asm.StoreImm(asm.R0, 12, 1, asm.Byte), // mode = 1 (exit)
		)
	} else {
		insns = append(insns,
			asm.StoreImm(asm.R0, 8, 0, asm.Word),
			asm.StoreImm(asm.R0, 12, 0, asm.Byte),
		)
	}
	insns = append(insns,
		asm.StoreImm(asm.R0, 13, 0, asm.Byte), // _pad
	)

	// --- copy_size = min(pkt_len, maxCapLen) → caplen field + save ---
	insns = append(insns,
		asm.Mov.Reg(asm.R3, asm.R9),
		asm.JLE.Imm(asm.R3, int32(maxCapLen), "rb_cap_ok"),
		asm.Mov.Imm(asm.R3, int32(maxCapLen)),
		asm.StoreMem(asm.R10, -40, asm.R3, asm.Word).WithSymbol("rb_cap_ok"),
		asm.StoreMem(asm.R0, 14, asm.R3, asm.Half),
	)

	// --- bpf_probe_read_kernel(R0 + 16, copy_size, packet_ptr) ---
	insns = append(insns,
		asm.Mov.Reg(asm.R1, asm.R0), asm.Add.Imm(asm.R1, int32(metadataSize)),
		asm.Mov.Reg(asm.R2, asm.R3),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.FnProbeReadKernel.Call(),
	)

	// --- bpf_ringbuf_submit(reservation_ptr, RingbufSubmitFlags) ---
	// Same flag plumbing as captureXDPNative — must honour
	// --no-wakeup uniformly across attach modes (the CLI flag
	// promises "every ringbuf submit", and the R22 sharded-ringbuf
	// hoist brought the tracing path under the same fast-reader as
	// XDP-native).
	insns = append(insns,
		asm.LoadMem(asm.R1, asm.R10, -32, asm.DWord),
		asm.Mov.Imm(asm.R2, int32(RingbufSubmitFlags)),
		asm.FnRingbufSubmit.Call(),
	)
	return insns
}

// buildArgFilter generates eBPF instructions to filter based on function arguments.
// Arguments are accessed from the fentry/fexit args array stored at stack[-48].
//
// The args array layout for fentry is:
//
//	args[0] = first parameter (xdp_buff *)
//	args[1] = second parameter
//	args[N] = N+1th parameter
//
// For each filter, we load the argument value and compare it.
// If any filter doesn't match, we jump to "exit".
func buildArgFilter(filters []filter.ArgFilter) asm.Instructions {
	if len(filters) == 0 {
		return nil
	}

	var insns asm.Instructions
	// Load args pointer once — R2 is not clobbered by subsequent loads/compares.
	insns = append(insns, asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord))

	for _, f := range filters {
		offset := int16(f.ParamIndex * 8)

		var loadSize asm.Size
		switch f.ParamSize {
		case 1:
			loadSize = asm.Byte
		case 2:
			loadSize = asm.Half
		case 4:
			loadSize = asm.Word
		default:
			loadSize = asm.DWord
		}
		insns = append(insns, asm.LoadMem(asm.R3, asm.R2, offset, loadSize))

		// Byte/Half/Word loads zero-extend into R3. For signed parameters we must
		// sign-extend to 64-bit so that JSLT/JSGT comparisons work correctly
		// (e.g. int8 -1 is loaded as 0xFF and must become 0xFFFFFFFFFFFFFFFF).
		if f.Signed && f.ParamSize < 8 {
			shift := int32((8 - f.ParamSize) * 8) // bits to shift
			insns = append(insns,
				asm.LSh.Imm(asm.R3, shift),
				asm.ArSh.Imm(asm.R3, shift),
			)
		}

		// Select unsigned or signed jump ops based on parameter signedness.
		jLT, jGT := asm.JLT, asm.JGT
		if f.Signed {
			jLT, jGT = asm.JSLT, asm.JSGT
		}

		switch f.Op {
		case filter.OpEqual:
			insns = appendCmpJump(insns, asm.JNE, f.Value)
		case filter.OpGreaterEqual:
			insns = appendCmpJump(insns, jLT, f.Value)
		case filter.OpLessEqual:
			insns = appendCmpJump(insns, jGT, f.Value)
		case filter.OpRange:
			insns = appendCmpJump(insns, jLT, f.Value)
			insns = appendCmpJump(insns, jGT, f.MaxValue)
		}
	}

	return insns
}

// appendCmpJump appends a conditional jump-to-exit comparing R3 against value.
// Uses an immediate operand when the value fits in int32, otherwise loads into R4.
func appendCmpJump(insns asm.Instructions, op asm.JumpOp, value uint64) asm.Instructions {
	if value <= 0x7FFFFFFF {
		return append(insns, op.Imm(asm.R3, int32(value), "exit"))
	}
	return append(insns,
		asm.LoadImm(asm.R4, int64(value), asm.DWord),
		op.Reg(asm.R3, asm.R4, "exit"),
	)
}
