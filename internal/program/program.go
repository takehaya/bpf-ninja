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
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"golang.org/x/net/bpf"
)

// Probe は fentry/fexit のトレーシングポイント群。単一ターゲットなら
// progs/links は1要素、multi-attach (複数の (prog, func) ペア) では
// 各ペアに1本ずつ載り、全プローブが同じ sharded ringbuf に emit する。
type Probe struct {
	EventsMap *ebpf.Map
	InnerMaps []*ebpf.Map // non-nil only in per-CPU sharded mode
	IsFexit   bool
	Warnings  []string // resolver / codegen non-fatal notices; CLI prints to stderr

	// --arg-echo diagnostic mode: non-nil EchoRing means this probe emits
	// the target function's integer args (EchoParams, in order) to a
	// dedicated ringbuf instead of capturing packets.
	EchoRing   *ebpf.Map
	EchoParams []attach.FuncParamInfo

	maps  []*ebpf.Map
	progs []*ebpf.Program // one per attached (target prog, func) pair
	links []link.Link     // parallel to progs
}

// Program returns the first underlying tracing program. Exposed so that
// benchmarks (E2 / B2) can call Program.Test() to measure the per-
// packet runtime cost of the filter via BPF_PROG_TEST_RUN. Not
// intended for general callers — production code should manipulate
// the probe through Close() / EventsMap.
func (p *Probe) Program() *ebpf.Program {
	if len(p.progs) == 0 {
		return nil
	}
	return p.progs[0]
}

// AttachCount reports how many (target prog, func) pairs this probe is
// attached to.
func (p *Probe) AttachCount() int {
	return len(p.links)
}

func (p *Probe) Close() error {
	var errs []error
	for _, l := range p.links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, pr := range p.progs {
		if err := pr.Close(); err != nil {
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
// useDSL=true のとき filterExpr は bpf-ninja DSL として解釈される。
// 単一ターゲット用の互換ラッパ (bare *ebpf.Program から Target を合成
// して loadMulti に委譲)。本番 CLI 経路は LoadMultiEntry/Exit を使う。
func LoadEntry(targetProg *ebpf.Program, funcName string, filterExpr string, argFilters []filter.ArgFilter, useDSL bool) (*Probe, error) {
	return loadProbe(targetProg, funcName, filterExpr, argFilters, false, useDSL)
}

// LoadExit は fexit (後段) probe を作成してアタッチする。
// useDSL=true のとき filterExpr は bpf-ninja DSL として解釈される。
func LoadExit(targetProg *ebpf.Program, funcName string, filterExpr string, argFilters []filter.ArgFilter, useDSL bool) (*Probe, error) {
	return loadProbe(targetProg, funcName, filterExpr, argFilters, true, useDSL)
}

func loadProbe(targetProg *ebpf.Program, funcName string, filterExpr string, argFilters []filter.ArgFilter, isFexit, useDSL bool) (*Probe, error) {
	progType, err := validateTracingTarget(targetProg)
	if err != nil {
		return nil, err
	}
	targets := []attach.Target{{Program: targetProg, FuncName: funcName, Type: progType}}
	return loadMulti(targets, filterExpr, []filter.TargetFilters{{Args: argFilters}}, isFexit, useDSL, nil)
}

// LoadMultiEntry attaches one fentry per (program, func) target, all
// emitting into a single shared sharded ringbuf, so a multi-stage
// dispatcher's per-direction capture points (UL + DL v4 + DL v6) are
// captured in one run and merge into one time-ordered pcap.
//
// filters is parallel to targets (nil, or one entry per target): the
// same param name can sit at a different arg index in different funcs, so
// arg filters and set-key bindings must be resolved against each target's
// own BTF params.
func LoadMultiEntry(targets []attach.Target, filterExpr string, filters []filter.TargetFilters, useDSL bool, sets []*setmap.Set) (*Probe, error) {
	return loadMulti(targets, filterExpr, filters, false, useDSL, sets)
}

// LoadMultiExit is LoadMultiEntry for fexit (sees the return action).
func LoadMultiExit(targets []attach.Target, filterExpr string, filters []filter.TargetFilters, useDSL bool, sets []*setmap.Set) (*Probe, error) {
	return loadMulti(targets, filterExpr, filters, true, useDSL, sets)
}

// loadMulti builds the shared capture infrastructure once (filter compile,
// sharded ringbuf, scratch map — all of which depend only on the program
// type, not the individual target) and then attaches one tracing program
// per (target prog, func) pair against it.
func loadMulti(targets []attach.Target, filterExpr string, filters []filter.TargetFilters, isFexit, useDSL bool, sets []*setmap.Set) (*Probe, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no attach targets")
	}
	if filters != nil && len(filters) != len(targets) {
		return nil, fmt.Errorf("filters length %d does not match %d targets", len(filters), len(targets))
	}
	progType := targets[0].Type
	h, ok := hook.ByProgramType(progType)
	if !ok {
		return nil, hook.UnsupportedTypeError(progType)
	}
	// Same-hook, not same-progType: SchedCLS and SchedACT targets share
	// the tc hook (identical prologue and capabilities) and may mix.
	for _, t := range targets[1:] {
		th, tok := hook.ByProgramType(t.Type)
		if !tok {
			return nil, hook.UnsupportedTypeError(t.Type)
		}
		if th != h {
			return nil, fmt.Errorf("mixed target hooks (%s and %s); attach one bpf-ninja per hook", h.Kind, th.Kind)
		}
	}

	// DSL `field in @set` extracts packet fields into a host key buffer;
	// build the slot resolver so kunai emits the extraction stores.
	var slots *pktSetSlots
	if len(sets) > 0 {
		slots = newPktSetSlots(sets)
	}
	filterOut, err := compileFilterWithSlots(filterExpr, useDSL, isFexit, progType, slots)
	if slots != nil && slots.allocErr() != nil {
		return nil, slots.allocErr() // clearer than the downstream codegen error
	}
	if err != nil {
		return nil, err
	}
	pktRefs := referencedSets(filterOut.Extractions)
	if SnaplenOverride > 0 {
		filterOut.Capture.MaxCapLen = SnaplenOverride
	}

	label, attachType := tracingLabel(isFexit)

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

	// Instructions are built per target: the packet-filter part depends
	// only on progType and the shared maps, but arg-filter offsets are
	// resolved against each target func's own BTF param layout.
	for i, t := range targets {
		var tf filter.TargetFilters
		if filters != nil {
			tf = filters[i]
		}
		insns, err := buildTracingInsns(filterOut, tf, outerMap.FD(), scratchFD, isFexit, progType, slots, pktRefs)
		if err != nil {
			_ = probe.Close()
			return nil, err
		}
		if err := attachTracingProbe(probe, t.Program, fmt.Sprintf("bpf_ninja_%s", label), t.FuncName, attachType, insns); err != nil {
			return nil, err
		}
	}
	return probe, nil
}

// validateTracingTarget checks targetProg is a type bpf-ninja can attach a
// fentry/fexit probe to, returning its program type.
func validateTracingTarget(targetProg *ebpf.Program) (ebpf.ProgramType, error) {
	info, err := targetProg.Info()
	if err != nil {
		return 0, fmt.Errorf("reading target program info: %w", err)
	}
	pt := info.Type
	if _, ok := hook.ByProgramType(pt); !ok {
		return 0, hook.UnsupportedTypeError(pt)
	}
	return pt, nil
}

// tracingLabel maps entry/exit to the short label (used in map/program
// names) and the BPF tracing attach type.
func tracingLabel(isFexit bool) (string, ebpf.AttachType) {
	if isFexit {
		return "exit", ebpf.AttachTraceFExit
	}
	return "entry", ebpf.AttachTraceFEntry
}

// attachTracingProbe loads insns as a Tracing program named `name`,
// attaches it to funcName on targetProg, and appends prog+link to probe.
// Callable multiple times to build up a multi-attach probe; on failure it
// closes probe (unwinding maps and any attaches already made).
// Shared by loadMulti (capture) and LoadArgEcho (diagnostic).
func attachTracingProbe(probe *Probe, targetProg *ebpf.Program, name, funcName string, attachType ebpf.AttachType, insns asm.Instructions) error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: name, Type: ebpf.Tracing, AttachType: attachType,
		AttachTo: funcName, AttachTarget: targetProg,
		Instructions: insns, License: "GPL",
	})
	if err != nil {
		_ = probe.Close()
		return fmt.Errorf("loading %s (%s) program: %w", name, funcName, err)
	}
	probe.progs = append(probe.progs, prog)

	l, err := link.AttachTracing(link.TracingOptions{Program: prog, AttachType: attachType})
	if err != nil {
		_ = probe.Close()
		return fmt.Errorf("attaching %s to %s: %w", name, funcName, err)
	}
	probe.links = append(probe.links, l)
	return nil
}

// --- Filter compilation ---
//
// Two paths share the runFilter contract (R0=scratch start, R1=scratch
// end, filter sets R2 and ends at "filter_result"):
//
//   useDSL=false: tcpdump expression → cBPF → eBPF via cbpfc (default)
//   useDSL=true:  bpf-ninja DSL → eBPF via kunai.Compile
//
// See docs/ja/dsl-overview.md for the DSL doc index. The codegen
// ABI this wrapper plugs into is documented in
// pkg/kunai/codegen/codegen.go (KunaiStackTop and the package doc).

func compileFilter(expr string, useDSL, isFexit bool, progType ebpf.ProgramType) (codegen.Output, error) {
	return compileFilterWithSlots(expr, useDSL, isFexit, progType, nil)
}

// compileFilterWithSlots is compileFilter plus a DSL set-slot resolver:
// when non-nil it lets `field in @set` predicates extract packet fields
// into host stack slots (the host does the map lookup afterward).
func compileFilterWithSlots(expr string, useDSL, isFexit bool, progType ebpf.ProgramType, slots *pktSetSlots) (codegen.Output, error) {
	// Empty expression == capture everything: no filter to compile,
	// callers wrap the zero Output with their own prologue/epilogue.
	// Centralised here so attach modes (entry/exit/xdp) don't
	// each reimplement the empty-filter policy and drift apart.
	if expr == "" {
		return codegen.Output{}, nil
	}
	if useDSL {
		// fexit attaches see the host retval at args[1] (XDP action
		// or TC verdict, ABI shared); fentry has no action value yet,
		// so action atoms are disabled. The bpf-ninja host wrapper saves
		// the tracing args ptr at stack[-48] in either case, which is
		// exactly the ABI every FexitFetcher implementation expects.
		// Per-hook capability details (action vocab, VLAN layout) live
		// in the internal/hook registry entries.
		var caps codegen.Capabilities
		if h, ok := hook.ByProgramType(progType); ok {
			if isFexit {
				caps = h.FexitCaps()
			} else {
				caps = h.EntryCaps()
			}
		}
		// DSL `field in @set`: hand kunai the host slot resolver so it can
		// extract packet fields into the host key buffer (host does the map
		// lookup after the filter — kunai stays map-agnostic).
		if slots != nil {
			caps.Lang.SetSlots = slots
		}
		out, err := kunai.Compile(expr, caps)
		if err != nil {
			return out, fmt.Errorf("DSL filter compile failed: %w\n\nhint: %s",
				err, dslHintFor(expr))
		}
		return out, nil
	}
	// Compile against the hook's link type: on an L3-start hook
	// (LinkTypeRaw) libpcap then resolves `ip` / `tcp port 80` at the
	// right offsets and rejects L2 atoms like `ether host` on its own.
	linkType := layers.LinkTypeEthernet
	if h, ok := hook.ByProgramType(progType); ok {
		linkType = h.LinkType
	}
	rawInsns, err := pcap.CompileBPFFilter(linkType, 65535, expr)
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
//   -57..-120: set filter のキーバッファ (emitSetFilters; runFilter の
//              前で死ぬ。kunai は KunaiStackTop=-56 以深を所有するが
//              それは runFilter 内のみ live — phase ordering で共存)
//
// 実際の on-wire フォーマットの正典は internal/capture/capture.go の
// コメント。現行は ringbuf reserve/submit で 20B のメタデータヘッダを
// パケットの前に置く:
//   [metadata (20B)] [パケットデータ (caplen B)]
//   metadata: u64 kernel_ts_ns + u32 action + u8 mode + u8 _pad
//             + u16 caplen + u32 tag

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
	metadataSize = 20
)

func buildTracingInsns(filterOut codegen.Output, tf filter.TargetFilters, eventsFD, scratchFD int, isFexit bool, progType ebpf.ProgramType, slots *pktSetSlots, pktRefs []string) (asm.Instructions, error) {
	var insns asm.Instructions
	prelude, err := loadPacketPointers(progType)
	if err != nil {
		return nil, err
	}
	insns = append(insns, prelude...)
	// Default the tag to 0 before any set lookup can overwrite it, so a
	// captured packet that matched no set (or a set-less filter) reports 0.
	insns = append(insns, emitTagSlotZero()...)
	insns = append(insns, buildArgFilter(tf.Args)...)
	insns = append(insns, emitSetFilters(tf.Sets)...)
	// DSL `field in @set`: zero the packet-key buffer, run the filter
	// (kunai extracts fields into it), then look each referenced set up
	// (miss → skip capture). ANDs with arg filters and the kunai verdict.
	if slots != nil {
		insns = append(insns, slots.emitPktSetKeyZeroing(pktRefs)...)
	}
	insns = append(insns, runFilter(filterOut.Main, scratchFD, filterScanLen(filterOut))...)
	if slots != nil {
		insns = append(insns, slots.emitPktSetLookups(pktRefs)...)
	}
	insns = append(insns, captureWithRingbuf(eventsFD, isFexit, filterOut.Capture.MaxCapLen)...)
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	// bpf2bpf subprograms (currently only DSL bpf_loop chain
	// callbacks) live after the tracing body so they sit past the
	// program's final Return. The kernel also needs BTF func_info
	// for the outer program in that case — tag the first tracing
	// insn with codegen's canonical func proto.
	if len(filterOut.Callbacks) > 0 {
		insns[0] = btf.WithFuncMetadata(insns[0], codegen.MainFilterFuncBTF("bpf_ninja_filter"))
		insns = append(insns, filterOut.Callbacks...)
	}
	return insns, nil
}

// loadPacketPointers は tracing args の args[0] (= host-specific
// packet ctx) から packet 先頭・末尾・長さを host 別に読み出す。
// trusted pointer (BTF 型付き) として trampoline が保証してくれる。
// host 別の実体は internal/hook の各 PacketPrologue。
//
// 終了時: R6=ctx, R7=data, R8=data_end, R9=pkt_len, stack[-48]=args
func loadPacketPointers(progType ebpf.ProgramType) (asm.Instructions, error) {
	h, ok := hook.ByProgramType(progType)
	if !ok {
		return nil, hook.UnsupportedTypeError(progType)
	}
	return h.PacketPrologue()
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
//	stack[-8]  = u64 tag slot (low 32 bits = set-map value, 0 if none)
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

	// --- Write tag metadata at slot[16..20] (0 unless a set matched) ---
	// tagSlot is a full 8-byte slot; the low 32 bits go into the u32 field.
	insns = append(insns,
		asm.LoadMem(asm.R1, asm.R10, tagSlot, asm.DWord),
		asm.StoreMem(asm.R0, 16, asm.R1, asm.Word),
	)

	// --- bpf_probe_read_kernel(R0 + 20, copy_size, packet_ptr) ---
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
// emitArgLoad loads a size-byte integer arg at base+offset into dst,
// sign-extending sub-word signed values to 64-bit. Byte/Half/Word loads
// zero-extend into dst; for signed params the LSh/ArSh pair widens the
// sign bit so JSLT/JSGT comparisons and int64 rendering are correct (e.g.
// int8 -1 loaded as 0xFF becomes 0xFFFFFFFFFFFFFFFF). Shared by the
// arg-filter gate and the arg-echo emitter so the sign-extend invariant
// lives in one place.
func emitArgLoad(dst, base asm.Register, offset int16, size uint32, signed bool) asm.Instructions {
	insns := asm.Instructions{asm.LoadMem(dst, base, offset, asmSizeFor(size))}
	if signed && size < 8 {
		shift := int32((8 - size) * 8)
		insns = append(insns, asm.LSh.Imm(dst, shift), asm.ArSh.Imm(dst, shift))
	}
	return insns
}

// asmSizeFor maps a 1/2/4/8-byte width to the matching load/store size.
func asmSizeFor(n uint32) asm.Size {
	switch n {
	case 1:
		return asm.Byte
	case 2:
		return asm.Half
	case 4:
		return asm.Word
	}
	return asm.DWord
}

func buildArgFilter(filters []filter.ArgFilter) asm.Instructions {
	if len(filters) == 0 {
		return nil
	}

	var insns asm.Instructions
	// Load args pointer once — R2 is not clobbered by subsequent loads/compares.
	insns = append(insns, asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord))

	for _, f := range filters {
		offset := int16(f.ParamIndex * 8)
		insns = append(insns, emitArgLoad(asm.R3, asm.R2, offset, f.ParamSize, f.Signed)...)

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

// setKeyBase is the stack offset of the set-filter key buffer:
// fp-120..fp-57, sized for setmap.MaxKeySize (64 B). It is written and
// consumed strictly before runFilter jumps into the packet filter, whose
// kunai codegen owns everything at/below KunaiStackTop (-56) — temporal
// reuse, not a partition (see the stack layout comment above).
const setKeyBase = -120

// emitSetFilters emits one pinned-map membership check per set filter:
// zero the key buffer (hash maps hash every key byte including padding,
// and the verifier requires the full key range initialized), build each
// key field from the target function's args, then bpf_map_lookup_elem —
// a NULL result jumps to "exit" (skip capture), so multiple sets and
// plain arg-filters AND together naturally.
func emitSetFilters(sets []filter.SetFilter) asm.Instructions {
	var insns asm.Instructions
	for _, s := range sets {
		// Only zero the key buffer when the fields leave padding gaps: hash
		// maps hash every key byte, and the verifier requires the full key
		// range initialized. Gapless keys (every scalar key, and structs
		// that tile [0,KeySize)) have every byte overwritten by the field
		// stores below, so the zeroing is pure per-packet waste there.
		if keyHasGaps(s) {
			// No 64-bit store-immediate in the BPF ISA — zero via a register.
			insns = append(insns, asm.Mov.Imm(asm.R3, 0))
			for off := 0; off < int(s.KeySize); off += 8 {
				insns = append(insns, asm.StoreMem(asm.R10, int16(setKeyBase+off), asm.R3, asm.DWord))
			}
		}

		// R2 = tracing args ptr (reload per set: lookup clobbers R0-R5, and
		// no callee-saved register is free — R6-R9 hold the capture prelude).
		insns = append(insns, asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord))
		for _, f := range s.Fields {
			// Load at param width, sign-extending signed params so a
			// narrow negative arg fills the wider key field the same way a
			// signed value written into the map would (ParamSize <=
			// FieldSize is enforced at resolve time); store at field width.
			insns = append(insns, emitArgLoad(asm.R3, asm.R2, int16(f.ParamIdx*8), f.ParamSize, f.ParamSigned)...)
			insns = append(insns, asm.StoreMem(asm.R10, int16(setKeyBase+int(f.FieldOff)), asm.R3, asmSizeFor(f.FieldSize)))
		}

		insns = append(insns, emitSetLookup(s.Map.FD(), setKeyBase, int(s.Map.ValueSize()))...)
	}
	return insns
}

// tagSlot holds the matched set's value (the tag) between the set lookup
// and the capture epilogue that writes it into the metadata. It is a full
// 8-byte slot at -8 (a sub-register 4-byte stack fill is rejected by the
// 6.1 verifier as "invalid size of register fill"), used by nobody else:
// clear of the pkt-key buffer ([-40,-24)), the epilogue slots
// (-16/-32/-40/-48/-56), and kunai's region (KunaiStackTop=-56). Always
// zeroed in the prelude so the no-set path yields tag 0.
const tagSlot = -8

// emitTagSlotZero defaults tagSlot to 0 (no 64-bit store-immediate in the
// BPF ISA, so zero via a register).
func emitTagSlotZero() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Imm(asm.R3, 0),
		asm.StoreMem(asm.R10, tagSlot, asm.R3, asm.DWord),
	}
}

// emitSetLookup emits the shared membership tail: look the pinned map
// (mapFD) up with the key at R10+keyOff; a NULL result jumps to "exit"
// (skip capture), so stacked lookups AND together. On a hit it copies the
// map value (the tag, tagSize bytes at value offset 0) into tagSlot so the
// capture epilogue can carry it out; stacked lookups store in source order,
// so the last matched set wins. tagSize is the map's value width (1/2/4/8);
// narrow loads zero-extend and an 8-byte value keeps only its low 32 bits
// when written to the u32 metadata field. Clobbers R0-R5. Shared by the
// arg-based emitSetFilters and the packet-based emitPktSetLookups
// (setslots.go).
func emitSetLookup(mapFD int, keyOff int16, tagSize int) asm.Instructions {
	insns := asm.Instructions{
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, int32(keyOff)),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
	}
	// R0 = value ptr (non-NULL past the jump). Read the tag only for the
	// exact loadable widths; an externally-pinned map with an odd value
	// size (3/5/6/7) would over-read (asmSizeFor rounds up to DWord) and
	// fail the verifier, so such a hit contributes tag 0. Either way this
	// matched set WRITES tagSlot, so last-match-wins stays deterministic:
	// an odd-sized last set does not silently inherit an earlier set's tag.
	// Narrow loads zero-extend R1, so the DWord store is correct for all.
	switch tagSize {
	case 1, 2, 4, 8:
		insns = append(insns, asm.LoadMem(asm.R1, asm.R0, 0, asmSizeFor(uint32(tagSize))))
	default:
		insns = append(insns, asm.Mov.Imm(asm.R1, 0))
	}
	insns = append(insns, asm.StoreMem(asm.R10, tagSlot, asm.R1, asm.DWord))
	return insns
}

// keyHasGaps reports whether the set's key has any byte not covered by a
// field (padding), which must be zeroed for a correct hash lookup. Fields
// are laid out in ascending offset order by resolution.
func keyHasGaps(s filter.SetFilter) bool {
	var covered uint32
	for _, f := range s.Fields {
		if f.FieldOff != covered {
			return true // hole before this field
		}
		covered += f.FieldSize
	}
	return covered != s.KeySize // trailing padding
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
