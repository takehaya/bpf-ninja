// Package dsltest provides an end-to-end harness for byte-level
// validation of kunai's DSL → BPF compilation. It compiles a DSL
// expression with the standard kunai pipeline, wraps the output in a
// minimal standalone XDP test program (per-CPU scratch map +
// bpf_xdp_load_bytes copy), loads it via cilium/ebpf, and exposes
// Match(packet) on top of BPF_PROG_TEST_RUN. Tests use it to
// verify that gopacket-built frames are accepted/rejected exactly
// as the DSL describes — i.e. that vocab parser declarations,
// codegen, and verifier semantics agree on real packet bytes.
package dsltest

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// skipIfNotRoot skips when the test is not running as root (the
// BPF_PROG_TEST_RUN ioctl requires CAP_SYS_ADMIN). Inlined here so
// pkg/kunai/dsltest stays self-contained and can be vendored as a
// kunai-test helper without pulling in bpf-ninja-internal packages.
func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
}

// scratchSize is shared with the host adapters via codegen.ScratchBufSize
// so the per-CPU scratch map and the kunai filter agree on the bound
// the verifier proves.
const scratchSize = codegen.ScratchBufSize

// fakeArgsSize is the tracing-args block the wrapper fakes after the
// packet prefix for exit-host filters (args[0], args[1]).
const fakeArgsSize = 16

// XDP retval constants (uapi/linux/bpf.h XDP_* values). Tests use
// them as the truth table when asserting Match outcomes.
const (
	XDPAborted = 0
	XDPDrop    = 1
	XDPPass    = 2
)

// Runner owns a loaded XDP test program plus its scratch map and
// runs gopacket-built packet bytes through it via
// BPF_PROG_TEST_RUN. Cleanup is scheduled on the *testing.T that
// constructed it, so callers don't need to Close() it explicitly.
type Runner struct {
	prog        *ebpf.Program
	scratchMap  *ebpf.Map
	keyMap      *ebpf.Map
	extractions []codegen.ExtractSlot
	expr        string
}

// Set keys: the wrapper zeroes the host's key region [setKeyLow,
// setKeyLow+16) before the filter, as bpf-ninja's hosts do, and copies it
// into the key map at filter_result together with a flag saying the
// filter reached it, so a test can read the bytes an `in @set` predicate
// wrote (MatchKey, SetKey).
const (
	setKeyLow       = int16(-40)
	keyRegionSize   = 16
	keyValueSize    = keyRegionSize + 8 // region, then the reached flag
	keyReachedField = keyRegionSize
)

// Target is the attachment the runner emulates. Caps shapes the compiled
// filter (packet layout, action vocabulary, VLAN in metadata, the host's
// ActionFetcher); Action is the return value of the traced program that
// an exit-host filter reads (`where action == XDP_DROP`). The filter only
// ever sees the scratch copy of the packet, so every target runs on the
// same XDP wrapper; the wrapper presents Action the way the bpf-ninja
// fexit programs do (see buildXDPWrapper), so the host's own fetcher is
// what the verifier checks.
type Target struct {
	Caps   codegen.Capabilities
	Action int32
}

// New compiles dslExpr against the bundled vocabulary for the default
// target (XDP entry) and loads the resulting filter into a standalone XDP
// wrapper. Skips the test when not running as root (BPF_PROG_TEST_RUN
// requires CAP_SYS_ADMIN). Verifier failures are reported as t.Fatalf so
// the test surfaces the kernel's diagnostic log, not a generic "load
// failed".
func New(t *testing.T, dslExpr string) *Runner {
	t.Helper()
	return NewOn(t, dslExpr, Target{})
}

// NewOn is New for another target: the filter is compiled with tg.Caps
// and the wrapper presents tg.Action. Compile errors are reported before
// the root check, so they surface on any machine.
func NewOn(t *testing.T, dslExpr string, tg Target) *Runner {
	t.Helper()
	out, err := kunai.Compile(dslExpr, tg.Caps)
	if err != nil {
		t.Fatalf("kunai.Compile(%q): %v", dslExpr, err)
	}
	return NewFromOutput(t, dslExpr, out, tg.Action)
}

// NewWithVocab is New against a caller-supplied vocabulary map —
// used by tests that exercise codegen on synthetic .p4 inputs
// without having to add them to the bundled vocab.
func NewWithVocab(t *testing.T, dslExpr string, v map[string]*vocab.ProtocolSpec) *Runner {
	t.Helper()
	out, err := kunai.CompileWithVocab(dslExpr, v, codegen.Capabilities{})
	if err != nil {
		t.Fatalf("kunai.CompileWithVocab(%q): %v", dslExpr, err)
	}
	return NewFromOutput(t, dslExpr, out, 0)
}

// NewFromOutput loads an already compiled filter into the XDP wrapper,
// which presents `action` as the traced program's return value. dslExpr
// only labels failures. Skips when not root (BPF_PROG_TEST_RUN needs
// CAP_SYS_ADMIN).
func NewFromOutput(t *testing.T, dslExpr string, out codegen.Output, action int32) *Runner {
	t.Helper()
	return newFromOutput(t, dslExpr, out, action, nil)
}

// NewFromOutputStackFilled is NewFromOutput with kunai's whole stack
// region (KunaiStackTop down to the 512-byte bottom) filled with `fill`
// before the filter runs. A filter that reads a slot it never wrote then
// sees that value instead of whatever the wrapper left there; running a
// vector under two different fills catches such a read.
func NewFromOutputStackFilled(t *testing.T, dslExpr string, out codegen.Output, action int32, fill int32) *Runner {
	t.Helper()
	return newFromOutput(t, dslExpr, out, action, &fill)
}

func newFromOutput(t *testing.T, dslExpr string, out codegen.Output, action int32, fill *int32) *Runner {
	t.Helper()
	skipIfNotRoot(t)

	scratch, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dslt_sc",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  scratchSize + fakeArgsSize,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create scratch map: %v", err)
	}

	keys, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dslt_key",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  keyValueSize,
		MaxEntries: 1,
	})
	if err != nil {
		_ = scratch.Close()
		t.Fatalf("create key map: %v", err)
	}

	insns := buildXDPWrapper(out, scratch.FD(), keys.FD(), action, fill)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "dslt_filter",
		Type:         ebpf.XDP,
		Instructions: insns,
		License:      "GPL",
	})
	if err != nil {
		_ = scratch.Close()
		_ = keys.Close()
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier:\n%+v", ve)
		}
		t.Fatalf("load XDP for %q: %v", dslExpr, err)
	}

	t.Cleanup(func() {
		_ = prog.Close()
		_ = scratch.Close()
		_ = keys.Close()
	})

	return &Runner{prog: prog, scratchMap: scratch, keyMap: keys, extractions: out.Extractions, expr: dslExpr}
}

// Match runs the filter against pkt and reports whether the verdict
// is XDP_PASS (= the DSL expression matched). Any other verdict is
// reported as a no-match. Errors from Run abort the test.
func (r *Runner) Match(t *testing.T, pkt []byte) bool {
	t.Helper()
	ret, _, err := r.prog.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test (%q): %v", r.expr, err)
	}
	switch ret {
	case XDPPass:
		return true
	case XDPDrop, XDPAborted:
		return false
	}
	t.Fatalf("unexpected XDP verdict %d for %q", ret, r.expr)
	return false
}

// MatchKey is Match that also returns the host's set key region as the
// filter left it at filter_result: 16 bytes, the first at fp-40. The
// region is zeroed before the filter, so bytes no predicate wrote read 0.
func (r *Runner) MatchKey(t *testing.T, pkt []byte) (bool, [keyRegionSize]byte) {
	t.Helper()
	var region [keyRegionSize]byte
	if err := r.keyMap.Put(uint32(0), make([]byte, keyValueSize)); err != nil {
		t.Fatalf("reset key map: %v", err)
	}
	matched := r.Match(t, pkt)
	value := make([]byte, keyValueSize)
	if err := r.keyMap.Lookup(uint32(0), &value); err != nil {
		t.Fatalf("read key map: %v", err)
	}
	if value[keyReachedField] != 1 {
		t.Fatalf("%q: the filter did not reach filter_result", r.expr)
	}
	copy(region[:], value[:keyRegionSize])
	return matched, region
}

// SetKey cuts set's key out of a region MatchKey returned: the bytes the
// filter wrote for it, from its lowest extraction slot to the end of its
// highest, in stack order (scalar fields native-endian, 16-byte fields in
// network order, as the hosts' `set add` writes them). For a scalar set
// that is the host's whole key; a composite key's unwritten fields, which
// the host's key size would cover, are left out. nil when the filter
// extracts no key for set.
func (r *Runner) SetKey(t *testing.T, region [keyRegionSize]byte, set string) []byte {
	t.Helper()
	lo, hi := int16(0), int16(0)
	found := false
	for _, x := range r.extractions {
		if x.SetName != set {
			continue
		}
		end := x.StackOff + int16(x.StoreSize)
		if !found || x.StackOff < lo {
			lo = x.StackOff
		}
		if !found || end > hi {
			hi = end
		}
		found = true
	}
	if !found {
		return nil
	}
	if lo < setKeyLow || hi > setKeyLow+keyRegionSize {
		t.Fatalf("set %s: key at [%d, %d) lies outside the key region [%d, %d)", set, lo, hi, setKeyLow, setKeyLow+keyRegionSize)
	}
	return append([]byte(nil), region[lo-setKeyLow:hi-setKeyLow]...)
}

// MustMatch fails the test when the filter rejects pkt. why is a
// short caller-supplied phrase explaining what shape was expected to
// match (e.g. "GTP-U with 2 ext headers"); it appears verbatim in
// the failure message so the report points straight at the case.
func (r *Runner) MustMatch(t *testing.T, pkt []byte, why string) {
	t.Helper()
	if !r.Match(t, pkt) {
		t.Fatalf("expected match (%s)", why)
	}
}

// MustReject is the negation of MustMatch: fails when the filter
// accepts pkt.
func (r *Runner) MustReject(t *testing.T, pkt []byte, why string) {
	t.Helper()
	if r.Match(t, pkt) {
		t.Fatalf("expected reject (%s)", why)
	}
}

// buildXDPWrapper assembles the test program: load packet pointers,
// copy a prefix into a scratch map, set up R0/R1/R9 to match the
// kunai filter ABI, run the filter, then translate R2 into XDP_PASS
// / XDP_DROP. Stack layout for the wrapper itself stays inside
// (-1, codegen.KunaiStackTop) so it cannot collide with kunai.
//
// The wrapper also reproduces how the bpf-ninja fexit programs present
// the traced program's return value, so an exit-host filter's own
// ActionFetcher runs under the verifier: a pointer to the tracing args
// block is saved at fp-48 and the return value sits in args[1] (the host
// packages' fexitFetcher, internal/program's fexit layout). The block is
// faked in the scratch value right after the packet prefix (the filter
// never reads past ScratchBufSize), with `action` in args[1]; the host
// stack slots [-40, -24) hold set keys, as on the real hosts: zeroed
// before the filter, copied into the key map at filter_result.
func buildXDPWrapper(filterOut codegen.Output, scratchFD, keyFD int, action int32, fill *int32) asm.Instructions {
	const (
		stackVerdict = int16(-8)
		stackKey     = int16(-16)
		stackScratch = int16(-24)
		stackArgsPtr = int16(-48)
	)

	insns := asm.Instructions{
		// R6 = ctx, R7 = ctx->data (u32 → PTR_TO_PACKET via verifier),
		// R8 = ctx->data_end, R9 = pkt_len.
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R7, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, 4, asm.Word),
		asm.Mov.Reg(asm.R9, asm.R8),
		asm.Sub.Reg(asm.R9, asm.R7),

		// Look up scratch[0]. NULL → drop (shouldn't happen on a
		// per-CPU array but the verifier insists on the check).
		asm.LoadMapPtr(asm.R1, scratchFD),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, int32(stackKey)),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.StoreMem(asm.R10, stackScratch, asm.R0, asm.DWord),

		// Fake tracing args after the packet prefix: args[1] = action
		// (read as a u32), pointer at fp-48.
		asm.Mov.Reg(asm.R2, asm.R0),
		asm.Add.Imm(asm.R2, int32(scratchSize)),
		asm.Mov.Imm(asm.R3, action),
		asm.StoreMem(asm.R2, 8, asm.R3, asm.DWord),
		asm.StoreMem(asm.R10, stackArgsPtr, asm.R2, asm.DWord),

		// Compute capped copy length: min(pkt_len, scratchSize). The
		// verifier rejects bpf_xdp_load_bytes when R4's umin can be
		// 0 (helper expects ARG_CONST_SIZE, not _OR_ZERO), so an
		// empty packet drops here before the helper call. The
		// `JLT R4, 1` after JLE clamping is the load-bearing umin
		// pin: kernel 6.1 / 6.6 don't propagate umin ≥ 1 from the
		// JEq R9, 0 above through `Mov R4, R9` + JLE clamp, but a
		// JLT against a strict imm narrows the fall-through range
		// to [1, ∞) directly. Newer kernels (6.12+) accept either
		// form; the JLT is the cross-version-safe spelling.
		asm.JEq.Imm(asm.R9, 0, "drop"),
		asm.Mov.Reg(asm.R4, asm.R9),
		asm.JLE.Imm(asm.R4, int32(scratchSize), "load_len_ok"),
		asm.Mov.Imm(asm.R4, int32(scratchSize)),

		// bpf_xdp_load_bytes(R6=ctx, R2=0, R3=scratch, R4=len).
		asm.JLT.Imm(asm.R4, 1, "drop").WithSymbol("load_len_ok"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.LoadMem(asm.R3, asm.R10, stackScratch, asm.DWord),
		asm.FnXdpLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "drop"),
	}
	if fill != nil {
		// Fill kunai's stack region with the pattern (an imm32 Mov sign-
		// extends, so -1 is all ones), down to the deepest slot the filter
		// itself addresses: going further would grow the frame, which the
		// verifier limits together with any bpf_loop callback's.
		insns = append(insns, asm.Mov.Imm(asm.R2, *fill))
		for off := int16(codegen.KunaiStackTop); off >= deepestStackSlot(filterOut.Main); off -= 8 {
			insns = append(insns, asm.StoreMem(asm.R10, off, asm.R2, asm.DWord))
		}
	}
	insns = append(insns,
		// The set key region starts zeroed, as the hosts' emitPktSetKeyZeroing
		// leaves it.
		asm.Mov.Imm(asm.R3, 0),
		asm.StoreMem(asm.R10, setKeyLow, asm.R3, asm.DWord),
		asm.StoreMem(asm.R10, setKeyLow+8, asm.R3, asm.DWord),
		// Hand off to the kunai filter: R0=scratch, R1=scratch+len,
		// R9=pkt_len.
		asm.LoadMem(asm.R0, asm.R10, stackScratch, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.JLE.Imm(asm.R1, int32(scratchSize), "filter_len_ok"),
		asm.Mov.Imm(asm.R1, int32(scratchSize)),
		asm.Add.Reg(asm.R1, asm.R0).WithSymbol("filter_len_ok"),
	)

	insns = append(insns, filterOut.Main...)

	insns = append(insns,
		// filter_result is where the kunai filter falls through. R2
		// holds 1 (match) or 0 (no match). Park it, copy the set key
		// region and the reached flag into the key map, then decide.
		asm.StoreMem(asm.R10, stackVerdict, asm.R2, asm.DWord).WithSymbol("filter_result"),
		asm.Mov.Imm(asm.R3, 0),
		asm.StoreMem(asm.R10, stackKey, asm.R3, asm.Word),
		asm.LoadMapPtr(asm.R1, keyFD),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, int32(stackKey)),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "key_done"),
		asm.LoadMem(asm.R3, asm.R10, setKeyLow, asm.DWord),
		asm.StoreMem(asm.R0, 0, asm.R3, asm.DWord),
		asm.LoadMem(asm.R3, asm.R10, setKeyLow+8, asm.DWord),
		asm.StoreMem(asm.R0, 8, asm.R3, asm.DWord),
		asm.StoreImm(asm.R0, keyReachedField, 1, asm.Byte),
		asm.LoadMem(asm.R2, asm.R10, stackVerdict, asm.DWord).WithSymbol("key_done"),
		asm.JEq.Imm(asm.R2, 0, "drop"),
		asm.Mov.Imm(asm.R0, XDPPass),
		asm.Return(),
		asm.Mov.Imm(asm.R0, XDPDrop).WithSymbol("drop"),
		asm.Return(),
	)

	if len(filterOut.Callbacks) > 0 {
		insns[0] = btf.WithFuncMetadata(insns[0], codegen.MainFilterFuncBTF("kunai_dsltest_filter"))
		insns = append(insns, filterOut.Callbacks...)
	}

	return insns
}

// deepestStackSlot is the lowest 8-byte-aligned R10 offset an instruction
// of insns loads from or stores to (KunaiStackTop when none goes below it).
func deepestStackSlot(insns asm.Instructions) int16 {
	low := int16(codegen.KunaiStackTop)
	for _, ins := range insns {
		cls := ins.OpCode.Class()
		if !cls.IsLoad() && !cls.IsStore() {
			continue
		}
		if (cls.IsLoad() && ins.Src == asm.R10) || (cls.IsStore() && ins.Dst == asm.R10) {
			if off := ins.Offset &^ 7; off < low {
				low = off
			}
		}
	}
	return low
}
