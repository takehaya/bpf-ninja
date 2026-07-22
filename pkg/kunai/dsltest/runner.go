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
	prog       *ebpf.Program
	scratchMap *ebpf.Map
	expr       string
}

// New compiles dslExpr against the bundled vocabulary and loads the
// resulting filter into a standalone XDP wrapper. Skips the test
// when not running as root (BPF_PROG_TEST_RUN requires CAP_SYS_ADMIN).
// Verifier failures are reported as t.Fatalf so the test surfaces
// the kernel's diagnostic log, not a generic "load failed".
func New(t *testing.T, dslExpr string) *Runner {
	t.Helper()
	return newWithCompiler(t, dslExpr, func() (codegen.Output, error) {
		return kunai.Compile(dslExpr, codegen.Capabilities{})
	})
}

// NewWithVocab is New against a caller-supplied vocabulary map —
// used by tests that exercise codegen on synthetic .p4 inputs
// without having to add them to the bundled vocab.
func NewWithVocab(t *testing.T, dslExpr string, v map[string]*vocab.ProtocolSpec) *Runner {
	t.Helper()
	return newWithCompiler(t, dslExpr, func() (codegen.Output, error) {
		return kunai.CompileWithVocab(dslExpr, v, codegen.Capabilities{})
	})
}

func newWithCompiler(t *testing.T, dslExpr string, compile func() (codegen.Output, error)) *Runner {
	t.Helper()
	skipIfNotRoot(t)

	out, err := compile()
	if err != nil {
		t.Fatalf("kunai.Compile(%q): %v", dslExpr, err)
	}

	scratch, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "dslt_sc",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  scratchSize,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create scratch map: %v", err)
	}

	insns := buildXDPWrapper(out, scratch.FD())
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "dslt_filter",
		Type:         ebpf.XDP,
		Instructions: insns,
		License:      "GPL",
	})
	if err != nil {
		_ = scratch.Close()
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier:\n%+v", ve)
		}
		t.Fatalf("load XDP for %q: %v", dslExpr, err)
	}

	t.Cleanup(func() {
		_ = prog.Close()
		_ = scratch.Close()
	})

	return &Runner{prog: prog, scratchMap: scratch, expr: dslExpr}
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
func buildXDPWrapper(filterOut codegen.Output, scratchFD int) asm.Instructions {
	const (
		stackKey     = int16(-16)
		stackScratch = int16(-24)
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

		// Hand off to the kunai filter: R0=scratch, R1=scratch+len,
		// R9=pkt_len.
		asm.LoadMem(asm.R0, asm.R10, stackScratch, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.JLE.Imm(asm.R1, int32(scratchSize), "filter_len_ok"),
		asm.Mov.Imm(asm.R1, int32(scratchSize)),
		asm.Add.Reg(asm.R1, asm.R0).WithSymbol("filter_len_ok"),
	}

	insns = append(insns, filterOut.Main...)

	insns = append(insns,
		// filter_result is where the kunai filter falls through. R2
		// holds 1 (match) or 0 (no match).
		asm.JEq.Imm(asm.R2, 0, "drop").WithSymbol("filter_result"),
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
