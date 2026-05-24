package xdp

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestActionsMapMatchesUAPI pins the Actions map to the integer
// verdicts declared in uapi/linux/bpf.h. A drift here would silently
// mis-resolve `where action == XDP_*` predicates against the wrong
// verdict at runtime; the verifier would still accept the program.
func TestActionsMapMatchesUAPI(t *testing.T) {
	want := map[string]int32{
		"XDP_ABORTED":  0,
		"XDP_DROP":     1,
		"XDP_PASS":     2,
		"XDP_TX":       3,
		"XDP_REDIRECT": 4,
	}
	if len(Actions) != len(want) {
		t.Fatalf("Actions has %d entries, want %d", len(Actions), len(want))
	}
	for name, wantCode := range want {
		got, ok := Actions[name]
		if !ok {
			t.Errorf("Actions missing %q", name)
			continue
		}
		if got != wantCode {
			t.Errorf("Actions[%q] = %d, want %d", name, got, wantCode)
		}
	}
}

// TestFexitFetcherEmitFetchShape pins the exact 2-instruction shape
// the fexit ActionFetcher emits. The host wrapper's stack contract
// (tracing args pointer at stack[-48], args[1] = XDP retval at +8)
// is load-bearing for `where action == XDP_*` predicates; a silent
// off-by-one in either offset would compile cleanly but read the
// wrong byte at runtime.
func TestFexitFetcherEmitFetchShape(t *testing.T) {
	insns := FexitFetcher().EmitFetch(asm.R3)
	if len(insns) != 2 {
		t.Fatalf("EmitFetch returned %d insns, want 2", len(insns))
	}

	// insn[0]: LoadMem R3, R10, -48, DWord
	got := insns[0]
	want := asm.LoadMem(asm.R3, asm.R10, -48, asm.DWord)
	if got.OpCode != want.OpCode || got.Dst != want.Dst || got.Src != want.Src || got.Offset != want.Offset {
		t.Errorf("insn[0] = %+v, want %+v (load tracing args ptr from stack[-48])", got, want)
	}

	// insn[1]: LoadMem R3, R3, 8, Word (= args[1] = XDP return value)
	got = insns[1]
	want = asm.LoadMem(asm.R3, asm.R3, 8, asm.Word)
	if got.OpCode != want.OpCode || got.Dst != want.Dst || got.Src != want.Src || got.Offset != want.Offset {
		t.Errorf("insn[1] = %+v, want %+v (load args[1] = XDP retval)", got, want)
	}
}

// TestFexitFetcherEmitFetchHonorsDstReg pins that the dst register
// flows through both loads. Codegen passes various dst registers
// depending on the call site; the fetcher must thread it without
// implicit assumption.
func TestFexitFetcherEmitFetchHonorsDstReg(t *testing.T) {
	for _, dst := range []asm.Register{asm.R0, asm.R3, asm.R5} {
		insns := FexitFetcher().EmitFetch(dst)
		if insns[0].Dst != dst {
			t.Errorf("dst=%v: insn[0].Dst = %v, want %v", dst, insns[0].Dst, dst)
		}
		if insns[1].Dst != dst || insns[1].Src != dst {
			t.Errorf("dst=%v: insn[1] dst/src = %v/%v, want %v/%v", dst, insns[1].Dst, insns[1].Src, dst, dst)
		}
	}
}

// TestFexitCapabilities pins the Capabilities struct shape: Action
// map is the package-level Actions, ActionFetcher is non-nil and
// returns the same 2-insn shape EmitFetch above pins.
func TestFexitCapabilities(t *testing.T) {
	caps := FexitCapabilities()
	if caps.Lang.Action == nil {
		t.Fatal("Capabilities.Lang.Action is nil")
	}
	if len(caps.Lang.Action) != len(Actions) {
		t.Errorf("caps.Lang.Action has %d entries, want %d (matching pkg-level Actions)", len(caps.Lang.Action), len(Actions))
	}
	if caps.Lang.ActionFetcher == nil {
		t.Fatal("Capabilities.Lang.ActionFetcher is nil")
	}
	insns := caps.Lang.ActionFetcher.EmitFetch(asm.R3)
	if len(insns) != 2 {
		t.Errorf("caps.ActionFetcher.EmitFetch returned %d insns, want 2", len(insns))
	}
}
