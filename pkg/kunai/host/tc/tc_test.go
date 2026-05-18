package tc

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestActionsMapMatchesUAPI pins the Actions map to the verdicts
// declared in uapi/linux/pkt_cls.h. A drift would silently
// mis-resolve `where action == TC_ACT_*` predicates at runtime.
func TestActionsMapMatchesUAPI(t *testing.T) {
	want := map[string]int32{
		"TC_ACT_UNSPEC":     -1,
		"TC_ACT_OK":         0,
		"TC_ACT_RECLASSIFY": 1,
		"TC_ACT_SHOT":       2,
		"TC_ACT_PIPE":       3,
		"TC_ACT_STOLEN":     4,
		"TC_ACT_QUEUED":     5,
		"TC_ACT_REPEAT":     6,
		"TC_ACT_REDIRECT":   7,
		"TC_ACT_TRAP":       8,
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

// TestFexitFetcherEmitFetchShape pins the 2-insn shape the fexit
// ActionFetcher emits for tc. Mirrors the xdp adapter's contract.
func TestFexitFetcherEmitFetchShape(t *testing.T) {
	insns := FexitFetcher().EmitFetch(asm.R3)
	if len(insns) != 2 {
		t.Fatalf("EmitFetch returned %d insns, want 2", len(insns))
	}

	got := insns[0]
	want := asm.LoadMem(asm.R3, asm.R10, -48, asm.DWord)
	if got.OpCode != want.OpCode || got.Dst != want.Dst || got.Src != want.Src || got.Offset != want.Offset {
		t.Errorf("insn[0] = %+v, want %+v (load tracing args ptr from stack[-48])", got, want)
	}

	got = insns[1]
	want = asm.LoadMem(asm.R3, asm.R3, 8, asm.Word)
	if got.OpCode != want.OpCode || got.Dst != want.Dst || got.Src != want.Src || got.Offset != want.Offset {
		t.Errorf("insn[1] = %+v, want %+v (load args[1] = TC verdict)", got, want)
	}
}

// TestFexitFetcherEmitFetchHonorsDstReg pins dst register threading.
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

// TestFexitCapabilities pins the Capabilities struct shape for tc.
func TestFexitCapabilities(t *testing.T) {
	caps := FexitCapabilities()
	if caps.Action == nil {
		t.Fatal("Capabilities.Action is nil")
	}
	if len(caps.Action) != len(Actions) {
		t.Errorf("caps.Action has %d entries, want %d", len(caps.Action), len(Actions))
	}
	if caps.ActionFetcher == nil {
		t.Fatal("Capabilities.ActionFetcher is nil")
	}
	insns := caps.ActionFetcher.EmitFetch(asm.R3)
	if len(insns) != 2 {
		t.Errorf("caps.ActionFetcher.EmitFetch returned %d insns, want 2", len(insns))
	}
}
