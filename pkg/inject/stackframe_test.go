package inject

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestStackFrameDepth(t *testing.T) {
	ptr := asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8)}
	for _, tc := range []struct {
		name string
		code asm.Instructions
		want int
	}{
		{"direct", asm.Instructions{asm.StoreImm(asm.RFP, -32, 0, asm.Word)}, 32},
		{"load", asm.Instructions{asm.LoadMem(asm.R0, asm.R2, -16, asm.Word)}, 24},
		{"store", asm.Instructions{asm.StoreImm(asm.R2, -24, 0, asm.Word)}, 32},
		{"copy-sub", asm.Instructions{asm.Mov.Reg(asm.R3, asm.R2), asm.Sub.Imm(asm.R3, 32), asm.StoreImm(asm.R3, -8, 0, asm.Word)}, 48},
		{"lookup", asm.Instructions{asm.FnMapLookupElem.Call()}, 8},
		{"delete", asm.Instructions{asm.FnMapDeleteElem.Call()}, 8},
		{"update", asm.Instructions{asm.Mov.Reg(asm.R3, asm.R2), asm.Add.Imm(asm.R3, -8), asm.FnMapUpdateElem.Call()}, 16},
		{"xdp-load", asm.Instructions{asm.Mov.Reg(asm.R3, asm.R2), asm.Mov.Imm(asm.R2, 0), asm.FnXdpLoadBytes.Call()}, 8},
		{"call-clobber", asm.Instructions{asm.FnMapLookupElem.Call(), asm.Add.Imm(asm.R2, -200)}, 8},
		{"saved-register", asm.Instructions{asm.Mov.Reg(asm.R6, asm.R2), asm.FnMapLookupElem.Call(), asm.StoreImm(asm.R6, -8, 0, asm.Word)}, 16},
		{"overwrite", asm.Instructions{asm.Mov.Imm(asm.R2, 0), asm.Add.Imm(asm.R2, -200)}, 8},
		{"load-overwrite", asm.Instructions{asm.LoadMem(asm.R2, asm.R2, -8, asm.Word), asm.Add.Imm(asm.R2, -200)}, 16},
		{"spill", asm.Instructions{asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord)}, 240},
		{"escape-store", asm.Instructions{asm.StoreMem(asm.R1, 0, asm.R2, asm.DWord)}, 240},
		{"callee", asm.Instructions{asm.Call.Label("sub")}, 240},
		{"unknown-helper", asm.Instructions{asm.FnProbeReadKernel.Call()}, 240},
		{"wrong-helper-arg", asm.Instructions{asm.FnXdpLoadBytes.Call()}, 240},
		{"variable-add", asm.Instructions{asm.Add.Reg(asm.R2, asm.R1)}, 240},
		{"alu32", asm.Instructions{asm.Add.Imm32(asm.R2, -8)}, 240},
		{"mov32", asm.Instructions{asm.Mov.Reg32(asm.R3, asm.R2)}, 240},
		{"branch", asm.Instructions{asm.JEq.Imm(asm.R1, 0, "end"), asm.Mov.Imm(asm.R2, 0), asm.Return().WithSymbol("end")}, 240},
		{"return-pointer", asm.Instructions{asm.Mov.Reg(asm.R0, asm.R2), asm.Return()}, 240},
		{"too-negative", asm.Instructions{asm.Add.Imm(asm.R2, -512)}, 240},
		{"positive", asm.Instructions{asm.Add.Imm(asm.R2, 16)}, 240},
		{"direct-past-audit", asm.Instructions{asm.StoreImm(asm.RFP, -256, 0, asm.Word), asm.Call.Label("sub")}, 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := append(append(asm.Instructions{}, ptr...), tc.code...)
			if got := stackFrameDepth(code, -240); got != tc.want {
				t.Fatalf("depth %d, want %d", got, tc.want)
			}
		})
	}
}

func TestStackFrameBlockEntries(t *testing.T) {
	// A jump into an alias sequence bypasses its definition. LDIMM64 also
	// checks that numeric targets use raw slots, rather than slice indices.
	for _, symbolic := range []bool{false, true} {
		jump := asm.JEq.Imm(asm.R1, 0, "")
		jump.Offset = 3
		if symbolic {
			jump = asm.JEq.Imm(asm.R1, 0, "use")
		}
		code := asm.Instructions{jump, asm.LoadImm(asm.R3, 1, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8).WithSymbol("use"), asm.FnMapLookupElem.Call()}
		if got := stackFrameDepth(code, -240); got != 240 {
			t.Fatalf("symbolic=%t: depth %d, want audit fallback", symbolic, got)
		}
	}
	// Distinct blocks can each consume their own aliases before branching.
	code := asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "again"), asm.Mov.Reg(asm.R2, asm.RFP).WithSymbol("again"),
		asm.Add.Imm(asm.R2, -16), asm.FnMapLookupElem.Call()}
	if got := stackFrameDepth(code, -240); got != 16 {
		t.Fatalf("depth %d, want 16", got)
	}
}

// Like stack_bound.bpf.c: a 240-byte entry updates a map, then calls a leaf
// that passes its own stack key to lookup. Only the entry is instrumented.
func stackBoundFixture(leaf int16) *ebpf.CollectionSpec {
	spec := lookupFixture()
	spec.Programs["p"].Instructions = asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("p").WithSource(asm.Comment("deep entry")), xdpFunc("p")),
		asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.RFP, -240, asm.R0, asm.DWord),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.Mov.Imm(asm.R4, 0), asm.FnMapUpdateElem.Call(),
		asm.Call.Label("leaf"), asm.Mov.Imm(asm.R0, 2), asm.Return(),
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("leaf").WithSource(asm.Comment("leaf key")), staticFunc("leaf")),
		asm.StoreMem(asm.RFP, -leaf, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -int32(leaf)),
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R0, 0), asm.Return(),
	}
	return spec
}

func stackBoundRequest(dispatch bool) LookupRequest {
	return LookupRequest{ProgramName: "p", Auto: true, Lookups: LookupNone, Updates: CallAny,
		Dispatch: dispatch, StaticUntrusted: true, HookName: "obs", Stack: StackAudit{LowestOffset: -240}}
}

func TestStackBoundShallowLeaf(t *testing.T) {
	for _, dispatch := range []bool{false, true} {
		work := stackBoundFixture(8)
		plan, err := transformLookup(work, stackBoundRequest(dispatch))
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.hooks) != 1 || len(plan.skipped) != 0 {
			t.Fatalf("want the update hook without skips: %+v", plan)
		}
		funcs, err := stackCallGraph(work.Programs["p"].Instructions, -240)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, fn := range funcs {
			if fn.name == "leaf" && fn.depth == 8 {
				found = true
			}
		}
		if !found {
			t.Fatalf("leaf frame: %+v", funcs)
		}
	}
}

func TestStackBoundUnusedPointerStillCountsSpills(t *testing.T) {
	before := stackBoundFixture(248).Programs["p"].Instructions
	// Formation alone does not grow the verifier's frame, but our model
	// counts it. Equal estimates must not hide the entry's new spill slots.
	before = append(before[:1:1], append(asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -320), asm.Mov.Imm(asm.R2, 0),
	}, before[1:]...)...)
	after := append(before[:1:1], append(asm.Instructions{asm.StoreImm(asm.RFP, -288, 0, asm.Word)}, before[1:]...)...)
	if err := checkStackLimits(before, after, -248); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "512-byte combined limit") {
		t.Fatalf("want changed entry chain refusal, got %v", err)
	}
}
