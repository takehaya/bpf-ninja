package inject

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func subprogramLookupFixture(source string) *ebpf.CollectionSpec {
	spec := lookupFixture()
	entryFn := btf.FuncMetadata(&spec.Programs["p"].Instructions[0])
	ctxType := entryFn.Type.(*btf.FuncProto).Params[0].Type
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	subFn := &btf.Func{Name: "sub", Linkage: btf.StaticFunc, Type: &btf.FuncProto{Return: i32,
		Params: []btf.FuncParam{{Name: "ctx", Type: ctxType}, {Name: "n", Type: i32}}}}
	entry := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R2, 1).WithSymbol("p").WithSource(asm.Comment("entry")), entryFn),
		asm.Call.Label("sub"), asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	var head asm.Instruction
	switch source {
	case "slot":
		head = asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord)
	case "dead":
		head = asm.Mov.Reg(asm.R6, asm.R1)
	default:
		head = asm.Mov.Reg(asm.R6, asm.R1)
	}
	sub := asm.Instructions{
		btf.WithFuncMetadata(head.WithSymbol("sub").WithSource(asm.Comment("sub")), subFn),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
	}
	if source == "dead" {
		sub = append(sub, asm.Mov.Imm(asm.R6, 0))
	}
	sub = append(sub, asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R0, 0), asm.Return())
	spec.Programs["p"].Instructions = append(entry, sub...)
	return spec
}

// subprogramTailLookupFixture has a lookup and tail call in the same static
// subprogram. Adding the lookup hook creates a second subprogram call there.
func subprogramTailLookupFixture() *ebpf.CollectionSpec {
	spec := subprogramLookupFixture("register")
	spec.Maps["jmp"] = &ebpf.MapSpec{Name: "jmp", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1}
	insns := spec.Programs["p"].Instructions
	for i, ins := range insns {
		if !ins.IsBuiltinCall() || asm.BuiltinFunc(ins.Constant) != asm.FnMapLookupElem {
			continue
		}
		tail := asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.R6), asm.LoadMapPtr(asm.R2, 0).WithReference("jmp"),
			asm.Mov.Imm(asm.R3, 0), asm.FnTailCall.Call(),
		}
		spec.Programs["p"].Instructions = append(insns[:i+1], append(tail, insns[i+1:]...)...)
		return spec
	}
	panic("lookup helper not found")
}

func TestSubprogramSiteCtxRegister(t *testing.T) {
	testSubprogramSiteCtx(t, "register", "r6")
}

func TestSubprogramSiteCtxSlot(t *testing.T) {
	testSubprogramSiteCtx(t, "slot", "fp-16")
}

func TestPerFrameSlots(t *testing.T) {
	spec := subprogramLookupFixture("register")
	req := autoReq()
	req.Stack = StackAudit{Frames: map[string]int16{"p": -8, "sub": -168}, Source: "verifier", FrameRounding: 16}
	if _, err := transformLookup(spec, req); err != nil {
		t.Fatal(err)
	}
	insns := spec.Programs["p"].Instructions
	if got, want := insns[0].Offset, int16(lookupSlots(-8).ctx); got != want {
		t.Fatalf("entry ctx slot = %d, want %d", got, want)
	}
	want := int16(lookupSlots(-168).ctx)
	for i, ins := range insns {
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnMapLookupElem) {
			for _, before := range insns[max(0, i-4):i] {
				if before.Dst == asm.RFP && before.Offset == want {
					return
				}
			}
			t.Fatalf("callee prelude before %d does not use ctx slot %d: %v", i, want, insns[max(0, i-4):i])
		}
	}
	t.Fatal("lookup helper not found")
}

func testSubprogramSiteCtx(t *testing.T, source, wantSource string) {
	spec := subprogramLookupFixture(source)
	req := autoReq()
	req.Stack.LowestOffset = -16
	original := append(asm.Instructions(nil), spec.Programs["p"].Instructions...)
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.sites) != 1 || plan.sites[0].CtxSource != wantSource || len(plan.skipped) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	ctx := int16(lookupSlots(req.Stack.LowestOffset).ctx)
	insns := spec.Programs["p"].Instructions
	before, err := stackCallGraph(original, req.Stack.LowestOffset)
	if err != nil {
		t.Fatal(err)
	}
	after, err := stackCallGraph(insns, req.Stack.LowestOffset)
	if err != nil {
		t.Fatal(err)
	}
	depth := func(funcs []stackFunc, name string) int {
		for _, fn := range funcs {
			if fn.name == name {
				return fn.depth
			}
		}
		return -1
	}
	if depth(after, "sub") <= depth(before, "sub") {
		t.Fatalf("subprogram stack depth before=%+v after=%+v", before, after)
	}
	for i, ins := range insns {
		if !ins.IsBuiltinCall() || ins.Constant != int64(asm.FnMapLookupElem) {
			continue
		}
		if source == "slot" {
			if i < 2 || !sameInstr(insns[i-2], asm.LoadMem(asm.R0, asm.RFP, -16, asm.DWord)) ||
				!sameInstr(insns[i-1], asm.StoreMem(asm.RFP, ctx, asm.R0, asm.DWord)) {
				t.Fatalf("slot prelude before %v: %v", ins, insns[max(0, i-3):i])
			}
		} else if i < 1 || !sameInstr(insns[i-1], asm.StoreMem(asm.RFP, ctx, asm.R6, asm.DWord)) {
			t.Fatalf("register prelude before %v: %v", ins, insns[max(0, i-2):i])
		}
		return
	}
	t.Fatal("lookup helper not found")
}

// A static function whose context is dead at the site saves the context it
// receives on entry.
func TestSubprogramSiteCtxDeadSaved(t *testing.T) {
	spec := subprogramLookupFixture("dead")
	req := autoReq()
	req.Stack.LowestOffset = -16
	_, plan, err := transformLookupProgramGuarded(spec.Programs["p"].Instructions, ebpf.XDP, nil, elfLookupMaps(spec), req, nil)
	if err != nil || len(plan.sites) != 1 || len(plan.skipped) != 0 || !strings.HasPrefix(plan.sites[0].CtxSource, "pass:saved-r1@") {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
}

func TestSubprogramCallbackSkipped(t *testing.T) {
	spec := subprogramLookupFixture("register")
	insns := spec.Programs["p"].Instructions
	load := (asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R3, Src: asm.PseudoFunc}).WithReference("sub")
	load.Constant = -1
	insns = append(insns[:1], append(asm.Instructions{load}, insns[1:]...)...)
	spec.Programs["p"].Instructions = insns
	sites, err := discoverLookups(spec, "p")
	if err != nil || len(sites) != 1 || sites[0].Reason != "callback: the function is also called directly; ctx pass: the function is used as a callback" {
		t.Fatalf("sites=%+v err=%v", sites, err)
	}
}

// A caller that passes no context in the context parameter passes it in a
// register the function never reads instead.
func TestSubprogramCallerWithoutCtxPassed(t *testing.T) {
	spec := subprogramLookupFixture("register")
	insns := spec.Programs["p"].Instructions
	insns = append(insns[:1], append(asm.Instructions{asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8)}, insns[1:]...)...)
	spec.Programs["p"].Instructions = insns
	sites, err := discoverLookups(spec, "p")
	if err != nil || len(sites) != 1 || sites[0].Reason != "" || !strings.HasPrefix(sites[0].CtxSource, "pass:r5@") {
		t.Fatalf("sites=%+v err=%v", sites, err)
	}
}

func TestSubprogramStaticHookAccepted(t *testing.T) {
	spec := subprogramLookupFixture("register")
	req := autoReq()
	req.Stack.LowestOffset, req.Dispatch, req.StaticUntrusted, req.Entry = -16, true, true, true
	plan, err := transformLookup(spec, req)
	if err != nil || len(plan.skipped) != 0 || len(plan.sites) != 1 || len(plan.hooks) != 2 || !plan.hooks[0].Static || !plan.hooks[1].Static {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
}

// A generic site in a subprogram with no audited stack floor is skipped, as a
// typed one is: the generic hook does not take a site in an unaudited frame.
func TestPerFrameGenericMissingFloor(t *testing.T) {
	for _, subFloor := range []bool{false, true} {
		spec := subprogramLookupFixture("register")
		m := spec.Maps["sessions"]
		m.Type, m.ValueSize = ebpf.HashOfMaps, 4
		m.Value = &btf.Int{Name: "u32", Size: 4}
		m.InnerMap = &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
		req := autoReq()
		req.Stack = StackAudit{Frames: map[string]int16{"p": -8}, Source: "verifier", FrameRounding: 16}
		if subFloor {
			req.Stack.Frames["sub"] = -168
		}
		plan, err := transformLookup(spec, req)
		if subFloor {
			if err != nil || len(plan.sites) != 1 || !plan.sites[0].Generic {
				t.Fatalf("audited generic site not selected: %+v %v", plan, err)
			}
			continue
		}
		if err == nil || len(plan.sites) != 0 || len(plan.skipped) != 1 || plan.skipped[0].Reason != "stack floor unavailable for this function" {
			t.Fatalf("unaudited generic site not skipped: %+v %v", plan, err)
		}
		// Generic would say Auto still instruments it.
		if plan.skipped[0].Generic {
			t.Fatalf("skipped unaudited site keeps Generic: %+v", plan.skipped[0])
		}
	}
}

// An entry function with no audited floor is refused as such, not as a
// program whose sites were all skipped or as an unusable site.
func TestPerFrameEntryMissingFloor(t *testing.T) {
	for _, auto := range []bool{true, false} {
		spec := lookupFixture()
		req := lookupReq()
		if auto {
			req = autoReq()
		}
		req.Stack = StackAudit{Frames: map[string]int16{}, Source: "verifier", FrameRounding: 16}
		_, err := transformLookup(spec, req)
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), `entry function "p" has no usable stack floor`) {
			t.Fatalf("auto %v: %v", auto, err)
		}
	}
}

// A typed site in a subprogram with no audited floor never falls back to
// Stack.LowestOffset: Auto skips it, and naming it is refused.
func TestPerFrameTypedMissingFloor(t *testing.T) {
	const reason = "stack floor unavailable for this function"
	stack := StackAudit{Frames: map[string]int16{"p": -8}, Source: "verifier", FrameRounding: 16}
	req := autoReq()
	req.Stack = stack
	plan, err := transformLookup(subprogramLookupFixture("register"), req)
	if err == nil || len(plan.sites) != 0 || len(plan.skipped) != 1 || plan.skipped[0].Reason != reason {
		t.Fatalf("auto: unaudited typed site not skipped: %+v %v", plan, err)
	}
	req = lookupReq()
	req.Stack = stack
	if _, err := transformLookup(subprogramLookupFixture("register"), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), reason) {
		t.Fatalf("explicit: unaudited typed site not refused: %v", err)
	}
}
