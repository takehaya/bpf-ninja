package inject

import (
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

func TestSubprogramSiteCtxRegister(t *testing.T) {
	testSubprogramSiteCtx(t, "register", "r6")
}

func TestSubprogramSiteCtxSlot(t *testing.T) {
	testSubprogramSiteCtx(t, "slot", "fp-16")
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

func TestSubprogramSiteCtxDeadSkipped(t *testing.T) {
	spec := subprogramLookupFixture("dead")
	req := autoReq()
	req.Stack.LowestOffset = -16
	_, plan, err := transformLookupProgram(spec.Programs["p"].Instructions, ebpf.XDP, nil, elfLookupMaps(spec), req)
	if err == nil || len(plan.skipped) != 1 || !strings.Contains(plan.skipped[0].Reason, "context is not held") {
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
	if err != nil || len(sites) != 1 || sites[0].Reason != "function is used as a callback" {
		t.Fatalf("sites=%+v err=%v", sites, err)
	}
}

func TestSubprogramCallerWithoutCtxSkipped(t *testing.T) {
	spec := subprogramLookupFixture("register")
	insns := spec.Programs["p"].Instructions
	insns = append(insns[:1], append(asm.Instructions{asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8)}, insns[1:]...)...)
	spec.Programs["p"].Instructions = insns
	sites, err := discoverLookups(spec, "p")
	if err != nil || len(sites) != 1 || !strings.HasPrefix(sites[0].Reason, "a caller does not pass the context") {
		t.Fatalf("sites=%+v err=%v", sites, err)
	}
}

func TestSubprogramStaticHookSkipped(t *testing.T) {
	spec := subprogramLookupFixture("register")
	req := autoReq()
	req.Stack.LowestOffset, req.Dispatch, req.StaticUntrusted, req.Entry = -16, true, true, true
	plan, err := transformLookup(spec, req)
	if err != nil || len(plan.skipped) != 1 || plan.skipped[0].Reason != "site in a callee frame needs a global hook; static hook form" {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
}
