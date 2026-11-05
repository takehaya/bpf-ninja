package ctxflow

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestProve(t *testing.T) {
	ctx := &btf.Struct{Name: "xdp_md", Size: 24}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	fn := func(name string, linkage btf.FuncLinkage, ctxParam int, head asm.Instruction) asm.Instruction {
		params := make([]btf.FuncParam, ctxParam+1)
		for i := range params {
			params[i] = btf.FuncParam{Name: "n", Type: i32}
		}
		params[ctxParam] = btf.FuncParam{Name: "ctx", Type: &btf.Pointer{Target: ctx}}
		return btf.WithFuncMetadata(head.WithSymbol(name), &btf.Func{Name: name, Linkage: linkage,
			Type: &btf.FuncProto{Return: i32, Params: params}})
	}
	fixture := func(entryHead, midExtra asm.Instructions) asm.Instructions {
		entry := asm.Instructions{
			fn("entry", btf.GlobalFunc, 0, asm.Mov.Reg(asm.R2, asm.R1)),
		}
		entry = append(entry, entryHead...)
		entry = append(entry, asm.Call.Label("mid"), asm.Mov.Imm(asm.R0, 0), asm.Return())
		mid := asm.Instructions{
			fn("mid", btf.StaticFunc, 1, asm.Mov.Reg(asm.R6, asm.R2)),
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		}
		mid = append(mid, midExtra...)
		mid = append(mid, asm.LoadImm(asm.R1, 0, asm.DWord), asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
			asm.Mov.Reg(asm.R1, asm.R6), asm.Call.Label("leaf"), asm.Mov.Imm(asm.R0, 0), asm.Return())
		leaf := asm.Instructions{
			fn("leaf", btf.StaticFunc, 0, asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord)),
			asm.LoadImm(asm.R1, 0, asm.DWord), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return(),
		}
		return append(append(entry, mid...), leaf...)
	}
	find := func(insns asm.Instructions, function string, nth int) int {
		inside := ""
		for it := insns.Iterate(); it.Next(); {
			if f := btf.FuncMetadata(it.Ins); f != nil {
				inside = f.Name
			}
			if inside == function && it.Ins.IsBuiltinCall() {
				if nth == 0 {
					return int(it.Offset)
				}
				nth--
			}
		}
		return -1
	}

	t.Run("call chain and held sources", func(t *testing.T) {
		insns := fixture(nil, nil)
		functions := functions(insns, ctx)
		if len(functions) != 3 || functions[0].Name != "entry" || functions[1].CtxParam != 1 || functions[2].CtxParam != 0 {
			t.Fatalf("functions = %+v", functions)
		}
		proofs := Prove(insns, ctx)
		for _, function := range functions {
			if proof := proofs[function.Start]; !proof.Proven {
				t.Errorf("%s: %+v", function.Name, proof)
			}
		}
		midPC, leafPC := find(insns, "mid", 0), find(insns, "leaf", 0)
		if reg, slot, ok := HeldAt(proofs[functions[1].Start].States[midPC]); !ok || reg != asm.R6 || slot != 0 {
			t.Errorf("mid HeldAt = %v,%d,%v", reg, slot, ok)
		}
		if reg, slot, ok := HeldAt(proofs[functions[2].Start].States[leafPC]); !ok || reg != 0 || slot != -16 {
			t.Errorf("leaf HeldAt = %v,%d,%v", reg, slot, ok)
		}
		if reason := CallsRefusal(insns, "leaf"); reason != "" {
			t.Fatalf("CallsRefusal: %s", reason)
		}
		bad := append(asm.Instructions(nil), insns...)
		for i := range bad {
			if bad[i].IsFunctionCall() && bad[i].Reference() == "leaf" {
				bad[i-1] = asm.Mov.Imm(asm.R1, 0)
				break
			}
		}
		if reason := CallsRefusal(bad, "leaf"); !strings.Contains(reason, "a caller does not pass the context") {
			t.Fatalf("wrong call accepted: %q", reason)
		}
		if reason := CallsRefusal(insns, "absent"); !strings.Contains(reason, "absent") {
			t.Fatalf("missing target reason = %q", reason)
		}
	})

	t.Run("global function is an independent context root", func(t *testing.T) {
		insns := fixture(asm.Instructions{asm.Mov.Imm(asm.R2, 0)}, nil)
		for i := range insns {
			if function := btf.FuncMetadata(&insns[i]); function != nil && function.Name == "mid" {
				function.Linkage = btf.GlobalFunc
				break
			}
		}
		functions := functions(insns, ctx)
		proof := Prove(insns, ctx)[functions[1].Start]
		if !proof.Proven {
			t.Fatalf("global function depends on a local caller: %s", proof.Reason)
		}
		pc := find(insns, "mid", 0)
		if reg, slot, ok := HeldAt(proof.States[pc]); !ok || reg != asm.R6 || slot != 0 {
			t.Fatalf("global HeldAt = %v,%d,%v", reg, slot, ok)
		}
	})

	for _, field := range []string{"constant", "offset"} {
		t.Run("translated numeric calls in "+field, func(t *testing.T) {
			insns := fixture(nil, nil)
			symbols := map[string]int{}
			for it := insns.Iterate(); it.Next(); {
				if symbol := it.Ins.Symbol(); symbol != "" {
					symbols[symbol] = int(it.Offset)
				}
			}
			for it := insns.Iterate(); it.Next(); {
				if !it.Ins.IsFunctionCall() || it.Ins.Reference() == "" {
					continue
				}
				rel := symbols[it.Ins.Reference()] - int(it.Offset) - 1
				if field == "constant" {
					it.Ins.Constant = int64(rel)
				} else {
					it.Ins.Offset = int16(rel)
					it.Ins.Constant = 0
				}
				*it.Ins = it.Ins.WithReference("")
			}
			functions := functions(insns, ctx)
			for _, function := range functions {
				if proof := Prove(insns, ctx)[function.Start]; !proof.Proven {
					t.Errorf("%s: %+v", function.Name, proof)
				}
			}
		})
	}

	for _, tc := range []struct {
		name      string
		entryHead asm.Instructions
		midExtra  asm.Instructions
		function  int
		want      string
	}{
		{"callback", asm.Instructions{(asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R3, Src: asm.PseudoFunc}).WithReference("mid")}, nil, 1, "function is used as a callback"},
		{"caller without ctx", asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP)}, nil, 1, "a caller does not pass the context (entry@"},
		{"r11 stack argument", nil, asm.Instructions{asm.StoreMem(regParams, -8, asm.R1, asm.DWord)}, 1, "function passes a stack argument through r11"},
		{"indirect jump", nil, asm.Instructions{{OpCode: asm.Ja.Op(asm.RegSource), Dst: asm.R7}}, 1, "indirect jump"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			insns := fixture(tc.entryHead, tc.midExtra)
			functions := functions(insns, ctx)
			proof := Prove(insns, ctx)[functions[tc.function].Start]
			if proof.Proven || !strings.Contains(proof.Reason, tc.want) {
				t.Fatalf("proof = %+v, want reason containing %q", proof, tc.want)
			}
		})
	}

	t.Run("entry context is not first", func(t *testing.T) {
		insns := fixture(nil, nil)
		entry := btf.FuncMetadata(&insns[0])
		proto := entry.Type.(*btf.FuncProto)
		proto.Params = append([]btf.FuncParam{{Name: "n", Type: i32}}, proto.Params...)
		functions := functions(insns, ctx)
		proof := Prove(insns, ctx)[functions[0].Start]
		if proof.Proven || proof.Reason != "entry function has no context first parameter" {
			t.Fatalf("proof = %+v", proof)
		}
	})

	t.Run("context dead at site", func(t *testing.T) {
		insns := fixture(nil, asm.Instructions{asm.Mov.Imm(asm.R6, 0)})
		functions := functions(insns, ctx)
		proof := Prove(insns, ctx)[functions[1].Start]
		if !proof.Proven {
			t.Fatal(proof.Reason)
		}
		pc := find(insns, "mid", 0)
		if _, _, ok := HeldAt(proof.States[pc]); ok {
			t.Fatal("dead context reported as held")
		}
	})

	for _, source := range []string{"register", "slot"} {
		t.Run("join drops overwritten "+source, func(t *testing.T) {
			entry := asm.Instructions{
				fn("entry", btf.GlobalFunc, 0, asm.Call.Label("sub")),
				asm.Mov.Imm(asm.R0, 0), asm.Return(),
			}
			var head, overwrite asm.Instruction
			if source == "register" {
				head = asm.Mov.Reg(asm.R6, asm.R1)
				overwrite = asm.Mov.Imm(asm.R6, 0)
			} else {
				head = asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord)
				overwrite = asm.StoreImm(asm.RFP, -12, 0, asm.Word)
			}
			sub := asm.Instructions{
				fn("sub", btf.StaticFunc, 0, head),
				asm.JEq.Imm(asm.R0, 0, "good"), overwrite, asm.Ja.Label("join"),
				asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("good"),
				asm.LoadImm(asm.R1, 0, asm.DWord).WithSymbol("join"),
				asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
				asm.FnMapLookupElem.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return(),
			}
			insns := append(entry, sub...)
			functions := functions(insns, ctx)
			proof := Prove(insns, ctx)[functions[1].Start]
			if !proof.Proven {
				t.Fatal(proof.Reason)
			}
			pc := find(insns, "sub", 0)
			if reg, slot, ok := HeldAt(proof.States[pc]); ok {
				t.Fatalf("overwritten context survived join: reg=%v slot=%d", reg, slot)
			}
		})
	}

	t.Run("static hook call refuses overwritten join", func(t *testing.T) {
		entry := asm.Instructions{
			fn("entry", btf.GlobalFunc, 0, asm.Call.Label("sub")),
			asm.Mov.Imm(asm.R0, 0), asm.Return(),
		}
		sub := asm.Instructions{
			fn("sub", btf.StaticFunc, 0, asm.Mov.Reg(asm.R6, asm.R1)),
			asm.JEq.Imm(asm.R0, 0, "good"), asm.Mov.Imm(asm.R6, 0), asm.Ja.Label("join"),
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("good"),
			asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("join"), asm.Call.Label("hook"),
			asm.Mov.Imm(asm.R0, 0), asm.Return(),
		}
		hook := asm.Instructions{
			fn("hook", btf.StaticFunc, 0, asm.Mov.Imm(asm.R0, 0)), asm.Return(),
		}
		if reason := CallsRefusal(append(append(entry, sub...), hook...), "hook"); !strings.Contains(reason, "a caller does not pass the context") {
			t.Fatalf("static hook join accepted: %q", reason)
		}
	})
}
