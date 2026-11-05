package ctxflow

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestProveCallback(t *testing.T) {
	ctx := &btf.Struct{Name: "xdp_md", Size: 24}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	head := func(name string, ins asm.Instruction, linkage btf.FuncLinkage, params ...btf.FuncParam) asm.Instruction {
		return btf.WithFuncMetadata(ins.WithSymbol(name), &btf.Func{Name: name, Linkage: linkage,
			Type: &btf.FuncProto{Return: i32, Params: params}})
	}
	ctxParam := btf.FuncParam{Name: "ctx", Type: &btf.Pointer{Target: ctx}}
	noCtx := btf.FuncParam{Name: "n", Type: i32}
	load := func(name string, dst asm.Register) asm.Instruction {
		return asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: dst, Src: asm.PseudoFunc, Constant: -1}.WithReference(name)
	}
	fp := func(off int32) asm.Instructions {
		return asm.Instructions{asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, off)}
	}
	pass := func(helper asm.BuiltinFunc, r3 asm.Instructions, cb string) asm.Instructions {
		out := append(asm.Instructions{}, r3...)
		return append(out, load(cb, asm.R2), asm.Mov.Imm(asm.R4, 0), helper.Call())
	}
	loop := func(off int32, cb string) asm.Instructions { return pass(asm.FnLoop, fp(off), cb) }
	end := asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
	entry := func(body ...asm.Instructions) asm.Instructions {
		out := asm.Instructions{head("entry", asm.Mov.Reg(asm.R6, asm.R1), btf.GlobalFunc, ctxParam)}
		for _, part := range body {
			out = append(out, part...)
		}
		return append(out, end...)
	}
	callback := func(name string, body ...asm.Instruction) asm.Instructions {
		out := asm.Instructions{head(name, asm.Mov.Imm(asm.R0, 0), btf.StaticFunc, noCtx, noCtx)}
		out = append(out, body...)
		return append(out, asm.Return())
	}
	join := func(parts ...asm.Instructions) asm.Instructions {
		var out asm.Instructions
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	prove := func(insns asm.Instructions, name string) Proof {
		for _, fn := range functions(insns, ctx) {
			if fn.Name == name {
				return Prove(insns, ctx)[fn.Start]
			}
		}
		t.Fatalf("no function %s", name)
		return Proof{}
	}

	for _, tc := range []struct {
		name   string
		insns  asm.Instructions
		helper asm.BuiltinFunc
		param  asm.Register
		arg    int16
	}{
		{"bpf_loop", join(entry(loop(-104, "cb")), callback("cb")), asm.FnLoop, asm.R2, -104},
		{"bpf_for_each_map_elem", join(entry(pass(asm.FnForEachMapElem, fp(-8), "cb")), callback("cb")), asm.FnForEachMapElem, asm.R4, -8},
		{"two calls, same X", join(entry(loop(-16, "cb"), loop(-16, "cb")), callback("cb")), asm.FnLoop, asm.R2, -16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := prove(tc.insns, "cb")
			want := Callback{Helper: tc.helper, Param: tc.param, Arg: tc.arg}
			if proof.Proven || proof.Callback == nil || *proof.Callback != want {
				t.Fatalf("proof = %+v, want callback %+v and not Proven", proof, want)
			}
		})
	}

	r3Var := asm.Instructions{asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16), asm.Add.Reg(asm.R3, asm.R7)}
	branchIn := asm.JEq.Imm(asm.R7, 0, "")
	branchIn.Offset = 2 // skips the second R3, into the middle of the first's block
	ontoCall := asm.JEq.Imm(asm.R7, 0, "")
	ontoCall.Offset = 5 // over the R3 setup, the function pointer and r4 = 0
	for _, tc := range []struct {
		name  string
		insns asm.Instructions
		cb    string
		want  string
	}{
		{"two X", join(entry(loop(-16, "cb"), loop(-24, "cb")), callback("cb")), "cb", "different callback contexts"},
		{"two helpers", join(entry(loop(-16, "cb"), pass(asm.FnForEachMapElem, fp(-16), "cb")), callback("cb")), "cb", "different helpers"},
		{"variable X", join(entry(pass(asm.FnLoop, r3Var, "cb")), callback("cb")), "cb", "not R10 plus a constant"},
		{"NULL", join(entry(pass(asm.FnLoop, asm.Instructions{asm.Mov.Imm(asm.R3, 0)}, "cb")), callback("cb")), "cb", "NULL"},
		{"map value", join(entry(pass(asm.FnLoop, asm.Instructions{asm.Mov.Reg(asm.R3, asm.R0)}, "cb")), callback("cb")), "cb", "not R10 plus a constant"},
		{"X joined across paths", join(entry(fp(-24), asm.Instructions{branchIn}, fp(-16), asm.Instructions{load("cb", asm.R2), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()}), callback("cb")), "cb", "a branch lands"},
		// The checker sees R3 only in straight-line code, so a merge is refused
		// even when both paths set the same R3.
		{"same X merged across paths", join(entry(fp(-16), asm.Instructions{branchIn}, fp(-16), asm.Instructions{load("cb", asm.R2), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()}), callback("cb")), "cb", "a branch lands"},
		{"xchg writes R3", join(entry(pass(asm.FnLoop, append(fp(-16), asm.Xchg.Mem(asm.RFP, asm.R3, asm.DWord, -24)), "cb")), callback("cb")), "cb", "atomic"},
		{"load-acquire writes R3", join(entry(pass(asm.FnLoop, append(fp(-16), asm.LoadAcquire(asm.R3, asm.RFP, asm.DWord, -24)), "cb")), callback("cb")), "cb", "atomic"},
		{"legacy packet load clobbers R3", join(entry(pass(asm.FnLoop, append(fp(-16), asm.LoadAbs(0, asm.Byte)), "cb")), callback("cb")), "cb", "atomic or legacy packet load"},
		{"legacy packet load clobbers R2", join(entry(fp(-16), asm.Instructions{load("cb", asm.R2), asm.LoadInd(asm.R0, asm.R2, 0, asm.Byte), asm.FnLoop.Call()}), callback("cb")), "cb", "overwritten"},
		{"branch onto the helper call", join(entry(asm.Instructions{ontoCall}, loop(-16, "cb")), callback("cb")), "cb", "a branch lands"},
		{"timer", join(entry(pass(asm.FnTimerSetCallback, nil, "cb")), callback("cb")), "cb", "asynchronous"},
		{"other helper", join(entry(pass(asm.FnFindVma, fp(-8), "cb")), callback("cb")), "cb", "not bpf_loop or bpf_for_each_map_elem"},
		{"pointer copied", join(entry(asm.Instructions{load("cb", asm.R2), asm.Mov.Reg(asm.R7, asm.R2), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8), asm.FnLoop.Call()}), callback("cb")), "cb", "copied"},
		{"pointer in another register", join(entry(asm.Instructions{load("cb", asm.R7)}), callback("cb")), "cb", "not loaded into"},
		{"direct-call reuse", join(entry(loop(-16, "cb"), asm.Instructions{asm.Call.Label("cb")}), callback("cb")), "cb", "called directly"},
		{"caller without context", join(entry(asm.Instructions{asm.Call.Label("sub")}),
			asm.Instructions{head("sub", asm.Mov.Reg(asm.R3, asm.RFP), btf.StaticFunc, noCtx), asm.Add.Imm(asm.R3, -8), load("cb", asm.R2), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()}, end, callback("cb")), "cb", "does not hold the context"},
		{"nested", join(entry(loop(-16, "outer")), callback("outer", loop(-8, "inner")...), callback("inner")), "inner", "does not hold the context"},
		{"entry not analyzed", join(entry(loop(-16, "cb"), asm.Instructions{asm.StoreMem(regParams, -8, asm.R1, asm.DWord)}), callback("cb")), "cb", "entry is not analyzed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := prove(tc.insns, tc.cb)
			if proof.Proven || proof.Callback != nil || !strings.Contains(proof.Reason, tc.want) {
				t.Fatalf("proof = %+v, want refusal containing %q", proof, tc.want)
			}
		})
	}

	t.Run("a callee of a callback stays refused", func(t *testing.T) {
		callee := asm.Instructions{head("callee", asm.Mov.Imm(asm.R0, 0), btf.StaticFunc, ctxParam), asm.Return()}
		insns := join(entry(loop(-16, "cb")), callback("cb", asm.Call.Label("callee")), callee)
		if proof := prove(insns, "cb"); proof.Callback == nil {
			t.Fatalf("callback proof = %+v", proof)
		}
		if proof := prove(insns, "callee"); proof.Proven || proof.Callback != nil || !strings.Contains(proof.Reason, "a caller does not pass the context") {
			t.Fatalf("callee proof = %+v", proof)
		}
	})

	t.Run("a static hook on a callback stays refused", func(t *testing.T) {
		insns := join(entry(loop(-16, "cb")), callback("cb"))
		fn := btf.FuncMetadata(&insns[len(insns)-2])
		fn.Type.(*btf.FuncProto).Params[0] = ctxParam
		if why := CallsRefusal(insns, "cb"); why == "" {
			t.Fatal("a callback's first argument was accepted as the context")
		}
	})
}
