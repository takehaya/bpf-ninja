package ctxflow

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func regs(rs ...asm.Register) uint8 {
	var out uint8
	for _, r := range rs {
		out |= 1 << r
	}
	return out
}

func TestArgReads(t *testing.T) {
	skip := func(op asm.JumpOp, r asm.Register, off int16) asm.Instruction {
		j := op.Imm(r, 0, "")
		j.Offset = off
		return j
	}
	call := func(off int32) asm.Instruction {
		c := asm.Call.Label("")
		c.Src, c.Constant = asm.PseudoCall, int64(off)
		return c
	}
	kfunc := asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: 1}
	for _, tc := range []struct {
		name  string
		insns asm.Instructions
		want  uint8
	}{
		{"nothing", asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}, 0},
		{"mov reads its source only", asm.Instructions{asm.Mov.Reg(asm.R0, asm.R2), asm.Return()}, regs(asm.R2)},
		{"alu reads its destination", asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Add.Reg(asm.R0, asm.R3), asm.Add.Imm(asm.R4, 1), asm.Return()}, regs(asm.R3, asm.R4)},
		{"written first", asm.Instructions{asm.Mov.Imm(asm.R1, 0), asm.Mov.Reg(asm.R0, asm.R1), asm.Return()}, 0},
		{"store reads both", asm.Instructions{asm.StoreMem(asm.R1, 0, asm.R2, asm.DWord), asm.StoreImm(asm.R3, 0, 0, asm.Word), asm.Mov.Imm(asm.R0, 0), asm.Return()}, regs(asm.R1, asm.R2, asm.R3)},
		{"load reads its base", asm.Instructions{asm.LoadMem(asm.R0, asm.R4, 0, asm.DWord), asm.Return()}, regs(asm.R4)},
		{"helper reads its arguments", asm.Instructions{asm.FnMapLookupElem.Call(), asm.Return()}, regs(asm.R1, asm.R2)},
		{"five-argument helper", asm.Instructions{asm.FnPerfEventOutput.Call(), asm.Return()}, regs(asm.R1, asm.R2, asm.R3, asm.R4, asm.R5)},
		// bpf_trace_printk is variadic and BPF_CALL_5: it reads R3-R5 whatever
		// its format uses, and the verifier checks only R1 and R2.
		{"trace_printk reads all", asm.Instructions{asm.FnTracePrintk.Call(), asm.Return()}, regs(asm.R1, asm.R2, asm.R3, asm.R4, asm.R5)},
		{"unknown helper reads all", asm.Instructions{asm.BuiltinFunc(9999).Call(), asm.Return()}, regs(asm.R1, asm.R2, asm.R3, asm.R4, asm.R5)},
		{"kfunc reads all", asm.Instructions{kfunc, asm.Return()}, regs(asm.R1, asm.R2, asm.R3, asm.R4, asm.R5)},
		{"call clobbers", asm.Instructions{asm.Mov.Imm(asm.R1, 0), asm.Mov.Imm(asm.R2, 0), asm.FnMapLookupElem.Call(), asm.Mov.Reg(asm.R0, asm.R3), asm.Return()}, 0},
		{"written on one path only", asm.Instructions{skip(asm.JEq, asm.R0, 1), asm.Mov.Imm(asm.R5, 0), asm.Mov.Reg(asm.R0, asm.R5), asm.Return()}, regs(asm.R5)},
		{"written on both paths", asm.Instructions{skip(asm.JEq, asm.R0, 2), asm.Mov.Imm(asm.R5, 0), asm.Ja.Label(""), asm.Mov.Imm(asm.R5, 1), asm.Mov.Reg(asm.R0, asm.R5), asm.Return()}, 0},
		{"branch reads its operand", asm.Instructions{skip(asm.JEq, asm.R3, 0), asm.Mov.Imm(asm.R0, 0), asm.Return()}, regs(asm.R3)},
		{"atomic reads R0 and operands", asm.Instructions{asm.StoreXAdd(asm.R1, asm.R2, asm.DWord), asm.Return()}, regs(asm.R1, asm.R2)},
		{"legacy packet load", asm.Instructions{asm.LoadInd(asm.R0, asm.R4, 0, asm.Byte), asm.Mov.Reg(asm.R0, asm.R1), asm.Return()}, regs(asm.R1, asm.R2, asm.R3, asm.R4, asm.R5)},
		{"subprogram reads what its callee reads", asm.Instructions{asm.Mov.Imm(asm.R1, 0), call(1), asm.Return(), asm.Mov.Reg(asm.R0, asm.R2), asm.Return()}, regs(asm.R2)},
	} {
		// The "written on both paths" jump is a ja +1.
		for i := range tc.insns {
			if tc.insns[i].OpCode.JumpOp() == asm.Ja && tc.insns[i].Reference() == "" && tc.insns[i].Offset == 0 && tc.insns[i].OpCode.Class() == asm.JumpClass {
				tc.insns[i].Offset = 1
			}
		}
		got, err := ArgReads(tc.insns, 0)
		if err != nil || got != tc.want {
			t.Errorf("%s: reads = %06b err = %v, want %06b", tc.name, got, err, tc.want)
		}
	}
	if _, err := ArgReads(asm.Instructions{call(-1), asm.Return()}, 0); err == nil || !strings.Contains(err.Error(), "recursive") {
		t.Errorf("recursion: %v", err)
	}
	if _, err := ArgReads(asm.Instructions{skip(asm.JEq, asm.R0, 5), asm.Return()}, 0); err == nil {
		t.Error("a jump outside the program was followed")
	}
	if FreeArg(regs(asm.R1, asm.R5)) != asm.R4 || FreeArg(regs(asm.R1, asm.R2, asm.R3, asm.R4, asm.R5)) != 0 {
		t.Error("FreeArg")
	}
}

// passProgram is entry(ctx) -> mid -> leaf. mid takes the context as its
// parameter when midCtx; leaf takes none. readAll makes the named function
// read R1-R5 before writing them.
func passProgram(midCtx bool, readAll string, linkage btf.FuncLinkage) (asm.Instructions, btf.Type) {
	ctx := &btf.Struct{Name: "xdp_md", Size: 24}
	i64 := &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed}
	ctxParam := btf.FuncParam{Name: "ctx", Type: &btf.Pointer{Target: ctx}}
	n := btf.FuncParam{Name: "n", Type: i64}
	head := func(name string, ins asm.Instruction, linkage btf.FuncLinkage, params ...btf.FuncParam) asm.Instruction {
		return btf.WithFuncMetadata(ins.WithSymbol(name), &btf.Func{Name: name, Linkage: linkage, Type: &btf.FuncProto{Return: i64, Params: params}})
	}
	body := func(name string) asm.Instructions {
		if name != readAll {
			return nil
		}
		return asm.Instructions{asm.Mov.Reg(asm.R0, asm.R1), asm.Add.Reg(asm.R0, asm.R2), asm.Add.Reg(asm.R0, asm.R3), asm.Add.Reg(asm.R0, asm.R4), asm.Add.Reg(asm.R0, asm.R5)}
	}
	entry := asm.Instructions{head("entry", asm.Mov.Reg(asm.R6, asm.R1), btf.GlobalFunc, ctxParam)}
	if !midCtx {
		entry = append(entry, asm.Mov.Imm(asm.R1, 7))
	}
	entry = append(entry, asm.Call.Label("mid"), asm.Return())
	midParam := n
	if midCtx {
		midParam = ctxParam
	}
	mid := asm.Instructions{head("mid", asm.Mov.Reg(asm.R6, asm.R1), btf.StaticFunc, midParam)}
	mid = append(mid, body("mid")...)
	mid = append(mid, asm.Mov.Imm(asm.R1, 1), asm.Call.Label("leaf"), asm.Return())
	leaf := asm.Instructions{head("leaf", asm.Mov.Imm(asm.R0, 0), linkage, n)}
	leaf = append(leaf, body("leaf")...)
	leaf = append(leaf, asm.Return())
	out := append(append(entry, mid...), leaf...)
	return out, ctx
}

func TestProvePass(t *testing.T) {
	proofOf := func(insns asm.Instructions, ctx btf.Type, name string) Proof {
		for _, fn := range functions(insns, ctx) {
			if fn.Name == name {
				return Prove(insns, ctx)[fn.Start]
			}
		}
		t.Fatalf("no function %s", name)
		return Proof{}
	}
	insns, ctx := passProgram(false, "", btf.StaticFunc)
	leaf := proofOf(insns, ctx, "leaf")
	if leaf.Proven || len(leaf.Pass) != 2 || leaf.Pass[0].Name != "leaf" || leaf.Pass[0].Reg != asm.R5 || leaf.Pass[0].Saved ||
		leaf.Pass[1].Name != "mid" || leaf.Pass[1].Reg != asm.R5 || leaf.Pass[1].Saved || leaf.Pass[0].Index != 8 || leaf.Pass[1].Start != 4 {
		t.Fatalf("free chain: %+v", leaf.Pass)
	}
	insns, ctx = passProgram(true, "", btf.StaticFunc)
	leaf = proofOf(insns, ctx, "leaf")
	if len(leaf.Pass) != 2 || leaf.Pass[0].Reg != asm.R5 || !leaf.Pass[1].Saved || leaf.Pass[1].Reg != asm.R1 {
		t.Fatalf("saved chain: %+v", leaf.Pass)
	}
	if entry := proofOf(insns, ctx, "entry"); entry.Pass != nil || entry.PassReason != "" {
		t.Fatalf("entry: %+v", entry)
	}
	for _, tc := range []struct {
		name    string
		midCtx  bool
		readAll string
		linkage btf.FuncLinkage
		want    string
	}{
		{"global", false, "", btf.GlobalFunc, "ctx pass: not a static function"},
		{"all read", false, "leaf", btf.StaticFunc, "ctx pass: every argument register is read before written"},
		{"caller cannot", false, "mid", btf.StaticFunc, "ctx pass: a caller cannot pass the context (mid@"},
	} {
		insns, ctx := passProgram(tc.midCtx, tc.readAll, tc.linkage)
		if leaf := proofOf(insns, ctx, "leaf"); leaf.Pass != nil || !strings.HasPrefix(leaf.PassReason, tc.want) {
			t.Errorf("%s: %+v", tc.name, leaf)
		}
	}
}
