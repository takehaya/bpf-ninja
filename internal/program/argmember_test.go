package program

import (
	"bytes"
	"encoding/binary"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
)

func marshalArgInsns(t *testing.T, insns asm.Instructions) []byte {
	t.Helper()
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	var buf bytes.Buffer
	if err := insns.Marshal(&buf, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Pin the pre-member instruction sequence, including wide constants, all
// comparison operators, signed extension, and reusing the tracing args pointer.
func TestIntegerArgFilterByteIdentical(t *testing.T) {
	filters := []filter.ArgFilter{
		{ParamIndex: 1, ParamSize: 8, Op: filter.OpEqual, Value: 262010000000001},
		{ParamIndex: 2, ParamSize: 1, Signed: true, Op: filter.OpGreaterEqual, Value: ^uint64(2)},
		{ParamIndex: 3, ParamSize: 2, Op: filter.OpLessEqual, Value: 65535},
		{ParamIndex: 4, ParamSize: 4, Signed: true, Op: filter.OpRange, Value: 1, MaxValue: 9},
	}
	before := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord),
		asm.LoadMem(asm.R3, asm.R2, 8, asm.DWord),
		asm.LoadImm(asm.R4, 262010000000001, asm.DWord),
		asm.JNE.Reg(asm.R3, asm.R4, "exit"),
		asm.LoadMem(asm.R3, asm.R2, 16, asm.Byte),
		asm.LSh.Imm(asm.R3, 56), asm.ArSh.Imm(asm.R3, 56),
		asm.LoadImm(asm.R4, -3, asm.DWord),
		asm.JSLT.Reg(asm.R3, asm.R4, "exit"),
		asm.LoadMem(asm.R3, asm.R2, 24, asm.Half),
		asm.JGT.Imm(asm.R3, 65535, "exit"),
		asm.LoadMem(asm.R3, asm.R2, 32, asm.Word),
		asm.LSh.Imm(asm.R3, 32), asm.ArSh.Imm(asm.R3, 32),
		asm.JSLT.Imm(asm.R3, 1, "exit"),
		asm.JSGT.Imm(asm.R3, 9, "exit"),
	}
	if got, want := marshalArgInsns(t, buildArgFilter(filters)), marshalArgInsns(t, before); !bytes.Equal(got, want) {
		t.Fatalf("integer bytecode changed:\ngot  %x\nwant %x", got, want)
	}
}

func TestMemberLoadCodegen(t *testing.T) {
	for _, size := range []uint32{1, 2, 4, 8} {
		for _, signed := range []bool{false, true} {
			insns := emitArgMemberLoad(1, 12, size, signed, "exit")
			// Null is checked before adding the offset; failed reads branch before
			// touching the temporary. R6-R9 remain available to the capture path.
			// The helper's output slot is zeroed first: older verifiers check it as a read.
			if insns[2] != asm.StoreImm(asm.R10, argMemberTmp, 0, asm.Word) || insns[3] != asm.StoreImm(asm.R10, argMemberTmp+4, 0, asm.Word) {
				t.Fatalf("output slot not initialised: %v", insns)
			}
			if !reflect.DeepEqual(insns[7], asm.JNE.Imm(asm.R0, 0, "exit")) || !reflect.DeepEqual(insns[9], asm.JEq.Imm(asm.R3, 0, "exit")) || insns[6] != asm.FnGetFuncArg.Call() || insns[14] != asm.FnProbeReadKernel.Call() || !reflect.DeepEqual(insns[15], asm.JNE.Imm(asm.R0, 0, "exit")) || insns[16].Offset != argMemberTmp {
				t.Fatalf("unexpected member load: %v", insns)
			}
			for _, in := range insns {
				if in.Dst >= asm.R6 && in.Dst <= asm.R9 {
					t.Fatalf("clobbers callee saved register: %v", in)
				}
			}
			marshalArgInsns(t, insns)
			wantLen := 17
			if signed && size < 8 {
				wantLen += 2
			}
			if len(insns) != wantLen {
				t.Fatalf("size=%d signed=%v: %d instructions", size, signed, len(insns))
			}
		}
	}
	if argMemberTmp+8 > setKeyBase {
		t.Fatal("member scratch overlaps set key buffer")
	}
	insns := buildArgFilter([]filter.ArgFilter{
		{ParamIndex: 1, ParamSize: 8, Deref: true},
		{ParamIndex: 2, ParamSize: 4},
	})
	// The helper clobbers R2, so the subsequent ordinary arg needs a reload.
	if insns[18] != asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord) {
		t.Fatalf("args pointer not restored: %v", insns)
	}
}

func TestEchoMemberRecordLimit(t *testing.T) {
	_, err := LoadArgEcho(nil, "", nil, make([]attach.FuncParamInfo, 4097), false, false, attach.FuncAvailability{})
	if err == nil || !strings.Contains(err.Error(), "store offsets") {
		t.Fatalf("oversized selection: %v", err)
	}
}

func TestPointerNullAndNotEqualCodegen(t *testing.T) {
	for _, op := range []filter.ArgFilterOp{filter.OpEqual, filter.OpNotEqual} {
		insns := buildArgFilter([]filter.ArgFilter{{ParamIndex: 2, ParamSize: 8, Pointer: true, Op: op}})
		calls := 0
		for _, in := range insns {
			if in == asm.FnProbeReadKernel.Call() {
				t.Fatal("NULL test dereferences pointer")
			}
			if in == asm.FnGetFuncArg.Call() {
				calls++
			}
		}
		if calls != 1 {
			t.Fatalf("get arg calls: %d", calls)
		}
		want := asm.JNE
		if op == filter.OpNotEqual {
			want = asm.JEq
		}
		if last := insns[len(insns)-1]; last.OpCode != want.Op(asm.ImmSource) || last.Constant != 0 || last.Reference() != "exit" {
			t.Fatalf("comparison: %v", last)
		}
		marshalArgInsns(t, insns)
	}
	// Wide != uses a register operand, just as wide equality does.
	insns := buildArgFilter([]filter.ArgFilter{{ParamIndex: 1, ParamSize: 8, Op: filter.OpNotEqual, Value: 1 << 40}})
	if insns[len(insns)-1].OpCode != asm.JEq.Op(asm.RegSource) {
		t.Fatalf("wide !=: %v", insns)
	}
	marshalArgInsns(t, insns)
}

func TestStaticXDPContextCodegen(t *testing.T) {
	h, _ := hook.ByName(hook.KindXDP)
	for _, exit := range []bool{false, true} {
		safe := staticXDPHook(h, exit)
		prologue, err := safe.PacketPrologue()
		if err != nil {
			t.Fatal(err)
		}
		identity, err := safe.Identity(asm.R1)
		if err != nil {
			t.Fatal(err)
		}
		for _, insns := range []asm.Instructions{prologue, identity} {
			calls := 0
			for _, in := range insns {
				if in == asm.FnProbeReadKernel.Call() {
					calls++
				}
				if in.OpCode.Class() == asm.LdXClass && in.Src == asm.R6 {
					t.Fatalf("direct scalar ctx read: %v", in)
				}
			}
			if calls != 1 {
				t.Fatalf("helper calls=%d", calls)
			}
			marshalArgInsns(t, insns)
		}
		savedR2 := false
		for _, in := range identity {
			if in == asm.StoreMem(asm.R10, -144, asm.R2, asm.DWord) {
				savedR2 = true
			}
		}
		if savedR2 != exit {
			t.Fatal("entry must not spill uninitialized R2; exit must preserve expected identity")
		}
	}
}
