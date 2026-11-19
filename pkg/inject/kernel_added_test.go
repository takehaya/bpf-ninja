package inject

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// pullFixture (tc) pulls 14 bytes at 3, bounds-checks the Ethernet header
// and then runs body with the packet start in R2; it returns TC_ACT_OK.
func pullFixture(typ ebpf.ProgramType, body ...asm.Instruction) *ebpf.CollectionSpec {
	data, end := int16(76), int16(80)
	if typ == ebpf.XDP {
		data, end = 0, 4
	}
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Imm(asm.R2, 14), asm.Mov.Reg(asm.R1, asm.R6)}
	if typ != ebpf.XDP {
		insns = append(insns, asm.FnSkbPullData.Call())
	}
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R6, data, asm.Word), asm.LoadMem(asm.R3, asm.R6, end, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R2), asm.Add.Imm(asm.R4, 14), asm.JGT.Reg(asm.R4, asm.R3, "out"))
	insns = append(append(insns, body...), asm.Mov.Imm(asm.R0, 0).WithSymbol("out"), asm.Return())
	return callFixtureSpec(typ, insns)
}

// A rule that hooks bpf_skb_pull_data in a tc program that writes packet
// data lists the call the verifier adds in front of the program, and keeps
// the hook at the program's own call. A program that only reads the packet,
// and an XDP program that writes it, get no such entry.
func TestKernelAddedPull(t *testing.T) {
	write := asm.StoreImm(asm.R2, 0, 0, asm.Byte)
	read := []asm.Instruction{asm.LoadMem(asm.R5, asm.R2, 0, asm.Byte), asm.StoreMem(asm.RFP, -8, asm.R5, asm.DWord)}
	for _, tc := range []struct {
		name string
		spec *ebpf.CollectionSpec
		want bool
	}{
		{"tc writes", pullFixture(ebpf.SchedCLS, write), true},
		{"tc reads", pullFixture(ebpf.SchedCLS, read...), false},
		{"xdp writes", pullFixture(ebpf.XDP, write), false},
	} {
		prog := tc.spec.Programs["p"]
		added, err := kernelAddedCalls(prog.Instructions, prog.Type, callReq("bpf_skb_pull_data"))
		if err != nil || (len(added) == 1) != tc.want {
			t.Fatalf("%s: %+v %v", tc.name, added, err)
		}
		if !tc.want {
			continue
		}
		if a := added[0]; a.Call != "bpf_skb_pull_data" || !a.KernelAdded || a.SitePC != 0 || a.Op != "" || UnknownCallsName(a) ||
			!strings.HasPrefix(a.Reason, "not hookable, added by the kernel at load: ") {
			t.Fatalf("%s: %+v", tc.name, a)
		}
		plan, err := transformLookup(tc.spec, callReq("bpf_skb_pull_data"))
		if err != nil || len(plan.hooks) != 1 || len(plan.hooks[0].Sites) != 1 || plan.hooks[0].Sites[0].SitePC != 3 ||
			len(plan.skipped) != 1 || plan.skipped[0] != added[0] {
			t.Fatalf("%s: err %v hooks %+v skipped %+v", tc.name, err, plan.hooks, plan.skipped)
		}
	}
	// Without a call of its own, the rule has nothing to hook and the refusal names the added call.
	spec := pullFixture(ebpf.SchedCLS, write)
	prog := spec.Programs["p"]
	prog.Instructions[3] = asm.Mov.Imm(asm.R0, 0)
	_, err := transformLookup(spec, callReq("bpf_skb_pull_data"))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), `no call site is instrumented (1 skipped); call "bpf_skb_pull_data" (not hookable, added by the kernel at load: `) {
		t.Fatalf("err %v", err)
	}
	// A rule that does not name bpf_skb_pull_data lists nothing.
	if added, err := kernelAddedCalls(prog.Instructions, prog.Type, callReq("bpf_ktime_get_ns")); added != nil || err != nil {
		t.Fatalf("%+v %v", added, err)
	}
}

// writesPacket follows a packet pointer through stack spills, bpf-to-bpf
// calls and their results, and counts bpf_dynptr_slice_rdwr.
func TestWritesPacket(t *testing.T) {
	ctxData := asm.LoadMem(asm.R2, asm.R1, 76, asm.Word)
	sub := func(name string, body ...asm.Instruction) asm.Instructions {
		fn := &btf.Func{Name: name, Linkage: btf.StaticFunc, Type: &btf.FuncProto{Return: &btf.Int{Name: "long", Size: 8}}}
		body[0] = btf.WithFuncMetadata(body[0].WithSymbol(name), fn)
		return body
	}
	for _, tc := range []struct {
		name  string
		insns asm.Instructions
		want  bool
	}{
		{"spill", asm.Instructions{ctxData, asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), asm.Mov.Imm(asm.R2, 0),
			asm.LoadMem(asm.R5, asm.RFP, -16, asm.DWord), asm.StoreImm(asm.R5, 0, 1, asm.Byte), asm.Return()}, true},
		{"spill overwritten", asm.Instructions{ctxData, asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), asm.StoreImm(asm.RFP, -12, 0, asm.Word),
			asm.LoadMem(asm.R5, asm.RFP, -16, asm.DWord), asm.StoreImm(asm.R5, 0, 1, asm.Byte), asm.Return()}, false},
		{"data_end", asm.Instructions{asm.LoadMem(asm.R2, asm.R1, 80, asm.Word), asm.StoreImm(asm.R2, 0, 1, asm.Byte), asm.Return()}, false},
		{"argument", append(asm.Instructions{ctxData, asm.Mov.Reg(asm.R1, asm.R2), asm.Call.Label("w"), asm.Return()},
			sub("w", asm.StoreImm(asm.R1, 0, 1, asm.Byte), asm.Return())...), true},
		{"context argument", append(asm.Instructions{asm.Call.Label("w"), asm.Return()},
			sub("w", asm.LoadMem(asm.R3, asm.R1, 140, asm.Word), asm.StoreImm(asm.R3, 0, 1, asm.Byte), asm.Return())...), true},
		{"result", append(asm.Instructions{asm.Call.Label("d"), asm.StoreImm(asm.R0, 0, 1, asm.Byte), asm.Return()},
			sub("d", asm.LoadMem(asm.R0, asm.R1, 76, asm.Word), asm.Return())...), true},
		{"scalar result", append(asm.Instructions{asm.Call.Label("d"), asm.StoreImm(asm.R0, 0, 1, asm.Byte), asm.Return()},
			sub("d", asm.Mov.Imm(asm.R0, 0), asm.Return())...), false},
		{"dynptr", asm.Instructions{asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: -1}.
			WithReference("bpf_dynptr_slice_rdwr"), asm.Return()}, true},
	} {
		insns := callFixtureSpec(ebpf.SchedCLS, tc.insns).Programs["p"].Instructions
		if got, err := writesPacket(insns, nil, nil); got != tc.want || err != nil {
			t.Errorf("%s: %v %v", tc.name, got, err)
		}
	}
}
