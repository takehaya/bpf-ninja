package inject

import (
	"errors"
	"strings"
	"testing"
	"time"

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
	spec := callFixtureSpec(typ, insns)
	spec.Programs["p"].Type = typ
	return spec
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
		{"sched_act writes", pullFixture(ebpf.SchedACT, write), true},
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
	// With no other hook selected, the refusal names the added call without counting it as skipped.
	spec := pullFixture(ebpf.SchedCLS, write)
	prog := spec.Programs["p"]
	prog.Instructions[3] = asm.Mov.Imm(asm.R0, 0)
	_, err := transformLookup(spec, callReq("bpf_skb_pull_data"))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), `no call site is instrumented (0 skipped); call "bpf_skb_pull_data" (not hookable, added by the kernel at load: `) {
		t.Fatalf("err %v", err)
	}
	// A real skipped site is still counted alongside the kernel-added entry.
	spec = pullFixture(ebpf.SchedCLS, write)
	req := callReq("bpf_skb_pull_data")
	req.Drop = map[uint32]string{3: "load: dropped"}
	_, err = transformLookup(spec, req)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no call site is instrumented (1 skipped)") {
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
		{"alias spill", asm.Instructions{ctxData, asm.Mov.Reg(asm.R7, asm.RFP), asm.Add.Imm(asm.R7, -8),
			asm.StoreMem(asm.R7, 0, asm.R2, asm.DWord), asm.LoadMem(asm.R5, asm.RFP, -8, asm.DWord), asm.StoreImm(asm.R5, 0, 1, asm.Byte), asm.Return()}, true},
		{"stack pointer spill", asm.Instructions{ctxData, asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord),
			asm.Mov.Reg(asm.R7, asm.RFP), asm.Add.Imm(asm.R7, -8), asm.StoreMem(asm.RFP, -16, asm.R7, asm.DWord),
			asm.LoadMem(asm.R4, asm.RFP, -16, asm.DWord), asm.LoadMem(asm.R5, asm.R4, 0, asm.DWord), asm.StoreImm(asm.R5, 0, 1, asm.Byte), asm.Return()}, true},
		{"caller context output", append(asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.Call.Label("put"),
			asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord), asm.LoadMem(asm.R4, asm.R3, 76, asm.Word), asm.StoreImm(asm.R4, 0, 1, asm.Byte), asm.Return()},
			sub("put", asm.StoreMem(asm.R2, 0, asm.R1, asm.DWord), asm.Return())...), true},
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

// packetStackFixtures covers stack aliases, cross-frame values and callbacks.
func packetStackFixtures() []struct {
	name string
	spec *ebpf.CollectionSpec
	want bool
} {
	ptr := &btf.Pointer{Target: &btf.Void{}}

	alias := pullFixture(ebpf.SchedCLS,
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord), asm.Mov.Reg(asm.R7, asm.RFP), asm.Add.Imm(asm.R7, -8),
		asm.Mov.Imm(asm.R2, 0), asm.LoadMem(asm.R5, asm.R7, 0, asm.DWord), asm.StoreImm(asm.R5, 0, 1, asm.Byte))
	in := packetSubFixture(pullFixture(ebpf.SchedCLS,
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord), asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8), asm.Call.Label("in")),
		"in", []btf.FuncParam{{Name: "slot", Type: ptr}},
		asm.LoadMem(asm.R3, asm.R1, 0, asm.DWord), asm.StoreImm(asm.R3, 0, 1, asm.Byte), asm.Mov.Imm(asm.R0, 0), asm.Return())
	out := packetSubFixture(pullFixture(ebpf.SchedCLS,
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8), asm.Call.Label("put"),
		asm.LoadMem(asm.R5, asm.RFP, -8, asm.DWord), asm.StoreImm(asm.R5, 0, 1, asm.Byte)),
		"put", []btf.FuncParam{{Name: "slot", Type: ptr}, {Name: "packet", Type: ptr}},
		asm.StoreMem(asm.R1, 0, asm.R2, asm.DWord), asm.Mov.Imm(asm.R0, 0), asm.Return())
	loadCallback := asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R2, Src: asm.PseudoFunc, Constant: -1}.WithReference("cb")
	callback := packetSubFixture(pullFixture(ebpf.SchedCLS,
		asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord), asm.Mov.Imm(asm.R1, 1), loadCallback,
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()),
		"cb", []btf.FuncParam{{Name: "i", Type: &btf.Int{Name: "u32", Size: 4}}, {Name: "state", Type: ptr}},
		asm.LoadMem(asm.R1, asm.R2, 0, asm.DWord), asm.LoadMem(asm.R2, asm.R1, 76, asm.Word), asm.LoadMem(asm.R3, asm.R1, 80, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R2), asm.Add.Imm(asm.R4, 1), asm.JGT.Reg(asm.R4, asm.R3, "cb_out"),
		asm.StoreImm(asm.R2, 0, 1, asm.Byte), asm.Mov.Imm(asm.R0, 0).WithSymbol("cb_out"), asm.Return())
	keys := pullFixture(ebpf.SchedCLS,
		asm.LoadMem(asm.R5, asm.R2, 0, asm.Word), asm.StoreMem(asm.RFP, -8, asm.R5, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.LoadMapPtr(asm.R1, 0).WithReference("out"), asm.FnMapLookupElem.Call())
	read := pullFixture(ebpf.SchedCLS,
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord), asm.Mov.Imm(asm.R2, 0),
		asm.LoadMem(asm.R5, asm.RFP, -8, asm.DWord), asm.LoadMem(asm.R5, asm.R5, 0, asm.Byte), asm.StoreMem(asm.RFP, -16, asm.R5, asm.DWord))
	return []struct {
		name string
		spec *ebpf.CollectionSpec
		want bool
	}{
		{"stack alias write", alias, true},
		{"caller stack input write", in, true},
		{"caller stack output write", out, true},
		{"loop callback stack context write", callback, true},
		{"read only stack map key", keys, false},
		{"read only R10 packet spill", read, false},
	}
}

func TestKernelAddedStack(t *testing.T) {
	for _, tc := range packetStackFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.spec.Programs["p"]
			added, err := kernelAddedCalls(p.Instructions, p.Type, callReq("bpf_skb_pull_data"))
			if err != nil || (len(added) == 1) != tc.want {
				t.Fatalf("added %+v, err %v, want listed %v", added, err, tc.want)
			}
		})
	}
}

// The callback input summary applies to every helper/kfunc signature and to
// both symbolic and numeric function addresses.
func TestKernelAddedCallbackInputs(t *testing.T) {
	for _, numeric := range []bool{false, true} {
		for _, call := range []asm.Instruction{asm.FnLoop.Call(), asm.FnForEachMapElem.Call(), kfuncCall(123).WithReference("callback")} {
			spec := packetStackFixtures()[3].spec
			insns := spec.Programs["p"].Instructions
			indices, cb := map[int]int{}, 0
			it := insns.Iterate()
			for it.Next() {
				indices[int(it.Offset)] = it.Index
				if it.Ins.Symbol() == "cb" {
					cb = int(it.Offset)
				}
			}
			for pc, idx := range indices {
				ins := &insns[idx]
				if numeric && ins.IsLoadOfFunctionPointer() {
					*ins = asm.Instruction{OpCode: ins.OpCode, Dst: ins.Dst, Src: asm.PseudoFunc, Constant: int64(cb - pc - 1)}
				}
				if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnLoop) {
					*ins = call
				}
			}
			// foreach passes the caller's context as R4, rather than loop's R2.
			if call.IsKfuncCall() {
				insns[indices[cb]].Src = asm.R5
			} else if call.Constant == int64(asm.FnForEachMapElem) {
				insns[indices[cb]].Src = asm.R4
			}
			if got, err := writesPacket(insns, nil, nil); !got || err != nil {
				t.Fatalf("numeric %v, call %v: writes %v, err %v", numeric, call, got, err)
			}
		}
	}
}

// packetAtomicFixtures covers pointer reloads through atomic stack accesses.
func packetAtomicFixtures() []struct {
	name string
	spec *ebpf.CollectionSpec
	want bool
} {
	var fixtures []struct {
		name string
		spec *ebpf.CollectionSpec
		want bool
	}
	for _, base := range []asm.Register{asm.RFP, asm.R7} {
		off := int16(-8)
		var prefix []asm.Instruction
		if base != asm.RFP {
			off = 0
			prefix = []asm.Instruction{asm.Mov.Reg(base, asm.RFP), asm.Add.Imm(base, -8)}
		}
		spill := asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord)
		for _, tc := range []struct {
			name string
			body []asm.Instruction
		}{
			{"xchg", []asm.Instruction{spill, asm.Mov.Imm(asm.R5, 0), atomicMem(asm.Xchg, base, asm.R5, off),
				asm.StoreImm(asm.R5, 0, 1, asm.Byte)}},
			{"cmpxchg R0", []asm.Instruction{spill, asm.Mov.Imm(asm.R0, 0), asm.Mov.Imm(asm.R5, 0),
				atomicMem(asm.CmpXchg, base, asm.R5, off), asm.StoreImm(asm.R0, 0, 1, asm.Byte)}},
			{"fetch_add", []asm.Instruction{spill, asm.Mov.Imm(asm.R5, 0), atomicMem(asm.FetchAdd, base, asm.R5, off),
				asm.StoreImm(asm.R5, 0, 1, asm.Byte)}},
			{"load-acquire", []asm.Instruction{spill, atomicMem(atomicLoadAcquire, asm.R5, base, off),
				asm.StoreImm(asm.R5, 0, 1, asm.Byte)}},
			{"store-release reload", []asm.Instruction{atomicMem(atomicStoreRelease, base, asm.R2, off),
				asm.LoadMem(asm.R5, asm.RFP, -8, asm.DWord), asm.StoreImm(asm.R5, 0, 1, asm.Byte)}},
		} {
			fixtures = append(fixtures, struct {
				name string
				spec *ebpf.CollectionSpec
				want bool
			}{tc.name + " through " + base.String(), pullFixture(ebpf.SchedCLS, append(prefix, tc.body...)...), true})
		}
	}
	return fixtures
}

func TestKernelAddedAtomic(t *testing.T) {
	for _, tc := range packetAtomicFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.spec.Programs["p"]
			added, err := kernelAddedCalls(p.Instructions, p.Type, callReq("bpf_skb_pull_data"))
			if err != nil || (len(added) == 1) != tc.want {
				t.Fatalf("added %+v, err %v, want listed %v", added, err, tc.want)
			}
		})
	}
}

func packetSubFixture(spec *ebpf.CollectionSpec, name string, params []btf.FuncParam, body ...asm.Instruction) *ebpf.CollectionSpec {
	fn := &btf.Func{Name: name, Linkage: btf.StaticFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed}, Params: params,
	}}
	body[0] = btf.WithFuncMetadata(body[0].WithSymbol(name).WithSource(asm.Comment(name)), fn)
	spec.Programs["p"].Instructions = equivResolveBranches(append(spec.Programs["p"].Instructions, body...))
	return spec
}

func TestKernelAddedRawKfunc(t *testing.T) {
	kernel := specOf(t, &btf.Func{Name: "bpf_dynptr_slice_rdwr", Linkage: btf.GlobalFunc,
		Type: &btf.FuncProto{Return: &btf.Pointer{Target: &btf.Void{}}}})
	call := testKfunc(t, kernel, "bpf_dynptr_slice_rdwr")
	other := specOf(t, &btf.Func{Name: "bpf_dynptr_slice", Linkage: btf.GlobalFunc,
		Type: &btf.FuncProto{Return: &btf.Pointer{Target: &btf.Void{}}}})
	for _, tc := range []struct {
		name   string
		call   asm.Instruction
		kernel *btf.Spec
		want   bool
	}{
		{"nil kernel", call, nil, true},
		{"resolved rdwr", call, kernel, true},
		{"missing ID", kfuncCall(1000000), kernel, true},
		{"resolved read only", testKfunc(t, other, "bpf_dynptr_slice"), other, false},
		{"unresolved module", func() asm.Instruction { c := call; c.Offset = 1; return c }(), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.call.Reference() != "" {
				t.Fatal("expected raw BTF-ID call")
			}
			spec := pullFixture(ebpf.SchedCLS, tc.call)
			req := callReq("bpf_skb_pull_data")
			req.Kernel = tc.kernel
			added, err := kernelAddedCalls(spec.Programs["p"].Instructions, ebpf.SchedCLS, req)
			if err != nil || (len(added) == 1) != tc.want {
				t.Fatalf("added %+v, err %v, want %v", added, err, tc.want)
			}
		})
	}
}

func TestKernelAddedNoExit(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		spec := callFixtureSpec(ebpf.SchedCLS, asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Imm(asm.R2, 14), asm.Mov.Reg(asm.R1, asm.R6),
			asm.FnSkbPullData.Call(), asm.Mov.Imm(asm.R0, 0),
		})
		if got, err := writesPacket(spec.Programs["p"].Instructions, nil, nil); got || err != nil {
			t.Errorf("writes %v, err %v", got, err)
			return
		}
		plan, err := transformLookup(spec, callReq("bpf_skb_pull_data"))
		if err != nil || len(plan.hooks) != 1 || len(plan.hooks[0].Sites) != 1 || plan.hooks[0].Sites[0].SitePC != 3 {
			t.Errorf("err %v hooks %+v", err, plan.hooks)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("analysis did not return for a program without exit")
	}
}

func packetReadOnlyStackFixtures() []struct {
	name string
	spec *ebpf.CollectionSpec
	want bool
} {
	ptr := &btf.Pointer{Target: &btf.Void{}}
	parser := func(spec *ebpf.CollectionSpec) *ebpf.CollectionSpec {
		return packetSubFixture(spec, "parse", []btf.FuncParam{{Name: "cursor", Type: ptr}, {Name: "skb", Type: ptr}},
			asm.LoadMem(asm.R3, asm.R2, 76, asm.Word), asm.StoreMem(asm.R1, 0, asm.R3, asm.DWord),
			asm.Mov.Imm(asm.R0, 0), asm.Return())
	}
	head := []asm.Instruction{
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Reg(asm.R2, asm.R6), asm.Call.Label("parse"),
	}
	ctx := parser(pullFixture(ebpf.SchedCLS, append(append([]asm.Instruction{}, head...),
		asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord), asm.FnKtimeGetNs.Call(),
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.DWord), asm.StoreMem(asm.R1, 8, asm.R0, asm.Word))...))
	value := parser(pullFixture(ebpf.SchedCLS, append(append([]asm.Instruction{}, head...),
		asm.StoreImm(asm.RFP, -24, 0, asm.Word), asm.LoadMapPtr(asm.R1, 0).WithReference("out"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -24), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"),
		asm.StoreMem(asm.RFP, -32, asm.R0, asm.DWord), asm.FnKtimeGetNs.Call(),
		asm.LoadMem(asm.R1, asm.RFP, -32, asm.DWord), asm.StoreMem(asm.R1, 0, asm.R0, asm.DWord))...))
	bump := packetSubFixture(pullFixture(ebpf.SchedCLS,
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord), asm.StoreImm(asm.RFP, -24, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference("out"), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -24),
		asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"), asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Call.Label("bump")),
		"bump", []btf.FuncParam{{Name: "val", Type: ptr}},
		asm.LoadMem(asm.R2, asm.R1, 0, asm.DWord), asm.StoreImm(asm.R2, 0, 1, asm.Word), asm.Mov.Imm(asm.R0, 0), asm.Return())
	return []struct {
		name string
		spec *ebpf.CollectionSpec
		want bool
	}{
		{"cursor then ctx mark", ctx, false},
		{"cursor then map value", value, false},
		{"packet spill then bump value", bump, false},
	}
}

func TestKernelAddedReadOnlyStack(t *testing.T) {
	for _, tc := range packetReadOnlyStackFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.spec.Programs["p"]
			added, err := kernelAddedCalls(p.Instructions, p.Type, callReq("bpf_skb_pull_data"))
			if err != nil || len(added) != 0 {
				t.Fatalf("added %+v, err %v", added, err)
			}
		})
	}
}

func TestKernelAddedStackFixpoint(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "constant alias", true: "variable alias"}[unknown], func(t *testing.T) {
			insns := asm.Instructions{
				asm.LoadMem(asm.R2, asm.R1, 76, asm.Word), asm.LoadMem(asm.R3, asm.R1, 80, asm.Word),
				asm.StoreImm(asm.RFP, -8, 0, asm.DWord), asm.Mov.Reg(asm.R7, asm.RFP), asm.Add.Imm(asm.R7, -8), asm.Mov.Imm(asm.R6, 0),
			}
			if unknown {
				insns = append(insns, asm.Mov.Imm(asm.R0, 0), asm.Add.Reg(asm.R7, asm.R0))
			}
			insns = append(insns,
				asm.LoadMem(asm.R5, asm.RFP, -8, asm.DWord).WithSymbol("top"), asm.JNE.Imm(asm.R6, 0, "w"),
				asm.StoreMem(asm.R7, 0, asm.R2, asm.DWord), asm.Mov.Imm(asm.R6, 1), asm.Ja.Label("top"),
				asm.Mov.Reg(asm.R4, asm.R5).WithSymbol("w"), asm.Add.Imm(asm.R4, 1), asm.JGT.Reg(asm.R4, asm.R3, "out"),
				asm.StoreImm(asm.R5, 0, 1, asm.Byte), asm.Mov.Imm(asm.R0, 0).WithSymbol("out"), asm.Return())
			insns = callFixtureSpec(ebpf.SchedCLS, insns).Programs["p"].Instructions
			if got, err := writesPacket(insns, nil, nil); !got || err != nil {
				t.Fatalf("writes %v, err %v", got, err)
			}
		})
	}
}
