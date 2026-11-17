package inject

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// Kernel tests of the result-only hooks of helpers without a row: one helper
// per result kind, each pointer kind of pointerResults, and a program with a
// locked region. Each loads the unmodified and the rewritten program, checks
// the rewrite with the load-time checker, and compares the action and the
// out value of one test run.

// callAllHooked transforms fixture() for req, checks the rewrite with the load-time checker, loads it, attaches an
// observer to each global hook, runs both programs once on data and
// compares their action and out value. It returns the hooked plan, the
// observers by callee (none for a static hook) and the out value.
func callAllHooked(t *testing.T, fixture func() *ebpf.CollectionSpec, req LookupRequest, data []byte) (lookupPlan, map[string]*ebpf.Collection, [4]uint64) {
	t.Helper()
	plain := loadCallFixture(t, fixture())
	work := fixture()
	in := slices.Clone(work.Programs["p"].Instructions)
	injectcheck.Label(work.Programs["p"].Instructions)
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != len(req.Calls) || len(plan.skipped) != 0 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	out := work.Programs["p"].Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
	if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != len(plan.sites) {
		t.Fatalf("checker: counts %+v sites %d err %v", counts, len(plan.sites), err)
	}
	hooked := loadHooked(t, work, plan.hooks)
	t.Cleanup(hooked.Close)
	obs := map[string]*ebpf.Collection{}
	for _, h := range plan.hooks {
		if !h.Static {
			obs[h.Call] = attachArgObserver(t, h.Name, hooked.Programs["p"], false, false)
		}
	}
	plainRet, plainOut := runCallFixture(t, plain, data, nil)
	ret, got := runCallFixture(t, hooked, data, nil)
	if ret != plainRet || got != plainOut {
		t.Fatalf("hooked action %d out %#x, plain %d %#x", ret, got, plainRet, plainOut)
	}
	for _, h := range plan.hooks {
		if o := obs[h.Call]; o != nil {
			if c := lastCall(t, o, 1); c[0] != uint64(h.Sites[0].SitePC) {
				t.Fatalf("%s: hook saw site %d, want %d", h.Call, c[0], h.Sites[0].SitePC)
			}
		}
	}
	return plan, obs, got
}

// scalarAllFixture (XDP) stores bpf_get_numa_node_id in out slot 0 and
// returns the action of bpf_redirect(1, 0).
func scalarAllFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.FnGetNumaNodeId.Call(), asm.Mov.Reg(asm.R7, asm.R0)}
	insns = append(insns, outStore(0, asm.R7)...)
	return callFixtureSpec(ebpf.XDP, append(insns, asm.Mov.Imm(asm.R1, 1), asm.Mov.Imm(asm.R2, 0), asm.FnRedirect.Call(), asm.Return()))
}

// Two scalar helpers without a row, one of them the program's action: the
// hooks see each site and result, and the action is unchanged.
func TestBpfCallAllScalar(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plan, obs, out := callAllHooked(t, scalarAllFixture, callReq("bpf_get_numa_node_id", "bpf_redirect"), make([]byte, 64))
	for _, h := range plan.hooks {
		if h.RetPtr || h.Static || h.Untrusted {
			t.Fatalf("hook %+v", h)
		}
	}
	if got := lastCall(t, obs["bpf_get_numa_node_id"], 1); got[1] != out[0] {
		t.Fatalf("numa hook saw %#x, out %#x", got, out)
	}
	if got := lastCall(t, obs["bpf_redirect"], 1); got[1] != 4 {
		t.Fatalf("redirect hook saw %#x, want XDP_REDIRECT", got)
	}
}

// A program with a locked region keeps its call hooks, both outside the
// region, and behaves as the unmodified one.
func TestBpfCallAllSpinLock(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plan, _, out := callAllHooked(t, spinLockFixture, callReq("bpf_get_numa_node_id", "bpf_ktime_get_ns"), make([]byte, 64))
	if out[1] != 1 {
		t.Fatalf("counter %d, want 1", out[1])
	}
	work := spinLockFixture()
	insns := work.Programs["p"].Instructions
	lock := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.IsBuiltinCall() && ins.Constant == int64(asm.FnSpinLock) })
	unlock := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.IsBuiltinCall() && ins.Constant == int64(asm.FnSpinUnlock) })
	for _, h := range plan.hooks {
		if at := h.Sites[0].InstructionIndex; at > lock && at < unlock {
			t.Fatalf("%s site %d inside the locked region %d..%d", h.Call, at, lock, unlock)
		}
	}
}

// testPointerKind runs callAllHooked for a pointer helper in the static and
// the global arg:untrusted form; the global one skips on kernels before
// arg:untrusted (6.18). kernel names the fixture's kfunc calls, if any.
func testPointerKind(t *testing.T, fixture func() *ebpf.CollectionSpec, call string, kernel *btf.Spec) {
	testutil.SkipIfNotRoot(t)
	for _, form := range []string{"static", "untrusted"} {
		t.Run(form, func(t *testing.T) {
			req := callReq(call)
			req.StaticUntrusted, req.Kernel = form == "static", kernel
			plan, obs, _ := callAllHooked(t, fixture, req, make([]byte, 64))
			if h := plan.hooks[0]; !h.RetPtr || h.ArgReg != 0 || h.Static != (form == "static") || h.Untrusted == (form == "static") {
				t.Fatalf("hook %+v", h)
			}
			if o := obs[call]; o != nil {
				t.Logf("%s ret %#x", call, lastCall(t, o, 1)[1])
			}
		})
	}
}

// sockFixture (tc) passes skb->sk through bpf_sk_fullsock and then
// bpf_tcp_sock, stores the full socket's family and the TCP socket's
// snd_cwnd, or zero for a NULL, in out slots 0 and 1 and returns TC_ACT_OK.
func sockFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R1, asm.R6, 168, asm.DWord), // __sk_buff.sk
		asm.JEq.Imm(asm.R1, 0, "done"),
		asm.FnSkFullsock.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LoadMem(asm.R8, asm.R7, 4, asm.Word), // bpf_sock.family
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.FnTcpSock.Call(),
		asm.JEq.Imm(asm.R0, 0, "store"),
		asm.LoadMem(asm.R9, asm.R0, 0, asm.Word), // bpf_tcp_sock.snd_cwnd
		asm.Mov.Imm(asm.R1, 0).WithSymbol("store"),
	}
	insns = append(append(insns, outStore(0, asm.R8)...), asm.Mov.Imm(asm.R0, 0), asm.Return())
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return())
	return callFixtureSpec(ebpf.SchedCLS, insns)
}

func TestBpfCallAllPointerSkFullsock(t *testing.T) { testPointerKind(t, sockFixture, "bpf_sk_fullsock", nil) }
func TestBpfCallAllPointerTcpSock(t *testing.T)    { testPointerKind(t, sockFixture, "bpf_tcp_sock", nil) }

// ringbufFixture (XDP) reserves 8 bytes of rb, writes 7 into them and, with
// submit, submits them; it stores 1 in out slot 0 when the reservation
// succeeded and returns XDP_PASS. Without submit the reference leaks and the
// kernel must refuse the program.
func ringbufFixture(submit bool) func() *ebpf.CollectionSpec {
	return func() *ebpf.CollectionSpec {
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Mov.Imm(asm.R7, 0),
			asm.LoadMapPtr(asm.R1, 0).WithReference("rb"),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Imm(asm.R3, 0),
			asm.FnRingbufReserve.Call(),
			asm.JEq.Imm(asm.R0, 0, "done"),
			asm.Mov.Imm(asm.R1, 7), asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R7, 1),
		}
		if submit {
			insns = append(insns, asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Imm(asm.R2, 0), asm.FnRingbufSubmit.Call())
		}
		insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("done"))
		insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 2), asm.Return())
		spec := callFixtureSpec(ebpf.XDP, insns)
		spec.Maps["rb"] = &ebpf.MapSpec{Name: "rb", Type: ebpf.RingBuf, MaxEntries: 4096}
		return spec
	}
}

func TestBpfCallAllPointerRingbufReserve(t *testing.T) {
	testPointerKind(t, ringbufFixture(true), "bpf_ringbuf_reserve", nil)
}

// Without the submit both the unmodified and the hooked program are refused
// in both forms: the hook does not hide the leaked reference.
func TestBpfCallAllPointerRingbufMissingSubmit(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if _, err := ebpf.NewCollection(ringbufFixture(false)()); err == nil || !strings.Contains(err.Error(), "reference") {
		t.Fatalf("unmodified program without submit: %v", err)
	}
	for _, static := range []bool{true, false} {
		work := ringbufFixture(false)()
		req := callReq("bpf_ringbuf_reserve")
		req.StaticUntrusted = static
		plan, err := transformLookup(work, req)
		if err != nil || len(plan.hooks) != 1 {
			t.Fatalf("static %v: hooks %+v err %v", static, plan.hooks, err)
		}
		coll, err := ebpf.NewCollection(work)
		if err == nil {
			coll.Close()
			t.Fatalf("static %v: the hooked program without submit loaded", static)
		}
		var ve *ebpf.VerifierError
		if !errors.As(err, &ve) {
			t.Fatalf("static %v: %v", static, err)
		}
		t.Logf("static %v: refused: %v", static, err)
	}
}

// thisCPUFixture (XDP) reads the int bpf_prog_active of this CPU through
// bpf_this_cpu_ptr, ignores it and returns XDP_PASS; a typed ksym of the
// running kernel, so it needs kernel BTF.
func thisCPUFixture(t *testing.T) func() *ebpf.CollectionSpec {
	kernel := kernelBTF(t)
	var v *btf.Var
	if err := kernel.TypeByName("bpf_prog_active", &v); err != nil {
		t.Skipf("kernel BTF has no bpf_prog_active: %v", err)
	}
	id, err := kernel.TypeID(v)
	if err != nil {
		t.Fatal(err)
	}
	return func() *ebpf.CollectionSpec {
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R1, Src: asm.R3, Constant: int64(id)}, // BPF_PSEUDO_BTF_ID
			asm.FnThisCpuPtr.Call(),
			asm.LoadMem(asm.R7, asm.R0, 0, asm.Word),
			asm.Mov.Imm(asm.R7, 1),
		}
		insns = append(append(insns, outStore(0, asm.R7)...), asm.Mov.Imm(asm.R0, 2), asm.Return())
		return callFixtureSpec(ebpf.XDP, insns)
	}
}

func TestBpfCallAllPointerThisCpuPtr(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	testPointerKind(t, thisCPUFixture(t), "bpf_this_cpu_ptr", nil)
}

// kptrFixture (tc) exchanges NULL into the referenced kptr of kptrs[0] with
// bpf_kptr_xchg, releases the old pointer if there was one and returns
// TC_ACT_OK. The kptr is a task_struct released by bpf_task_release (6.2
// and later), or on kernels without it the test_run kfuncs'
// prog_test_ref_kfunc released by bpf_kfunc_call_test_release (6.1, which
// spells a referenced kptr kptr_ref).
func kptrFixture(t *testing.T) (func() *ebpf.CollectionSpec, *btf.Spec) {
	kernel := kernelBTF(t)
	target, release, tag := "task_struct", "bpf_task_release", "kptr"
	var fn *btf.Func
	if kernel.TypeByName(release, &fn) != nil {
		target, release, tag = "prog_test_ref_kfunc", "bpf_kfunc_call_test_release", "kptr_ref"
		if err := kernel.TypeByName(release, &fn); err != nil {
			t.Skipf("kernel has neither bpf_task_release nor %s: %v", release, err)
		}
	}
	call := kernelKfunc(t, release)
	return func() *ebpf.CollectionSpec {
		u32 := &btf.Int{Name: "u32", Size: 4}
		obj := &btf.Struct{Name: target, Size: 4, Members: []btf.Member{{Name: "dummy", Type: u32}}}
		value := &btf.Struct{Name: "kval", Size: 8, Members: []btf.Member{
			{Name: "p", Type: &btf.Pointer{Target: &btf.TypeTag{Value: tag, Type: obj}}}}}
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
			asm.LoadMapPtr(asm.R1, 0).WithReference("kptrs"), asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "done"),
			asm.Mov.Reg(asm.R1, asm.R0),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnKptrXchg.Call(),
			asm.JEq.Imm(asm.R0, 0, "done"),
			asm.Mov.Reg(asm.R1, asm.R0),
			call,
			asm.Mov.Imm(asm.R0, 0).WithSymbol("done"),
			asm.Return(),
		}
		spec := callFixtureSpec(ebpf.SchedCLS, insns)
		spec.Maps["kptrs"] = &ebpf.MapSpec{Name: "kptrs", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1, Key: u32, Value: value}
		return spec
	}, kernel
}

func TestBpfCallAllPointerKptrXchg(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	fixture, kernel := kptrFixture(t)
	testPointerKind(t, fixture, "bpf_kptr_xchg", kernel)
}
