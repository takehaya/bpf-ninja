package inject

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

// callHooked transforms spec for req, loads it and attaches an fentry
// observer to each hook. The observer records the arguments after ctx: the
// site, then for a hook with arg the first 8 bytes through it, then ret raw.
func callHooked(t *testing.T, spec *ebpf.CollectionSpec, req LookupRequest) (*ebpf.Collection, lookupPlan, map[string]*ebpf.Collection) {
	t.Helper()
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != len(req.Calls) {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	coll := loadHooked(t, spec, plan.hooks)
	t.Cleanup(coll.Close)
	obs := map[string]*ebpf.Collection{}
	for _, h := range plan.hooks {
		ptr := []bool{false, false}
		if h.ArgReg != 0 {
			ptr = []bool{false, true, false}
		}
		obs[h.Call] = attachArgObserver(t, h.Name, coll.Programs["p"], ptr...)
	}
	return coll, plan, obs
}

// lastCall is the last call obs recorded, after n calls in all.
func lastCall(t *testing.T, obs *ebpf.Collection, n int) [4]uint64 {
	t.Helper()
	calls := observed(t, obs)
	if len(calls) != n {
		t.Fatalf("%d hook calls, want %d", len(calls), n)
	}
	return calls[n-1]
}

func kernelBTF(t *testing.T) *btf.Spec {
	t.Helper()
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("kernel BTF: %v", err)
	}
	return spec
}

// callLookupFixture calls bpf_jiffies64 and looks up sessions[7] in the same
// entry frame, stores both results in out, and returns the map value.
func callLookupFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -4, 7, asm.Word),
		asm.FnJiffies64.Call(),
	}
	insns = append(insns, outStore(0, asm.R0)...)
	insns = append(insns,
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"), asm.LoadMem(asm.R7, asm.R0, 0, asm.DWord))
	insns = append(insns, outStore(1, asm.R7)...)
	insns = append(insns,
		asm.Mov.Reg(asm.R0, asm.R7), asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("drop"), asm.Return())
	spec := callFixtureSpec(ebpf.XDP, insns)
	spec.Maps["sessions"] = lookupFixture().Maps["sessions"]
	return spec
}

// Calls and Auto share the same frame without changing either site's saved
// state: both hooks see their values and the program matches the plain one.
func TestBpfCallHookWithAutoLookup(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain := loadCallFixture(t, callLookupFixture())
	work := callLookupFixture()
	req := callReq("bpf_jiffies64")
	req.Auto = true
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	var lookup, call LookupHook
	for _, h := range plan.hooks {
		switch h.Kind {
		case HookLookup:
			lookup = h
		case HookCall:
			call = h
		}
	}
	if lookup.Name == "" || call.Name == "" {
		t.Fatalf("hooks %+v", plan.hooks)
	}
	hooked := loadHooked(t, work, plan.hooks)
	t.Cleanup(hooked.Close)
	for _, coll := range []*ebpf.Collection{plain, hooked} {
		if err := coll.Maps["sessions"].Put(uint32(7), [2]uint64{2, 0x1234}); err != nil {
			t.Fatal(err)
		}
	}
	callObs := attachArgObserver(t, call.Name, hooked.Programs["p"], false, false)
	lookupObs := attachArgObserver(t, lookup.Name, hooked.Programs["p"], false, true, true)
	plainRet, plainOut := runCallFixture(t, plain, make([]byte, 64), nil)
	ret, out := runCallFixture(t, hooked, make([]byte, 64), nil)
	if ret != plainRet || out != plainOut || ret != 2 {
		t.Fatalf("hooked %d %#x, plain %d %#x", ret, out, plainRet, plainOut)
	}
	if got := lastCall(t, callObs, 1); got[0] != uint64(call.Sites[0].SitePC) || got[1] != out[0] {
		t.Fatalf("call hook saw %#x, want site %d ret %#x", got, call.Sites[0].SitePC, out[0])
	}
	if got := lastCall(t, lookupObs, 1); got[0] != uint64(lookup.Sites[0].SitePC) || uint32(got[1]) != 7 || got[2] != 2 {
		t.Fatalf("lookup hook saw %#x, want site %d key 7 value 2", got, lookup.Sites[0].SitePC)
	}
}

func TestBpfCallHookInCallbackWithContext(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain := loadCallFixture(t, callbackCallFixture())
	work := callbackCallFixture()
	req := callReq("bpf_jiffies64")
	req.Stack.LowestOffset = -16
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || len(plan.sites) != 1 || plan.sites[0].FuncName != "cb" {
		t.Fatalf("plan %+v", plan)
	}
	hooked := loadHooked(t, work, plan.hooks)
	t.Cleanup(hooked.Close)
	obs := attachArgObserver(t, plan.hooks[0].Name, hooked.Programs["p"], false, false)
	plainRet, plainOut := runCallFixture(t, plain, make([]byte, 64), nil)
	ret, out := runCallFixture(t, hooked, make([]byte, 64), nil)
	if ret != plainRet || out != plainOut || ret != 3 || out[0] == 0 {
		t.Fatalf("hooked %d %#x, plain %d %#x", ret, out, plainRet, plainOut)
	}
	calls := observed(t, obs)
	if len(calls) != 3 {
		t.Fatalf("hook calls %d, want 3", len(calls))
	}
	for i, got := range calls {
		if got[0] != uint64(plan.sites[0].SitePC) || got[1] == 0 || i == 2 && got[1] != out[0] {
			t.Fatalf("call %d: hook saw %#x, want site %d and final ret %#x", i, got, plan.sites[0].SitePC, out[0])
		}
	}
}

// Shape S: the hooks after bpf_get_prandom_u32 and bpf_jiffies64 see the R0
// the program then stores, at their site, and the action is unchanged.
func TestBpfCallHookScalars(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain := loadCallFixture(t, scalarFixture())
	coll, plan, obs := callHooked(t, scalarFixture(), callReq("bpf_get_prandom_u32", "bpf_jiffies64"))
	slot := map[string]int{"bpf_get_prandom_u32": 2, "bpf_jiffies64": 3}
	for run := 1; run <= 3; run++ {
		if ret, _ := runCallFixture(t, plain, make([]byte, 64), nil); ret != 2 {
			t.Fatalf("plain action %d", ret)
		}
		ret, out := runCallFixture(t, coll, make([]byte, 64), nil)
		if ret != 2 {
			t.Fatalf("hooked action %d, want XDP_PASS", ret)
		}
		for _, h := range plan.hooks {
			got := lastCall(t, obs[h.Call], run)
			if got[0] != uint64(h.Sites[0].SitePC) || got[1] != out[slot[h.Call]] {
				t.Fatalf("run %d %s: site %d ret %#x, want %d and %#x", run, h.Call, got[0], got[1], h.Sites[0].SitePC, out[slot[h.Call]])
			}
		}
	}
}

// fibVariant is one hooked form of the fib fixtures.
type fibVariant struct {
	name   string
	spec   func(ebpf.ProgramType) *ebpf.CollectionSpec
	static bool
}

// testCallHookFib runs the fib steps of testCallFixtureFib on the plain and
// hooked fixtures: each hooked program returns the plain program's action
// and stores the same code, ifindex and MAC, and its hook sees the stored
// code as ret and the AF_INET family through arg.
func testCallHookFib(t *testing.T, typ ebpf.ProgramType, name string, variants []fibVariant) {
	testutil.SkipIfNotRoot(t)
	isolatedNetNS(t)
	kernel := kernelBTF(t)
	type pair struct {
		v                fibVariant
		plain, coll, obs *ebpf.Collection
		site             uint64
	}
	var pairs []pair
	for _, v := range variants {
		req := callReq("bpf_fib_lookup")
		req.Kernel, req.StaticUntrusted = kernel, v.static
		coll, plan, obs := callHooked(t, v.spec(typ), req)
		h := plan.hooks[0]
		if h.ArgType != "bpf_fib_lookup" || h.ArgSize != 64 || h.Static != v.static {
			t.Fatalf("%s: hook %+v", v.name, h)
		}
		pairs = append(pairs, pair{v: v, plain: loadCallFixture(t, v.spec(typ)), coll: coll, obs: obs["bpf_fib_lookup"], site: uint64(h.Sites[0].SitePC)})
	}
	dev := fibDevice(t, name)
	index := dev.Attrs().Index
	packet := make([]byte, 64)
	ctx := fibCtx(typ, index, len(packet))
	run := 0
	fwd, pass, drop := callVerdicts(typ)
	actions := map[uint64]int32{4: pass, 2: drop, 7: pass, 0: fwd}
	fibSteps(t, index, func(step string, code uint64) {
		t.Helper()
		run++
		for _, p := range pairs {
			wantRet, want := runCallFixture(t, p.plain, packet, ctx)
			ret, out := runCallFixture(t, p.coll, packet, ctx)
			if ret != wantRet || ret != uint32(actions[code]) || out != want || out[0] != code {
				t.Fatalf("%s, %s: hooked %d %#x, plain %d %#x, want code %d", step, p.v.name, ret, out, wantRet, want, code)
			}
			got := lastCall(t, p.obs, run)
			if got[0] != p.site || got[2] != out[0] || byte(got[1]) != unix.AF_INET {
				t.Fatalf("%s, %s: hook saw site %d arg %#x ret %d; want %d, AF_INET, %d", step, p.v.name, got[0], got[1], got[2], p.site, out[0])
			}
		}
	})
}

func TestBpfCallHookFibXDP(t *testing.T) {
	testCallHookFib(t, ebpf.XDP, "chkfibx", []fibVariant{{"entry", fibFixture, false}, {"subprogram", fibSubprogFixture, false},
		{"static", func(ebpf.ProgramType) *ebpf.CollectionSpec { return fibUntypedFixture() }, true}})
}

func TestBpfCallHookFibTC(t *testing.T) {
	testCallHookFib(t, ebpf.SchedCLS, "chkfibt", []fibVariant{{"entry", fibFixture, false}, {"subprogram", fibSubprogFixture, false}})
}

// The untyped global hook takes arg:untrusted, which 6.15 and older lack.
func TestBpfCallHookFibUntrusted(t *testing.T) {
	testCallHookFib(t, ebpf.XDP, "chkfibu", []fibVariant{{"untrusted", func(ebpf.ProgramType) *ebpf.CollectionSpec { return fibUntypedFixture() }, false}})
}

// testCallHookCt runs the conntrack lookup hooked, with the result tested
// before and after other code: a miss gives the hook a NULL ret and drops as
// the plain program does, a hit after the insert a non-NULL ret and passes.
func testCallHookCt(t *testing.T, typ ebpf.ProgramType, dport uint16, static bool) {
	testutil.SkipIfNotRoot(t)
	kernel := kernelBTF(t)
	kfunc := func(name string) asm.Instruction { return kernelKfunc(t, name) }
	status := nfConnStatusOffset(t)
	name := ctPrefix(typ) + "lookup"
	type pair struct{ plain, coll, obs *ebpf.Collection }
	var pairs []pair
	for _, unchecked := range []bool{false, true} {
		req := callReq(name)
		req.Kernel, req.StaticUntrusted = kernel, static
		coll, plan, obs := callHooked(t, ctFixture(typ, kfunc, status, dport, unchecked), req)
		if h := plan.hooks[0]; !h.RetPtr || h.ArgReg != 4 || h.Static != static || h.Untrusted == static || h.Sites[0].SitePC != 17 {
			t.Fatalf("hook %+v", h)
		}
		pairs = append(pairs, pair{loadCallFixture(t, ctFixture(typ, kfunc, status, dport, unchecked)), coll, obs[name]})
	}
	_, pass, drop := callVerdicts(typ)
	step := func(run int, action int32) {
		t.Helper()
		for i, p := range pairs {
			wantRet, want := runCallFixture(t, p.plain, make([]byte, 64), nil)
			ret, out := runCallFixture(t, p.coll, make([]byte, 64), nil)
			if ret != uint32(action) || wantRet != ret || out[0] != want[0] || out[1] != want[1] {
				t.Fatalf("run %d, fixture %d: hooked %d %#x, plain %d %#x, want action %d", run, i, ret, out, wantRet, want, action)
			}
			got := lastCall(t, p.obs, run)
			if got[0] != 17 || (got[2] != 0) != (action == pass) {
				t.Fatalf("run %d, fixture %d: hook saw site %d ret %#x", run, i, got[0], got[2])
			}
		}
	}
	step(1, drop)
	insert := loadCallFixture(t, ctInsertProgram(typ, kfunc, dport))
	if ret, err := insert.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 1 {
		t.Fatalf("insert: %d, %v; want 1", ret, err)
	}
	step(2, pass)
}

func TestBpfCallHookCtXDP(t *testing.T) { testCallHookCt(t, ebpf.XDP, 8111, true) }
func TestBpfCallHookCtTC(t *testing.T)  { testCallHookCt(t, ebpf.SchedCLS, 8112, true) }

// The global pointer-result hook takes arg:untrusted, which 6.15 and older lack.
func TestBpfCallHookCtUntrusted(t *testing.T) { testCallHookCt(t, ebpf.XDP, 8113, false) }

// Without the release the hooked conntrack program is rejected as the plain
// one is: the hook does not hide the acquired reference.
func TestBpfCallHookCtNoRelease(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	kernel := kernelBTF(t)
	release := kernelKfunc(t, "bpf_ct_release")
	spec := func() *ebpf.CollectionSpec {
		spec := ctFixture(ebpf.XDP, func(name string) asm.Instruction { return kernelKfunc(t, name) }, nfConnStatusOffset(t), 8114, false)
		insns := spec.Programs["p"].Instructions
		for i := range insns {
			if insns[i].IsKfuncCall() && insns[i].Constant == release.Constant {
				insns[i] = asm.Mov.Imm(asm.R1, 0)
			}
		}
		return spec
	}
	if coll, err := ebpf.NewCollection(spec()); err == nil {
		coll.Close()
		t.Fatal("plain program without the release loaded")
	}
	req := callReq("bpf_xdp_ct_lookup")
	req.Kernel, req.StaticUntrusted = kernel, true
	work := spec()
	if _, err := transformLookup(work, req); err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(work)
	if err == nil {
		coll.Close()
		t.Fatal("hooked program without the release loaded")
	}
	if log := fmt.Sprintf("%+v", err); !strings.Contains(log, "Unreleased reference") && !strings.Contains(log, "reference leak") {
		t.Fatalf("hooked program rejected for another reason: %+v", err)
	}
}
