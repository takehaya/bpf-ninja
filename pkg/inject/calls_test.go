package inject

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// callReq is a request for hooks named obs_<callee> at the named callees.
func callReq(calls ...string) LookupRequest {
	return LookupRequest{ProgramName: "p", HookName: "obs", Stack: StackAudit{LowestOffset: -64}, Calls: calls}
}

// sameInsns compares instructions by encoding, ignoring call targets.
func sameInsns(a, b asm.Instructions) bool {
	return slices.EqualFunc(a, b, func(x, y asm.Instruction) bool {
		return x.OpCode == y.OpCode && x.Dst == y.Dst && x.Src == y.Src && x.Offset == y.Offset &&
			(x.Constant == y.Constant || x.IsFunctionCall()) && x.Reference() == y.Reference()
	})
}

// callHookFn returns the BTF function and parameter names of the parameter names of the hook name in insns.
func callHookFn(t *testing.T, insns asm.Instructions, name string) (*btf.Func, []string) {
	t.Helper()
	at := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Symbol() == name })
	if at < 0 {
		t.Fatalf("hook %s not in the output", name)
	}
	fn := btf.FuncMetadata(&insns[at])
	var params []string
	for _, p := range fn.Type.(*btf.FuncProto).Params {
		params = append(params, p.Name)
	}
	return fn, params
}

// callAt returns the indexes of the calls of hook in out.
func callAt(t *testing.T, out asm.Instructions, hook string) []int {
	t.Helper()
	var at []int
	for i, ins := range out {
		if ins.IsFunctionCall() && ins.Reference() == hook {
			at = append(at, i)
		}
	}
	return at
}

// Shape S: a site in the entry function has no prelude and sequence A after
// the call; a call that starts its function is skipped; hooks follow the
// order of their first site.
func TestCallSequenceA(t *testing.T) {
	spec := scalarFixture()
	plan, err := transformLookup(spec, callReq("bpf_jiffies64", "bpf_ktime_get_ns", "bpf_get_prandom_u32"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, h := range plan.hooks {
		names = append(names, h.Name)
		if h.Kind != HookCall || h.When != "any" || !h.SiteArg || h.ArgReg != 0 || h.RetPtr || h.Untrusted || h.Static || len(h.Sites) != 1 || h.Sites[0].Call != h.Call {
			t.Errorf("hook %+v", h)
		}
	}
	if !slices.Equal(names, []string{"obs_bpf_get_prandom_u32", "obs_bpf_jiffies64"}) {
		t.Fatalf("hooks %v", names)
	}
	if len(plan.skipped) != 1 || plan.skipped[0].Call != "bpf_ktime_get_ns" || plan.skipped[0].Op != HookCall ||
		plan.skipped[0].Reason != "call: the call is the first instruction of its function" {
		t.Fatalf("skipped %+v", plan.skipped)
	}
	out := spec.Programs["p"].Instructions
	slots := lookupSlots(-64)
	at := callAt(t, out, "obs_bpf_get_prandom_u32")
	if len(at) != 1 {
		t.Fatalf("hook calls %v", at)
	}
	want := asm.Instructions{
		asm.LoadMapValue(asm.R1, 0, 0).WithReference("out"), asm.StoreMem(asm.R1, 8, asm.R0, asm.DWord),
		asm.FnGetPrandomU32.Call(),
		asm.StoreMem(asm.RFP, int16(slots.result), asm.R0, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, int16(slots.ctx), asm.DWord),
		asm.Mov.Imm32(asm.R2, 8),
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Call.Label("obs_bpf_get_prandom_u32"),
		asm.LoadMem(asm.R0, asm.RFP, int16(slots.result), asm.DWord),
	}
	if got := out[at[0]-7 : at[0]+2]; !sameInsns(got, want) {
		t.Errorf("site:\n%v\nwant\n%v", got, want)
	}
	if _, params := callHookFn(t, out, "obs_bpf_get_prandom_u32"); !slices.Equal(params, []string{"ctx", "site", "ret"}) {
		t.Errorf("params %v", params)
	}
}

// Neighbouring calls skip both sites, and a request left with nothing to
// instrument is refused.
func TestCallAdjacent(t *testing.T) {
	plan, err := transformLookup(adjacentFixture(), callReq("bpf_ktime_get_ns", "bpf_jiffies64"))
	if err == nil || err.Error() != "inject: no call site is instrumented (2 skipped)" && !strings.HasSuffix(err.Error(), "no call site is instrumented (2 skipped)") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range plan.skipped {
		if s.Reason != "call: the instruction before or after the call is a call" {
			t.Errorf("skipped %+v", s)
		}
	}
	// With Entry, the request stands with the entry hook only.
	req := callReq("bpf_jiffies64")
	req.Entry = true
	if plan, err = transformLookup(adjacentFixture(), req); err != nil || len(plan.hooks) != 1 || plan.hooks[0].Kind != HookEntry {
		t.Fatalf("plan %+v err %v", plan.hooks, err)
	}
}

// A call in a bpf_loop callback that gets no context is skipped with the
// context proof's reason, which comes before the call rules.
func TestCallInCallback(t *testing.T) {
	plan, err := transformLookup(loopFixture(), callReq("bpf_ktime_get_ns"))
	if err == nil || !strings.Contains(err.Error(), "no call site is instrumented (1 skipped)") {
		t.Fatalf("err = %v", err)
	}
	if len(plan.skipped) != 1 || plan.skipped[0].FuncName != "cb" || !strings.HasPrefix(plan.skipped[0].Reason, "callback: the callback context is NULL") {
		t.Fatalf("skipped %+v", plan.skipped)
	}
}

// callbackCallFixture passes a non-NULL bpf_loop context, calls jiffies in the
// callback, and stores its result for the kernel test.
func callbackCallFixture() *ebpf.CollectionSpec {
	spec := callbackSiteFixture("loop", false)
	insns := spec.Programs["p"].Instructions
	cb := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Symbol() == "cb" })
	at := cb + slices.IndexFunc(insns[cb:], func(ins asm.Instruction) bool {
		return ins.OpCode == asm.Mov.Imm(asm.R0, 0).OpCode && ins.Dst == asm.R0 && ins.Constant == 0
	})
	call := append(asm.Instructions{asm.FnJiffies64.Call()}, outStore(0, asm.R0)...)
	spec.Programs["p"].Instructions = slices.Insert(insns, at, call...)
	spec.Maps["out"] = scalarFixture().Maps["out"]
	return spec
}

func TestCallInCallbackWithContext(t *testing.T) {
	req := callReq("bpf_jiffies64")
	req.Stack.LowestOffset = -16
	plan, err := transformLookup(callbackCallFixture(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || len(plan.sites) != 1 || len(plan.skipped) != 0 ||
		plan.sites[0].FuncName != "cb" || plan.sites[0].CtxSource != "callback:r2:fp-16" {
		t.Fatalf("plan %+v", plan)
	}
}

// Request-level refusals of the call rules.
func TestCallRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  func(*LookupRequest)
		want string
	}{
		{"dispatch", func(r *LookupRequest) { r.Dispatch = true }, "Calls does not combine with Dispatch"},
		{"unknown", func(r *LookupRequest) { r.Calls = []string{"bpf_dynptr_from_xdp"} },
			`Calls name "bpf_dynptr_from_xdp" is not supported: it is neither a helper nor a kernel function with a row (bpf_xdp_ct_lookup, bpf_skb_ct_lookup)`},
		{"lock", func(r *LookupRequest) { r.Calls = []string{"bpf_spin_lock"} }, `Calls name "bpf_spin_lock" cannot be hooked: takes or releases a lock or a critical section`},
		{"callback", func(r *LookupRequest) { r.Calls = []string{"bpf_loop"} }, `Calls name "bpf_loop" cannot be hooked: runs or registers a callback`},
		{"void", func(r *LookupRequest) { r.Calls = []string{"bpf_ringbuf_submit"} }, `Calls name "bpf_ringbuf_submit" cannot be hooked: returns nothing`},
		{"map helper", func(r *LookupRequest) { r.Calls = []string{"bpf_map_update_elem"} }, `Calls name "bpf_map_update_elem" cannot be hooked: a map helper: the rule's maps and ops observe it`},
		{"tail call", func(r *LookupRequest) { r.Calls = []string{"bpf_tail_call"} }, `Calls name "bpf_tail_call" cannot be hooked: a tail call: the rule's tail_calls observes it`},
		{"unspec", func(r *LookupRequest) { r.Calls = []string{"bpf_unspec"} }, `Calls name "bpf_unspec" cannot be hooked: not a callable helper`},
		{"pointer kind", func(r *LookupRequest) { r.Calls = []string{"bpf_get_listener_sock"} }, `Calls name "bpf_get_listener_sock" cannot be hooked: ` + noPointerTest},
		{"denied kfunc", func(r *LookupRequest) { r.Calls = []string{"bpf_throw"} }, `Calls name "bpf_throw" cannot be hooked: does not return`},
		{"repeated", func(r *LookupRequest) { r.Calls = []string{"bpf_jiffies64", "bpf_jiffies64"} }, `Calls names must be non-empty and unique; got "bpf_jiffies64"`},
		{"empty", func(r *LookupRequest) { r.Calls = []string{""} }, `Calls names must be non-empty and unique; got ""`},
		{"no site", func(r *LookupRequest) { r.Calls = []string{"bpf_fib_lookup"} }, "no call site is instrumented (0 skipped)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := callReq("bpf_jiffies64")
			tc.req(&req)
			_, err := transformLookup(scalarFixture(), req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.name != "no site" {
				if err := ValidateRaw(LookupRequestRaw{HookName: req.HookName, Dispatch: req.Dispatch, Calls: req.Calls, Stack: req.Stack}); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("ValidateRaw: %v", err)
				}
			}
		})
	}
}

// A program that takes a spin lock gets no call hook at all.
func TestCallBlockedBySpinLock(t *testing.T) {
	spec := scalarFixture()
	insns := spec.Programs["p"].Instructions
	// A spin-lock call before the return, never reached on a load.
	insns = slices.Insert(insns, len(insns)-1, asm.Mov.Imm(asm.R1, 0), asm.FnSpinLock.Call(), asm.Mov.Imm(asm.R0, 2))
	spec.Programs["p"].Instructions = insns
	plan, err := transformLookup(spec, callReq("bpf_jiffies64"))
	if err == nil || !strings.Contains(err.Error(), "no call site is instrumented (1 skipped)") {
		t.Fatalf("err = %v", err)
	}
	if len(plan.skipped) != 1 || !strings.HasPrefix(plan.skipped[0].Reason, "call: the program calls bpf_spin_lock") {
		t.Fatalf("skipped %+v", plan.skipped)
	}
}

// An unnameable kfunc skips every requested call site without affecting the
// request's other hooks.
func TestCallBlockedByUnnameableKfunc(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int16
		kernel *btf.Spec
	}{
		{name: "nil kernel"},
		{name: "missing module", offset: 1, kernel: testKernelSpec(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := scalarFixture()
			insns := spec.Programs["p"].Instructions
			call := kfuncCall(1)
			call.Offset = tc.offset
			spec.Programs["p"].Instructions = slices.Insert(insns, len(insns)-1, call)
			req := callReq("bpf_get_prandom_u32", "bpf_jiffies64")
			req.Entry, req.Kernel = true, tc.kernel
			plan, err := transformLookup(spec, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 1 || plan.hooks[0].Kind != HookEntry || len(plan.skipped) != 2 {
				t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
			}
			for _, site := range plan.skipped {
				if site.Reason != "call: a kernel-function call in the program cannot be named" {
					t.Errorf("skipped %+v", site)
				}
			}
		})
	}
}

// Auto names its map hooks around the call hooks' names, which do not count
// as map sites.
func TestCallWithAutoAndNames(t *testing.T) {
	req := callReq("bpf_jiffies64")
	req.Auto = true
	plan, err := transformLookup(scalarFixture(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Name != "obs_bpf_jiffies64" {
		t.Fatalf("hooks %+v", plan.hooks)
	}
	if got := hookSuffix(callReq("bpf_ktime_get_ns", "bpf_get_prandom_u32")); got != "_bpf_get_prandom_u32" {
		t.Errorf("hookSuffix = %q", got)
	}
	if got := LookupStackReserve(LookupRequest{Calls: []string{"bpf_jiffies64"}, Entry: true}); got < 24 {
		t.Errorf("LookupStackReserve = %d", got)
	}
}

// A site whose slots do not fit below its function's floor is skipped by
// itself.
func TestCallSiteFit(t *testing.T) {
	req := callReq("bpf_jiffies64", "bpf_get_prandom_u32")
	req.Stack = StackAudit{LowestOffset: -64, Frames: map[string]int16{"p": -488}}
	plan, err := transformLookup(scalarFixture(), req)
	if err == nil || !strings.Contains(err.Error(), "no call site is instrumented") {
		t.Fatalf("err = %v hooks %+v", err, plan.hooks)
	}
	if len(plan.skipped) != 2 || plan.skipped[0].Reason != `call: the hook's slots do not fit below function "p" stack floor -488` {
		t.Fatalf("skipped %+v", plan.skipped)
	}
}

// fibReq hooks bpf_fib_lookup with the synthetic kernel BTF.
func fibReq(t *testing.T) LookupRequest {
	req := callReq("bpf_fib_lookup")
	req.Stack.LowestOffset = -64
	req.Kernel = testKernelSpec(t)
	return req
}

// Shape M typed: the argument is the function's own stack in this block and
// bpf_fib_lookup writes it, so the hook takes const struct bpf_fib_lookup *
// from kernel BTF; sequence B keeps R2 in the key slot.
func TestCallSequenceBTyped(t *testing.T) {
	spec := fibFixture(ebpf.XDP)
	plan, err := transformLookup(spec, fibReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	h := plan.hooks[0]
	if h.Name != "obs_bpf_fib_lookup" || h.ArgReg != 2 || h.ArgType != "bpf_fib_lookup" || h.ArgSize != 64 || h.Untrusted || h.Static || h.RetPtr {
		t.Fatalf("hook %+v", h)
	}
	out := spec.Programs["p"].Instructions
	slots := lookupSlots(-64)
	at := callAt(t, out, h.Name)
	if len(at) != 1 {
		t.Fatalf("hook calls %v", at)
	}
	want := asm.Instructions{
		asm.StoreMem(asm.RFP, int16(slots.key), asm.R2, asm.DWord),
		asm.FnFibLookup.Call(),
		asm.StoreMem(asm.RFP, int16(slots.result), asm.R0, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, int16(slots.ctx), asm.DWord),
		asm.Mov.Imm32(asm.R2, 20),
		asm.LoadMem(asm.R3, asm.RFP, int16(slots.key), asm.DWord),
		asm.Mov.Reg(asm.R4, asm.R0),
		asm.Call.Label(h.Name),
		asm.LoadMem(asm.R0, asm.RFP, int16(slots.result), asm.DWord),
	}
	if got := out[at[0]-7 : at[0]+2]; !sameInsns(got, want) {
		t.Errorf("site:\n%v\nwant\n%v", got, want)
	}
	fn, params := callHookFn(t, out, h.Name)
	if !slices.Equal(params, []string{"ctx", "site", "arg", "ret"}) || fn.Linkage != btf.GlobalFunc || fn.ParamTags != nil {
		t.Errorf("hook %v params %v", fn, params)
	}
	arg := btf.UnderlyingType(fn.Type.(*btf.FuncProto).Params[2].Type).(*btf.Pointer).Target.(*btf.Const).Type
	if s, ok := arg.(*btf.Struct); !ok || s.Name != "bpf_fib_lookup" || s.Size != 64 {
		t.Errorf("arg type %v", arg)
	}
	targets, err := BuildLookupTargets(out, plan.hooks)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []injectcheck.ArgRole{injectcheck.ArgCtx, injectcheck.ArgSite, injectcheck.ArgArg, injectcheck.ArgRet}
	if len(targets) != 1 || targets[0].When != injectcheck.TargetAny || targets[0].ArgReg != 2 || targets[0].SitePC != 20 ||
		!slices.Equal(targets[0].Args, wantArgs) || targets[0].Site != plan.sites[0].InstructionIndex {
		t.Errorf("targets %+v", targets)
	}
}

// fibUntypedFixture is fibFixture with the buffer address copied through R8,
// so R2 is not own stack set in this block.
func fibUntypedFixture() *ebpf.CollectionSpec {
	spec := fibFixture(ebpf.XDP)
	insns := spec.Programs["p"].Instructions
	i := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Dst == asm.R2 && ins.Src == asm.RFP })
	insns[i] = asm.Mov.Reg(asm.R8, asm.RFP)
	insns = slices.Insert(insns, i+2, asm.Mov.Reg(asm.R2, asm.R8))
	insns[i+1] = asm.Add.Imm(asm.R8, -64)
	spec.Programs["p"].Instructions = insns
	return spec
}

// Shape M untyped: an argument that is not own stack in this block makes the
// hook untrusted with the size tag, or static with StaticUntrusted.
func TestCallSequenceBUntyped(t *testing.T) {
	spec := fibUntypedFixture()
	plan, err := transformLookup(spec, fibReq(t))
	if err != nil {
		t.Fatal(err)
	}
	h := plan.hooks[0]
	if !h.Untrusted || h.Static || h.ArgSize != 64 || h.ArgType != "bpf_fib_lookup" {
		t.Fatalf("hook %+v", h)
	}
	fn, _ := callHookFn(t, spec.Programs["p"].Instructions, h.Name)
	if !slices.Contains(fn.Tags, "bpf-ninja:arg_size=64") || fn.ParamTags[2][0] != "arg:untrusted" {
		t.Errorf("tags %v %v", fn.Tags, fn.ParamTags)
	}
	spec = fibUntypedFixture()
	req := fibReq(t)
	req.StaticUntrusted = true
	if plan, err = transformLookup(spec, req); err != nil {
		t.Fatal(err)
	}
	if h = plan.hooks[0]; !h.Static || h.Untrusted {
		t.Fatalf("hook %+v", h)
	}
	if fn, _ = callHookFn(t, spec.Programs["p"].Instructions, h.Name); fn.Linkage != btf.StaticFunc {
		t.Errorf("linkage %v", fn.Linkage)
	}
}

// A size that is not a constant set in this block skips the site.
func TestCallSizeNotConstant(t *testing.T) {
	spec := fibFixture(ebpf.XDP)
	insns := spec.Programs["p"].Instructions
	i := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Dst == asm.R3 && ins.Constant == 64 })
	insns[i] = asm.Mov.Reg(asm.R3, asm.R8)
	insns = slices.Insert(insns, 1, asm.Mov.Imm(asm.R8, 64))
	spec.Programs["p"].Instructions = insns
	plan, err := transformLookup(spec, fibReq(t))
	if err == nil || len(plan.skipped) != 1 || plan.skipped[0].Reason != "call: the argument size in r3 is not a constant set in this basic block" {
		t.Fatalf("err %v skipped %+v", err, plan.skipped)
	}
}

// Shape P on the raw path: a conntrack lookup named by its kernel BTF id
// gets const void *arg and const void *ret, both untrusted, with the opts
// struct's size.
func TestCallKfuncRaw(t *testing.T) {
	kernel := testKernelSpec(t)
	spec := ctFixture(ebpf.XDP, func(name string) asm.Instruction { return testKfunc(t, kernel, name) }, 0, 8101, false)
	req := callReq("bpf_xdp_ct_lookup")
	req.Kernel = kernel
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	h := plan.hooks[0]
	if h.Call != "bpf_xdp_ct_lookup" || !h.RetPtr || h.ArgReg != 4 || h.ArgSize != 12 || !h.Untrusted || h.Static {
		t.Fatalf("hook %+v", h)
	}
	fn, params := callHookFn(t, spec.Programs["p"].Instructions, h.Name)
	if !slices.Equal(params, []string{"ctx", "site", "arg", "ret"}) || fn.ParamTags[2][0] != "arg:untrusted" || fn.ParamTags[3][0] != "arg:untrusted" {
		t.Errorf("params %v tags %v", params, fn.ParamTags)
	}
	// Without kernel BTF the kfunc cannot be named: every call site is skipped.
	req.Kernel = nil
	spec = ctFixture(ebpf.XDP, func(name string) asm.Instruction { return testKfunc(t, kernel, name) }, 0, 8101, false)
	plan, err = transformLookup(spec, req)
	if err == nil || !strings.Contains(err.Error(), "no call site is instrumented (0 skipped)") {
		t.Fatalf("err %v skipped %+v", err, plan.skipped)
	}
}

// A module kfunc (nonzero offset) is named through Modules, and its argument
// struct, absent from vmlinux, is typed from the module BTF.
func TestCallKfuncModule(t *testing.T) {
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}
	module := specOf(t, &btf.Struct{Name: "bpf_ct_opts", Size: 12},
		&btf.Func{Name: "bpf_xdp_ct_lookup", Type: proto, Linkage: btf.GlobalFunc},
		&btf.Func{Name: "bpf_ct_release", Type: proto, Linkage: btf.GlobalFunc})
	spec := ctFixture(ebpf.XDP, func(name string) asm.Instruction {
		ins := testKfunc(t, module, name)
		ins.Offset = 1
		return ins
	}, 0, 8101, false)
	req := callReq("bpf_xdp_ct_lookup")
	req.Kernel = specOf(t, &btf.Struct{Name: "bpf_fib_lookup", Size: 64})
	req.Modules = map[int16]*btf.Spec{1: module}
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Call != "bpf_xdp_ct_lookup" || plan.hooks[0].ArgType != "bpf_ct_opts" {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
}

// Requests without Calls never see a call site.
func TestCallSitesNotListedWithoutCalls(t *testing.T) {
	spec := fibFixture(ebpf.XDP)
	prog := spec.Programs["p"]
	sites, err := discoverSites(prog.Instructions, prog.Type, elfLookupMaps(spec), LookupRequest{Calls: []string{"bpf_jiffies64"}})
	if err != nil || len(sites) != 0 {
		t.Fatalf("sites %+v err %v", sites, err)
	}
}

// The load-time checker accepts the emitted sequences A and B at a helper
// and at a kfunc call.
func TestCallCheckerAccepts(t *testing.T) {
	kernel := testKernelSpec(t)
	ct := func() *ebpf.CollectionSpec {
		return ctFixture(ebpf.XDP, func(name string) asm.Instruction { return testKfunc(t, kernel, name) }, 0, 8101, false)
	}
	for _, tc := range []struct {
		name  string
		spec  func() *ebpf.CollectionSpec
		calls []string
	}{
		{"scalar", scalarFixture, []string{"bpf_get_prandom_u32", "bpf_jiffies64"}},
		{"fib", func() *ebpf.CollectionSpec { return fibFixture(ebpf.XDP) }, []string{"bpf_fib_lookup"}},
		{"fib untyped", fibUntypedFixture, []string{"bpf_fib_lookup"}},
		{"fib subprogram", func() *ebpf.CollectionSpec { return fibSubprogFixture(ebpf.SchedCLS) }, []string{"bpf_fib_lookup"}},
		{"ct", ct, []string{"bpf_xdp_ct_lookup"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := tc.spec()
			in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
			injectcheck.Label(work.Programs["p"].Instructions)
			req := callReq(tc.calls...)
			req.Kernel = kernel
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			out := work.Programs["p"].Instructions
			cert, premises := validationCertificate(t, in, out, plan.hooks, -64)
			counts, err := injectcheck.Check(in, out, cert, premises)
			if err != nil || counts.Sites != len(plan.sites) {
				t.Fatalf("counts %+v sites %d err %v", counts, len(plan.sites), err)
			}
		})
	}
}

// Two sizes for one callee skip all its sites.
func TestCallTwoSizes(t *testing.T) {
	second := fibCall(ebpf.XDP)
	i := slices.IndexFunc(second, func(ins asm.Instruction) bool { return ins.Dst == asm.R3 && ins.Constant == 64 })
	second[i] = asm.Mov.Imm(asm.R3, 48)
	insns := append(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, fibCall(ebpf.XDP)...)
	insns = append(append(insns, second...), fibVerdict(ebpf.XDP)...)
	plan, err := transformLookup(callFixtureSpec(ebpf.XDP, insns), fibReq(t))
	if err == nil || len(plan.skipped) != 2 {
		t.Fatalf("err %v skipped %+v", err, plan.skipped)
	}
	for _, s := range plan.skipped {
		if s.Reason != "call: bpf_fib_lookup is called with more than one argument size in this program (64 and 48)" {
			t.Errorf("skipped %+v", s)
		}
	}
}

// A hook that would take the program past the kernel's 256 functions drops
// every call site.
func TestCallFunctionLimit(t *testing.T) {
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.FnJiffies64.Call(), asm.Mov.Imm(asm.R0, 2)}
	for i := range 255 {
		insns = append(insns, asm.Call.Label(fmt.Sprintf("f%d", i)), asm.Mov.Imm(asm.R0, 2))
	}
	insns = append(insns, asm.Return())
	for i := range 255 {
		name := fmt.Sprintf("f%d", i)
		insns = append(insns, btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(name).WithSource(asm.Comment(name)), staticFunc(name)), asm.Return())
	}
	plan, err := transformLookup(callFixtureSpec(ebpf.XDP, insns), callReq("bpf_jiffies64"))
	if err == nil || !strings.Contains(err.Error(), "no call site is instrumented (1 skipped)") ||
		len(plan.skipped) != 1 || plan.skipped[0].Reason != "call: the program would have 257 functions, more than the kernel's 256" {
		t.Fatalf("err %v skipped %+v", err, plan.skipped)
	}
}

// spliceLookupCalls gives a call site with nothing to keep no prelude, also
// at the start of a function: the function's symbol stays on the call.
func TestCallEmptyPreludeAtFunctionStart(t *testing.T) {
	spec := loopFixture()
	insns := spec.Programs["p"].Instructions
	cb := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Symbol() == "cb" })
	pc := uint32(0)
	for i := range cb {
		pc += uint32(insns[i].Size() / asm.InstructionSize)
	}
	out, err := spliceLookupCalls(insns, map[uint32]siteCall{pc: {hook: "h", op: HookCall, withSite: true, frameFloor: -64}},
		StackAudit{LowestOffset: -64}, scalarHook("h", &btf.Int{Name: "u64", Size: 8}), entryCall{frameFloor: -64})
	if err != nil {
		t.Fatal(err)
	}
	at := slices.IndexFunc(out, func(ins asm.Instruction) bool { return ins.Symbol() == "cb" })
	if at < 0 || !out[at].IsBuiltinCall() || btf.FuncMetadata(&out[at]) == nil {
		t.Fatalf("cb starts with %v", out[at])
	}
}

// ValidateRaw leaves room for "_" plus the longest Calls name, and Calls
// reserves the three base slots with Entry or TailCalls alone.
func TestCallNameRoomAndReserve(t *testing.T) {
	long := strings.Repeat("h", MaxHookName-len("_bpf_jiffies64"))
	if err := ValidateRaw(LookupRequestRaw{HookName: long, Calls: []string{"bpf_jiffies64"}}); err != nil {
		t.Fatalf("fitting name: %v", err)
	}
	if err := ValidateRaw(LookupRequestRaw{HookName: long + "h", Calls: []string{"bpf_jiffies64"}}); err == nil {
		t.Fatal("ValidateRaw accepts a hook name with no room for the call suffix")
	}
	for _, req := range []LookupRequest{{Calls: []string{"bpf_jiffies64"}, Entry: true}, {Calls: []string{"bpf_jiffies64"}, TailCalls: true}} {
		if got := LookupStackReserve(req); got != 24 {
			t.Errorf("LookupStackReserve(%+v) = %d, want 24", req, got)
		}
	}
}
