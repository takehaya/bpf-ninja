package inject

import (
	"errors"
	"fmt"
	"math"
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
		{"unknown", func(r *LookupRequest) { r.Calls, r.Kernel = []string{"bpf_dynptr_from_xdp"}, testKernelSpec(t) },
			`Calls name "bpf_dynptr_from_xdp" is not supported: it is neither a helper nor a kernel function of the running kernel or of a module BTF the program passes`},
		{"lock", func(r *LookupRequest) { r.Calls = []string{"bpf_spin_lock"} }, `Calls name "bpf_spin_lock" cannot be hooked: takes or releases a lock or a critical section`},
		{"callback", func(r *LookupRequest) { r.Calls = []string{"bpf_loop"} }, `Calls name "bpf_loop" cannot be hooked: runs or registers a callback`},
		{"void", func(r *LookupRequest) { r.Calls = []string{"bpf_ringbuf_submit"} }, `Calls name "bpf_ringbuf_submit" cannot be hooked: returns nothing`},
		{"map helper", func(r *LookupRequest) { r.Calls = []string{"bpf_map_update_elem"} }, `Calls name "bpf_map_update_elem" cannot be hooked: a map helper: the rule's maps and ops observe it`},
		{"tail call", func(r *LookupRequest) { r.Calls = []string{"bpf_tail_call"} }, `Calls name "bpf_tail_call" cannot be hooked: a tail call: the rule's tail_calls observes it`},
		{"unspec", func(r *LookupRequest) { r.Calls = []string{"bpf_unspec"} }, `Calls name "bpf_unspec" cannot be hooked: not a callable helper`},
		{"pointer kind", func(r *LookupRequest) { r.Calls = []string{"bpf_get_local_storage"} }, `Calls name "bpf_get_local_storage" cannot be hooked: ` + noPointerTest},
		{"native stack", func(r *LookupRequest) { r.Calls = []string{"bpf_get_stackid"} },
			`Calls name "bpf_get_stackid" cannot be hooked: reads native code addresses or branch records, which inserted code may change`},
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
			// Without kernel BTF a configuration check cannot tell an unknown name from a kernel function.
			if tc.name != "no site" && tc.name != "unknown" {
				if err := ValidateRaw(LookupRequestRaw{HookName: req.HookName, Dispatch: req.Dispatch, Calls: req.Calls, Stack: req.Stack}); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("ValidateRaw: %v", err)
				}
			}
		})
	}
}

// A program that takes a spin lock keeps its call hooks: the lock blocks
// nothing, and the lock helpers themselves are never hooked.
func TestCallNotBlockedBySpinLock(t *testing.T) {
	plan, err := transformLookup(spinLockFixture(), callReq("bpf_get_numa_node_id", "bpf_ktime_get_ns"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || len(plan.skipped) != 0 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
}

// Neither an unnameable kfunc nor bpf_preempt_disable keeps the program's
// other call sites from their hooks: a site the kernel refuses inside a
// preemption-disabled region is left to the load retry. The unnameable call
// is listed as skipped.
func TestCallNotBlockedByKfuncs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		call    asm.Instruction
		kernel  *btf.Spec
		skipped int
	}{
		{"nil kernel", kfuncCall(1), nil, 1},
		{"missing module", asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: 1, Offset: 1}, testKernelSpec(t), 1},
		{"preempt disable", kfuncCall(-1).WithReference("bpf_preempt_disable"), nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := scalarFixture()
			insns := spec.Programs["p"].Instructions
			spec.Programs["p"].Instructions = slices.Insert(insns, len(insns)-1, tc.call)
			req := callReq("bpf_get_prandom_u32", "bpf_jiffies64")
			req.Entry, req.Kernel = true, tc.kernel
			plan, err := transformLookup(spec, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 3 || len(plan.skipped) != tc.skipped {
				t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
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

// A size that is not a constant set in this block gives the callee the
// result-only hook, with the reason in ArgReason.
func TestCallSizeNotConstant(t *testing.T) {
	spec := fibFixture(ebpf.XDP)
	insns := spec.Programs["p"].Instructions
	i := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Dst == asm.R3 && ins.Constant == 64 })
	insns[i] = asm.Mov.Reg(asm.R3, asm.R8)
	insns = slices.Insert(insns, 1, asm.Mov.Imm(asm.R8, 64))
	spec.Programs["p"].Instructions = insns
	pc := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.IsBuiltinCall() && ins.Constant == int64(asm.FnFibLookup) })
	checkResultOnly(t, spec, fibReq(t), 1, fmt.Sprintf("the argument size in r3 at pc %d is not a constant set in its basic block", insns[:pc].Size()/asm.InstructionSize))
}

// checkResultOnly checks that req gives spec one result-only scalar hook of
// bpf_fib_lookup over sites sites, with reason, that injectcheck accepts.
func checkResultOnly(t *testing.T, spec *ebpf.CollectionSpec, req LookupRequest, sites int, reason string) {
	t.Helper()
	injectcheck.Label(spec.Programs["p"].Instructions)
	in := append(asm.Instructions(nil), spec.Programs["p"].Instructions...)
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || len(plan.skipped) != 0 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	h := plan.hooks[0]
	if h.Call != "bpf_fib_lookup" || h.ArgReg != 0 || h.ArgSize != 0 || h.ArgType != "" || h.RetPtr || h.Untrusted || h.Static ||
		len(h.Sites) != sites || h.ArgReason != reason {
		t.Fatalf("hook %+v", h)
	}
	out := spec.Programs["p"].Instructions
	if _, params := callHookFn(t, out, h.Name); !slices.Equal(params, []string{"ctx", "site", "ret"}) {
		t.Errorf("params %v", params)
	}
	cert, premises := validationCertificate(t, in, out, plan.hooks, -64)
	if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != sites {
		t.Fatalf("counts %+v err %v", counts, err)
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
	// Without kernel BTF the kfuncs cannot be named: their sites are skipped
	// with that reason, each under its own stand-in name.
	req.Kernel = nil
	spec = ctFixture(ebpf.XDP, func(name string) asm.Instruction { return testKfunc(t, kernel, name) }, 0, 8101, false)
	plan, err = transformLookup(spec, req)
	if err == nil || !strings.Contains(err.Error(), "no call site is instrumented (2 skipped)") {
		t.Fatalf("err %v skipped %+v", err, plan.skipped)
	}
	checkUnnamedSkipped(t, plan.skipped, kernel)
	// With another hook the rule loads, and the skipped sites are still listed.
	req.Entry = true
	spec = ctFixture(ebpf.XDP, func(name string) asm.Instruction { return testKfunc(t, kernel, name) }, 0, 8101, false)
	if plan, err = transformLookup(spec, req); err != nil || len(plan.hooks) != 1 || plan.hooks[0].Kind != HookEntry {
		t.Fatalf("err %v hooks %+v", err, plan.hooks)
	}
	checkUnnamedSkipped(t, plan.skipped, kernel)
}

// checkUnnamedSkipped checks that skipped lists the two unnamed kfunc calls
// of ctFixture, the lookup and the release, apart.
func checkUnnamedSkipped(t *testing.T, skipped []LookupSite, kernel *btf.Spec) {
	t.Helper()
	lookup, release := testKfunc(t, kernel, "bpf_xdp_ct_lookup"), testKfunc(t, kernel, "bpf_ct_release")
	if len(skipped) != 2 || skipped[0].Op != HookCall || skipped[0].Reason != "call: a kernel-function call that cannot be named" ||
		skipped[0].Call != fmt.Sprintf("kfunc_0_%d", lookup.Constant) || skipped[1].Call != fmt.Sprintf("kfunc_0_%d", release.Constant) ||
		skipped[1].Reason != skipped[0].Reason {
		t.Fatalf("skipped %+v", skipped)
	}
}

// A kfunc the rule names whose prototype cannot be read (ELF path, no kernel
// BTF) is listed as skipped with that reason.
func TestCallKfuncNoProtoSkipped(t *testing.T) {
	insns := asm.Instructions{asm.Mov.Imm(asm.R6, 1), asm.FnKtimeGetNs.Call(), asm.Mov.Imm(asm.R7, 1), kfuncCall(0).WithReference("bpf_some_kfunc")}
	insns = append(insns, outStore(0, asm.R0)...)
	spec := callFixtureSpec(ebpf.XDP, append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return()))
	plan, err := transformLookup(spec, callReq("bpf_some_kfunc", "bpf_ktime_get_ns"))
	if err != nil || len(plan.hooks) != 1 || plan.hooks[0].Call != "bpf_ktime_get_ns" {
		t.Fatalf("err %v hooks %+v", err, plan.hooks)
	}
	if len(plan.skipped) != 1 || plan.skipped[0].Call != "bpf_some_kfunc" || plan.skipped[0].Reason != "call: its prototype is not in the kernel BTF at hand" {
		t.Fatalf("skipped %+v", plan.skipped)
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

// Two sizes for one callee give all its sites the result-only hook.
func TestCallTwoSizes(t *testing.T) {
	second := fibCall(ebpf.XDP)
	i := slices.IndexFunc(second, func(ins asm.Instruction) bool { return ins.Dst == asm.R3 && ins.Constant == 64 })
	second[i] = asm.Mov.Imm(asm.R3, 48)
	insns := append(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, fibCall(ebpf.XDP)...)
	insns = append(append(insns, second...), fibVerdict(ebpf.XDP)...)
	checkResultOnly(t, callFixtureSpec(ebpf.XDP, insns), fibReq(t), 2, "bpf_fib_lookup is called with more than one argument size in this program (64 and 48)")
}

// Two sites with one size keep the typed hook, with no ArgReason.
func TestCallOneSizeTwice(t *testing.T) {
	insns := append(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, fibCall(ebpf.XDP)...)
	insns = append(append(insns, fibCall(ebpf.XDP)...), fibVerdict(ebpf.XDP)...)
	plan, err := transformLookup(callFixtureSpec(ebpf.XDP, insns), fibReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || len(plan.skipped) != 0 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	if h := plan.hooks[0]; h.ArgReg != 2 || h.ArgSize != 64 || h.ArgType != "bpf_fib_lookup" || h.Untrusted || len(h.Sites) != 2 || h.ArgReason != "" {
		t.Fatalf("hook %+v", h)
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

// Past the kernel's 256 functions, call groups go from the end of
// RetryRank's order until the program fits: the result-only hook of a helper
// without a row before the hook of a row callee.
func TestCallFunctionLimitDropsFromTheEnd(t *testing.T) {
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.FnGetNumaNodeId.Call(), asm.Mov.Imm(asm.R0, 2), asm.FnJiffies64.Call(), asm.Mov.Imm(asm.R0, 2)}
	for i := range 254 {
		insns = append(insns, asm.Call.Label(fmt.Sprintf("f%d", i)), asm.Mov.Imm(asm.R0, 2))
	}
	insns = append(insns, asm.Return())
	for i := range 254 {
		name := fmt.Sprintf("f%d", i)
		insns = append(insns, btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(name).WithSource(asm.Comment(name)), staticFunc(name)), asm.Return())
	}
	plan, err := transformLookup(callFixtureSpec(ebpf.XDP, insns), callReq("bpf_get_numa_node_id", "bpf_jiffies64"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Call != "bpf_jiffies64" || len(plan.skipped) != 1 || plan.skipped[0].Call != "bpf_get_numa_node_id" ||
		plan.skipped[0].Reason != "call: the program would have 257 functions, more than the kernel's 256" {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
}

// RetryRank orders the kinds as the retry tries them.
func TestRetryRank(t *testing.T) {
	hooks := []LookupHook{{Kind: HookLookup}, {Kind: HookDelete}, {Kind: HookTailCall}, {Kind: HookCall, Call: "bpf_fib_lookup"},
		{Kind: HookCall, Call: "bpf_get_numa_node_id"}, {Kind: HookCall, Call: "bpf_sk_fullsock", RetPtr: true},
		{Kind: HookCall, Call: "bpf_dynptr_from_xdp"}, {Kind: HookCall, Call: "bpf_task_from_pid", RetPtr: true}}
	for i, h := range hooks {
		if got := RetryRank(h); got != i {
			t.Errorf("RetryRank(%+v) = %d, want %d", h, got, i)
		}
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

// Drop takes the sites it names out of the request, whatever their kind,
// and lists them as skipped with the given reason; the other sites keep
// their hooks. An explicitly selected lookup is refused instead.
func TestDrop(t *testing.T) {
	const reason = "load: dropped by the caller"
	sitePCs := func(plan lookupPlan) []uint32 {
		var pcs []uint32
		for _, h := range plan.hooks {
			for _, s := range h.Sites {
				pcs = append(pcs, s.SitePC)
			}
		}
		return pcs
	}
	for _, tc := range []struct {
		name string
		spec func() *ebpf.CollectionSpec
		req  LookupRequest
	}{
		{"calls", scalarFixture, callReq("bpf_jiffies64", "bpf_get_prandom_u32")},
		{"auto lookups", multiLookupFixture, LookupRequest{ProgramName: "p", HookName: "obs", Auto: true, Entry: true, Stack: StackAudit{LowestOffset: -16}}},
		{"generic lookup", mapInMapFixture, LookupRequest{ProgramName: "p", HookName: "obs", Auto: true, Entry: true, Stack: StackAudit{LowestOffset: -16}}},
		{"tail calls", tailCallerFixture, LookupRequest{ProgramName: "caller", HookName: "h", TailCalls: true, Entry: true, Stack: StackAudit{LowestOffset: -8}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full, err := transformLookup(tc.spec(), tc.req)
			if err != nil {
				t.Fatal(err)
			}
			all := sitePCs(full)
			if len(all) == 0 {
				t.Fatalf("no site hooked: %+v", full.hooks)
			}
			req := tc.req
			req.Drop = map[uint32]string{all[0]: reason}
			plan, err := transformLookup(tc.spec(), req)
			if err != nil {
				t.Fatal(err)
			}
			if got := sitePCs(plan); !slices.Equal(got, all[1:]) {
				t.Fatalf("hooked sites %v, want %v", got, all[1:])
			}
			i := slices.IndexFunc(plan.skipped, func(s LookupSite) bool { return s.SitePC == all[0] })
			if i < 0 || plan.skipped[i].Reason != reason || len(plan.skipped) != len(full.skipped)+1 {
				t.Fatalf("skipped %+v", plan.skipped)
			}
		})
	}
	req := LookupRequest{ProgramName: "p", HookName: "obs", Site: LookupSelector{MapName: "sessions"}, Stack: StackAudit{LowestOffset: -16}}
	full, err := transformLookup(lookupFixture(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.Drop = map[uint32]string{full.hooks[0].Sites[0].SitePC: reason}
	if _, err := transformLookup(lookupFixture(), req); err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("explicit site dropped: err = %v", err)
	}
}

// branchFixture branches from slot 1 over a bpf_ktime_get_ns site at slot 3
// to the verdict pad instructions later.
func branchFixture(pad int) *ebpf.CollectionSpec {
	insns := asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.JNE.Imm(asm.R0, 0, ""), asm.Mov.Imm(asm.R6, 1), asm.FnKtimeGetNs.Call()}
	insns = append(insns, outStore(0, asm.R0)...)
	for range pad {
		insns = append(insns, asm.Mov.Imm(asm.R7, 0))
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return())
	insns[1].Offset = int16(7 + pad - 2) // slots: 0, 1 jne, 2, 3 call, 4-5 ldimm64, 6 store, then the pad
	return callFixtureSpec(ebpf.XDP, insns)
}

// A branch that the call site's code pushes out of int16 range drops the
// call sites, and the rule's other hooks stay; with nothing else to hook the
// rule is refused as having no call site.
func TestCallBranchRangeDropsCalls(t *testing.T) {
	const pad = math.MaxInt16 - 5 // the branch offset is exactly MaxInt16
	if off := branchFixture(pad).Programs["p"].Instructions[1].Offset; off != math.MaxInt16 {
		t.Fatalf("offset %d", off)
	}
	req := callReq("bpf_ktime_get_ns")
	req.Entry = true
	plan, err := transformLookup(branchFixture(pad), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Kind != HookEntry || len(plan.skipped) != 1 || plan.skipped[0].Call != "bpf_ktime_get_ns" ||
		plan.skipped[0].Reason != "branch at 4 overflows int16 after insertion" {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	req.Entry = false
	if _, err := transformLookup(branchFixture(pad), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no call site is instrumented (1 skipped)") {
		t.Fatalf("err %v", err)
	}
	// A shorter branch keeps the call hook.
	req.Entry = true
	if plan, err := transformLookup(branchFixture(10), req); err != nil || len(plan.hooks) != 2 || len(plan.skipped) != 0 {
		t.Fatalf("err %v hooks %+v skipped %+v", err, plan.hooks, plan.skipped)
	}
	// The refusal itself keeps its text and stays a refusal.
	var ins asm.Instruction
	if err := relocateOffset(&ins, 0, math.MaxInt16+2, false); !errors.Is(err, ErrRefused) || err.Error() != "inject: refused: branch at 0 overflows int16 after insertion" {
		t.Fatalf("err %v", err)
	}
}
