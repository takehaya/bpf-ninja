package inject

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// fibEdited is fibFixture whose "r3 = 64" (the size of the fib argument) is
// replaced by edit(i, insns).
func fibEdited(edit func(i int, insns asm.Instructions) asm.Instructions) *ebpf.CollectionSpec {
	spec := fibFixture(ebpf.XDP)
	insns := spec.Programs["p"].Instructions
	i := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Dst == asm.R3 && ins.Constant == 64 })
	spec.Programs["p"].Instructions = edit(i, insns)
	return spec
}

// onlyHook transforms spec for req and returns its one hook.
func onlyHook(t *testing.T, spec *ebpf.CollectionSpec, req LookupRequest) LookupHook {
	t.Helper()
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	return plan.hooks[0]
}

// The argument size counts only as a constant set in the call's basic block
// and in 1..512: anything that changes the register after the constant, a
// constant set in another block, or a size out of range gives the
// result-only hook; a 32-bit move of the constant keeps the typed one.
func TestCallSizeConstantLimits(t *testing.T) {
	jumpOver := asm.JEq.Imm(asm.R8, 0, "")
	jumpOver.Offset = 1 // over "r3 = 64"
	for _, tc := range []struct {
		name string
		edit func(i int, insns asm.Instructions) asm.Instructions
	}{
		{"overwritten by a register", func(i int, insns asm.Instructions) asm.Instructions {
			return slices.Insert(insns, i+1, asm.Mov.Reg(asm.R3, asm.R8))
		}},
		{"changed by ALU", func(i int, insns asm.Instructions) asm.Instructions {
			return slices.Insert(insns, i+1, asm.Add.Reg(asm.R3, asm.R8))
		}},
		{"from another block", func(i int, insns asm.Instructions) asm.Instructions {
			return slices.Insert(insns, i, asm.Mov.Reg(asm.R3, asm.R8), jumpOver)
		}},
		{"atomic fetch", func(i int, insns asm.Instructions) asm.Instructions {
			return slices.Insert(insns, i+1, asm.FetchAdd.Mem(asm.RFP, asm.R3, asm.DWord, -8))
		}},
		{"zero", func(i int, insns asm.Instructions) asm.Instructions { insns[i] = asm.Mov.Imm(asm.R3, 0); return insns }},
		{"513", func(i int, insns asm.Instructions) asm.Instructions {
			insns[i] = asm.Mov.Imm(asm.R3, 513)
			return insns
		}},
		{"negative", func(i int, insns asm.Instructions) asm.Instructions { insns[i] = asm.Mov.Imm(asm.R3, -1); return insns }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if h := onlyHook(t, fibEdited(tc.edit), fibReq(t)); h.ArgReg != 0 || h.ArgReason == "" {
				t.Fatalf("hook %+v", h)
			}
		})
	}
	if h := onlyHook(t, fibEdited(func(i int, insns asm.Instructions) asm.Instructions {
		insns[i] = asm.Mov.Imm32(asm.R3, 64)
		return insns
	}), fibReq(t)); h.ArgReg != 2 || h.ArgSize != 64 || h.ArgReason != "" {
		t.Errorf("w3 = 64: %+v", h)
	}
}

// Every deny-list entry, and names next to them that are not on it.
func TestDenyReason(t *testing.T) {
	const (
		lock     = "takes or releases a lock or a critical section"
		native   = "reads native code addresses or branch records, which inserted code may change"
		perf     = "reads a perf event counter, which counts inserted code too"
		iter     = "an iterator: the verifier forks and prunes loop states at its next"
		locked   = "the verifier lets it run with a lock held"
		inserted = "the verifier inserts arguments at the call"
		rewrite  = "the verifier rewrites the call to a register move"
		inline   = "the verifier inlines or refuses the call"
	)
	for name, want := range map[string]string{
		"bpf_spin_lock": lock, "bpf_spin_unlock": lock, "bpf_res_spin_lock": lock, "bpf_res_spin_lock_irqsave": lock,
		"bpf_res_spin_unlock": lock, "bpf_res_spin_unlock_irqrestore": lock, "bpf_preempt_disable": lock, "bpf_preempt_enable": lock,
		"bpf_rcu_read_lock": lock, "bpf_rcu_read_unlock": lock, "bpf_local_irq_save": lock, "bpf_local_irq_restore": lock,
		"bpf_for_each_map_elem": callbackReason, "bpf_loop": callbackReason, "bpf_find_vma": callbackReason,
		"bpf_user_ringbuf_drain": callbackReason, "bpf_timer_set_callback": callbackReason, "bpf_rbtree_add_impl": callbackReason,
		"bpf_wq_set_callback": callbackReason, "bpf_wq_set_callback_impl": callbackReason,
		"bpf_task_work_schedule_signal": callbackReason, "bpf_task_work_schedule_signal_impl": callbackReason,
		"bpf_task_work_schedule_resume": callbackReason, "bpf_task_work_schedule_resume_impl": callbackReason,
		"bpf_throw":     "does not return",
		"bpf_get_stack": native, "bpf_get_stackid": native, "bpf_get_task_stack": native, "bpf_get_branch_snapshot": native, "bpf_get_func_ip": native,
		"bpf_perf_event_read": perf, "bpf_perf_event_read_value": perf,
		"bpf_iter_num_new": iter, "bpf_iter_task_next": iter, "bpf_iter_css_destroy": iter,
		"bpf_list_push_front_impl": locked, "bpf_list_pop_back": locked, "bpf_rbtree_remove": locked, "bpf_rbtree_first": locked,
		"bpf_refcount_acquire_impl": locked, "bpf_stream_vprintk": locked, "bpf_arena_alloc_pages": locked, "bpf_arena_free_pages": locked,
		"bpf_obj_new_impl": inserted, "bpf_percpu_obj_new_impl": inserted, "bpf_obj_drop_impl": inserted, "bpf_percpu_obj_drop_impl": inserted,
		"bpf_cast_to_kern_ctx": rewrite, "bpf_rdonly_cast": rewrite,
		"bpf_session_cookie": inline, "bpf_session_is_return": inline, "__bpf_trap": inline,
		// Not on the list.
		"bpf_ktime_get_ns": "", "bpf_iter_num_value": "", "bpf_arena_reserve": "", "bpf_spin_lock_x": "", "bpf_perf_event_output": "",
		"bpf_obj_new": "", "bpf_wq_start": "", "bpf_local_irq": "",
	} {
		if got := denyReason(name); got != want {
			t.Errorf("denyReason(%q) = %q, want %q", name, got, want)
		}
	}
}

// When call hooks break the kernel's 256-byte caller depth for a
// subprogram that tail-calls, the call sites are dropped with that limit
// and the rule keeps its entry hook.
func TestCallStackLimitDropsCalls(t *testing.T) {
	req := LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Calls: []string{"bpf_ktime_get_ns"}, Stack: StackAudit{LowestOffset: -208}}
	plan, err := transformLookup(stackCallFixture(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Kind != HookEntry || len(plan.skipped) != 1 || plan.skipped[0].Call != "bpf_ktime_get_ns" ||
		!strings.Contains(plan.skipped[0].Reason, "256-byte caller-depth limit for a subprogram that calls bpf_tail_call") {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	// With room the call keeps its hook.
	req.Stack.LowestOffset = -200
	if plan, err := transformLookup(stackCallFixture(), req); err != nil || len(plan.hooks) != 2 {
		t.Fatalf("err %v hooks %+v", err, plan.hooks)
	}
}

// With every tail call skipped, no tail-call hook is generated, also when
// the rule's other hooks are call hooks without Entry, and when the tail
// calls are skipped for stack room rather than dropped.
func TestTailCallHookLeftOut(t *testing.T) {
	hasTailHook := func(insns asm.Instructions, name string) bool {
		return slices.ContainsFunc(insns, func(ins asm.Instruction) bool { fn := btf.FuncMetadata(&ins); return fn != nil && fn.Name == name })
	}
	t.Run("other groups, no entry", func(t *testing.T) {
		spec := tailCallerFixture()
		spec.Programs["caller"].Instructions = slices.Insert(spec.Programs["caller"].Instructions, 1, asm.FnKtimeGetNs.Call())
		drop := map[uint32]string{}
		for _, tail := range tailCallSites(spec.Programs["caller"].Instructions) {
			drop[tail.SitePC] = "dropped"
		}
		req := LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "h", Stack: StackAudit{LowestOffset: -8}, Drop: drop, Calls: []string{"bpf_ktime_get_ns"}}
		plan, err := transformLookup(spec, req)
		if err != nil || len(plan.hooks) != 1 || plan.hooks[0].Call != "bpf_ktime_get_ns" {
			t.Fatalf("err %v hooks %+v skipped %+v", err, plan.hooks, plan.skipped)
		}
		if out := spec.Programs["caller"].Instructions; hasTailHook(out, "h_tail_call") || len(uncalled(out)) != 0 {
			t.Fatalf("tail-call hook generated: %v", uncalled(out))
		}
	})
	t.Run("tails skipped for stack room", func(t *testing.T) {
		spec := subTailCallerFixture()
		req := LookupRequest{ProgramName: "caller", Entry: true, TailCalls: true, HookName: "h", Stack: StackAudit{LowestOffset: -8, Frames: map[string]int16{"caller": -8, "sub": -496}}}
		plan, err := transformLookup(spec, req)
		if err != nil || len(plan.hooks) != 1 || plan.hooks[0].Kind != HookEntry || len(plan.skipped) != 1 ||
			!strings.HasPrefix(plan.skipped[0].Reason, "tail-call hook does not fit below function \"sub\"") {
			t.Fatalf("err %v hooks %+v skipped %+v", err, plan.hooks, plan.skipped)
		}
		if out := spec.Programs["caller"].Instructions; hasTailHook(out, "h_tail_call") || len(uncalled(out)) != 0 {
			t.Fatalf("tail-call hook generated: %v", uncalled(out))
		}
	})
}

// The listing fingerprint covers the instructions, the value offset of a
// map value reference, the map type, the sites and the function ranges.
func TestListingFingerprintParts(t *testing.T) {
	listing := func(p RawProgram) CallDiscovery {
		t.Helper()
		mapCalls, err := DiscoverMapCallsRaw(p)
		if err != nil {
			t.Fatal(err)
		}
		d, err := DiscoverCallSitesRaw(p, mapCalls)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	base := calleesRaw(t, 7, 8)
	d := listing(base)
	want := d.Fingerprint
	if again := listing(calleesRaw(t, 7, 8)).Fingerprint; again != want {
		t.Fatalf("fingerprint not stable: %s %s", want, again)
	}
	imm := calleesRaw(t, 7, 8)
	imm.Instructions[6].Constant = 1 // r0 = 1 before bpf_ktime_get_ns
	if listing(imm).Fingerprint == want {
		t.Error("an instruction immediate is not covered")
	}
	typ := calleesRaw(t, 7, 8)
	m := typ.Maps[7]
	m.Type = ebpf.LRUHash
	typ.Maps[7] = m
	if listing(typ).Fingerprint == want {
		t.Error("the map type is not covered")
	}
	withValue := func(off uint32) string {
		p := calleesRaw(t, 7, 8)
		p.Instructions = slices.Insert(p.Instructions, 1, asm.LoadMapValue(asm.R7, 7, off))
		return listing(p).Fingerprint
	}
	if withValue(0) == withValue(4) {
		t.Error("the map value offset is not covered")
	}
	all := slices.Concat(d.Sites, d.TailCalls)
	fp := func(funcs []FuncRange, sites []LookupSite) string {
		t.Helper()
		got, err := ListingFingerprint(base, funcs, d.Labels, sites)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	ref := fp(d.Funcs, all)
	line := slices.Clone(all)
	line[0].Line++
	if fp(d.Funcs, line) == ref || fp(d.Funcs, all[1:]) == ref {
		t.Error("the sites are not covered")
	}
	funcs := slices.Clone(d.Funcs)
	funcs[0].End--
	if fp(funcs, all) == ref {
		t.Error("the function ranges are not covered")
	}
}
