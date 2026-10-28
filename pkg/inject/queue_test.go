package inject

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Push, pop and peek each get a typed hook named after the map, taking the
// value where an update takes the key, and under Dispatch the dispatch hook.
// An error-only hook is guarded like an update.
func TestQueueOps(t *testing.T) {
	spec := queueFixture(ebpf.Queue, false)
	req := autoReq()
	req.Lookups, req.Pushes, req.Pops, req.Peeks, req.Stack.LowestOffset = LookupNone, CallError, CallAny, CallError, -8
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name string
		kind HookKind
		when CallWhen
		pc   uint32
	}{
		{"lookup_hook_q_push", HookPush, CallError, queuePushPC},
		{"lookup_hook_q_pop", HookPop, CallAny, queuePopPC},
		{"lookup_hook_q_peek", HookPeek, CallError, queuePeekPC},
	}
	if len(plan.hooks) != len(want) {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	for i, h := range plan.hooks {
		w := want[i]
		if h.Name != w.name || h.Kind != w.kind || h.When != string(w.when) || h.Generic || len(h.Sites) != 1 || h.Sites[0].SitePC != w.pc {
			t.Errorf("hook %d: %+v, want %+v", i, h, w)
		}
	}
	insns := spec.Programs["p"].Instructions
	params := hookParamNames(insns)
	for _, w := range want {
		if got := params[w.name]; !slices.Equal(got, []string{"ctx", "site", "value", "status"}) {
			t.Errorf("%s params = %v", w.name, got)
		}
	}
	guards := 0
	for _, ins := range insns {
		if ins.OpCode.JumpOp() == asm.JSGE && ins.OpCode.Class() == asm.Jump32Class {
			guards++
		}
	}
	if guards != 3 { // the fixture's own and the push and peek guards
		t.Errorf("guards = %d, want 3", guards)
	}

	spec = queueFixture(ebpf.Queue, false)
	req.Dispatch, req.HookName = true, "d"
	plan, err = transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 3 || slices.ContainsFunc(plan.hooks, func(h LookupHook) bool { return h.Name != "d" || !h.Dispatch }) {
		t.Fatalf("dispatch hooks: %+v", plan.hooks)
	}
	for op, want := range map[HookKind]int32{HookPush: 3, HookPop: 4, HookPeek: 5} {
		if infoOps[op] != want {
			t.Errorf("infoOps[%s] = %d, want %d", op, infoOps[op], want)
		}
	}
	// Every map call has an info op; a missing one would pass 0, a lookup's.
	for _, op := range []HookKind{HookLookup, HookEntry, HookTailCall, HookUpdate, HookDelete, HookPush, HookPop, HookPeek} {
		if _, ok := infoOps[op]; ok != op.MapCall() {
			t.Errorf("infoOps[%s] present = %v, MapCall = %v", op, ok, op.MapCall())
		}
	}
}

// Push, pop and peek are skipped on a map that is not a queue, stack or bloom
// filter, whose value BTF does not match its size, or whose value type a
// global function takes as something other than memory.
func TestQueueOpsSkipped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ebpf.MapSpec)
		reason string
	}{
		{"hash", func(m *ebpf.MapSpec) { m.Type, m.KeySize = ebpf.Hash, 4 }, "map type Hash is unsupported"},
		{"value size", func(m *ebpf.MapSpec) { m.ValueSize = 16 }, "map value BTF size does not match map size 16"},
		{"ctx value", func(m *ebpf.MapSpec) { m.Value = &btf.Struct{Name: "xdp_md", Size: m.ValueSize} },
			`map value type "xdp_md" has a special global-function pointer ABI`},
	} {
		spec := queueFixture(ebpf.Queue, false)
		tc.mutate(spec.Maps["q"])
		req := autoReq()
		req.Lookups, req.Pushes, req.Pops, req.Peeks, req.Stack.LowestOffset = LookupNone, CallAny, CallAny, CallAny, -8
		plan, err := transformLookup(spec, req)
		if err == nil || len(plan.hooks) != 0 || len(plan.skipped) != 3 ||
			slices.ContainsFunc(plan.skipped, func(s LookupSite) bool { return !strings.Contains(s.Reason, tc.reason) }) {
			t.Errorf("%s: hooks %+v skipped %+v err %v", tc.name, plan.hooks, plan.skipped, err)
		}
	}
	req := autoReq()
	req.Pushes = "miss"
	if _, err := transformLookup(queueFixture(ebpf.Queue, false), req); err == nil ||
		!strings.Contains(err.Error(), "Pushes, Pops and Peeks must be error or any") {
		t.Errorf("err = %v", err)
	}
}

// bpf_map_lookup_percpu_elem takes the lookup hooks.
func TestLookupPercpuHooks(t *testing.T) {
	spec := percpuFixture()
	req := autoReq()
	req.Lookups, req.Stack.LowestOffset = LookupAny, -8
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || plan.hooks[0].Kind != HookLookup || plan.hooks[0].Sites[0].SitePC != 13 ||
		plan.hooks[1].Name != "lookup_hook_m_miss" {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	if got := hookParamNames(spec.Programs["p"].Instructions)["lookup_hook_m"]; !slices.Equal(got, []string{"ctx", "site", "key", "value"}) {
		t.Errorf("params = %v", got)
	}
}

// A push or update whose pointer comes from a read-only map takes untrusted
// hooks, or static ones under StaticUntrusted; reading through the pointer
// ends the tracking.
func TestReadOnlyArgHooks(t *testing.T) {
	for _, static := range []bool{false, true} {
		req := autoReq()
		req.Lookups, req.Pushes, req.Updates, req.StaticUntrusted, req.Stack.LowestOffset = LookupNone, CallAny, CallAny, static, -8
		plan, err := transformLookup(readOnlyArgFixture(), req)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.hooks) != 2 || slices.ContainsFunc(plan.hooks, func(h LookupHook) bool { return h.Untrusted == static || h.Static != static }) {
			t.Errorf("static=%v: hooks %+v", static, plan.hooks)
		}
	}
	spec := readOnlyArgFixture()
	insns := spec.Programs["p"].Instructions
	// r2 = *(u64 *)r2 is no longer a pointer into ro.
	spec.Programs["p"].Instructions = append(insns[:2:2], append(asm.Instructions{asm.LoadMem(asm.R2, asm.R2, 0, asm.DWord)}, insns[2:]...)...)
	req := autoReq()
	req.Lookups, req.Pushes, req.Stack.LowestOffset = LookupNone, CallAny, -8
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Untrusted {
		t.Errorf("after a load: hooks %+v", plan.hooks)
	}
}
