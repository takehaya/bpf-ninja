package inject

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// mixedFixture looks up, updates and deletes in sessions, then updates
// through a clobbered R1, which only the generic hook can take. The
// subprogram sub deletes too. The transform never loads it.
func mixedFixture() *ebpf.CollectionSpec {
	spec := lookupFixture()
	key := func() asm.Instructions {
		return asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8)}
	}
	sessions := func() asm.Instruction { return asm.LoadMapPtr(asm.R1, 0).WithReference("sessions") }
	var insns asm.Instructions
	insns = append(insns, key()...)                                                                       // slots 0-1
	insns = append(insns, sessions(), asm.FnMapLookupElem.Call())                                         // 2-4
	insns = append(insns, key()...)                                                                       // 5-6
	insns = append(insns, asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -24), asm.Mov.Imm(asm.R4, 0)) // 7-9
	insns = append(insns, sessions(), asm.FnMapUpdateElem.Call())                                         // 10-12
	insns = append(insns, key()...)                                                                       // 13-14
	insns = append(insns, sessions(), asm.FnMapDeleteElem.Call())                                         // 15-17
	insns = append(insns, asm.FnMapUpdateElem.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return())               // 18-20
	sub := len(insns)
	insns = append(insns, key()...)                                             // 21-22: sub
	insns = append(insns, sessions(), asm.FnMapDeleteElem.Call(), asm.Return()) // 23-26: delete at 25
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("mixed fixture")), btf.FuncMetadata(&spec.Programs["p"].Instructions[0]))
	insns[sub] = btf.WithFuncMetadata(insns[sub].WithSymbol("sub").WithSource(asm.Comment("sub")), &btf.Func{Name: "sub", Linkage: btf.StaticFunc,
		Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}})
	spec.Programs["p"].Instructions = insns
	return spec
}

func mixedReq() LookupRequest {
	req := autoReq()
	req.Lookups, req.Updates, req.Deletes, req.Stack.LowestOffset = LookupAny, CallError, CallAny, -24
	return req
}

// Every op of a map gets its own hook, named after the map, and an update on
// a map known only at run time the generic PREFIX_any_update. An update
// observing errors is guarded by "R0 >= 0 skips"; a delete observing any
// result is not guarded.
func TestMapCalls(t *testing.T) {
	spec := mixedFixture()
	plan, err := transformLookup(spec, mixedReq())
	if err != nil {
		t.Fatal(err)
	}
	type hook struct {
		name    string
		kind    HookKind
		when    string
		generic bool
		sites   []uint32
	}
	var hooks []hook
	for _, h := range plan.hooks {
		var pcs []uint32
		for _, site := range h.Sites {
			pcs = append(pcs, site.SitePC)
		}
		hooks = append(hooks, hook{h.Name, h.Kind, h.When, h.Generic, pcs})
	}
	want := []hook{
		{"lookup_hook_sessions", HookLookup, "hit", false, []uint32{4}},
		{"lookup_hook_sessions_miss", HookLookup, "miss", false, []uint32{4}},
		{"lookup_hook_sessions_update", HookUpdate, "error", false, []uint32{12}},
		{"lookup_hook_sessions_delete", HookDelete, "any", false, []uint32{17}},
		{"lookup_hook_any_update", HookUpdate, "error", true, []uint32{18}},
	}
	if !slices.EqualFunc(hooks, want, func(a, b hook) bool {
		return a.name == b.name && a.kind == b.kind && a.when == b.when && a.generic == b.generic && slices.Equal(a.sites, b.sites)
	}) {
		t.Fatalf("hooks = %+v\nwant %+v", hooks, want)
	}
	if len(plan.skipped) != 1 || plan.skipped[0].SitePC != 25 || !strings.HasPrefix(plan.skipped[0].Reason, "delete is not in the entry function") {
		t.Fatalf("skipped = %+v", plan.skipped)
	}
	insns := spec.Programs["p"].Instructions
	params := hookParamNames(insns)
	for name, want := range map[string][]string{
		"lookup_hook_sessions_update": {"ctx", "site", "key", "value", "status"},
		"lookup_hook_sessions_delete": {"ctx", "site", "key", "status"},
		"lookup_hook_any_update":      {"ctx", "info", "key", "value", "map"},
	} {
		if !slices.Equal(params[name], want) {
			t.Errorf("%s params = %v, want %v", name, params[name], want)
		}
	}
	var guards, calls []string
	for _, ins := range insns {
		if ins.OpCode.JumpOp() == asm.JSGE && ins.OpCode.Class() == asm.Jump32Class {
			guards = append(guards, "jsge")
		}
		if ins.IsFunctionCall() {
			calls = append(calls, ins.Reference())
		}
	}
	if len(guards) != 2 {
		t.Errorf("guards = %v, want one per update site", guards)
	}
	if !slices.Equal(calls, []string{"lookup_hook_sessions", "lookup_hook_sessions_miss", "lookup_hook_sessions_update",
		"lookup_hook_sessions_delete", "lookup_hook_any_update"}) {
		t.Errorf("calls = %v", calls)
	}
}

// An update keeps its value pointer in the map slot, or with a hook that also
// takes the map in a fifth slot: those sites need one or two slots more than
// a lookup, and Auto skips the generic update whose fifth slot passes the
// limit. CheckLookupStack holds the typed update to the map slot and a
// dispatch update to the fifth.
func TestMapCallStack(t *testing.T) {
	req := mixedReq()
	req.Stack.LowestOffset = -448
	plan, err := transformLookup(mixedFixture(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(plan.hooks, func(h LookupHook) bool { return h.Name == "lookup_hook_sessions_update" }) ||
		!slices.ContainsFunc(plan.skipped, func(s LookupSite) bool {
			return s.SitePC == 18 && strings.HasPrefix(s.Reason, "update hook needs 5 spill slots")
		}) {
		t.Fatalf("hooks = %+v\nskipped = %+v", plan.hooks, plan.skipped)
	}
	for _, tc := range []struct {
		dispatch bool
		lowest   int16
		ok       bool
	}{{false, -448, true}, {false, -449, false}, {true, -440, true}, {true, -441, false}} {
		req := mixedReq()
		req.Dispatch, req.HookName, req.Stack.LowestOffset = tc.dispatch, "d", tc.lowest
		if err := CheckLookupStack(req); (err == nil) != tc.ok {
			t.Errorf("dispatch=%v lowest=%d: %v", tc.dispatch, tc.lowest, err)
		}
	}
	for want, req := range map[int]LookupRequest{
		24: {Auto: true},
		32: {Auto: true, Updates: CallError},
		40: {Auto: true, Updates: CallAny, Dispatch: true},
	} {
		if got := LookupStackReserve(req); got != want {
			t.Errorf("LookupStackReserve(%+v) = %d, want %d", req, got, want)
		}
	}
}

func TestMapCallRefusals(t *testing.T) {
	for _, tc := range []struct {
		req  func() LookupRequest
		want string
	}{
		{func() LookupRequest { r := lookupReq(); r.Updates = CallError; return r }, "Updates and Deletes need Auto"},
		{func() LookupRequest { r := autoReq(); r.Deletes = "sometimes"; return r }, "Updates and Deletes must be error or any"},
		{func() LookupRequest { r := lookupReq(); r.Lookups = LookupNone; return r }, "Lookups none selects no lookup"},
		// The fixture has no update or delete, and lookups are not observed.
		{func() LookupRequest { r := autoReq(); r.Lookups, r.Updates = LookupNone, CallAny; return r }, "no supported lookup sites"},
	} {
		if _, err := transformLookup(lookupFixture(), tc.req()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("err = %v, want %q", err, tc.want)
		}
	}
	raw := LookupRequestRaw{Auto: true, Updates: CallError, HookName: strings.Repeat("h", MaxHookName-len("_0_update")),
		Stack: StackAudit{LowestOffset: -8}}
	if err := ValidateRaw(raw); err != nil {
		t.Fatal(err)
	}
	raw.HookName += "h"
	if err := ValidateRaw(raw); err == nil || !strings.Contains(err.Error(), `the suffix "_0_update"`) {
		t.Fatalf("err = %v", err)
	}
}
