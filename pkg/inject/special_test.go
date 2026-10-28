package inject

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// specialValue is the fixtures' session value {seid, imsi} followed at byte
// 16 by the special field kind names: spin_lock, timer or kptr.
func specialValue(kind string) (btf.Type, uint32) {
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	field, size := btf.Member{Offset: 128}, uint32(24)
	switch kind {
	case "spin_lock":
		field.Name, field.Type = "lock", &btf.Struct{Name: "bpf_spin_lock", Size: 4, Members: []btf.Member{{Name: "val", Type: u32}}}
	case "timer":
		field.Name, field.Type = "timer", &btf.Struct{Name: "bpf_timer", Size: 16,
			Members: []btf.Member{{Name: "__opaque", Type: &btf.Array{Index: u32, Type: u64, Nelems: 2}}}}
		size = 32
	case "kptr":
		field.Name, field.Type = "task", &btf.Pointer{Target: &btf.TypeTag{Value: "kptr_untrusted", Type: &btf.Struct{Name: "task_struct"}}}
	}
	return &btf.Struct{Name: "session", Size: size, Members: []btf.Member{
		{Name: "seid", Type: u64}, {Name: "imsi", Type: u64, Offset: 64}, field}}, size
}

// withSpecialValue gives spec's sessions map the specialValue of kind.
func withSpecialValue(spec *ebpf.CollectionSpec, kind string) *ebpf.CollectionSpec {
	m := spec.Maps["sessions"]
	m.Value, m.ValueSize = specialValue(kind)
	return spec
}

func TestSpecialField(t *testing.T) {
	u64 := &btf.Int{Name: "u64", Size: 8}
	lock, _ := specialValue("spin_lock")
	timer, _ := specialValue("timer")
	kptr, _ := specialValue("kptr")
	for _, tc := range []struct {
		name string
		typ  btf.Type
		want string
	}{
		{"nil", nil, ""},
		{"scalars", lookupFixture().Maps["sessions"].Value, ""},
		{"spin_lock", lock, "bpf_spin_lock"},
		{"timer", timer, "bpf_timer"},
		{"kptr", kptr, "kptr_untrusted"},
		{"plain pointer", &btf.Struct{Name: "v", Size: 8, Members: []btf.Member{{Name: "p", Type: &btf.Pointer{Target: u64}}}}, ""},
		{"nested in a typedef'd array", &btf.Typedef{Name: "t", Type: &btf.Struct{Name: "outer", Size: 72, Members: []btf.Member{
			{Name: "inner", Type: &btf.Array{Index: u64, Type: timer, Nelems: 2}, Offset: 64}}}}, "bpf_timer"},
		{"in a union", &btf.Union{Name: "u", Size: 16, Members: []btf.Member{
			{Name: "x", Type: u64}, {Name: "root", Type: &btf.Struct{Name: "bpf_rb_root", Size: 16}}}}, "bpf_rb_root"},
	} {
		if got := specialField(tc.typ); got != tc.want {
			t.Errorf("%s: specialField = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A lookup hook on a value with a special field takes untrusted pointers, or
// is static, and is never copied; update and delete hooks stay typed.
func TestSpecialFieldHooks(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		opts                    LookupRequest
		flags                   uint32
		untrusted, static, copy bool
	}{
		{"auto", LookupRequest{}, 0, true, false, false},
		{"static", LookupRequest{StaticUntrusted: true}, 0, false, true, false},
		{"read-only copy", LookupRequest{CopyReadOnly: true}, bpfFRdonlyProg, true, false, false},
	} {
		for _, kind := range []string{"spin_lock", "timer", "kptr"} {
			spec := withSpecialValue(lookupFixture(), kind)
			spec.Maps["sessions"].Flags = tc.flags
			req := autoReq()
			req.StaticUntrusted, req.CopyReadOnly = tc.opts.StaticUntrusted, tc.opts.CopyReadOnly
			plan, err := transformLookup(spec, req)
			if err != nil {
				t.Fatal(err)
			}
			if h := plan.hooks; len(h) != 1 || h[0].Untrusted != tc.untrusted || h[0].Static != tc.static || h[0].Copied != tc.copy {
				t.Errorf("%s %s: hooks %+v", tc.name, kind, h)
			}
		}
	}
	spec := withSpecialValue(mapCallFixture(), "spin_lock")
	req := autoReq()
	req.Lookups, req.Updates, req.Deletes, req.Stack.LowestOffset = LookupNone, CallAny, CallAny, -24
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || plan.hooks[0].Untrusted || plan.hooks[0].Static || plan.hooks[1].Untrusted {
		t.Errorf("update and delete hooks: %+v", plan.hooks)
	}
}

// An update or delete on a sockmap or sockhash goes to the generic hook; on a
// devmap, which programs cannot update, it is skipped.
func TestSockMapUpdateGeneric(t *testing.T) {
	for _, tc := range []struct {
		typ     ebpf.MapType
		generic bool
	}{{ebpf.SockHash, true}, {ebpf.SockMap, true}, {ebpf.DevMap, false}} {
		spec := sockUpdateFixture()
		spec.Maps["m"].Type = tc.typ
		req := LookupRequest{ProgramName: "p", Auto: true, Lookups: LookupNone, Updates: CallError, Deletes: CallError,
			HookName: "obs", Stack: StackAudit{LowestOffset: -8}}
		plan, err := transformLookup(spec, req)
		if !tc.generic {
			if err == nil || len(plan.hooks) != 0 {
				t.Errorf("%s: hooks %+v err %v", tc.typ, plan.hooks, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if h := plan.hooks; len(h) != 2 || h[0].Name != "obs_any_update" || !h[0].Generic || h[0].Kind != HookUpdate ||
			h[1].Name != "obs_any_delete" || !h[1].Generic || h[1].Kind != HookDelete {
			t.Errorf("%s: hooks %+v", tc.typ, h)
		}
	}
}
