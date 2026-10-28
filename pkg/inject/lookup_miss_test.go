package inject

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// hookParamNames lists the parameter names of each generated hook in spec.
func hookParamNames(insns asm.Instructions) map[string][]string {
	params := map[string][]string{}
	for _, ins := range insns {
		fn := btf.FuncMetadata(&ins)
		if fn == nil || !strings.HasPrefix(fn.Name, "lookup_hook") && fn.Name != "d" {
			continue
		}
		for _, p := range fn.Type.(*btf.FuncProto).Params {
			params[fn.Name] = append(params[fn.Name], p.Name)
		}
	}
	return params
}

// The site guard follows Lookups: a hit hook behind "R0 == 0 skips", a miss
// hook behind "R0 != 0 skips", and with LookupAny both, each on its branch.
func TestLookupMiss(t *testing.T) {
	type hook struct {
		name string
		when LookupWhen
	}
	for _, tc := range []struct {
		name     string
		req      func() LookupRequest
		hooks    []hook
		calls    []string // hook calls in program order
		params   map[string][]string
		guards   []asm.JumpOp
		dispatch bool
	}{
		{"auto-miss", func() LookupRequest { r := autoReq(); r.Lookups = LookupMiss; return r },
			[]hook{{"lookup_hook_sessions_miss", LookupMiss}}, []string{"lookup_hook_sessions_miss"},
			map[string][]string{"lookup_hook_sessions_miss": {"ctx", "site", "key"}}, []asm.JumpOp{asm.JNE}, false},
		{"auto-any", func() LookupRequest { r := autoReq(); r.Lookups = LookupAny; return r },
			[]hook{{"lookup_hook_sessions", LookupHit}, {"lookup_hook_sessions_miss", LookupMiss}},
			[]string{"lookup_hook_sessions", "lookup_hook_sessions_miss"},
			map[string][]string{"lookup_hook_sessions": {"ctx", "site", "key", "value"}, "lookup_hook_sessions_miss": {"ctx", "site", "key"}},
			[]asm.JumpOp{asm.JEq, asm.Ja}, false},
		{"selector-miss", func() LookupRequest { r := lookupReq(); r.Lookups = LookupMiss; return r },
			[]hook{{"lookup_hook_miss", LookupMiss}}, []string{"lookup_hook_miss"},
			map[string][]string{"lookup_hook_miss": {"ctx", "key"}}, []asm.JumpOp{asm.JNE}, false},
		{"dispatch-miss", func() LookupRequest {
			r := autoReq()
			r.Dispatch, r.HookName, r.Lookups, r.Stack.LowestOffset = true, "d", LookupMiss, -8
			return r
		}, []hook{{"d", LookupMiss}}, []string{"d"},
			map[string][]string{"d": {"ctx", "site", "key", "value", "map"}}, []asm.JumpOp{asm.JNE}, true},
		{"dispatch-any", func() LookupRequest {
			r := autoReq()
			r.Dispatch, r.HookName, r.Lookups, r.Stack.LowestOffset = true, "d", LookupAny, -8
			return r
		}, []hook{{"d", LookupAny}}, []string{"d", "d"},
			map[string][]string{"d": {"ctx", "site", "key", "value", "map"}}, []asm.JumpOp{asm.JEq, asm.Ja}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := lookupFixture()
			plan, err := transformLookup(spec, tc.req())
			if err != nil {
				t.Fatal(err)
			}
			var hooks []hook
			for _, h := range plan.hooks {
				hooks = append(hooks, hook{h.Name, h.When})
			}
			if !slices.Equal(hooks, tc.hooks) {
				t.Fatalf("hooks = %v, want %v", hooks, tc.hooks)
			}
			insns := spec.Programs["p"].Instructions
			// The instrumentation after the lookup: R0 spill, guards, calls,
			// R0 restore.
			at := slices.IndexFunc(insns, func(ins asm.Instruction) bool {
				return ins.IsBuiltinCall() && ins.Constant == int64(asm.FnMapLookupElem)
			})
			var calls []string
			var guards []asm.JumpOp
			for _, ins := range insns[at+1:] {
				if ins.OpCode.Class() == asm.LdXClass && ins.Dst == asm.R0 {
					break // R0 restored
				}
				switch {
				case ins.IsFunctionCall():
					calls = append(calls, ins.Reference())
				case ins.OpCode.Class().IsJump():
					guards = append(guards, ins.OpCode.JumpOp())
				}
			}
			if !slices.Equal(calls, tc.calls) || !slices.Equal(guards, tc.guards) {
				t.Fatalf("calls = %v guards = %v, want %v %v", calls, guards, tc.calls, tc.guards)
			}
			params := hookParamNames(insns)
			for name, want := range tc.params {
				if !slices.Equal(params[name], want) {
					t.Errorf("%s params = %v, want %v", name, params[name], want)
				}
			}
			if len(params) != len(tc.params) {
				t.Errorf("hooks with BTF: %v", params)
			}
		})
	}
}

func TestLookupMissRefusals(t *testing.T) {
	req := autoReq()
	req.Lookups = "sometimes"
	if _, err := transformLookup(lookupFixture(), req); err == nil || !strings.Contains(err.Error(), "Lookups must be hit, miss or any") {
		t.Fatalf("err = %v", err)
	}
	req = lookupReq()
	req.Lookups, req.HookName = LookupMiss, strings.Repeat("h", MaxHookName-len("_miss")+1)
	if _, err := transformLookup(lookupFixture(), req); err == nil || !strings.Contains(err.Error(), "invalid or used twice") {
		t.Fatalf("err = %v", err)
	}
	// The miss suffix counts toward the hook name limit.
	raw := LookupRequestRaw{Auto: true, Lookups: LookupMiss, HookName: strings.Repeat("h", MaxHookName-len("_0_miss")+1),
		Stack: StackAudit{LowestOffset: -8}}
	if err := ValidateRaw(raw); err == nil || !strings.Contains(err.Error(), `the suffix "_0_miss"`) {
		t.Fatalf("err = %v", err)
	}
	raw.HookName = raw.HookName[1:]
	if err := ValidateRaw(raw); err != nil {
		t.Fatal(err)
	}
}

func TestMissHookName(t *testing.T) {
	used := map[string]bool{"p_s_miss": true}
	if got := missHookName("p_s", used); got != "p_s_miss_" || !used["p_s_miss_"] {
		t.Fatalf("missHookName = %q", got)
	}
}
