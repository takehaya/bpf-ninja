//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// TestConfigHookPrefix: hook_prefix names the hooks as hook does, both keys
// must agree, and one of them is required.
func TestConfigHookPrefix(t *testing.T) {
	for input, want := range map[string]string{
		`[{"program":"p","auto":true,"maps":["a"],"ops":["lookup"],"hook_prefix":"h"}]`:            "",
		`[{"program":"p","auto":true,"maps":["a"],"ops":["lookup"],"hook":"h","hook_prefix":"h"}]`: "",
		`[{"program":"p","auto":true,"hook":"a","hook_prefix":"b"}]`:                               `rule 0: hook and hook_prefix are both given and differ ("a" and "b"); keep hook_prefix`,
		`[{"program":"p","auto":true}]`:                                                            "rule 0: hook_prefix is required",
		// An empty hook_prefix beside a hook would read as a hook rule and select every map.
		`[{"program":"p","auto":true,"entry":true,"hook":"h","hook_prefix":"","maps":[],"ops":[]}]`:   "rule 0: hook_prefix is empty; give the prefix or remove the key",
		`[{"program":"p","auto":true,"entry":true,"hook":"h","hook_prefix":null,"maps":[],"ops":[]}]`: "rule 0: hook_prefix is empty; give the prefix or remove the key",
		// encoding/json matches keys without regard to case, so a case variant
		// of the key is the key, and the key given twice is refused.
		`[{"program":"p","auto":true,"entry":true,"hook":"h","Hook_Prefix":""}]`:         "rule 0: hook_prefix is empty; give the prefix or remove the key",
		`[{"program":"p","auto":true,"entry":true,"hook":"h","HOOK_PREFIX":null}]`:       "rule 0: hook_prefix is empty; give the prefix or remove the key",
		`[{"program":"p","auto":true,"entry":true,"hook_prefix":"h","Hook_Prefix":"h"}]`: "rule 0: hook_prefix is given more than once",
		`[{"program":"p","auto":true,"entry":true,"hook_prefix":"h","hook_prefix":"h"}]`: "rule 0: hook_prefix is given more than once",
		// A map rule names its one site itself: without ops it observes that lookup.
		`[{"program":"p","map":"m","hook_prefix":"h"}]`: "",
	} {
		_, err := ParseConfig(strings.NewReader(input))
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: %v, want %q", input, err, want)
		}
	}
	// The single hook of map and dispatch rules is named by either key.
	for _, rule := range []string{`"map":"m","ops":["lookup"]`, `"map":"m"`, `"auto":true,"maps":["m"],"ops":["lookup"],"dispatch":true`} {
		var a, b []Rule
		if err := json.Unmarshal([]byte(`[{"program":"p",`+rule+`,"hook":"h"}]`), &a); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(`[{"program":"p",`+rule+`,"hook_prefix":"h"}]`), &b); err != nil {
			t.Fatal(err)
		}
		if got, want := b[0].request(), a[0].request(); got.HookName != "h" || got.Lookups != want.Lookups || !slices.Equal(got.Maps, want.Maps) || got.Site.MapName != want.Site.MapName {
			t.Errorf("%s: %+v, want %+v", rule, got, want)
		}
	}
	// With hook, missing maps and ops keep their old meaning: every map, lookup hits.
	old := Rule{Program: "p", Auto: true, Hook: "h"}
	if req := old.request(); req.Lookups != "" || req.Maps != nil {
		t.Errorf("hook rule: %+v", req)
	}
	for _, r := range []Rule{
		{Program: "p", Auto: true, HookPrefix: "h"},
		{Program: "p", Auto: true, Maps: []string{"a"}, HookPrefix: "h"},
		{Program: "p", Auto: true, Ops: []string{"update:any"}, HookPrefix: "h"},
		{Program: "p", Auto: true, Maps: []string{}, Ops: []string{}, HookPrefix: "h"},
	} {
		if req := r.request(); req.Lookups != inject.LookupNone || req.Updates != "" || len(req.Maps) != 0 {
			t.Errorf("%+v: observes map calls: %+v", r, req)
		}
	}
}

// explicitRuleProgram is the raw load of p(ctx), which looks up key 0 in a
// (fd 7), stores 0 at key 0 in b (fd 8) and reads the clock.
func explicitRuleProgram(t *testing.T) inject.RawProgram {
	t.Helper()
	u32 := &btf.Int{Name: "u32", Size: 4}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	ctx := &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24, Members: []btf.Member{
		{Name: "data", Type: u32}, {Name: "data_end", Type: u32, Offset: 32}}}}
	pFn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: i32, Params: []btf.FuncParam{{Name: "ctx", Type: ctx}}}}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("p").WithSource(asm.Comment("entry")), pFn),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 7), asm.FnMapLookupElem.Call(),
		asm.StoreImm(asm.RFP, -8, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8),
		asm.LoadMapPtr(asm.R1, 8), asm.Mov.Imm(asm.R4, 0), asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.FnKtimeGetNs.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	builder := new(btf.Builder)
	fi, li, err := btf.MarshalExtInfos(insns, builder)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	types, err := btf.LoadSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := insns.Marshal(&buf, wire); err != nil {
		t.Fatal(err)
	}
	raw, err := asm.AppendInstructions(nil, &buf, wire, "linux")
	if err != nil {
		t.Fatal(err)
	}
	return inject.RawProgram{Instructions: raw, Type: ebpf.XDP, BTF: types, FuncInfo: fi, LineInfo: li,
		Maps: map[int32]inject.RawMap{
			7: {Name: "a", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, Key: u32, Value: u32},
			8: {Name: "b", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, Key: u32, Value: u32},
		}}
}

// explicitHooks counts the sites the transform hooks for r, the entry
// counting as one, or returns the refusal.
func explicitHooks(t *testing.T, raw inject.RawProgram, r Rule) (int, error) {
	t.Helper()
	if err := Validate([]Rule{r}); err != nil {
		return 0, err
	}
	req := r.request()
	req.Stack = inject.StackAudit{Frames: map[string]int16{"p": -8}, Source: "verifier", FrameRounding: 16}
	result, err := inject.TransformLookupRaw(raw, req)
	if err != nil {
		return 0, err
	}
	sites := map[int64]bool{}
	for _, hook := range result.Hooks {
		for _, site := range hook.Sites {
			sites[int64(site.SitePC)] = true
		}
		if hook.Kind == inject.HookEntry {
			sites[-1] = true
		}
	}
	return len(sites), nil
}

// In a hook_prefix rule each kind is explicit: deleting a name or a key never
// adds a hook, and an empty list hooks nothing of its kind.
func TestExplicitRuleNeverWidens(t *testing.T) {
	raw := explicitRuleProgram(t)
	ready := Rule{Program: "p", Auto: true, Maps: []string{"a", "b"}, Ops: []string{"lookup:any", "update:any"},
		Entry: true, Calls: []string{"bpf_ktime_get_ns"}, HookPrefix: "ninja"}
	all, err := explicitHooks(t, raw, ready)
	if err != nil || all != 4 {
		t.Fatalf("ready rule: %d hooked sites, want 4 (lookup, update, call, entry)", all)
	}
	for name, c := range map[string]struct {
		change func(*Rule)
		want   int
	}{
		"zero maps":  {func(r *Rule) { r.Maps = nil }, 2},
		"empty maps": {func(r *Rule) { r.Maps = []string{} }, 2},
		"zero ops":   {func(r *Rule) { r.Ops = nil }, 2},
		"zero calls": {func(r *Rule) { r.Calls = nil }, 3},
		"no entry":   {func(r *Rule) { r.Entry = false }, 3},
		"map a":      {func(r *Rule) { r.Maps = []string{"a"} }, 3},
		"map b":      {func(r *Rule) { r.Maps = []string{"b"} }, 3},
		"lookup":     {func(r *Rule) { r.Maps, r.Ops = []string{"a"}, []string{"lookup:any"} }, 3},
		"update":     {func(r *Rule) { r.Maps, r.Ops = []string{"b"}, []string{"update:any"} }, 3},
		"calls only": {func(r *Rule) { r.Maps, r.Ops, r.Entry = nil, nil, false }, 1},
		"entry only": {func(r *Rule) { r.Maps, r.Ops, r.Calls = nil, nil, nil }, 1},
		"maps only":  {func(r *Rule) { r.Calls, r.Entry = nil, false }, 2},
		"nothing":    {func(r *Rule) { r.Maps, r.Ops, r.Calls, r.Entry = nil, nil, nil, false }, -1},
	} {
		r := ready
		r.Maps, r.Ops, r.Calls = slices.Clone(r.Maps), slices.Clone(r.Ops), slices.Clone(r.Calls)
		c.change(&r)
		got, err := explicitHooks(t, raw, r)
		if c.want < 0 && err == nil || c.want >= 0 && (err != nil || got != c.want) {
			t.Errorf("%s: %d hooked sites (%v), want %d", name, got, err, c.want)
		}
	}
	// Removing names one at a time, down to none, never hooks more sites
	// than the rule before it. A maps name with no call of the listed ops is
	// skipped, so the only refusal on the way is a rule that hooks nothing.
	var shrink func(r Rule, have int)
	shrink = func(r Rule, have int) {
		for _, list := range []*[]string{&r.Maps, &r.Ops, &r.Calls} {
			for i := range *list {
				next := r
				next.Maps, next.Ops, next.Calls = slices.Clone(r.Maps), slices.Clone(r.Ops), slices.Clone(r.Calls)
				l := map[*[]string]*[]string{&r.Maps: &next.Maps, &r.Ops: &next.Ops, &r.Calls: &next.Calls}[list]
				*l = slices.Delete(*l, i, i+1)
				got, err := explicitHooks(t, raw, next)
				switch {
				case err != nil && !strings.Contains(err.Error(), "nothing"):
					t.Errorf("%+v: %v", next, err)
				case err != nil:
					got = have
				case got > have:
					t.Errorf("%+v: %d hooked sites, more than %d before removing a name", next, got, have)
				}
				shrink(next, got)
			}
		}
	}
	shrink(ready, all)
}

// A maps name with no call of the listed ops: a hook_prefix rule skips it
// with the reason and keeps every other hook; a hook rule still refuses.
func TestExplicitRuleSkipsUnmatchedMap(t *testing.T) {
	raw := explicitRuleProgram(t)
	stack := inject.StackAudit{Frames: map[string]int16{"p": -8}, Source: "verifier", FrameRounding: 16}
	explicit := Rule{Program: "p", Auto: true, Maps: []string{"a", "b"}, Ops: []string{"lookup:any"}, Calls: []string{"bpf_ktime_get_ns"}, HookPrefix: "ninja"}
	req := explicit.request()
	req.Stack = stack
	result, err := inject.TransformLookupRaw(raw, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hooks) != 3 || !slices.ContainsFunc(result.Skipped, func(s inject.LookupSite) bool {
		return s.MapName == "b" && s.Reason == `Maps name "b" matches no lookup`
	}) {
		t.Fatalf("hooks %+v skipped %+v", result.Hooks, result.Skipped)
	}
	old := explicit
	old.HookPrefix, old.Hook = "", "ninja"
	req = old.request()
	req.Stack = stack
	if _, err := inject.TransformLookupRaw(raw, req); err == nil || !strings.Contains(err.Error(), `Maps name "b" matches no lookup`) {
		t.Fatalf("hook rule: %v", err)
	}
}

// A single-site map rule without ops gives the same bytes with hook_prefix as with hook.
func TestExplicitMapRuleSameBytes(t *testing.T) {
	raw := explicitRuleProgram(t)
	var out [2][]byte
	for i, r := range []Rule{{Program: "p", Map: "a", Hook: "h"}, {Program: "p", Map: "a", HookPrefix: "h"}} {
		req := r.request()
		req.Stack = inject.StackAudit{Frames: map[string]int16{"p": -8}, Source: "verifier", FrameRounding: 16}
		result, err := inject.TransformLookupRaw(raw, req)
		if err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		var buf bytes.Buffer
		if err := result.Instructions.Marshal(&buf, wire); err != nil {
			t.Fatal(err)
		}
		out[i] = buf.Bytes()
	}
	if !bytes.Equal(out[0], out[1]) {
		t.Fatal("hook_prefix map rule differs from the hook spelling")
	}
}

// A rule's sites only remove hooks: with any single site selected or
// excepted, by label or by number, the transform hooks a subset of the
// sites the same rule hooks without sites, and never a site left out.
func TestSitesNeverWiden(t *testing.T) {
	raw := explicitRuleProgram(t)
	mapCalls, list, err := listing(raw)
	if err != nil {
		t.Fatal(err)
	}
	all := slices.Concat(mapCalls, list.Sites, list.TailCalls)
	ready := Rule{Program: "p", Auto: true, Maps: []string{"a", "b"}, Ops: []string{"lookup:any", "update:any"},
		Entry: true, Calls: []string{"bpf_ktime_get_ns"}, HookPrefix: "ninja"}
	hooked := func(drop map[uint32]string) map[uint32]bool {
		t.Helper()
		req := ready.request()
		req.Drop = drop
		req.Stack = inject.StackAudit{Frames: map[string]int16{"p": -8}, Source: "verifier", FrameRounding: 16}
		result, err := inject.TransformLookupRaw(raw, req)
		if err != nil {
			t.Fatalf("drop %v: %v", drop, err)
		}
		sites := map[uint32]bool{}
		for _, hook := range result.Hooks {
			for _, site := range hook.Sites {
				sites[site.SitePC] = true
			}
		}
		return sites
	}
	base := hooked(nil)
	if len(all) != 3 || len(base) != 3 {
		t.Fatalf("listing %+v, hooked %v: want 3 sites", all, base)
	}
	for _, site := range all {
		pc := site.SitePC
		for _, sel := range []Sites{{Only: []SiteRef{pcRef(pc)}}, {Only: []SiteRef{{Label: list.Labels[pc]}}},
			{Except: []SiteRef{pcRef(pc)}}, {Except: []SiteRef{{Label: list.Labels[pc]}}}} {
			sel.Build = list.Fingerprint
			r := ready
			r.Sites = &sel
			if err := Validate([]Rule{r}); err != nil {
				t.Fatal(err)
			}
			drop, err := sel.drop(list.Fingerprint, all, list.Labels)
			if err != nil {
				t.Fatal(err)
			}
			got := hooked(drop)
			for pc := range got {
				if !base[pc] || drop[pc] != "" {
					t.Errorf("%+v: hooks pc %d (dropped %q), not hooked without sites or left out", sel, pc, drop[pc])
				}
			}
			if sel.Except != nil && got[pc] || sel.Only != nil && !got[pc] {
				t.Errorf("%+v: hooked %v", sel, got)
			}
		}
	}
}
