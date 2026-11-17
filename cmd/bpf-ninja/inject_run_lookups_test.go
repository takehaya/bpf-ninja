//go:build linux && amd64

package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

// legacyKinds lists lookups alone, which writes the file and rule of version 2
// apart from version, build and labels.
var legacyKinds = map[string]bool{"lookups": true}

func TestDiscoveryJSON(t *testing.T) {
	d := syscallhook.Discovery{
		Program: "tail_lb_ipv4", Func: "tail_lb_ipv4_full", Type: ebpf.SchedCLS,
		Lookups: []inject.LookupSite{
			{Op: inject.HookLookup, SitePC: 12, MapName: "services", FuncName: "tail_lb_ipv4_full", CtxSource: "entry"},
			{Op: inject.HookLookup, SitePC: 30, MapName: "backends", FuncName: "tail_lb_ipv4_full", File: "lb.c", Line: 7},
			{Op: inject.HookLookup, SitePC: 41, MapName: "services", FuncName: "sub", Reason: "lookup is not in the entry function"},
			{Op: inject.HookLookup, SitePC: 50, FuncName: "tail_lb_ipv4_full", Reason: "R1 is not a direct map reference", Generic: true},
		},
		Calls: []inject.LookupSite{
			{Op: inject.HookLookup, SitePC: 12, MapName: "services", FuncName: "tail_lb_ipv4_full", CtxSource: "entry"},
			{Op: inject.HookUpdate, SitePC: 20, MapName: "services", FuncName: "tail_lb_ipv4_full"},
			{Op: inject.HookLookup, SitePC: 30, MapName: "backends", FuncName: "tail_lb_ipv4_full", File: "lb.c", Line: 7},
			{Op: inject.HookDelete, SitePC: 35, MapName: "x.bss", FuncName: "tail_lb_ipv4_full"},
			{Op: inject.HookLookup, SitePC: 41, MapName: "services", FuncName: "sub", Reason: "lookup is not in the entry function"},
			{Op: inject.HookLookup, SitePC: 50, FuncName: "tail_lb_ipv4_full", Reason: "R1 is not a direct map reference", Generic: true},
		},
		Maps: map[string]ebpf.MapType{"x.bss": ebpf.Hash, "services": ebpf.Hash, "backends": ebpf.Hash, "calls": ebpf.ProgramArray, "x.rodata": ebpf.Array, "": ebpf.Array},
	}
	got, err := json.Marshal(discoveryJSON(d, legacyKinds))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"program":"tail_lb_ipv4","func":"tail_lb_ipv4_full","type":"SchedCLS","ctx_type":"__sk_buff",` +
		`"maps":[{"name":"services","type":"Hash","sites":[12,41],"ops":["lookup","update"]},{"name":"backends","type":"Hash","sites":[30],"ops":["lookup"]},` +
		`{"name":"calls","type":"ProgramArray","sites":[],"ops":[]},{"name":"x.bss","type":"Hash","sites":[],"ops":["delete"]},` +
		`{"name":"x.rodata","type":"Array","sites":[],"ops":[]}],` +
		`"lookups":[{"kind":"lookup","pc":12,"map":"services","func":"tail_lb_ipv4_full","ctx_source":"entry"},` +
		`{"kind":"lookup","pc":30,"map":"backends","func":"tail_lb_ipv4_full","file":"lb.c","line":7},` +
		`{"kind":"lookup","pc":41,"map":"services","func":"sub","reason":"lookup is not in the entry function"},` +
		`{"kind":"lookup","pc":50,"func":"tail_lb_ipv4_full","reason":"R1 is not a direct map reference","generic":true}],` +
		`"calls":[{"kind":"lookup","pc":12,"map":"services","func":"tail_lb_ipv4_full","ctx_source":"entry"},` +
		`{"kind":"update","pc":20,"map":"services","func":"tail_lb_ipv4_full"},` +
		`{"kind":"lookup","pc":30,"map":"backends","func":"tail_lb_ipv4_full","file":"lb.c","line":7},` +
		`{"kind":"delete","pc":35,"map":"x.bss","func":"tail_lb_ipv4_full"},` +
		`{"kind":"lookup","pc":41,"map":"services","func":"sub","reason":"lookup is not in the entry function"},` +
		`{"kind":"lookup","pc":50,"func":"tail_lb_ipv4_full","reason":"R1 is not a direct map reference","generic":true}],` +
		`"rule":{"program":"tail_lb_ipv4_full","auto":true,"maps":["services","backends"],"hook":"ninja"}}`
	if string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// Discovery emits a rule that parses without a caller-supplied floor.
	rule, _ := json.Marshal([]syscallhook.Rule{discoveryJSON(d, legacyKinds).Rule})
	if rules, err := syscallhook.ParseConfig(strings.NewReader(string(rule))); err != nil || len(rules[0].Maps) != 2 {
		t.Fatalf("%s: %+v %v", rule, rules, err)
	}
}

// A site in a function the trial load gives no usable floor (dead, a
// skip_reason, or not listed) is listed as auto skips it: with the floor
// reason and not generic, whether its hook would be typed or generic.
func TestDiscoveryJSONUnauditedFrame(t *testing.T) {
	sites := []inject.LookupSite{
		{Op: inject.HookLookup, SitePC: 5, MapName: "services", FuncName: "p"},
		{Op: inject.HookLookup, SitePC: 20, MapName: "services", FuncName: "dead"},
		{Op: inject.HookLookup, SitePC: 30, FuncName: "dead", Reason: "R1 is not a direct map reference", Generic: true},
		{Op: inject.HookLookup, SitePC: 40, FuncName: "old", Reason: "R1 is not a direct map reference", Generic: true},
		{Op: inject.HookLookup, SitePC: 50, MapName: "services", FuncName: "unlisted"},
	}
	d := syscallhook.Discovery{Program: "p", Func: "p", Type: ebpf.XDP, Lookups: sites, Calls: sites,
		Maps: map[string]ebpf.MapType{"services": ebpf.Hash},
		Stack: inject.StackReport{Source: "verifier", Functions: []inject.FrameFloor{
			{Name: "p", Floor: -16}, {Name: "dead", Dead: true}, {Name: "old", Floor: -8, SkipReason: "kernel before 6.8"}}}}
	out := discoveryJSON(d, legacyKinds)
	for _, list := range [][]hookSiteJSON{out.Lookups, out.Calls} {
		for _, s := range list {
			want := "stack floor unavailable for this function"
			if s.Func == "p" {
				want = ""
			}
			if s.Reason != want || s.Generic {
				t.Errorf("pc %d in %s: reason %q generic %v, want reason %q and not generic", s.PC, s.Func, s.Reason, s.Generic, want)
			}
		}
	}
	if !sites[2].Generic || sites[1].Reason != "" {
		t.Fatal("discoveryJSON changed the caller's sites")
	}
}

// inject-run does not transform a load whose trial load failed, so the
// listing marks every site of such a load as skipped.
func TestDiscoveryJSONUnavailableStack(t *testing.T) {
	sites := []inject.LookupSite{
		{Op: inject.HookLookup, SitePC: 5, MapName: "services", FuncName: "p"},
		{Op: inject.HookLookup, SitePC: 30, FuncName: "p", Reason: "R1 is not a direct map reference", Generic: true},
	}
	d := syscallhook.Discovery{Program: "p", Func: "p", Type: ebpf.XDP, Lookups: sites, Calls: sites,
		Maps:  map[string]ebpf.MapType{"services": ebpf.Hash},
		Stack: inject.StackReport{Source: "unavailable", Error: "trial load failed"}}
	out := discoveryJSON(d, legacyKinds)
	for _, list := range [][]hookSiteJSON{out.Lookups, out.Calls} {
		for _, s := range list {
			if s.Reason != "stack audit unavailable" || s.Generic {
				t.Errorf("pc %d: reason %q generic %v, want the audit reason and not generic", s.PC, s.Reason, s.Generic)
			}
		}
	}
	if !sites[1].Generic || sites[0].Reason != "" {
		t.Fatal("discoveryJSON changed the caller's sites")
	}
}

// The listing reads the file inject-run writes.
func TestLookupsFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookups.json")
	w, err := newLookupsWriter(path, map[string]bool{"lookups": true})
	if err != nil {
		t.Fatal(err)
	}
	site := inject.LookupSite{Op: inject.HookLookup, SitePC: 5, MapName: "services", FuncName: "p", File: "p.c", Line: 3}
	if err := w.add(syscallhook.Discovery{Program: "p", Func: "p", Type: ebpf.XDP, Lookups: []inject.LookupSite{site}, Calls: []inject.LookupSite{site},
		Maps: map[string]ebpf.MapType{"services": ebpf.Hash}}); err != nil {
		t.Fatal(err)
	}
	calls, err := readLoadCalls(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []loadCall{{Kind: "lookup", PC: 5, Map: "services", Func: "p", File: "p.c", Line: 3}}
	if !reflect.DeepEqual(calls["p"], want) {
		t.Fatalf("calls = %+v, want %+v", calls, want)
	}
}

// With every kind the rule is a hook_prefix rule naming each named map with
// a listed op, those ops as op:any, the callees with a row, the entry and the
// tail calls; callees without a row are listed with their reason; every site
// carries its label, and the file carries the listing fingerprint.
func TestDiscoveryJSONReadyRule(t *testing.T) {
	calls := []inject.LookupSite{
		{Op: inject.HookLookup, SitePC: 12, MapName: "services", FuncName: "p"},
		{Op: inject.HookUpdate, SitePC: 20, MapName: "flows", FuncName: "p"},
		{Op: inject.HookLookup, SitePC: 25, FuncName: "p", Reason: "R1 is not a direct map reference", Generic: true},
	}
	d := syscallhook.Discovery{Program: "p", Func: "p", Type: ebpf.XDP, Lookups: calls[:1], Calls: calls,
		Maps: map[string]ebpf.MapType{"services": ebpf.Hash, "flows": ebpf.Hash, "progs": ebpf.ProgramArray},
		CallSites: inject.CallDiscovery{
			Sites: []inject.LookupSite{
				{Op: inject.HookCall, SitePC: 30, Call: "bpf_ktime_get_ns", FuncName: "p", CtxSource: "entry"},
				{Op: inject.HookCall, SitePC: 34, Call: "bpf_get_numa_node_id", FuncName: "p", Reason: "no hook form yet"},
				{Op: inject.HookCall, SitePC: 38, Call: "bpf_xdp_ct_lookup", FuncName: "p", CtxSource: "entry"},
			},
			TailCalls: []inject.LookupSite{{Op: inject.HookTailCall, SitePC: 40, FuncName: "p"}},
			Callees: []inject.Callee{
				{Name: "bpf_ktime_get_ns", Kind: "helper", Ret: inject.RetScalar, Typed: true, Sites: []uint32{30}},
				{Name: "bpf_get_numa_node_id", Kind: "helper", Ret: inject.RetScalar, Sites: []uint32{34}, Reason: "no hook form yet"},
				{Name: "bpf_xdp_ct_lookup", Kind: "kfunc", Ret: inject.RetPointer, Typed: true, Sites: []uint32{38}},
			},
			Labels:      map[uint32]string{12: "services@p+12", 20: "flows.update@p+20", 25: "any@p+25", 30: "bpf_ktime_get_ns@p+30", 34: "bpf_get_numa_node_id@p+34", 38: "bpf_xdp_ct_lookup@p+38", 40: "tail_call@p+40"},
			Fingerprint: "sha256:00",
		}}
	all, _ := parseLookupsKinds("")
	out := discoveryJSON(d, all)
	rule, _ := json.Marshal(out.Rule)
	if want := `{"program":"p","auto":true,"maps":["services","flows"],"entry":true,"tail_calls":true,` +
		`"calls":["bpf_ktime_get_ns","bpf_xdp_ct_lookup"],"ops":["lookup:any","update:any"],"hook_prefix":"ninja"}`; string(rule) != want {
		t.Errorf("rule\n%s\nwant\n%s", rule, want)
	}
	if _, err := syscallhook.ParseConfig(strings.NewReader("[" + string(rule) + "]")); err != nil {
		t.Errorf("rule does not parse: %v", err)
	}
	if out.Build != "sha256:00" || len(out.Callees) != 3 || out.Callees[1].Reason != "no hook form yet" || len(out.CallSites) != 3 || len(out.TailCalls) != 1 {
		t.Errorf("build %q callees %+v call sites %+v tail calls %+v", out.Build, out.Callees, out.CallSites, out.TailCalls)
	}
	for _, list := range [][]hookSiteJSON{out.Lookups, out.Calls, out.CallSites, out.TailCalls} {
		for _, s := range list {
			if s.Label != d.CallSites.Labels[s.PC] || s.Label == "" {
				t.Errorf("pc %d: label %q", s.PC, s.Label)
			}
		}
	}
	// Each subset of kinds names only its kinds; a key left out hooks nothing of its kind.
	for kinds, want := range map[string]string{
		"helpers":           `{"program":"p","auto":true,"calls":["bpf_ktime_get_ns"],"hook_prefix":"ninja"}`,
		"kfuncs":            `{"program":"p","auto":true,"calls":["bpf_xdp_ct_lookup"],"hook_prefix":"ninja"}`,
		"map_calls":         `{"program":"p","auto":true,"maps":["flows"],"ops":["update:any"],"hook_prefix":"ninja"}`,
		"lookups,entry":     `{"program":"p","auto":true,"maps":["services"],"entry":true,"ops":["lookup:any"],"hook_prefix":"ninja"}`,
		"tail_calls":        `{"program":"p","auto":true,"tail_calls":true,"hook_prefix":"ninja"}`,
		"entry":             `{"program":"p","auto":true,"entry":true,"hook_prefix":"ninja"}`,
		"lookups,map_calls": `{"program":"p","auto":true,"maps":["services","flows"],"ops":["lookup:any","update:any"],"hook_prefix":"ninja"}`,
		"lookups":           `{"program":"p","auto":true,"maps":["services"],"hook":"ninja"}`,
	} {
		k, err := parseLookupsKinds(kinds)
		if err != nil {
			t.Fatal(err)
		}
		out := discoveryJSON(d, k)
		if rule, _ := json.Marshal(out.Rule); string(rule) != want {
			t.Errorf("%s: rule\n%s\nwant\n%s", kinds, rule, want)
		}
		if got := len(out.CallSites); got != map[string]int{"helpers": 2, "kfuncs": 1}[kinds] {
			t.Errorf("%s: %d call sites", kinds, got)
		}
	}
	if _, err := parseLookupsKinds("lookups,calls"); err == nil {
		t.Error("accepted an unknown kind")
	}
}
