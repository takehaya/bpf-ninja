//go:build linux && amd64

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

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
	got, err := json.Marshal(discoveryJSON(d))
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
	rule, _ := json.Marshal([]syscallhook.Rule{discoveryJSON(d).Rule})
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
	out := discoveryJSON(d)
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
