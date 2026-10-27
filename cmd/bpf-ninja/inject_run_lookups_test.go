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
			{SitePC: 12, MapName: "services", FuncName: "tail_lb_ipv4_full"},
			{SitePC: 30, MapName: "backends", FuncName: "tail_lb_ipv4_full", File: "lb.c", Line: 7},
			{SitePC: 41, MapName: "services", FuncName: "sub", Reason: "lookup is not in the entry function"},
			{SitePC: 50, FuncName: "tail_lb_ipv4_full"},
		},
		Calls: []inject.LookupSite{
			{Op: inject.HookLookup, SitePC: 12, MapName: "services", FuncName: "tail_lb_ipv4_full"},
			{Op: inject.HookUpdate, SitePC: 20, MapName: "services", FuncName: "tail_lb_ipv4_full"},
			{Op: inject.HookLookup, SitePC: 30, MapName: "backends", FuncName: "tail_lb_ipv4_full", File: "lb.c", Line: 7},
			{Op: inject.HookDelete, SitePC: 35, MapName: "x.bss", FuncName: "tail_lb_ipv4_full"},
			{Op: inject.HookLookup, SitePC: 41, MapName: "services", FuncName: "sub", Reason: "lookup is not in the entry function"},
			{Op: inject.HookLookup, SitePC: 50, FuncName: "tail_lb_ipv4_full"},
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
		`"lookups":[{"kind":"lookup","pc":12,"map":"services","func":"tail_lb_ipv4_full"},` +
		`{"kind":"lookup","pc":30,"map":"backends","func":"tail_lb_ipv4_full","file":"lb.c","line":7},` +
		`{"kind":"lookup","pc":41,"map":"services","func":"sub","reason":"lookup is not in the entry function"},` +
		`{"kind":"lookup","pc":50,"func":"tail_lb_ipv4_full"}],` +
		`"calls":[{"kind":"lookup","pc":12,"map":"services","func":"tail_lb_ipv4_full"},` +
		`{"kind":"update","pc":20,"map":"services","func":"tail_lb_ipv4_full"},` +
		`{"kind":"lookup","pc":30,"map":"backends","func":"tail_lb_ipv4_full","file":"lb.c","line":7},` +
		`{"kind":"delete","pc":35,"map":"x.bss","func":"tail_lb_ipv4_full"},` +
		`{"kind":"lookup","pc":41,"map":"services","func":"sub","reason":"lookup is not in the entry function"},` +
		`{"kind":"lookup","pc":50,"func":"tail_lb_ipv4_full"}],` +
		`"rule":{"program":"tail_lb_ipv4_full","auto":true,"maps":["services","backends"],"hook":"ninja","stack_lowest_offset":null}}`
	if string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// The rule is refused until the stack audit is filled in, and then parses.
	rule, _ := json.Marshal([]syscallhook.Rule{discoveryJSON(d).Rule})
	if _, err := syscallhook.ParseConfig(strings.NewReader(string(rule))); err == nil {
		t.Fatal("accepted a rule without stack_lowest_offset")
	}
	filled := strings.Replace(string(rule), `"stack_lowest_offset":null`, `"stack_lowest_offset":-64`, 1)
	if rules, err := syscallhook.ParseConfig(strings.NewReader(filled)); err != nil || len(rules[0].Maps) != 2 {
		t.Fatalf("%s: %+v %v", filled, rules, err)
	}
}
