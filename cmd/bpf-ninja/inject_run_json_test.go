//go:build linux && amd64

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

func TestInjectionJSON(t *testing.T) {
	site := func(pc uint32, m string) inject.LookupSite {
		return inject.LookupSite{SitePC: pc, MapName: m, FuncName: "xdp_ingress", File: "x.c", Line: pc}
	}
	for _, tc := range []struct {
		name string
		inj  syscallhook.Injection
		want string
	}{
		{"auto", syscallhook.Injection{Program: "xdp_ingress", Func: "xdp_ingress", Type: ebpf.XDP, ProgID: 42, Hooks: []inject.LookupHook{
			{Name: "obs_sessions", Kind: inject.HookLookup, When: inject.LookupHit, MapName: "sessions", Sites: []inject.LookupSite{site(12, "sessions")}},
			{Name: "obs_sessions_miss", Kind: inject.HookLookup, When: inject.LookupMiss, MapName: "sessions", Sites: []inject.LookupSite{site(12, "sessions")}},
			{Name: "obs_flows", Kind: inject.HookLookup, MapName: "flows", ReadOnly: true, Copied: true, Sites: []inject.LookupSite{site(18, "flows")}},
			{Name: "obs_any", Kind: inject.HookLookup, Generic: true, Untrusted: true, Sites: []inject.LookupSite{{SitePC: 51}}},
			{Name: "obs_entry", Kind: inject.HookEntry},
			{Name: "obs_tail_call", Kind: inject.HookTailCall, Sites: []inject.LookupSite{{SitePC: 60, FuncName: "sub"}}},
		}, Skipped: []inject.LookupSite{{SitePC: 7, MapName: "socks", Reason: "sockhash has no typed hook"}}},
			`{"program":"xdp_ingress","func":"xdp_ingress","type":"XDP","prog_id":42,"ctx_type":"xdp_md","hooks":[` +
				`{"name":"obs_sessions","kind":"typed","when":"hit","map":"sessions","sites":[{"kind":"lookup","pc":12,"map":"sessions","func":"xdp_ingress","file":"x.c","line":12}],"untrusted":false,"copied":false,"static":false,"read_only":false},` +
				`{"name":"obs_sessions_miss","kind":"typed","when":"miss","map":"sessions","sites":[{"kind":"lookup","pc":12,"map":"sessions","func":"xdp_ingress","file":"x.c","line":12}],"untrusted":false,"copied":false,"static":false,"read_only":false},` +
				`{"name":"obs_flows","kind":"typed","map":"flows","sites":[{"kind":"lookup","pc":18,"map":"flows","func":"xdp_ingress","file":"x.c","line":18}],"untrusted":false,"copied":true,"static":false,"read_only":true},` +
				`{"name":"obs_any","kind":"generic","sites":[{"kind":"lookup","pc":51}],"untrusted":true,"copied":false,"static":false,"read_only":false},` +
				`{"name":"obs_entry","kind":"entry","sites":[],"untrusted":false,"copied":false,"static":false,"read_only":false},` +
				`{"name":"obs_tail_call","kind":"tail_call","sites":[{"kind":"tail_call","pc":60,"func":"sub"}],"untrusted":false,"copied":false,"static":false,"read_only":false}],` +
				`"skipped":[{"kind":"lookup","pc":7,"map":"socks","reason":"sockhash has no typed hook"}]}`},
		// Dispatch hooks share one name: one function, every site, the entry
		// as DispatchEntrySite first and then by PC across maps and kinds.
		{"dispatch", syscallhook.Injection{Program: "tc_main", Type: ebpf.SchedCLS, Hooks: []inject.LookupHook{
			{Name: "d", Kind: inject.HookLookup, When: inject.LookupAny, MapName: "a", Static: true, Dispatch: true, Sites: []inject.LookupSite{{SitePC: 13, MapName: "a"}}},
			{Name: "d", Kind: inject.HookLookup, When: inject.LookupAny, MapName: "b", Static: true, Dispatch: true, Sites: []inject.LookupSite{{SitePC: 30, MapName: "b"}}},
			{Name: "d", Kind: inject.HookEntry, Static: true, Dispatch: true},
			{Name: "d", Kind: inject.HookTailCall, Static: true, Dispatch: true, Sites: []inject.LookupSite{{SitePC: 20}}},
		}},
			`{"program":"tc_main","func":"","type":"SchedCLS","prog_id":0,"ctx_type":"__sk_buff","hooks":[` +
				`{"name":"d","kind":"dispatch","when":"any","sites":[{"kind":"entry","pc":4294967295},{"kind":"lookup","pc":13,"map":"a"},{"kind":"tail_call","pc":20},{"kind":"lookup","pc":30,"map":"b"}],"untrusted":false,"copied":false,"static":true,"read_only":false}],` +
				`"skipped":[]}`},
	} {
		got, err := json.Marshal(injectionJSON(tc.inj))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Fatalf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
}

func TestHooksWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	read := func() hooksFileJSON {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var f hooksFileJSON
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	w, err := newHooksWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if f := read(); f.Version != 1 || f.Programs == nil || len(f.Programs) != 0 {
		t.Fatalf("initial file: %+v", f)
	}
	for _, name := range []string{"a", "b"} {
		if err := w.add(syscallhook.Injection{Program: name, Type: ebpf.XDP, Hooks: []inject.LookupHook{{Name: name + "_entry", Kind: inject.HookEntry}}}); err != nil {
			t.Fatal(err)
		}
	}
	f := read()
	if len(f.Programs) != 2 || f.Programs[1].Program != "b" || f.Programs[1].Hooks[0].Name != "b_entry" {
		t.Fatalf("after two loads: %+v", f)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode: %v %v", info, err)
	}
}
