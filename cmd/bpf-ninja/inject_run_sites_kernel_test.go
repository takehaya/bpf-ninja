//go:build linux && amd64

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

// sitesResult is what the sites loader saw: the test run's action and the
// names of the loaded program's functions, or the load error.
type sitesResult struct {
	Action uint32   `json:"action"`
	Funcs  []string `json:"funcs"`
	Error  string   `json:"error,omitempty"`
}

// loadSitesProgram is the loader: an XDP program that calls
// bpf_ktime_get_ns twice with bpf_jiffies64 between them and returns the
// value at key 0 of sessions. With changed, one instruction before the
// second clock call differs. It writes a sitesResult to path; a refused load
// is written as its error.
func loadSitesProgram(t *testing.T, path string, changed bool) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1, Key: u32, Value: u32})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Put(uint32(0), uint32(2)); err != nil {
		t.Fatal(err)
	}
	fn := &btf.Func{Name: "sites", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	second := asm.Mov.Imm(asm.R9, 0)
	if changed {
		second = asm.Mov.Imm(asm.R9, 1)
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R9, 0), asm.FnKtimeGetNs.Call(),
		asm.Mov.Imm(asm.R9, 0), asm.FnJiffies64.Call(),
		second, asm.FnKtimeGetNs.Call(),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, m.FD()), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "miss"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word), asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("miss"), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fn.Name).WithSource(asm.Comment("sites loader")), fn)
	var out sitesResult
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "sites", Type: ebpf.XDP, License: "GPL", Instructions: insns})
	if err == nil {
		defer func() { _ = p.Close() }()
		out.Action, _, err = p.Test(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		info, err := p.Info()
		if err != nil {
			t.Fatal(err)
		}
		funcs, err := info.FuncInfos()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range funcs {
			out.Funcs = append(out.Funcs, f.Func.Name)
		}
	} else {
		out.Error = err.Error()
	}
	data, _ := json.Marshal(out)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// List, select one of two sites of the same callee by label and by number,
// load: only that site of the callee is hooked, its other names keep their
// hooks, and the program acts as the unmodified one. The same selection
// against a program with one instruction changed is refused with both
// fingerprints, and the original loads; with --fail-closed the load fails.
func TestBpfSitesSelection(t *testing.T) {
	if out := os.Getenv("BPF_NINJA_SITES_CHILD"); out != "" {
		loadSitesProgram(t, out, os.Getenv("BPF_NINJA_SITES_CHANGED") != "")
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	t.Setenv("BPF_NINJA_INJECT_CONFIG", "")
	dir := t.TempDir()
	child := []string{"--", os.Args[0], "-test.run=^TestBpfSitesSelection$"}
	run := func(name string, changed bool, flags ...string) sitesResult {
		t.Helper()
		out := filepath.Join(dir, name+".out")
		t.Setenv("BPF_NINJA_SITES_CHILD", out)
		t.Setenv("BPF_NINJA_SITES_CHANGED", map[bool]string{true: "1"}[changed])
		if err := newRootCommand().Run(context.Background(), append(append([]string{"bpf-ninja", "inject-run"}, flags...), child...)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var r sitesResult
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	sites := filepath.Join(dir, "sites.json")
	plain := run("list", false, "--lookups-json", sites)
	if plain.Action != 2 || !slices.Equal(plain.Funcs, []string{"sites"}) {
		t.Fatalf("listing run: %+v", plain)
	}
	data, err := os.ReadFile(sites)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("listing:\n%s", data)
	var listing lookupsFileJSON
	if err := json.Unmarshal(data, &listing); err != nil || len(listing.Programs) != 1 {
		t.Fatalf("listing: %v", err)
	}
	prog := listing.Programs[0]
	var clock []hookSiteJSON
	for _, site := range prog.CallSites {
		if site.Call == "bpf_ktime_get_ns" {
			clock = append(clock, site)
		}
	}
	if len(clock) != 2 || clock[0].Label == clock[1].Label || !strings.HasPrefix(prog.Build, "sha256:") {
		t.Fatalf("clock sites %+v, build %q", clock, prog.Build)
	}
	load := func(name string, changed bool, sel syscallhook.Sites, flags ...string) (sitesResult, hooksFileJSON) {
		t.Helper()
		rule := prog.Rule
		rule.Sites = &sel
		encoded, err := json.Marshal([]syscallhook.Rule{rule})
		if err != nil {
			t.Fatal(err)
		}
		config, hooks := filepath.Join(dir, name+"-rules.json"), filepath.Join(dir, name+"-hooks.json")
		if err := os.WriteFile(config, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		r := run(name, changed, append([]string{"--config", config, "--hooks-json", hooks}, flags...)...)
		data, err := os.ReadFile(hooks)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s rule %s\nhooks:\n%s", name, encoded, data)
		var file hooksFileJSON
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		return r, file
	}
	for i, ref := range []syscallhook.SiteRef{{Label: clock[1].Label}, {PC: &clock[0].PC}} {
		keep, left := clock[1-i], clock[i]
		name := []string{"by-label", "by-number"}[i]
		r, file := load(name, false, syscallhook.Sites{Build: prog.Build, Only: []syscallhook.SiteRef{ref}})
		if r.Action != plain.Action || len(file.Programs) != 1 || len(file.Refused) != 0 || file.Programs[0].Build != prog.Build {
			t.Fatalf("%s: %+v, unmodified %+v", name, r, plain)
		}
		calls := map[string][]hookSiteJSON{}
		for _, h := range file.Programs[0].Hooks {
			if h.Kind == "call" {
				calls[h.Call] = h.Sites
			}
		}
		if got := calls["bpf_ktime_get_ns"]; len(got) != 1 || got[0].PC != keep.PC || got[0].Label != keep.Label {
			t.Errorf("%s: clock hook sites %+v, want only pc %d %s", name, got, keep.PC, keep.Label)
		}
		if len(calls["bpf_jiffies64"]) != 1 || !slices.Contains(r.Funcs, "ninja_entry") || !slices.Contains(r.Funcs, "ninja_sessions") {
			t.Errorf("%s: other names lost hooks: %v, funcs %v", name, calls, r.Funcs)
		}
		if !slices.ContainsFunc(file.Programs[0].Skipped, func(s hookSiteJSON) bool {
			return s.PC == left.PC && s.Label == left.Label && s.Reason == "not selected by the rule's sites"
		}) {
			t.Errorf("%s: skipped %+v, want pc %d not selected", name, file.Programs[0].Skipped, left.PC)
		}
	}
	// One instruction differs: the selection is refused and the original loads.
	sel := syscallhook.Sites{Build: prog.Build, Only: []syscallhook.SiteRef{{Label: clock[1].Label}}}
	r, file := load("changed", true, sel)
	if r.Error != "" || r.Action != plain.Action || !slices.Equal(r.Funcs, []string{"sites"}) || len(file.Programs) != 0 || len(file.Refused) != 1 {
		t.Fatalf("changed program: %+v, hooks file %+v", r, file)
	}
	reason := file.Refused[0].Reason
	if !strings.HasPrefix(reason, "rule sites were listed from build "+prog.Build+" but this load is build sha256:") ||
		!strings.HasSuffix(reason, "; list again with --lookups-json and copy the sites from the new file") || file.Refused[0].Program != "sites" || file.Refused[0].Func != "sites" {
		t.Errorf("refusal %+v", file.Refused[0])
	}
	// The loader library repeats a refused load once, so each is refused.
	r, file = load("changed-fail-closed", true, sel, "--fail-closed")
	if !strings.Contains(r.Error, "operation not permitted") || len(file.Refused) == 0 || len(file.Programs) != 0 {
		t.Errorf("--fail-closed: %+v, hooks file %+v", r, file)
	}
}
