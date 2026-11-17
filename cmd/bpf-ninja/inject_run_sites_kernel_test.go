//go:build linux && amd64

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
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
// is written as its error. With loaded, it calls loaded with the program
// before it writes the result.
func loadSitesProgram(t *testing.T, path string, changed bool, loaded func(*ebpf.Program)) {
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
		if loaded != nil {
			loaded(p)
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
		loadSitesProgram(t, out, os.Getenv("BPF_NINJA_SITES_CHANGED") != "", nil)
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

// captureSite captures at the clock site labelled site with --site while
// prog runs: the hook reports both clock calls, the capture only the one at
// site, once per run. Three runs leave the capture of four packets running;
// the fourth ends it.
func captureSite(t *testing.T, prog *ebpf.Program, hooks, site string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	pcap := filepath.Join(filepath.Dir(hooks), "site.pcapng")
	c := startCapture(t, "-p", fmt.Sprint(id), "--hooks-json", hooks, "--site", site, "-w", pcap, "-c", "4", "--no-cpu-affinity", "-v")
	c.waitFor("capturing (")
	runs := func(n int) {
		for range n {
			if _, _, err := prog.Test(make([]byte, 64)); err != nil {
				t.Fatal(err)
			}
		}
	}
	runs(3)
	select {
	case err := <-c.done:
		c.restore()
		t.Fatalf("the capture ended after three runs (%v): the filter let the other clock call through", err)
	case <-time.After(time.Second):
	}
	runs(1)
	stderr := c.finish()
	if n := len(epbInterfaces(t, pcap)); n != 4 {
		t.Errorf("%d packets, want 4\n%s", n, stderr)
	}
	if strings.Contains(stderr, "follow_attached") {
		t.Errorf("a --site capture follows reloads:\n%s", stderr)
	}
	if !strings.Contains(stderr, fmt.Sprintf("attach target: prog id=%d func=\"ninja_bpf_ktime_get_ns\"", id)) {
		t.Errorf("no attach to the clock hook:\n%s", stderr)
	}
}

// Capture by label: the ready rule hooks both clock calls through one hook;
// --site with the second call's label from the hooks file captures only
// that call. The capture runs in the loader while its program is loaded.
func TestBpfSitesCapture(t *testing.T) {
	if out := os.Getenv("BPF_NINJA_SITES_CHILD"); out != "" {
		var capture func(*ebpf.Program)
		if site := os.Getenv("BPF_NINJA_SITES_SITE"); site != "" { // not while listing
			capture = func(p *ebpf.Program) { captureSite(t, p, os.Getenv("BPF_NINJA_SITES_HOOKS"), site) }
		}
		loadSitesProgram(t, out, false, capture)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	t.Setenv("BPF_NINJA_INJECT_CONFIG", "")
	dir := t.TempDir()
	child := []string{"--", os.Args[0], "-test.run=^TestBpfSitesCapture$"}
	run := func(name string, flags ...string) {
		t.Helper()
		t.Setenv("BPF_NINJA_SITES_CHILD", filepath.Join(dir, name+".out"))
		if err := newRootCommand().Run(context.Background(), append(append([]string{"bpf-ninja", "inject-run"}, flags...), child...)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, name+".out")); err != nil {
			t.Fatalf("%s: the loader did not finish: %v", name, err)
		}
	}
	sites := filepath.Join(dir, "sites.json")
	run("list", "--lookups-json", sites)
	data, err := os.ReadFile(sites)
	if err != nil {
		t.Fatal(err)
	}
	var listing lookupsFileJSON
	if err := json.Unmarshal(data, &listing); err != nil || len(listing.Programs) != 1 {
		t.Fatalf("listing: %v", err)
	}
	var clock []string
	for _, site := range listing.Programs[0].CallSites {
		if site.Call == "bpf_ktime_get_ns" {
			clock = append(clock, site.Label)
		}
	}
	if len(clock) != 2 {
		t.Fatalf("clock labels %v", clock)
	}
	encoded, _ := json.Marshal([]syscallhook.Rule{listing.Programs[0].Rule})
	config, hooks := filepath.Join(dir, "rules.json"), filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(config, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BPF_NINJA_SITES_HOOKS", hooks)
	t.Setenv("BPF_NINJA_SITES_SITE", clock[1])
	run("capture", "--config", config, "--hooks-json", hooks)
	data, _ = os.ReadFile(hooks)
	t.Logf("hooks:\n%s", data)
}

// Capture by site at a queue push: the ready rule is auto, so the push gets a
// typed hook whose prototype takes the site, and --site with the push's label
// from the hooks file attaches to that hook. The loader pushes once per run.
func TestBpfSitesCaptureQueue(t *testing.T) {
	if out := os.Getenv("BPF_NINJA_SITES_CHILD"); out != "" {
		loadQueueProgram(t, out, os.Getenv("BPF_NINJA_SITES_HOOKS"))
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	t.Setenv("BPF_NINJA_INJECT_CONFIG", "")
	dir := t.TempDir()
	child := []string{"--", os.Args[0], "-test.run=^TestBpfSitesCaptureQueue$"}
	// The loader must load the program and run it (XDP_PASS): a loader
	// whose load failed writes its error and captures nothing.
	run := func(name string, flags ...string) {
		t.Helper()
		t.Setenv("BPF_NINJA_SITES_CHILD", filepath.Join(dir, name+".out"))
		if err := newRootCommand().Run(context.Background(), append(append([]string{"bpf-ninja", "inject-run"}, flags...), child...)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := os.ReadFile(filepath.Join(dir, name+".out"))
		if err != nil {
			t.Fatalf("%s: the loader did not finish: %v", name, err)
		}
		var out sitesResult
		if err := json.Unmarshal(data, &out); err != nil || out.Error != "" || out.Action != 2 {
			t.Fatalf("%s: loader result %s: %v", name, data, err)
		}
	}
	sites := filepath.Join(dir, "sites.json")
	run("list", "--lookups-json", sites)
	data, err := os.ReadFile(sites)
	if err != nil {
		t.Fatal(err)
	}
	var listing lookupsFileJSON
	if err := json.Unmarshal(data, &listing); err != nil || len(listing.Programs) != 1 || !listing.Programs[0].Rule.Auto {
		t.Fatalf("listing: %v\n%s", err, data)
	}
	encoded, _ := json.Marshal([]syscallhook.Rule{listing.Programs[0].Rule})
	config, hooks := filepath.Join(dir, "rules.json"), filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(config, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BPF_NINJA_SITES_HOOKS", hooks)
	run("capture", "--config", config, "--hooks-json", hooks)
	data, _ = os.ReadFile(hooks)
	t.Logf("rule %s\nhooks:\n%s", encoded, data)
}

// loadQueueProgram loads an XDP program that pushes a u32 from an array to
// the queue q and returns XDP_PASS. While it is loaded it reads the hooks file at hooks,
// captures the push site with --site and runs the program twice: the capture
// of two packets ends. It writes a sitesResult to path.
func loadQueueProgram(t *testing.T, path, hooks string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	u32 := &btf.Int{Name: "u32", Size: 4}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "q", Type: ebpf.Queue, ValueSize: 4, MaxEntries: 4, Value: u32})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	// The value is in an array, not on the stack: before 6.8 a stack
	// pointer passed to a push makes the stack floor unknown.
	scratch, err := ebpf.NewMap(&ebpf.MapSpec{Name: "scratch", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = scratch.Close() }()
	fn := &btf.Func{Name: "pushes", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	insns := asm.Instructions{
		asm.LoadMapValue(asm.R2, scratch.FD(), 0), asm.StoreImm(asm.R2, 0, 7, asm.Word), asm.Mov.Imm(asm.R3, 0),
		asm.LoadMapPtr(asm.R1, m.FD()), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fn.Name).WithSource(asm.Comment("queue loader")), fn)
	var out sitesResult
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "pushes", Type: ebpf.XDP, License: "GPL", Instructions: insns})
	if err != nil {
		out.Error = err.Error()
	} else {
		defer func() { _ = p.Close() }()
		if out.Action, _, err = p.Test(make([]byte, 64)); err != nil {
			t.Fatal(err)
		}
		if hooks != "" { // not while listing
			captureQueueSite(t, p, hooks)
		}
	}
	data, _ := json.Marshal(out)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// captureQueueSite captures prog's push site by its label with --site.
func captureQueueSite(t *testing.T, prog *ebpf.Program, hooks string) {
	data, err := os.ReadFile(hooks)
	if err != nil {
		t.Fatal(err)
	}
	var file hooksFileJSON
	if err := json.Unmarshal(data, &file); err != nil || len(file.Programs) != 1 {
		t.Fatalf("hooks file: %v\n%s", err, data)
	}
	var hook, label string
	for _, h := range file.Programs[0].Hooks {
		for _, s := range h.Sites {
			if s.Kind == "push" {
				hook, label = h.Name, s.Label
			}
		}
	}
	if label == "" {
		t.Fatalf("no push site in the hooks file:\n%s", data)
	}
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	pcap := filepath.Join(filepath.Dir(hooks), "queue.pcapng")
	c := startCapture(t, "-p", fmt.Sprint(id), "--hooks-json", hooks, "--site", label, "-w", pcap, "-c", "2", "--no-cpu-affinity", "-v")
	// A refused --site returns before the capture writes a line.
	for started := false; !started; {
		select {
		case line := <-c.lines:
			c.all.WriteString(line + "\n")
			started = strings.Contains(line, "capturing (")
		case err := <-c.done:
			c.restore()
			t.Fatalf("capture --site %s: %v\n%s", label, err, c.all.String())
		case <-time.After(20 * time.Second):
			t.Fatalf("no \"capturing (\" within 20s:\n%s", c.all.String())
		}
	}
	for range 2 {
		if _, _, err := prog.Test(make([]byte, 64)); err != nil {
			t.Fatal(err)
		}
	}
	stderr := c.finish()
	if n := len(epbInterfaces(t, pcap)); n != 2 {
		t.Errorf("%d packets, want 2\n%s", n, stderr)
	}
	if !strings.Contains(stderr, fmt.Sprintf("attach target: prog id=%d func=%q", id, hook)) {
		t.Errorf("no attach to the push hook %s:\n%s", hook, stderr)
	}
}
