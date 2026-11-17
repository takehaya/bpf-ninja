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
)

// readyCalls are the callees the ready-rule loader calls: five with a
// call-table row and bpf_get_numa_node_id, a helper without one.
var readyCalls = []string{"bpf_ktime_get_ns", "bpf_jiffies64", "bpf_get_prandom_u32", "bpf_get_smp_processor_id", "bpf_xdp_get_buff_len", "bpf_get_numa_node_id"}

// readyResult is what the ready-rule loader saw: the test run's action, the
// map value afterwards and the names of the loaded program's functions.
type readyResult struct {
	Action uint32   `json:"action"`
	Value  uint32   `json:"value"`
	Funcs  []string `json:"funcs"`
}

// loadReadyProgram is the loader: an XDP program that calls five row
// callees and bpf_get_numa_node_id, which has no row, then returns the value
// at key 0 of sessions. It writes a readyResult to path.
func loadReadyProgram(t *testing.T, path string) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1, Key: u32, Value: u32})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Put(uint32(0), uint32(2)); err != nil {
		t.Fatal(err)
	}
	fn := &btf.Func{Name: "ready", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R9, 0), asm.FnKtimeGetNs.Call(),
		asm.Mov.Imm(asm.R9, 0), asm.FnJiffies64.Call(),
		asm.Mov.Imm(asm.R9, 0), asm.FnGetPrandomU32.Call(),
		asm.Mov.Imm(asm.R9, 0), asm.FnGetSmpProcessorId.Call(),
		asm.Mov.Reg(asm.R1, asm.R6), asm.FnXdpGetBuffLen.Call(),
		asm.Mov.Imm(asm.R9, 0), asm.FnGetNumaNodeId.Call(),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, m.FD()), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "miss"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word), asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("miss"), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fn.Name).WithSource(asm.Comment("ready loader")), fn)
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ready", Type: ebpf.XDP, License: "GPL", Instructions: insns})
	if err != nil {
		t.Fatalf("program load: %+v", err)
	}
	defer func() { _ = p.Close() }()
	var out readyResult
	if out.Action, _, err = p.Test(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(uint32(0), &out.Value); err != nil {
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
	data, _ := json.Marshal(out)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The list, edit and load workflow: inject-run --lookups-json lists the
// loader's program with a ready rule, which loads unchanged with a hook for
// every listed row callee, the lookup and the entry, and the program acts as
// the unmodified one. Deleting one name gives fewer hooks, never more.
func TestBpfReadyRuleRoundTrip(t *testing.T) {
	if out := os.Getenv("BPF_NINJA_READY_CHILD"); out != "" {
		loadReadyProgram(t, out)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	t.Setenv("BPF_NINJA_INJECT_CONFIG", "")
	dir := t.TempDir()
	child := []string{"--", os.Args[0], "-test.run=^TestBpfReadyRuleRoundTrip$"}
	run := func(name string, flags ...string) readyResult {
		t.Helper()
		out := filepath.Join(dir, name+".out")
		t.Setenv("BPF_NINJA_READY_CHILD", out)
		if err := newRootCommand().Run(context.Background(), append(append([]string{"bpf-ninja", "inject-run"}, flags...), child...)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var r readyResult
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// List: nothing is rewritten.
	sites := filepath.Join(dir, "sites.json")
	plain := run("list", "--lookups-json", sites)
	if plain.Action != 2 || plain.Value != 2 || !slices.Equal(plain.Funcs, []string{"ready"}) {
		t.Fatalf("listing run: %+v", plain)
	}
	data, err := os.ReadFile(sites)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Version  int `json:"version"`
		Programs []struct {
			Build   string            `json:"build"`
			Callees []calleeJSON      `json:"callees"`
			Rule    json.RawMessage   `json:"rule"`
			Labels  []json.RawMessage `json:"call_sites"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != 3 || len(file.Programs) != 1 || !strings.HasPrefix(file.Programs[0].Build, "sha256:") || len(file.Programs[0].Labels) != 6 {
		t.Fatalf("listing:\n%s", data)
	}
	t.Logf("listing:\n%s", data)
	var numa *calleeJSON
	for i, c := range file.Programs[0].Callees {
		if c.Name == "bpf_get_numa_node_id" {
			numa = &file.Programs[0].Callees[i]
		}
	}
	if numa == nil || numa.Typed || numa.Reason != "" {
		t.Fatalf("callee without a row: %+v", numa)
	}
	// Load with the rule as emitted (jq '[.programs[].rule]').
	rule := file.Programs[0].Rule
	load := func(name string, rule json.RawMessage) (readyResult, []hookJSON) {
		t.Helper()
		config, hooks := filepath.Join(dir, name+"-rules.json"), filepath.Join(dir, name+"-hooks.json")
		if err := os.WriteFile(config, []byte("["+string(rule)+"]"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := run(name, "--config", config, "--hooks-json", hooks)
		data, err := os.ReadFile(hooks)
		if err != nil {
			t.Fatal(err)
		}
		var file hooksFileJSON
		if err := json.Unmarshal(data, &file); err != nil || len(file.Programs) != 1 {
			t.Fatalf("%s hooks file: %v\n%s", name, err, data)
		}
		t.Logf("%s hooks:\n%s", name, data)
		if r.Action != plain.Action || r.Value != plain.Value {
			t.Fatalf("%s: %+v, unmodified %+v", name, r, plain)
		}
		return r, file.Programs[0].Hooks
	}
	ready, hooks := load("ready", rule)
	calls := map[string]bool{}
	for _, h := range hooks {
		if h.Kind == "call" && len(h.Sites) == 1 {
			calls[h.Call] = true
		}
	}
	for _, name := range readyCalls {
		if !calls[name] || !slices.Contains(ready.Funcs, "ninja_"+name) {
			t.Errorf("%s: no hook (hooks %v, funcs %v)", name, calls, ready.Funcs)
		}
	}
	if len(calls) != len(readyCalls) || !slices.Contains(ready.Funcs, "ninja_entry") || !slices.Contains(ready.Funcs, "ninja_sessions") {
		t.Errorf("ready rule hooks: %v, funcs %v", calls, ready.Funcs)
	}
	// Delete one name.
	var r map[string]any
	if err := json.Unmarshal(rule, &r); err != nil {
		t.Fatal(err)
	}
	r["calls"] = slices.DeleteFunc(r["calls"].([]any), func(v any) bool { return v == "bpf_jiffies64" })
	edited, _ := json.Marshal(r)
	fewer, fewerHooks := load("edited", edited)
	if len(fewerHooks) >= len(hooks) || len(fewer.Funcs) != len(ready.Funcs)-1 || slices.Contains(fewer.Funcs, "ninja_bpf_jiffies64") {
		t.Errorf("after deleting bpf_jiffies64: %d hooks (was %d), funcs %v", len(fewerHooks), len(hooks), fewer.Funcs)
	}
}
