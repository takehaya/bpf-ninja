//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// The child is an ordinary cilium/ebpf loader. It has no injector calls and
// reports kernel program metadata; merely producing transformed bytes cannot
// satisfy this test. No interface attachment, pin, or global setting is used.
func TestIntegrationLoader(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if expected := os.Getenv("SYSCALLHOOK_INTEGRATION_CHILD"); expected != "" {
		loadIntegrationProgram(t, expected)
		return
	}
	// Prove the same loader succeeds without the supervisor and has no hook.
	t.Setenv("SYSCALLHOOK_INTEGRATION_CHILD", "plain")
	child := []string{os.Args[0], "-test.run=^TestIntegrationLoader$"}
	if out, err := exec.Command(child[0], child[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("baseline loader: %v\n%s", err, out)
	}
	for _, tc := range []struct {
		name, expected string
		closed         bool
		change         func(*Rule)
	}{
		{"kernel-name", "hook", false, func(r *Rule) {}},
		{"func-info-name", "hook", false, func(r *Rule) { r.Program = "entry_with_long_name" }},
		{"fail-open", "plain", false, func(r *Rule) { r.Map = "missing" }},
		{"fail-closed", "refused", true, func(r *Rule) { r.Map = "missing" }},
		{"unmatched", "plain", true, func(r *Rule) { r.Program = "unmatched" }},
		{"auto", "hook", true, func(r *Rule) { r.Auto, r.Map = true, "" }},
		{"entry-only", "hook", true, func(r *Rule) { r.Entry, r.Map = true, "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SYSCALLHOOK_INTEGRATION_CHILD", tc.expected)
			out, err := os.Create(filepath.Join(t.TempDir(), "loader.out"))
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			rule := testRule()
			tc.change(&rule)
			var logs bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			code, err := Run(ctx, child, Options{Rules: []Rule{rule}, FailClosed: tc.closed, Stdout: out, Stderr: out, Log: &logs})
			data, _ := os.ReadFile(out.Name())
			t.Logf("supervisor:\n%sloader:\n%s", &logs, data)
			if err != nil || code != 0 {
				t.Fatalf("code=%d err=%v", code, err)
			}
			if tc.expected == "hook" && !strings.Contains(logs.String(), "injected hook") {
				t.Fatal("no successful injection reported")
			}
		})
	}
}

func loadIntegrationProgram(t *testing.T, expected string) {
	t.Helper()
	u32 := &btf.Int{Name: "u32", Size: 4}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1, Key: u32, Value: u32})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Put(uint32(0), uint32(2)); err != nil {
		t.Fatal(err)
	}
	fn := &btf.Func{Name: "entry_with_long_name", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, m.FD()), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fn.Name).WithSource(asm.Comment("loader lookup")), fn)
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns})
	if expected == "refused" {
		if err == nil {
			p.Close()
			t.Fatal("fail-closed load unexpectedly succeeded")
		}
		fmt.Println("matched load refused")
		return
	}
	if err != nil {
		t.Fatalf("program load: %+v", err)
	}
	defer p.Close()
	info, err := p.Info()
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := info.FuncInfos()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range funcs {
		// Auto and entry rules name the hook lookup_hook_sessions or lookup_hook_entry.
		if strings.HasPrefix(f.Func.Name, "lookup_hook") {
			found = true
		}
	}
	if found != (expected == "hook") {
		t.Fatalf("kernel func_info hook=%v, expected %s; funcs=%+v", found, expected, funcs)
	}
	action, _, err := p.Test(make([]byte, 64))
	if err != nil || action != 2 {
		t.Fatalf("BPF_PROG_TEST_RUN: action=%d err=%v", action, err)
	}
	fmt.Printf("kernel hook=%v, action=%d, functions=%d\n", found, action, len(funcs))
}
