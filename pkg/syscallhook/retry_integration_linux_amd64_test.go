//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// retryProgram is the loader of the retry tests: an XDP program "p" that
// calls bpf_ktime_get_ns (site 1) and bpf_get_prandom_u32 (site 5) and, when
// preempt is set, holds preemption off around the second call
// (bpf_preempt_disable at 3, bpf_preempt_enable at 7). It returns XDP_PASS.
// The loader prints the names of the loaded program's functions.
func retryProgram(t *testing.T, preempt, refused bool) {
	t.Helper()
	fn := &btf.Func{Name: "entry_with_long_name", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	nop := asm.Mov.Imm(asm.R8, 0)
	disable, enable := nop, nop
	if preempt {
		disable, enable = retryKfunc(t, "bpf_preempt_disable"), retryKfunc(t, "bpf_preempt_enable")
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnKtimeGetNs.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		disable,
		asm.Mov.Imm(asm.R8, 0),
		asm.FnGetPrandomU32.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		enable,
		asm.Mov.Imm(asm.R0, 2),
		asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fn.Name).WithSource(asm.Comment("retry loader")), fn)
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns})
	if refused {
		if err == nil {
			_ = p.Close()
			t.Fatal("fail-closed load unexpectedly succeeded")
		}
		fmt.Println("load refused")
		return
	}
	if err != nil {
		t.Fatalf("program load: %+v", err)
	}
	defer func() { _ = p.Close() }()
	info, err := p.Info()
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := info.FuncInfos()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range funcs {
		names = append(names, f.Func.Name)
	}
	action, _, err := p.Test(make([]byte, 64))
	if err != nil || action != 2 {
		t.Fatalf("BPF_PROG_TEST_RUN: action=%d err=%v", action, err)
	}
	fmt.Printf("functions=%s action=%d\n", strings.Join(names, ","), action)
}

// retryKfunc is a call of the kernel function name by its BTF id; the test
// skips when the running kernel lacks it.
func retryKfunc(t *testing.T, name string) asm.Instruction {
	t.Helper()
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatalf("kernel BTF: %v", err)
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		t.Skipf("kernel lacks %s: %v", name, err)
	}
	id, err := spec.TypeID(fn)
	if err != nil {
		t.Fatal(err)
	}
	return asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: int64(id)}
}

// runRetryLoader runs the loader of test under the supervisor with a rule that
// hooks the entry and both calls, and returns the injections, the
// supervisor's log and the loader's output.
func runRetryLoader(t *testing.T, test, mode string, failClosed bool, fault func([]inject.LookupHook) error) ([]Injection, string, string) {
	t.Helper()
	t.Setenv("SYSCALLHOOK_RETRY_CHILD", mode)
	out, err := os.CreateTemp(t.TempDir(), "loader.out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	rule := Rule{Program: "p", Hook: "h", Entry: true, Calls: []string{"bpf_ktime_get_ns", "bpf_get_prandom_u32"}}
	var logs bytes.Buffer
	var injected []Injection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := Options{Rules: []Rule{rule}, FailClosed: failClosed, Stdout: out, Stderr: out, Log: &logs, loadFault: fault,
		OnInject: func(inj Injection) { injected = append(injected, inj) }}
	code, err := Run(ctx, []string{os.Args[0], "-test.run=^" + test + "$"}, opts)
	data, _ := os.ReadFile(out.Name())
	t.Logf("supervisor:\n%sloader:\n%s", &logs, data)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if strings.Contains(logs.String(), "checker rejected") {
		t.Fatal("the load-time checker rejected a rewrite")
	}
	return injected, logs.String(), string(data)
}

// hookedSites returns the sites of the call hooks of inj.
func hookedSites(inj Injection) []uint32 {
	var pcs []uint32
	for _, h := range inj.Hooks {
		for _, site := range h.Sites {
			pcs = append(pcs, site.SitePC)
		}
	}
	slices.Sort(pcs)
	return pcs
}

// A rewrite the kernel refuses (planted through loadFault whenever the hook
// of site 5 is in it) loads after the retry drops that site: the other
// call hook and the entry hook stay, the dropped site is skipped as refused
// in this combination, and the program runs as before. When every rewrite is
// refused the original loads, or with --fail-closed the load is refused.
func TestIntegrationRetry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if mode := os.Getenv("SYSCALLHOOK_RETRY_CHILD"); mode != "" {
		retryProgram(t, false, mode == "refused")
		return
	}
	planted := errors.New("planted refusal")
	withSite := func(pc uint32) func([]inject.LookupHook) error {
		return func(hooks []inject.LookupHook) error {
			for _, h := range hooks {
				if slices.ContainsFunc(h.Sites, func(site inject.LookupSite) bool { return site.SitePC == pc }) {
					return planted
				}
			}
			return nil
		}
	}
	t.Run("one-site", func(t *testing.T) {
		injected, logs, out := runRetryLoader(t, "TestIntegrationRetry", "hook", false, withSite(5))
		if len(injected) != 1 || !slices.Equal(hookedSites(injected[0]), []uint32{1}) || len(injected[0].Hooks) != 2 {
			t.Fatalf("injections %+v", injected)
		}
		skipped := injected[0].Skipped
		if len(skipped) != 1 || skipped[0].SitePC != 5 || !strings.HasPrefix(skipped[0].Reason, "load: refused in this combination") ||
			!strings.Contains(skipped[0].Reason, "planted refusal") {
			t.Fatalf("skipped %+v", skipped)
		}
		if !strings.Contains(logs, `program "p": 2 sites requested, 1 kept after `) || !strings.Contains(logs, "checker accepted") ||
			!strings.Contains(out, "h_entry") || !strings.Contains(out, "h_bpf_ktime_get_ns") || strings.Contains(out, "h_bpf_get_prandom_u32") {
			t.Fatal("retry not reported or hooks missing")
		}
	})
	all := func([]inject.LookupHook) error { return planted }
	t.Run("nothing-loads", func(t *testing.T) {
		injected, logs, out := runRetryLoader(t, "TestIntegrationRetry", "plain", false, all)
		if len(injected) != 0 || !strings.Contains(logs, "no trial load passed") || strings.Contains(out, "h_entry") {
			t.Fatalf("injections %+v", injected)
		}
	})
	t.Run("nothing-loads-fail-closed", func(t *testing.T) {
		injected, _, out := runRetryLoader(t, "TestIntegrationRetry", "refused", true, all)
		if len(injected) != 0 || !strings.Contains(out, "load refused") {
			t.Fatalf("injections %+v", injected)
		}
	})
}

// X7: a global hook call inside a preemption-disabled region. Kernels 6.10
// to 6.14 refuse it, and the retry drops exactly that site; later kernels
// load both call hooks.
func TestIntegrationRetryPreempt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if mode := os.Getenv("SYSCALLHOOK_RETRY_CHILD"); mode != "" {
		retryProgram(t, true, false)
		return
	}
	retryKfunc(t, "bpf_preempt_disable")
	injected, logs, _ := runRetryLoader(t, "TestIntegrationRetryPreempt", "hook", false, nil)
	if len(injected) != 1 {
		t.Fatalf("injections %+v", injected)
	}
	kernel := runningKernelInfo()
	refuses := kernel.Major == 6 && kernel.Minor >= 10 && kernel.Minor <= 14
	got := hookedSites(injected[0])
	t.Logf("kernel %d.%d: hooked sites %v, skipped %+v", kernel.Major, kernel.Minor, got, injected[0].Skipped)
	if refuses {
		if !slices.Equal(got, []uint32{1}) || len(injected[0].Skipped) != 1 || injected[0].Skipped[0].SitePC != 5 ||
			!strings.Contains(injected[0].Skipped[0].Reason, "refused in this combination") || !strings.Contains(logs, "trial loads") {
			t.Fatalf("hooked %v skipped %+v", got, injected[0].Skipped)
		}
		return
	}
	if !slices.Equal(got, []uint32{1, 5}) || len(injected[0].Skipped) != 0 || strings.Contains(logs, "trial loads") {
		t.Fatalf("hooked %v skipped %+v", got, injected[0].Skipped)
	}
}
