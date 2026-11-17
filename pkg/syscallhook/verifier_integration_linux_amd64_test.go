//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// TestIntegrationVerifierRefused: the verifier refuses the trial load of a
// program under a map rule (R0 is never written). The kernel prints its
// statistics after the refusal too; the supervisor still recognises the
// refusal, so the loader gets the kernel's own EACCES and log for its load,
// and the refusal says "verifier" and "original_refused".
func TestIntegrationVerifierRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if os.Getenv("SYSCALLHOOK_VERIFIER_CHILD") != "" {
		fn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
			Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
			Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md"}}}}}}
		spec := &ebpf.ProgramSpec{Name: "p", Type: ebpf.XDP, License: "GPL",
			Instructions: asm.Instructions{btf.WithFuncMetadata(asm.Return(), fn)}}
		prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction})
		if err == nil {
			_ = prog.Close()
			t.Fatal("the verifier accepted a program that never writes R0")
		}
		var verr *ebpf.VerifierError
		if !errors.Is(err, unix.EACCES) || !errors.As(err, &verr) || !strings.Contains(strings.Join(verr.Log, "\n"), "R0 !read_ok") {
			t.Fatalf("load error %v, want EACCES with the verifier's log", err)
		}
		return
	}
	t.Setenv("SYSCALLHOOK_VERIFIER_CHILD", "1")
	child := []string{os.Args[0], "-test.run=^TestIntegrationVerifierRefused$"}
	if out, err := exec.Command(child[0], child[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("baseline loader: %v\n%s", err, out)
	}
	out, err := os.Create(filepath.Join(t.TempDir(), "loader.out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	var logs bytes.Buffer
	var refusals []Refusal
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	code, err := Run(ctx, child, Options{Rules: []Rule{testRule()}, Stdout: out, Stderr: out, Log: &logs,
		OnRefuse: func(r Refusal) { refusals = append(refusals, r) }})
	data, _ := os.ReadFile(out.Name())
	t.Logf("supervisor:\n%sloader:\n%s", &logs, data)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if len(refusals) != 1 || refusals[0].Cause != "verifier" || refusals[0].Outcome != "original_refused" {
		t.Fatalf("refusals %+v, want one with cause verifier and outcome original_refused", refusals)
	}
}
