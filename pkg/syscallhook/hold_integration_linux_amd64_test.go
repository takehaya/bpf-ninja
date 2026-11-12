//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// TestIntegrationInjectHold pins what a capture that confirms its observers
// from OnInject relies on: while the callback runs, the substituted program
// is loaded and can be opened by ID, but the loader's bpf() call has not
// returned, so the loader cannot run or install the program yet.
func TestIntegrationInjectHold(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	// The child is TestIntegrationLoader's loader. It prints its program ID
	// only after the load returned.
	t.Setenv("SYSCALLHOOK_INTEGRATION_CHILD", "hook")
	child := []string{os.Args[0], "-test.run=^TestIntegrationLoader$"}
	out, err := os.Create(filepath.Join(t.TempDir(), "loader.out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	loaderPrinted := func() bool {
		data, err := os.ReadFile(out.Name())
		if err != nil {
			t.Error(err)
		}
		return strings.Contains(string(data), "prog_id=")
	}
	const hold = 500 * time.Millisecond
	var calls int
	var id uint32
	var problems []string
	var logs bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	code, err := Run(ctx, child, Options{Rules: []Rule{testRule()}, FailClosed: true, Stdout: out, Stderr: out, Log: &logs,
		OnInject: func(inj Injection) {
			calls++
			id = inj.ProgID
			p, err := ebpf.NewProgramFromID(ebpf.ProgramID(inj.ProgID))
			if err != nil {
				problems = append(problems, fmt.Sprintf("the injected program cannot be opened by ID during OnInject: %v", err))
			} else {
				_ = p.Close()
			}
			for deadline := time.Now().Add(hold); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				if loaderPrinted() {
					problems = append(problems, "the loader's load returned while OnInject was running")
					return
				}
			}
		}})
	data, _ := os.ReadFile(out.Name())
	t.Logf("supervisor:\n%sloader:\n%s", &logs, data)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	if calls != 1 || id == 0 || !strings.Contains(string(data), fmt.Sprintf("prog_id=%d\n", id)) {
		t.Fatalf("OnInject calls=%d id=%d do not match the loader", calls, id)
	}
	if elapsed := time.Since(start); elapsed < hold {
		t.Fatalf("the run took %s, less than the %s OnInject held the load", elapsed, hold)
	}
}
