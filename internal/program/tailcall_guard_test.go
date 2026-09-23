package program

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

// TestBpfGatedRefusesTailCallTarget pins the guard that keeps a gated
// capture away from the Linux 7.0 second-attach failure: a target that
// holds a PROG_ARRAY is refused up front, a plain one is not. On
// kernels below 7.0 both are allowed, so the refusal is only asserted
// where the kernel actually rejects the second attach.
func TestBpfGatedRefusesTailCallTarget(t *testing.T) {
	plain := loadDummyXDP(t)
	tailer, _ := loadTailCallXDP(t)
	stages := []Stage{{Expr: ""}, {IsFexit: true, Expr: ""}}

	probe, err := LoadMultiPoint([]attach.Target{{Program: plain, FuncName: xdpFuncName, Type: ebpf.XDP}},
		stages, nil, true, nil, EmitBoth)
	if err != nil {
		t.Fatalf("gated capture on a plain target: %v", err)
	}
	_ = probe.Close()

	_, err = LoadMultiPoint([]attach.Target{{Program: tailer, FuncName: tailCallFuncName, Type: ebpf.XDP}},
		stages, nil, true, nil, EmitBoth)
	switch {
	case kernelAtLeast(tailCallGuardMinMajor, 0):
		if err == nil || !strings.Contains(err.Error(), "performs tail calls") {
			t.Fatalf("gated capture on a tail-calling target: err = %v, want the tail-call refusal", err)
		}
	case err != nil:
		t.Fatalf("kernel below %d.0 should still allow it: %v", tailCallGuardMinMajor, err)
	}
}

// TestKernelAtLeast checks the comparison, not this machine's version.
func TestKernelAtLeast(t *testing.T) {
	if !kernelAtLeast(1, 0) {
		t.Error("kernelAtLeast(1, 0) = false, want true on any Linux")
	}
	if kernelAtLeast(99, 0) {
		t.Error("kernelAtLeast(99, 0) = true, want false")
	}
}
