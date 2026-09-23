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

	guarded, err := LoadMultiPoint([]attach.Target{{Program: tailer, FuncName: tailCallFuncName, Type: ebpf.XDP}},
		stages, nil, true, nil, EmitBoth)
	if guarded != nil {
		t.Cleanup(func() { _ = guarded.Close() })
	}
	switch {
	case kernelHasTailCallAttachBug():
		if err == nil || !strings.Contains(err.Error(), "tail call") {
			t.Fatalf("gated capture on a tail-calling target: err = %v, want the tail-call refusal", err)
		}
	case err != nil:
		t.Fatalf("a kernel outside the CVE-2026-92485 window should still allow it: %v", err)
	}
}

// TestKernelVersion checks the release parses at all; the value is
// whatever this machine runs.
func TestKernelVersion(t *testing.T) {
	major, minor, _, ok := kernelVersion()
	if !ok || major < 4 {
		t.Fatalf("kernelVersion() = %d.%d, ok=%v; want a parsed Linux release", major, minor, ok)
	}
}

// TestLeadingInt pins the release-component parsing the guard relies
// on: a suffix straight after the number must still compare, since a
// release like 7.2-rc2 would otherwise disable the guard on an
// affected kernel.
func TestLeadingInt(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"7", 7, true},
		{"2-rc2", 2, true},
		{"0-btf-fixed+", 0, true},
		{"18", 18, true},
		{"rc2", 0, false},
		{"", 0, false},
	} {
		got, ok := leadingInt(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("leadingInt(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestTailCallAttachBugWindow pins the CVE-2026-92485 range the guard
// refuses in: 7.0 up to the 7.2.6 / 7.3-rc1 fix, with anything it
// cannot parse counted as affected.
func TestTailCallAttachBugWindow(t *testing.T) {
	for _, tc := range []struct {
		major, minor, patch int
		ok                  bool
		want                bool
	}{
		{6, 18, 0, true, false},
		{6, 6, 2, true, false},
		{7, 0, 0, true, true},
		{7, 1, 9, true, true},
		{7, 2, 0, true, true}, // 7.2.0-rc2, the host that panicked
		{7, 2, 5, true, true},
		{7, 2, 6, true, false},
		{7, 3, 0, true, false},
		{8, 0, 0, true, false},
		{0, 0, 0, false, true}, // unparsable reads as affected
	} {
		if got := tailCallAttachBugIn(tc.major, tc.minor, tc.patch, tc.ok); got != tc.want {
			t.Errorf("tailCallAttachBugIn(%d, %d, %d, %v) = %v, want %v",
				tc.major, tc.minor, tc.patch, tc.ok, got, tc.want)
		}
	}
}
