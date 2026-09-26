// Package testutil provides shared test helpers for BPF/XDP integration tests.
package testutil

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// SkipIfNotRoot skips the test if not running as root.
func SkipIfNotRoot(t testing.TB) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
}

// CompileBPFSource compiles a BPF C source string to an object file with BTF.
// Missing clang is optional locally, but a failure in CI. Compilation failures
// are always test failures, including an installed compiler without BPF support.
func CompileBPFSource(t testing.TB, source string) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) && os.Getenv("CI") != "true" && os.Getenv("CI") != "1" {
			t.Skipf("clang not installed: %v", err)
		}
		t.Fatalf("finding required clang: %v", err)
	}
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "xdp.c")
	objFile := filepath.Join(dir, "xdp.o")
	if err := os.WriteFile(srcFile, []byte(source), 0644); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	out, err := exec.Command(clang, "-O2", "-g", "-target", "bpf", "-c", srcFile, "-o", objFile).CombinedOutput()
	if err != nil {
		t.Fatalf("compiling BPF source: %v\n%s", err, out)
	}
	return objFile
}

// XDPSubfuncSource is a BPF C program with a __noinline subfunction that accesses ctx.
// The body must be non-trivial; otherwise clang -O2 constant-folds
// the call away and no bpf2bpf call survives in the bytecode.
const XDPSubfuncSource = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

__attribute__((noinline))
int process_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return 1;
    return 2;
}

SEC("xdp")
int xdp_subfunc_test(struct xdp_md *ctx) { return process_packet(ctx); }
char _license[] SEC("license") = "GPL";
`
