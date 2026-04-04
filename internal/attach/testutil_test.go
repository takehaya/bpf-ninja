package attach

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// xdpSubfuncSource has a __noinline subfunction that accesses ctx.
// The body must be non-trivial; otherwise clang -O2 constant-folds
// the call away and no bpf2bpf call survives in the bytecode.
const xdpSubfuncSource = `
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

func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
}

// loadTestXDP compiles and loads an XDP program with a __noinline subfunction.
func loadTestXDP(t *testing.T) *ebpf.Program {
	t.Helper()
	skipIfNotRoot(t)

	dir := t.TempDir()
	srcFile := filepath.Join(dir, "xdp.c")
	objFile := filepath.Join(dir, "xdp.o")
	if err := os.WriteFile(srcFile, []byte(xdpSubfuncSource), 0644); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	out, err := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-c", srcFile, "-o", objFile).CombinedOutput()
	if err != nil {
		t.Skipf("clang not available: %v\n%s", err, out)
	}

	spec, err := ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_subfunc_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading XDP program: %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })
	return objs.Prog
}
