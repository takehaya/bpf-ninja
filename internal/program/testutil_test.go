package program

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

const xdpFuncName = "xdp_pass_test"

const xdpPassSource = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("xdp")
int xdp_pass_test(struct xdp_md *ctx) { return 2; }
char _license[] SEC("license") = "GPL";
`

const xdpSubfuncName = "process_packet"

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

// compileXDPObjFromSource compiles a BPF C source string to an object file with BTF.
// Skips the test if clang is not available.
func compileXDPObjFromSource(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "xdp.c")
	objFile := filepath.Join(dir, "xdp.o")
	os.WriteFile(srcFile, []byte(source), 0644)

	out, err := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-c", srcFile, "-o", objFile).CombinedOutput()
	if err != nil {
		t.Skipf("clang not available: %v\n%s", err, out)
	}
	return objFile
}

// compileXDPObj compiles the dummy XDP program with BTF.
func compileXDPObj(t *testing.T) string {
	t.Helper()
	return compileXDPObjFromSource(t, xdpPassSource)
}

// loadDummyXDP compiles and loads a minimal XDP_PASS program with BTF.
func loadDummyXDP(t *testing.T) *ebpf.Program {
	t.Helper()
	skipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(compileXDPObj(t))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_pass_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading XDP program: %v", err)
	}
	t.Cleanup(func() { objs.Prog.Close() })
	return objs.Prog
}

// loadDummyXDPWithSubfunc compiles and loads an XDP program with a __noinline subfunction.
// Returns the loaded program (entry = "xdp_subfunc_test", subfunction = "process_packet").
func loadDummyXDPWithSubfunc(t *testing.T) *ebpf.Program {
	t.Helper()
	skipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(compileXDPObjFromSource(t, xdpSubfuncSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_subfunc_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading XDP program: %v", err)
	}
	t.Cleanup(func() { objs.Prog.Close() })
	return objs.Prog
}

// loadProbeOrFail loads a probe and fails with verifier output on error.
func loadProbeOrFail(t *testing.T, xdpProg *ebpf.Program, funcName, filterExpr string, exit bool) *Probe {
	t.Helper()
	var probe *Probe
	var err error
	if exit {
		probe, err = LoadExit(xdpProg, funcName, filterExpr)
	} else {
		probe, err = LoadEntry(xdpProg, funcName, filterExpr)
	}
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error:\n%+v", ve)
		}
		t.Fatalf("loading probe: %v", err)
	}
	t.Cleanup(func() { probe.Close() })
	return probe
}
