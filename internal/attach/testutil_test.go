package attach

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// loadTestXDP compiles and loads an XDP program with a __noinline subfunction.
func loadTestXDP(t *testing.T) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, testutil.XDPSubfuncSource))
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
