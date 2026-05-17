package program

import (
	"testing"

	"github.com/cilium/ebpf"
)

// Verifier-load coverage for the paper's canonical F1-F10 (E4 / Table 2).
// Each filter is compiled and loaded against both attach hosts (XDP and
// tc clsact); the kernel BPF verifier rejecting any filter on any host
// fails the corresponding subtest. Subtest names are Fn so that CI logs
// line up directly with the FilterSet IDs used in
// docs/paper/filter-set.md and paper/sections/06_evaluation.tex.
//
// These tests need root + a recent kernel and are skipped under plain
// `go test`. CI runs them through vimto on the 4-kernel matrix
// configured in .github/workflows/bpf_load_test.yaml; locally a single
// kernel is exercised via `make test-bpf`.

func TestBpfFilterSetXDP(t *testing.T) {
	runFilterSetMatrix(t, loadDummyXDP(t), xdpFuncName)
}

func TestBpfFilterSetTC(t *testing.T) {
	runFilterSetMatrix(t, loadDummyTC(t), tcFuncName)
}

func runFilterSetMatrix(t *testing.T, hostProg *ebpf.Program, funcName string) {
	t.Helper()
	for _, fs := range FilterSet {
		t.Run(fs.ID, func(t *testing.T) {
			loadProbeOrFail(t, hostProg, funcName, fs.Expr, false /*exit*/, true /*useDSL*/)
		})
	}
}
