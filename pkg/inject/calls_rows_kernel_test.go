package inject

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// loadWithDepth loads spec, closes it at cleanup and returns the verifier's
// stack depth of its first function.
func loadWithDepth(t *testing.T, spec *ebpf.CollectionSpec) (*ebpf.Collection, int) {
	t.Helper()
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats, LogSizeStart: 64 << 10},
	})
	if err != nil {
		t.Fatalf("load: %+v", err)
	}
	t.Cleanup(coll.Close)
	depths, err := ParseStackDepths(coll.Programs["p"].VerifierLog)
	if err != nil {
		t.Fatal(err)
	}
	return coll, depths[0]
}

// textDepth is the deepest direct stack access of function p in spec.
func textDepth(t *testing.T, spec *ebpf.CollectionSpec) int {
	t.Helper()
	insns := spec.Programs["p"].Instructions
	ranges, err := instructionFunctions(insns)
	if err != nil {
		t.Fatal(err)
	}
	depth, _ := stackFrameDepthExact(insns[ranges[0].start:ranges[0].end], 0)
	return depth
}

// E3: a hook at bpf_get_smp_processor_id between its fastcall spill and fill
// loads and sees the CPU the program stores, the filled R1 is unchanged, and
// the frame floor taken from the trial load covers the spill even where the
// kernel removed it. The hooked p's verifier depth is its text depth: the
// hook breaks the pattern, so nothing is removed after rewriting.
func TestBpfCallHookRowSmpProcessorID(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain, plainDepth := loadWithDepth(t, fastcallFixture())
	report, err := FrameFloors([]int{plainDepth}, []string{"p"}, fastcallFixture().Programs["p"].Instructions, KernelInfo{})
	if err != nil {
		t.Fatal(err)
	}
	spec := fastcallFixture()
	req := callReq("bpf_get_smp_processor_id")
	req.Stack = StackAudit{Frames: report.Frames(), Source: "verifier"}
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	coll, hookedDepth := loadWithDepth(t, spec)
	obs := attachArgObserver(t, plan.hooks[0].Name, coll.Programs["p"], false, false)
	text := textDepth(t, spec)
	t.Logf("plain verifier depth %d, tool floor %d, hooked verifier depth %d, hooked text depth %d", plainDepth, -report.Functions[0].Floor, hookedDepth, text)
	if -int(report.Functions[0].Floor) < 8 {
		t.Fatalf("tool floor %d does not cover the spill at fp-8", report.Functions[0].Floor)
	}
	if hookedDepth != text {
		t.Fatalf("hooked verifier depth %d, text depth %d", hookedDepth, text)
	}
	for run := 1; run <= 3; run++ {
		pret, pout := runCallFixture(t, plain, make([]byte, 64), nil)
		ret, out := runCallFixture(t, coll, make([]byte, 64), nil)
		if pret != 2 || ret != 2 || pout[1] != 7 || out[1] != 7 {
			t.Fatalf("run %d: actions %d %d, filled R1 %d %d", run, pret, ret, pout[1], out[1])
		}
		got := lastCall(t, obs, run)
		if got[0] != uint64(plan.hooks[0].Sites[0].SitePC) || got[1] != out[0] {
			t.Fatalf("run %d: hook site %d ret %d, want %d and %d", run, got[0], got[1], plan.hooks[0].Sites[0].SitePC, out[0])
		}
	}
}
