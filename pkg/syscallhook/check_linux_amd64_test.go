//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
	"golang.org/x/sys/unix"
)

func TestCheckLoadRejectsTamperedStream(t *testing.T) {
	data, err := os.ReadFile("../../cmd/inject-check/testdata/pairs/fixture-1-static-any.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair injectcheck.Pair
	if err := json.Unmarshal(data, &pair); err != nil {
		t.Fatal(err)
	}
	encode := func(insns asm.Instructions) []byte {
		t.Helper()
		var buf bytes.Buffer
		if err := insns.Marshal(&buf, wire); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	original, err := asm.AppendInstructions(nil, bytes.NewReader(encode(asm.Instructions(pair.Original))), wire, "linux")
	if err != nil {
		t.Fatal(err)
	}
	stream := encode(asm.Instructions(pair.Transformed))
	verdict, err := checkLoad(original, stream, pair.Certificate, pair.Premises)
	if err != nil || !verdict.Accepted {
		t.Fatalf("baseline: %+v: %v", verdict, err)
	}

	decoded, err := asm.AppendInstructions(nil, bytes.NewReader(stream), wire, "linux")
	if err != nil {
		t.Fatal(err)
	}
	decoded[pair.Certificate.Hooks[0].Start] = asm.FnKtimeGetNs.Call()
	verdict, err = checkLoad(original, encode(decoded), pair.Certificate, pair.Premises)
	if err == nil || verdict.Accepted {
		t.Fatalf("tampered load was not rejected: %+v: %v", verdict, err)
	}
	for _, failClosed := range []bool{false, true} {
		retried := false
		ret, policyErr := retryOriginalOrRefuse(failClosed, func() (int64, error) {
			retried = true
			return 42, nil
		})
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		if failClosed && (retried || ret != -int64(unix.EPERM)) {
			t.Fatalf("fail-closed retried=%v ret=%d", retried, ret)
		}
		if !failClosed && (!retried || ret != 42) {
			t.Fatalf("default retried=%v ret=%d", retried, ret)
		}
	}
}

func TestCallxCheckPolicy(t *testing.T) {
	callx := asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call).SetSource(asm.RegSource), Src: asm.R3}
	_, notApplicable := inject.BuildLookupTargets(asm.Instructions{callx}, nil)
	if !errors.Is(notApplicable, inject.ErrCheckerNotApplicable) {
		t.Fatalf("callx was not classified: %v", notApplicable)
	}
	check, err := loadCheckPolicy(notApplicable, false)
	if check || err != nil {
		t.Fatalf("default did not proceed unchecked: check=%v err=%v", check, err)
	}
	check, err = loadCheckPolicy(notApplicable, true)
	if check || !errors.Is(err, inject.ErrCheckerNotApplicable) {
		t.Fatalf("fail-closed did not refuse: check=%v err=%v", check, err)
	}
}

// Only a rule that names its one site with map refuses a load whose stack
// audit is unavailable; a rule with calls, entry or tail_calls and no auto
// loads the original like an auto rule, and --fail-closed refuses every kind.
func TestRefuseOriginal(t *testing.T) {
	audit := fmt.Errorf("offloaded programs do not expose local verifier stack accounting")
	for _, tc := range []struct {
		name       string
		rule       Rule
		failClosed bool
		stackErr   error
		want       bool
	}{
		{"map", Rule{Map: "sessions"}, false, audit, true},
		{"map-audited", Rule{Map: "sessions"}, false, nil, false},
		{"map-trial-verifier", Rule{Map: "sessions"}, false, fmt.Errorf("%w: x", errTrialVerifier), false},
		{"map-indirect-jump", Rule{Map: "sessions"}, false, fmt.Errorf("%w at instruction 3", errIndirectJump), false},
		// A program the analysis refuses or panics on loads as the original:
		// no rewrite of it is possible, unlike an audit the kernel cannot give.
		{"map-analysis-refused", Rule{Map: "sessions"}, false, deadRegisterStackErr(t), false},
		{"map-analysis-panic", Rule{Map: "sessions"}, false, guard("parsing verifier stats", func() error { panic("boom") }), false},
		{"map-analysis-fail-closed", Rule{Map: "sessions"}, true, deadRegisterStackErr(t), true},
		{"auto", Rule{Auto: true}, false, audit, false},
		{"calls", Rule{HookPrefix: "h", Calls: []string{"bpf_xdp_metadata_rx_timestamp"}}, false, audit, false},
		{"entry", Rule{Hook: "h", Entry: true}, false, audit, false},
		{"tail-calls", Rule{Hook: "h", TailCalls: true}, false, audit, false},
		{"calls-fail-closed", Rule{HookPrefix: "h", Calls: []string{"bpf_ktime_get_ns"}}, true, audit, true},
		{"auto-fail-closed", Rule{Auto: true}, true, nil, true},
	} {
		if got := refuseOriginal(tc.failClosed, tc.rule, tc.stackErr); got != tc.want {
			t.Errorf("%s: refuseOriginal = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Every matched load that ends without hooks names what ended it.
func TestRefusalCause(t *testing.T) {
	audit := fmt.Errorf("offloaded programs do not expose local verifier stack accounting")
	refused := refusedLoad{error: fmt.Errorf("transformed PROG_LOAD: permission denied")}
	for _, tc := range []struct {
		err, stackErr error
		retried       bool
		want          string
	}{
		{sitesRefusal{fmt.Errorf("rule sites: pc 3 names no site of this program")}, nil, false, "sites"},
		{fmt.Errorf("stack depth unavailable: %w", audit), audit, false, "stack"},
		{fmt.Errorf("stack depth unavailable: %w", deadRegisterStackErr(t)), deadRegisterStackErr(t), false, "analysis"},
		{checkerRejection{fmt.Errorf("checker rejected [x]: y")}, nil, false, "checker"},
		{fmt.Errorf("%w; %w", refused, checkerRejection{fmt.Errorf("checker rejected the transform")}), nil, true, "checker"},
		{inject.ErrCheckerNotApplicable, nil, false, "checker"},
		{fmt.Errorf("%w; %w", refused, errNothingLoads), nil, true, "retry"},
		{fmt.Errorf("inject: refused: no call site is instrumented"), nil, false, "transform"},
		{fmt.Errorf("rewriting the load: %w: boom", errAnalysisPanic), nil, false, "transform"},
	} {
		if got := refusalCause(tc.err, tc.stackErr, tc.retried); got != tc.want {
			t.Errorf("%v: cause %q, want %q", tc.err, got, tc.want)
		}
	}
	if refusalOutcome(true) != "refused_fail_closed" || refusalOutcome(false) != "original_loaded" {
		t.Fatal("outcomes")
	}
	if _, err := loadCheckPolicy(fmt.Errorf("bad"), false); !errors.As(err, &checkerRejection{}) {
		t.Fatalf("loadCheckPolicy: %v", err)
	}
}

// A real load that failed with ENOSPC on the loader's own log is not
// retried; ENOSPC without a log request, or another errno, is.
func TestLoaderLogFull(t *testing.T) {
	attr := make([]byte, 128)
	refused := refusedLoad{error: fmt.Errorf("transformed PROG_LOAD: %w", unix.ENOSPC)}
	if loaderLogFull(refused, attr) {
		t.Fatal("no log requested")
	}
	put32(attr, 24, 1)
	if !loaderLogFull(refused, attr) || loaderLogFull(refusedLoad{error: fmt.Errorf("transformed PROG_LOAD: %w", unix.EACCES)}, attr) {
		t.Fatal("log level 1")
	}
	put32(attr, 24, 4) // BPF_LOG_STATS alone
	if loaderLogFull(refused, attr) {
		t.Fatal("stats only")
	}
}

// deadRegisterStackErr is the stack analysis's error for a program the kernel
// accepts with r13 in a pruned branch: the analysis refuses it.
func deadRegisterStackErr(t *testing.T) error {
	t.Helper()
	_, err := frameFloors([]int{8}, []string{"p"}, deadRegisterProgram(t, asm.Register(13)), inject.KernelInfo{Major: 7})
	if !errors.Is(err, inject.ErrRefused) {
		t.Fatalf("frameFloors on r13 = %v, want an ErrRefused", err)
	}
	return err
}
