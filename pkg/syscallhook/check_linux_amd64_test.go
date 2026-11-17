//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
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
		{fmt.Errorf("stack depth unavailable: %w", fmt.Errorf("%w: x", errTrialVerifier)), fmt.Errorf("%w: x", errTrialVerifier), false, "verifier"},
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
	// The outcome is what happened to the load.
	for _, tc := range []struct {
		refused bool
		ret     int64
		want    string
	}{
		{true, -int64(unix.EPERM), "load_refused"},
		{false, 5, "original_loaded"},
		{false, -int64(unix.EACCES), "original_refused"},
	} {
		if got := refusalOutcome(tc.refused, tc.ret); got != tc.want {
			t.Errorf("refusalOutcome(%v, %d) = %q, want %q", tc.refused, tc.ret, got, tc.want)
		}
	}
	if _, err := loadCheckPolicy(fmt.Errorf("bad"), false); !errors.As(err, &checkerRejection{}) {
		t.Fatalf("loadCheckPolicy: %v", err)
	}
}

// The loader asks for a verifier log with log_level 1 or 2; stats alone
// (BPF_LOG_STATS) do not count.
func TestLoaderLog(t *testing.T) {
	attr := make([]byte, 128)
	for level, want := range map[uint32]bool{0: false, 1: true, 2: true, 3: true, 4: false, 5: true} {
		put32(attr, 24, level)
		if got := loaderLog(attr); got != want {
			t.Errorf("log_level %d: loaderLog = %v, want %v", level, got, want)
		}
	}
	if loaderLog(attr[:24]) {
		t.Error("short attr")
	}
}

// failedLoad is the whole decision for a matched load whose rewrite did not
// load: retry, original or refuse, with the cause, and the outcome once the
// original load returned.
func TestFailedLoad(t *testing.T) {
	audit := fmt.Errorf("offloaded programs do not expose local verifier stack accounting")
	analysis := deadRegisterStackErr(t)
	panicked := guard("parsing verifier stats", func() error { panic("boom") })
	verifier := fmt.Errorf("%w: x", errTrialVerifier)
	refused := refusedLoad{error: fmt.Errorf("transformed PROG_LOAD: %w", unix.EACCES)}
	logFull := refusedLoad{error: fmt.Errorf("transformed PROG_LOAD: %w", unix.ENOSPC)}
	retryFailed := fmt.Errorf("%w; %w", refused, errNothingLoads)
	stackFailed := func(err error) error { return fmt.Errorf("stack depth unavailable: %w", err) }
	mapRule, autoRule := Rule{Program: "p", HookPrefix: "h", Map: "m"}, Rule{Program: "p", HookPrefix: "h", Auto: true}
	for _, tc := range []struct {
		name       string
		f          loadFailure
		failClosed bool
		rule       Rule
		ret        int64 // what the original load returned, when it ran
		step       loadStep
		cause      string
		outcome    string
	}{
		{"refused-retries", loadFailure{err: refused}, false, autoRule, 0, stepRetry, "", ""},
		{"refused-retries-fail-closed", loadFailure{err: refused}, true, mapRule, 0, stepRetry, "", ""},
		{"enospc-without-log-retries", loadFailure{err: logFull}, false, autoRule, 0, stepRetry, "", ""},
		{"enospc-with-log", loadFailure{err: logFull, loaderLog: true}, false, autoRule, 5, stepOriginal, "transform", "original_loaded"},
		{"eacces-with-log-retries", loadFailure{err: refused, loaderLog: true}, false, autoRule, 0, stepRetry, "", ""},
		{"retry-failed", loadFailure{err: retryFailed, retried: true}, false, autoRule, 5, stepOriginal, "retry", "original_loaded"},
		{"retry-failed-fail-closed", loadFailure{err: retryFailed, retried: true}, true, autoRule, -int64(unix.EPERM), stepRefuse, "retry", "load_refused"},
		{"retry-failed-original-refused", loadFailure{err: retryFailed, retried: true}, false, autoRule, -int64(unix.EACCES), stepOriginal, "retry", "original_refused"},
		{"transform", loadFailure{err: fmt.Errorf("%w: no lookup", inject.ErrRefused)}, false, mapRule, 5, stepOriginal, "transform", "original_loaded"},
		{"transform-panic", loadFailure{err: fmt.Errorf("rewriting the load: %w: boom", errAnalysisPanic)}, false, mapRule, 5, stepOriginal, "transform", "original_loaded"},
		{"checker", loadFailure{err: checkerRejection{fmt.Errorf("checker rejected [x]: y")}}, false, autoRule, 5, stepOriginal, "checker", "original_loaded"},
		{"sites", loadFailure{err: sitesRefusal{fmt.Errorf("rule sites: pc 3 names no site")}}, true, autoRule, -int64(unix.EPERM), stepRefuse, "sites", "load_refused"},
		{"stack-map", loadFailure{err: stackFailed(audit), stackErr: audit}, false, mapRule, -int64(unix.EPERM), stepRefuse, "stack", "load_refused"},
		{"stack-auto", loadFailure{err: stackFailed(audit), stackErr: audit}, false, autoRule, 5, stepOriginal, "stack", "original_loaded"},
		{"analysis-map", loadFailure{err: stackFailed(analysis), stackErr: analysis}, false, mapRule, 5, stepOriginal, "analysis", "original_loaded"},
		{"analysis-panic-map", loadFailure{err: stackFailed(panicked), stackErr: panicked}, false, mapRule, 5, stepOriginal, "analysis", "original_loaded"},
		{"analysis-map-fail-closed", loadFailure{err: stackFailed(analysis), stackErr: analysis}, true, mapRule, -int64(unix.EPERM), stepRefuse, "analysis", "load_refused"},
		{"verifier-map", loadFailure{err: stackFailed(verifier), stackErr: verifier}, false, mapRule, -int64(unix.EACCES), stepOriginal, "verifier", "original_refused"},
		// A stack error is never retried: there is no rewrite.
		{"stack-refused-no-retry", loadFailure{err: refused, stackErr: audit}, false, autoRule, 5, stepOriginal, "stack", "original_loaded"},
	} {
		step, cause := failedLoad(tc.f, tc.failClosed, tc.rule)
		outcome := ""
		if step != stepRetry {
			outcome = refusalOutcome(step == stepRefuse, tc.ret)
		}
		if step != tc.step || cause != tc.cause || outcome != tc.outcome {
			t.Errorf("%s: step %d cause %q outcome %q, want step %d cause %q outcome %q", tc.name, step, cause, outcome, tc.step, tc.cause, tc.outcome)
		}
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

// A matched load left to run unchanged is reported at its exit stop with
// what the kernel returned; with --fail-closed it is refused at once.
func TestSkipMatched(t *testing.T) {
	var logs bytes.Buffer
	var got []Refusal
	s := &supervisor{options: Options{Log: &logs, OnRefuse: func(r Refusal) { got = append(got, r) }}}
	th := &thread{}
	regs := unix.PtraceRegs{Rdi: unix.BPF_PROG_LOAD}
	refusal := Refusal{Program: "p", Reason: "ambiguous program selectors", Cause: "selector"}
	if err := s.skipMatched(1, th, regs, refusal); err != nil || len(got) != 0 || th.refusal == nil {
		t.Fatalf("entry: err %v, reported %+v, pending %+v", err, got, th.refusal)
	}
	errno := unix.EACCES
	regs.Rax = uint64(-int64(errno))
	if err := s.exit(1, th, regs); err != nil || th.refusal != nil {
		t.Fatalf("exit: err %v, pending %+v", err, th.refusal)
	}
	want := refusal
	want.Outcome = "original_refused"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("reported %+v, want %+v", got, want)
	}
	if !strings.Contains(logs.String(), "injection skipped: ambiguous program selectors") {
		t.Fatalf("log %q", logs.String())
	}
}
