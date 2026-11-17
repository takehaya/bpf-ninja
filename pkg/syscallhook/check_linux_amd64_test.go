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
	audit := offloadAudit(nil)
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
	audit := offloadAudit(nil)
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
	audit := offloadAudit(nil)
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
		// ENOSPC on the loader's log: one trial with a log of the supervisor's own.
		{"enospc-with-log", loadFailure{err: logFull, loaderLog: true}, false, autoRule, 0, stepLogTrial, "", ""},
		{"log-trial-passed", loadFailure{err: logFull, loaderLog: true, logTried: true, logPassed: true}, false, autoRule, -int64(unix.ENOSPC), stepOriginal, "loader_log", "original_refused"},
		{"log-trial-passed-original-loads", loadFailure{err: logFull, loaderLog: true, logTried: true, logPassed: true}, false, mapRule, 5, stepOriginal, "loader_log", "original_loaded"},
		{"log-trial-passed-fail-closed", loadFailure{err: logFull, loaderLog: true, logTried: true, logPassed: true}, true, autoRule, -int64(unix.EPERM), stepRefuse, "loader_log", "load_refused"},
		{"log-trial-refused-retries", loadFailure{err: refused, loaderLog: true, logTried: true}, false, autoRule, 0, stepRetry, "", ""},
		{"log-trial-enospc-retries", loadFailure{err: logFull, loaderLog: true, logTried: true}, false, autoRule, 0, stepRetry, "", ""},
		{"log-trial-error", loadFailure{err: fmt.Errorf("tracee extended BTF load: %w", unix.ENOMEM), loaderLog: true, logTried: true}, false, autoRule, 5, stepOriginal, "transform", "original_loaded"},
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
		if step == stepOriginal || step == stepRefuse {
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

// Every error the stack audit can return is classified in one place: only an
// audit the kernel cannot give refuses the load under a map rule; a trial the
// verifier refused and every error of the analysis load the original.
func TestStackErrorClass(t *testing.T) {
	analysisErr := func(err error) error {
		t.Helper()
		if err == nil {
			t.Fatal("the analysis step returned no error")
		}
		return err
	}
	raw := deadRegisterProgram(t, asm.R1)
	_, noDepth := stackDepths("processed 3 insns (limit 1000000)")
	_, depthCount := frameFloors([]int{8, 8}, []string{"p"}, raw, inject.KernelInfo{Major: 7})
	_, ambiguous := frameFloors([]int{8, 8}, []string{"p", "p"}, raw, inject.KernelInfo{Major: 7})
	_, badDepth := frameFloors([]int{600}, []string{"p"}, raw, inject.KernelInfo{Major: 7})
	_, absent := frameFloors([]int{8}, []string{"q"}, raw, inject.KernelInfo{Major: 7})
	offload := make([]byte, 128)
	put32(offload, 64, 3)
	const refusedStats = "verification time 6 usec\nstack depth 0\nprocessed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n"
	refusedLog := "0: R1=ctx() R10=fp0\n0: (95) exit\nR0 !read_ok\n" + refusedStats
	mapRule := Rule{Program: "p", HookPrefix: "h", Map: "m"}
	for _, tc := range []struct {
		name     string
		stackErr error
		step     loadStep
		cause    string
	}{
		{"offload", offloadAudit(offload), stepRefuse, "stack"},
		{"short-attr", offloadAudit(make([]byte, 64)), stepRefuse, "stack"},
		{"trial-enomem", trialLoadError(unix.ENOMEM, ""), stepRefuse, "stack"},
		{"func-info", fmt.Errorf("%w: %w", errAuditUnavailable, unix.EFAULT), stepRefuse, "stack"},
		{"trial-verifier", trialLoadError(unix.EACCES, "R0 !read_ok"), stepOriginal, "verifier"},
		// The kernel prints the statistics after a refused check as well.
		{"trial-verifier-stats", trialLoadError(unix.EACCES, refusedLog), stepOriginal, "verifier"},
		{"trial-einval-stats", trialLoadError(unix.EINVAL, "func#0 @0\n"+refusedStats), stepOriginal, "verifier"},
		// Refused before the verifier ran (a device that is gone): the original loads.
		{"trial-einval-no-log", trialLoadError(unix.EINVAL, ""), stepOriginal, "verifier"},
		// The check passed and the load failed later.
		{"trial-einval-stats-only", trialLoadError(unix.EINVAL, refusedStats), stepRefuse, "stack"},
		{"trial-eperm-log", trialLoadError(unix.EPERM, refusedLog), stepRefuse, "stack"},
		{"no-depth-line", analysisErr(noDepth), stepOriginal, "analysis"},
		{"depth-count", analysisErr(depthCount), stepOriginal, "analysis"},
		{"ambiguous-name", analysisErr(ambiguous), stepOriginal, "analysis"},
		{"bad-depth", analysisErr(badDepth), stepOriginal, "analysis"},
		{"absent-function", analysisErr(absent), stepOriginal, "analysis"},
		{"refused", deadRegisterStackErr(t), stepOriginal, "analysis"},
		{"panic", guard("parsing verifier stats", func() error { panic("boom") }), stepOriginal, "analysis"},
		{"indirect-jump", fmt.Errorf("%w at instruction 3 is unsupported", errIndirectJump), stepOriginal, "analysis"},
		{"reading-log", fmt.Errorf("reading verifier stats: %w", unix.ESRCH), stepOriginal, "analysis"},
	} {
		step, cause := failedLoad(loadFailure{err: fmt.Errorf("stack depth unavailable: %w", tc.stackErr), stackErr: tc.stackErr}, false, mapRule)
		if step != tc.step || cause != tc.cause {
			t.Errorf("%s (%v): step %d cause %q, want step %d cause %q", tc.name, tc.stackErr, step, cause, tc.step, tc.cause)
		}
	}
}

// A trial keeps the loader's device binding: statsLog changes only the log
// fields of a cloned attr, and preloadDepths refuses an offload request
// before it touches the tracee, but not a device-bound load.
func TestTrialKeepsDevice(t *testing.T) {
	attr := make([]byte, progAttrSize)
	put32(attr, 44, devBoundOnly)
	put32(attr, 64, 3)
	put32(attr, 24, 1)
	trial := statsLog(bytes.Clone(attr), 64<<10, 0x1000)
	if u32(trial, 44) != devBoundOnly || u32(trial, 64) != 3 || u32(trial, 24) != 4 || u32(trial, 28) != 64<<10 || u64(trial, 32) != 0x1000 {
		t.Fatalf("trial attr flags %#x ifindex %d log %d/%d/%#x", u32(trial, 44), u32(trial, 64), u32(trial, 24), u32(trial, 28), u64(trial, 32))
	}
	if u32(attr, 24) != 1 {
		t.Fatal("statsLog changed the loader's attr")
	}
	offload := make([]byte, progAttrSize)
	put32(offload, 64, 3)
	if _, err := (&supervisor{}).preloadDepths(nil, offload, 0); !errors.Is(err, errAuditUnavailable) || !strings.Contains(err.Error(), "offloaded programs do not expose") {
		t.Fatalf("offload request: %v", err)
	}
	if err := offloadAudit(attr); err != nil {
		t.Fatalf("device-bound load: %v", err)
	}
}
