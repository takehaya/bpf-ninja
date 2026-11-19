//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
	"golang.org/x/sys/unix"
)

// Options configures the launcher. Nil streams inherit the supervisor's streams.
// Run owns wait/ptrace on its locked OS thread; do not run other child waiters on
// that thread. Only the launched process and its threads are instrumented.
type Options struct {
	Rules                 []Rule
	FailClosed            bool
	Stdin, Stdout, Stderr *os.File
	Log                   io.Writer
	FrameRounding         int
	// preloadError is a test-only fault injection point. It is deliberately
	// unexported so callers cannot bypass verifier accounting.
	preloadError error
	// OnInject, if set, is called on the tracing thread for each load the
	// transformed program replaced, before the target sees the new fd. The
	// loading thread stays stopped until it returns, so the program is
	// loaded but the loader cannot run or install it yet
	// (TestIntegrationInjectHold). inject-run uses this to let captures
	// attach their observers first. Callbacks are serialized on this tracing
	// thread. Other target threads keep running until the supervisor handles
	// their next stop, then wait behind this callback. It must not wait on the target.
	OnInject func(Injection)
	// OnRefuse, if set, is called on the tracing thread for each load a rule
	// matched that ended without hooks (see Refusal), once the original program
	// was loaded in its place or, with FailClosed, the load was refused.
	OnRefuse func(Refusal)
	// OnDiscover, if set, is called on the tracing thread for every XDP, tc or
	// cgroup_skb program load whose attr carries BTF, whether or not a rule selects it,
	// before any transform. Rules may then be empty. It must not wait on the
	// target.
	OnDiscover func(Discovery)
	// EverySyscall stops the target at the entry and exit of every syscall.
	// Otherwise Run installs a seccomp filter in the target at its first
	// syscall, stops it only on program and BTF loads, and follows every child
	// process except one created with CLONE_UNTRACED. Run then returns when the
	// target and every followed process have exited, with the target's status;
	// cancelling ctx kills them all. Where the filter cannot
	// be installed, Run logs why and stops on every syscall. See
	// docs/en/inject-run.md for what each mode changes for the target.
	EverySyscall bool
	// stops counts ptrace stops, for tests.
	stops *int
	// leftThreads records thread-map keys when wait reports ECHILD, for tests.
	leftThreads *[]int
	// pidfdOpen is a test-only fault injection point.
	pidfdOpen func(int, int) (int, error)
	// loadFault is a test-only fault injection point: a rewritten program
	// the kernel loaded is refused when it returns an error for the hooks.
	loadFault func([]inject.LookupHook) error
}

// Discovery lists the lookups of one program load (see
// inject.DiscoverLookupsRaw), all its map calls with lookups among them
// (inject.DiscoverMapCallsRaw), and the kinds of the maps it references, by
// kernel map name. Program is the kernel program name and Func the entry
// function. CallSites lists every other helper and kernel-function call, with
// labels for every site and the listing fingerprint
// (inject.DiscoverCallSitesRaw); kernel functions are named only when the
// running kernel's BTF loaded.
type Discovery struct {
	Program, Func string
	Type          ebpf.ProgramType
	Lookups       []inject.LookupSite
	Calls         []inject.LookupSite
	Maps          map[string]ebpf.MapType
	Stack         inject.StackReport
	CallSites     inject.CallDiscovery
}

// Injection describes one successful injected load. Program is the kernel
// program name and Func the entry function. ProgID is the loaded program's
// kernel ID, zero if the tracee could not query it. Hooks and Skipped are
// the transform's (see inject.LookupResult). Build is the listing
// fingerprint of the original program and Labels its site labels by pc, as
// a listing of the same load gives them (inject.CallDiscovery); both are
// empty when the listing failed.
type Injection struct {
	HookForm      HookForm
	Program, Func string
	Type          ebpf.ProgramType
	ProgID        uint32
	Hooks         []inject.LookupHook
	Skipped       []inject.LookupSite
	Stack         inject.StackReport
	Build         string
	Labels        map[uint32]string
	Tag           string // the loaded program's kernel tag in hex, empty with ProgID zero
	// OutsidePremise names the denied callees the original program calls
	// (inject.PremiseCalls): the theorem is not claimed for this load.
	OutsidePremise []string
	// NotReviewed names the kernel functions the original program calls
	// that have no review record (inject.NotReviewed): the theorem is
	// claimed only for loads without them.
	NotReviewed []string
}

// Refusal is a matched load that ended without hooks; Reason is the message.
// Cause is what ended it: "sites" (the rule's sites refused the load),
// "stack" (the kernel cannot give the stack audit: errAuditUnavailable, or
// the tracee failed a request of the audit: errTracee),
// "analysis" (any other error of the stack analysis: see unanalysable),
// "verifier" (the verifier refused the trial load of the original program),
// "checker" (the load-time checker refused the rewrite), "retry" (the kernel
// refused the rewrite and the retry loaded none), "loader_log" (the rewrite
// passes with a log of its own, but not with the loader's log buffer: see
// failedLoad), "selector" (more than one rule matches the load) or
// "transform" (the load could not be rewritten). Outcome is what happened:
// "original_loaded", "original_refused" (the kernel refused the original
// program as well) or "load_refused" (the supervisor refused the load: with
// FailClosed, or for a map rule whose stack audit the kernel cannot give).
type Refusal struct {
	Program, Func, Reason string
	Cause, Outcome        string
}

// refusalCause is the Refusal.Cause of a matched load whose rewrite failed
// with err; stackErr is the stack audit's error and retried says whether the
// retry ran.
func refusalCause(err, stackErr error, retried bool) string {
	switch {
	case errors.As(err, &sitesRefusal{}):
		return "sites"
	case stackErr != nil && unanalysable(stackErr):
		return "analysis"
	case errors.Is(stackErr, errTrialVerifier):
		return "verifier"
	case stackErr != nil:
		return "stack"
	case errors.As(err, &checkerRejection{}) || errors.Is(err, inject.ErrCheckerNotApplicable):
		return "checker"
	case retried:
		return "retry"
	}
	return "transform"
}

// refusalOutcome is the Refusal.Outcome of a matched load that ended without
// hooks: refused says the supervisor refused it, ret is the kernel's return
// value for the original program otherwise.
func refusalOutcome(refused bool, ret int64) string {
	switch {
	case refused:
		return "load_refused"
	case ret < 0:
		return "original_refused"
	}
	return "original_loaded"
}

type rememberedBTF struct {
	blob []byte
	id   uint32
}
type thread struct {
	btf     []byte
	newborn bool
	// foreign marks a followed child process: it is only kept running.
	foreign bool
	// traceExit asks for the exit stop of the bpf call stopped at seccomp.
	traceExit bool
	// refusal is a matched load left to run unchanged at its entry stop; it
	// is reported at the exit stop, with the outcome the kernel gave.
	refusal *Refusal
}
type supervisor struct {
	probeUntrusted            func() error
	probeTailCallReachability func() error
	options                   Options
	btf                       map[uint32]rememberedBTF
	cacheBytes                int
	// filterPending waits for the first syscall-exit stop to install the filter.
	filterPending bool
	filtered      bool
	// kernel is the running kernel's BTF for rules with calls; nil without.
	kernel *btf.Spec
	// extra counts the extra verifications of the current load (see
	// trialBudget) before the retry.
	extra int
}

var errTrialVerifier = errors.New("trial load was rejected by the verifier")

// errAuditUnavailable marks a stack audit the kernel cannot give: the program
// is offloaded, the trial load failed with no verdict on the program, or the
// kernel did not return the loaded program's functions.
var errAuditUnavailable = errors.New("stack audit unavailable")

var errIndirectJump = errors.New("indirect jump")

// errTracee marks a failure on the traced process's side, in whatever step:
// its memory could not be allocated, read or written, or a query on one of
// its descriptors failed. A query the kernel answers with nothing usable is
// not one (see loadedFunctions). As for a trial that fails other than by the
// kernel's refusal in the retry, the original then loads under every rule,
// and only FailClosed refuses it (see refuseOriginal).
var errTracee = errors.New("tracee")

// traceeError marks err as a failure on the traced process's side
// (errTracee); nil stays nil.
func traceeError(err error) error {
	if err == nil || errors.Is(err, errTracee) {
		return err
	}
	return fmt.Errorf("%w: %w", errTracee, err)
}

// errAnalysisPanic marks a panic in the analysis of one load (see guard).
var errAnalysisPanic = errors.New("analysis of the load panicked")

// guard runs f, a step of the analysis of one load that issues no ptrace
// call, and turns a panic in it into an error, so that the load ends on the
// ordinary fallback path (the original loads, or --fail-closed refuses)
// instead of ending the supervisor.
func guard(what string, f func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%s: %w: %v", what, errAnalysisPanic, p)
		}
	}()
	return f()
}

// The analyses the guarded steps run; a test replaces each with a panic to
// pin its guard.
var (
	parseStackDepths    = inject.ParseStackDepths
	frameFloorsRaw      = inject.FrameFloorsRaw
	discoverMapCallsRaw = inject.DiscoverMapCallsRaw
	transformLookupRaw  = inject.TransformLookupRawGuarded
)

// errJumpLimit marks a rewritten load the verifier refused for too long a
// sequence of pending jumps.
var errJumpLimit = errors.New("verifier jump sequence limit")

func (s *supervisor) log(format string, args ...any) {
	_, _ = fmt.Fprintf(s.options.Log, "inject-run: "+format+"\n", args...)
}

// loadKernel sets s.kernel once, when there are rules or loads are listed:
// a listing, and the site labels and fingerprint of an injected load, name
// kfunc calls with it. Without kernel BTF the transform cannot name a kfunc
// call and skips every call site of a program that makes one; programs
// without kfunc calls are unaffected.
func (s *supervisor) loadKernel(load func() (*btf.Spec, error)) {
	if s.options.OnDiscover == nil && len(s.options.Rules) == 0 {
		return
	}
	spec, err := load()
	if err != nil {
		s.log("kernel BTF unavailable: kernel-function calls are not hooked: %v", err)
		return
	}
	s.kernel = spec
}

// moduleBTFs returns the module BTF, split on s.kernel, of each distinct
// nonzero offset of a kfunc call in insns, keyed by that offset: as in the
// verifier, the u32 at fdArray + 4*offset is a module BTF fd of the tracee.
// read reads tracee memory, info returns the fd's 32-byte bpf_btf_info and
// load opens a kernel BTF by id and gives its module's name, which homes
// keeps by the same offset. An offset that fails is left out and logged,
// so its calls stay unnamed and the load goes on. A BTF whose name load
// cannot read is kept with an empty home and logged: its calls are hooked
// and reported as not reviewed.
func (s *supervisor) moduleBTFs(insns asm.Instructions, fdArray uint64, read func(addr, size uint64) ([]byte, error),
	info func(fd uint32) ([]byte, error), load func(id btf.ID, base *btf.Spec) (*btf.Spec, string, error)) (modules map[int16]*btf.Spec, homes map[int16]string) {
	failed := map[int16]bool{}
	for i := range insns {
		off := insns[i].Offset
		if !insns[i].IsKfuncCall() || off == 0 || modules[off] != nil || failed[off] {
			continue
		}
		spec, home, err := func() (*btf.Spec, string, error) {
			if off < 0 || fdArray == 0 {
				return nil, "", fmt.Errorf("no fd_array entry")
			}
			fd, err := read(fdArray+4*uint64(off), 4)
			if err != nil {
				return nil, "", err
			}
			bi, err := info(u32(fd, 0))
			if err != nil {
				return nil, "", err
			}
			if u32(bi, 28) != 1 {
				return nil, "", fmt.Errorf("fd %d is not a kernel BTF", u32(fd, 0))
			}
			return load(btf.ID(u32(bi, 12)), s.kernel)
		}()
		if err != nil && spec == nil {
			failed[off] = true
			s.log("module BTF at fd_array offset %d unavailable: its kernel-function calls are not hooked: %v", off, err)
			continue
		}
		if err != nil {
			s.log("module BTF at fd_array offset %d has no name: its kernel-function calls are reported as not reviewed: %v", off, err)
		}
		if modules == nil {
			modules, homes = map[int16]*btf.Spec{}, map[int16]string{}
		}
		modules[off], homes[off] = spec, home
	}
	return modules, homes
}

// loadModuleBTF opens the kernel BTF id, split on base, and gives the name
// the kernel gives it: the module's. When only the name cannot be read it
// returns the BTF with an empty name and the error.
func loadModuleBTF(id btf.ID, base *btf.Spec) (*btf.Spec, string, error) {
	h, err := btf.NewHandleFromID(id)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = h.Close() }()
	spec, err := h.Spec(base)
	if err != nil {
		return nil, "", err
	}
	info, err := h.Info()
	if err != nil {
		return spec, "", fmt.Errorf("kernel BTF %d name: %w", id, err)
	}
	return spec, info.Name, nil
}

// loaderLog says whether the loader asked for a verifier log (log_level 1
// or 2) in attr. A real load then fails with ENOSPC when the log does not fit
// its buffer, whatever the verifier decided.
func loaderLog(attr []byte) bool {
	return len(attr) >= 28 && u32(attr, 24)&3 != 0
}

// loadStep is what happens next to a matched load whose rewrite did not load.
type loadStep int

const (
	stepOriginal loadStep = iota // the original program loads
	stepRefuse                   // the load is refused with EPERM
	stepRetry                    // the retry looks for a rewrite with fewer sites (retryLoad)
	stepLogTrial                 // the rewrite is tried once with a log of the supervisor's own
)

// loadFailure is a matched load whose rewrite did not load: err is why,
// stackErr the stack audit's error, loaderLog says that the loader asked for
// a verifier log (loaderLog) and retried that the retry ran. logTried says
// that the rewrite was tried with a log of the supervisor's own
// (stepLogTrial) and logPassed that this trial passed.
type loadFailure struct {
	err, stackErr                           error
	loaderLog, retried, logTried, logPassed bool
}

// failedLoad decides what happens to the load f describes: the retry, once,
// for a rewrite the kernel refused, else the original or, by refuseOriginal,
// a refusal. cause is the Refusal.Cause (refusalCause) of a load that ends
// without hooks. The kernel returns ENOSPC whenever the loader's log does
// not fit its buffer, also in place of the verifier's own refusal, so a
// rewrite refused with ENOSPC on the loader's log is first tried with a log
// of the supervisor's own: the retry runs on that trial's refusal, and when
// the trial passes the loader's log buffer is the problem (cause
// "loader_log"), for which no site is dropped.
func failedLoad(f loadFailure, failClosed bool, rule Rule) (step loadStep, cause string) {
	if f.stackErr == nil && !f.retried && !f.logPassed && errors.As(f.err, &refusedLoad{}) {
		if f.loaderLog && !f.logTried && errors.Is(f.err, unix.ENOSPC) {
			return stepLogTrial, ""
		}
		return stepRetry, ""
	}
	cause = refusalCause(f.err, f.stackErr, f.retried)
	if f.logPassed {
		cause = "loader_log"
	}
	if refuseOriginal(failClosed, rule, f.stackErr) {
		return stepRefuse, cause
	}
	return stepOriginal, cause
}

// refuseOriginal says whether a matched load whose rewrite did not load is
// refused instead of loading the original: always with failClosed, and when
// the kernel cannot give the stack audit (errAuditUnavailable) for a rule
// that names its one site with map, which must be hooked. A rule with calls,
// entry or tail_calls and no auto loads the original like an auto rule. A
// program the verifier refuses, or one the analysis cannot take
// (unanalysable), loads as the original under every rule.
func refuseOriginal(failClosed bool, rule Rule, stackErr error) bool {
	return failClosed || errors.Is(stackErr, errAuditUnavailable) && !rule.Auto && rule.Map != ""
}

// unanalysable says whether the stack audit failed in the analysis of the
// program rather than in the kernel: every error of preloadDepths but an
// audit the kernel cannot give (errAuditUnavailable), a trial the
// verifier refused (errTrialVerifier) and a failure of the tracee
// (errTracee). Among them are the analysis's own
// refusals (inject.ErrRefused and the plain errors of the stack-depth and
// frame-floor steps), a panic in it (errAnalysisPanic) and a trial load it
// cannot run (errIndirectJump). No rewrite of such a program is possible.
func unanalysable(stackErr error) bool {
	return stackErr != nil && !errors.Is(stackErr, errAuditUnavailable) && !errors.Is(stackErr, errTrialVerifier) && !errors.Is(stackErr, errTracee)
}

func retryOriginalOrRefuse(failClosed bool, retry func() (int64, error)) (int64, error) {
	if failClosed {
		return -int64(unix.EPERM), nil
	}
	return retry()
}

// Run starts argv under PTRACE_SEIZE (see seize) and returns the child's exit status (or
// 128+signal). A supervisor error terminates the tracee: resuming with uncertain
// registers is unsafe even in fail-open mode. No network attachments are made.
func Run(ctx context.Context, argv []string, opts Options) (int, error) {
	return run(ctx, argv, opts, probeGlobalUntrusted, probeTailCallReachability)
}

func run(ctx context.Context, argv []string, opts Options, probeUntrusted, probeTailCallReachability func() error) (int, error) {
	if len(argv) == 0 {
		return 0, fmt.Errorf("target command is required after --")
	}
	if opts.FrameRounding == 0 {
		opts.FrameRounding = 32
	}
	if len(opts.Rules) != 0 || opts.OnDiscover == nil {
		if err := Validate(opts.Rules); err != nil {
			return 0, err
		}
		opts.Rules = uniqueRules(opts.Rules)
	}
	if opts.Stdin == nil {
		opts.Stdin = os.Stdin
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Log == nil {
		opts.Log = opts.Stderr
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.Stdin, opts.Stdout, opts.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	defer func() { _ = cmd.Process.Release() }()
	// procs holds a pidfd for the target and for each followed child process,
	// which a cancel or a supervisor error kills. Unlike a pid, a pidfd never
	// reaches another process that reuses the number after a reap.
	var procsMu sync.Mutex
	procs := map[int]int{}
	pidfdOpen := opts.pidfdOpen
	if pidfdOpen == nil {
		pidfdOpen = unix.PidfdOpen
	}
	addProc := func(p int) error {
		procsMu.Lock()
		_, exists := procs[p]
		procsMu.Unlock()
		if exists {
			return nil
		}
		fd, err := pidfdOpen(p, 0)
		if err != nil {
			return err
		}
		procsMu.Lock()
		procs[p] = fd
		procsMu.Unlock()
		return nil
	}
	dropProc := func(p int) {
		procsMu.Lock()
		defer procsMu.Unlock()
		if fd, ok := procs[p]; ok {
			_ = unix.Close(fd)
			delete(procs, p)
		}
	}
	killAll := func() {
		procsMu.Lock()
		defer procsMu.Unlock()
		for _, fd := range procs {
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		}
	}
	defer func() {
		procsMu.Lock()
		defer procsMu.Unlock()
		for _, fd := range procs {
			_ = unix.Close(fd)
		}
	}()
	if err := addProc(pid); err != nil {
		_ = unix.Kill(pid, unix.SIGKILL)
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("pidfd_open (Linux >=5.3 required): %w", err)
	}
	done := make(chan struct{})
	cancelDone := make(chan struct{})
	defer func() {
		close(done)
		<-cancelDone
	}()
	go func() {
		defer close(cancelDone)
		select {
		case <-ctx.Done():
			killAll()
		case <-done:
		}
	}()
	threads := map[int]*thread{pid: {}}
	finished := false
	defer func() {
		if finished {
			return
		}
		killAll()
		for _, tracee := range tracedProcesses(unix.Gettid()) {
			threads[tracee] = &thread{}
			_ = unix.Kill(tracee, unix.SIGKILL)
		}
		// Reap any thread first: waiting for the leader before its dying siblings
		// can deadlock because Linux delays the leader's final wait notification.
		for len(threads) != 0 {
			var status unix.WaitStatus
			tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOTHREAD, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				break
			}
			if status.Exited() || status.Signaled() {
				delete(threads, tid)
				dropProc(tid)
				continue
			}
			if status.Stopped() {
				threads[tid] = &thread{}
				switch status.TrapCause() {
				case unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
					if child, err := unix.PtraceGetEventMsg(tid); err == nil {
						threads[int(child)] = &thread{}
					}
				}
				// A signal supplied to PTRACE_CONT is not delivered at an event stop.
				_ = unix.Kill(tid, unix.SIGKILL)
				_ = unix.PtraceCont(tid, 0)
			}
		}
	}()
	status, err := waitThread(pid)
	if err != nil {
		return 0, err
	}
	if !status.Stopped() {
		delete(threads, pid)
		dropProc(pid)
		return 0, fmt.Errorf("target did not stop at exec: %#x", uint32(status))
	}
	flags := unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_EXITKILL
	if err := seize(pid, flags); err != nil {
		return 0, err
	}
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		return 0, err
	}
	s := supervisor{probeUntrusted: sync.OnceValue(probeUntrusted), probeTailCallReachability: sync.OnceValue(probeTailCallReachability),
		options: opts, btf: make(map[uint32]rememberedBTF), filterPending: !opts.EverySyscall && !testEverySyscall}
	s.loadKernel(btf.LoadKernelSpec)
	exitCode := 0
	pending := map[int]struct{}{}
	recordLeftThreads := func() {
		if opts.leftThreads != nil {
			*opts.leftThreads = slices.Sorted(maps.Keys(threads))
		}
	}
	for {
		procsMu.Lock()
		haveProcs := len(procs) != 0
		procsMu.Unlock()
		waitFor := -1
		if !haveProcs {
			for waitFor = range pending {
				break
			}
			if waitFor == -1 {
				recordLeftThreads()
				break
			}
		}
		tid, err := unix.Wait4(waitFor, &status, unix.WALL|unix.WNOTHREAD, nil)
		if err == unix.EINTR {
			continue
		}
		if err == unix.ECHILD && waitFor != -1 {
			delete(pending, waitFor)
			continue
		}
		// No tracee is left. threads cannot tell: an entry can stay behind for a
		// thread reaped before its creator's clone event was handled, which adds
		// the tid again, and a tracee can be missing from it, such as the child
		// of a fork event that ended in ESRCH.
		if err == unix.ECHILD {
			recordLeftThreads()
			break
		}
		if err != nil {
			return 0, err
		}
		delete(pending, tid)
		if opts.stops != nil {
			*opts.stops++
		}
		t := threads[tid]
		if t == nil {
			t = &thread{newborn: true}
			threads[tid] = t
		}
		if status.Exited() || status.Signaled() {
			delete(threads, tid)
			// Only leaders have an entry in procs. Linux reports their exit only
			// after every other thread of the group has exited.
			dropProc(tid)
			if tid == pid {
				if status.Exited() {
					exitCode = status.ExitStatus()
				} else {
					exitCode = 128 + int(status.Signal())
				}
				// Followed child processes run on, traced, until they exit too.
				procsMu.Lock()
				left := slices.Sorted(maps.Keys(procs))
				procsMu.Unlock()
				if len(left) != 0 {
					s.log("target exited with status %d; waiting for %d child processes (PIDs %s); interrupt to kill them",
						exitCode, len(left), strings.Trim(fmt.Sprint(left), "[]"))
				}
			}
			continue
		}
		if !status.Stopped() {
			continue
		}
		sig := int(status.StopSignal())
		event := status.TrapCause()
		// PTRACE_EVENT_STOP comes with SIGTRAP for a newborn or an interrupt and
		// with the stop signal for a group stop, which only PTRACE_LISTEN keeps.
		stopEvent := uint32(status)>>16 == unix.PTRACE_EVENT_STOP
		listen := stopEvent && status.StopSignal() != unix.SIGTRAP
		switch {
		case event == unix.PTRACE_EVENT_CLONE || event == unix.PTRACE_EVENT_FORK || event == unix.PTRACE_EVENT_VFORK:
			child, err := unix.PtraceGetEventMsg(tid)
			if err == unix.ESRCH {
				continue
			}
			if err != nil {
				return 0, err
			}
			if threads[int(child)] == nil {
				threads[int(child)] = &thread{newborn: true}
				pending[int(child)] = struct{}{}
			}
			sig = 0
		case event == unix.PTRACE_EVENT_EXEC:
			sig = 0
			if t.foreign {
				// exec from a nonleader gives it the leader's tid; the old tid has
				// no exit to report.
				former, err := unix.PtraceGetEventMsg(tid)
				if err == unix.ESRCH {
					continue
				}
				if err != nil {
					return 0, err
				}
				if int(former) != tid {
					delete(threads, int(former))
				}
				break
			}
			// exec from a nonleader changes its tid to pid and destroys other threads.
			maps.DeleteFunc(threads, func(_ int, t *thread) bool { return !t.foreign })
			threads[pid] = &thread{}
			s.btf = make(map[uint32]rememberedBTF)
			s.cacheBytes = 0
		case event == unix.PTRACE_EVENT_SECCOMP:
			sig = 0
			regs, ok, err := s.seccompStop(tid, t)
			if err != nil {
				return 0, err
			}
			if !ok {
				continue
			}
			t.traceExit = (t.btf != nil || t.refusal != nil) && !t.foreign && regs.Orig_rax == unix.SYS_BPF
		case t.newborn && stopEvent:
			t.newborn = false
			// A new process: on the every-syscall path, only a clone without
			// CLONE_THREAD comes here (fork and vfork are not traced); it is detached
			// without changes. With the filter, every new process is followed.
			group, err := threadGroup(tid)
			if err != nil {
				_ = unix.PtraceCont(tid, int(unix.SIGKILL))
				return 0, fmt.Errorf("thread group of %d: %w", tid, err)
			}
			if group != pid {
				if !s.filtered {
					if err := unix.PtraceDetach(tid); err != nil {
						return 0, err
					}
					delete(threads, tid)
					continue
				}
				t.foreign = true
				if err := addProc(group); err != nil {
					_ = unix.Kill(group, unix.SIGKILL)
					return 0, fmt.Errorf("child process %d: pidfd_open: %w", group, err)
				}
				if ctx.Err() != nil {
					killAll()
				}
			}
			sig = 0
		case stopEvent:
			sig = 0
		case status.StopSignal() == unix.SIGTRAP|0x80:
			op, arch, err := syscallStop(tid)
			// exit_group in another thread can destroy a reported syscall stop.
			// Keep the tid until its final wait notification is reaped.
			if err == unix.ESRCH {
				continue
			}
			if err != nil {
				return 0, fmt.Errorf("PTRACE_GET_SYSCALL_INFO (Linux >=5.3 required): %w", err)
			}
			var regs unix.PtraceRegs
			if err := unix.PtraceGetRegs(tid, &regs); err != nil {
				if err == unix.ESRCH {
					continue
				}
				return 0, err
			}
			if arch == 0xc000003e && regs.Orig_rax == unix.SYS_BPF {
				switch op {
				case 1:
					err = s.entry(tid, t, regs)
				case 2:
					err = s.exit(tid, t, regs)
				}
				if err != nil {
					return 0, err
				}
			}
			t.traceExit = false
			if s.filterPending && op == 2 {
				if err := s.installFilter(tid, len(threads), arch, regs); err != nil {
					return 0, err
				}
			}
			sig = 0
		}
		resume := unix.PtraceSyscall
		if s.filtered && !t.traceExit {
			resume = unix.PtraceCont
		}
		if listen {
			resume = func(tid, _ int) error { return ptrace(unix.PTRACE_LISTEN, tid, 0) }
		}
		if err := resume(tid, sig); err != nil && err != unix.ESRCH {
			return 0, err
		}
	}
	finished = true
	if ctx.Err() != nil {
		return exitCode, ctx.Err()
	}
	return exitCode, nil
}

func tracedProcesses(tracer int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	want := fmt.Appendf(nil, "TracerPid:\t%d\n", tracer)
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil && bytes.Contains(status, want) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func ptrace(request, pid int, data uintptr) error {
	if _, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(request), uintptr(pid), 0, data, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// seize moves the PTRACE_TRACEME attach of the target, stopped after its exec,
// to PTRACE_SEIZE, which group stops need. The target runs none of its code in
// between: it leaves the exec stop for a SIGSTOP group stop and is seized there.
// SIGCONT then ends the group stop, and seize returns at its signal-delivery
// stop, for the caller to resume without the signal. A SIGCONT blocked across
// exec is unblocked until that stop, so the target never sees the signal.
// Another signal reported before it is held back and sent again afterwards.
func seize(pid, flags int) error {
	if err := ptrace(unix.PTRACE_DETACH, pid, uintptr(unix.SIGSTOP)); err != nil {
		return err
	}
	var status unix.WaitStatus
	for {
		_, err := unix.Wait4(pid, &status, unix.WUNTRACED|unix.WCONTINUED, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if !status.Stopped() {
		return fmt.Errorf("target did not stop for PTRACE_SEIZE: %#x", uint32(status))
	}
	if err := ptrace(unix.PTRACE_SEIZE, pid, uintptr(flags)); err != nil {
		return err
	}
	if err := unix.Kill(pid, unix.SIGCONT); err != nil {
		return err
	}
	var mask uint64
	masked := false
	var held []unix.Signal
	for {
		status, err := waitThread(pid)
		if err != nil {
			return err
		}
		switch {
		case status.Stopped() && status.StopSignal() == unix.SIGCONT && uint32(status)>>16 == 0:
			if masked {
				if err := signalMask(pid, unix.PTRACE_SETSIGMASK, &mask); err != nil {
					return err
				}
			}
			for _, sig := range held {
				if err := unix.Tgkill(pid, pid, sig); err != nil {
					return err
				}
			}
			return nil
		case status.Stopped() && uint32(status)>>16 == unix.PTRACE_EVENT_STOP:
			if !masked {
				if err := signalMask(pid, unix.PTRACE_GETSIGMASK, &mask); err != nil {
					return err
				}
				unblocked := mask &^ (1 << (unix.SIGCONT - 1))
				if err := signalMask(pid, unix.PTRACE_SETSIGMASK, &unblocked); err != nil {
					return err
				}
				masked = true
			}
			if err := unix.PtraceSyscall(pid, 0); err != nil {
				return err
			}
		case status.Stopped() && uint32(status)>>16 == 0 && status.StopSignal() != unix.SIGTRAP|0x80:
			held = append(held, status.StopSignal())
			if err := unix.PtraceSyscall(pid, 0); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected stop while seizing the target: %#x", uint32(status))
		}
	}
}

// seccompMode returns the Seccomp field of the thread's status.
func seccompMode(tid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if mode, ok := strings.CutPrefix(line, "Seccomp:\t"); ok {
			return mode
		}
	}
	return ""
}

// The action data tells our stop apart from a target filter's own.
const seccompDataBPF = 0x4250

// bpfCommonAttrs is the bpf(2) command flag of Linux 7.3 that adds a common
// attr in the 4th and 5th arguments; __sys_bpf clears it before dispatching.
const bpfCommonAttrs = 1 << 16

// testEverySyscall lets the test suite run on the every-syscall path.
var testEverySyscall = false

// bpfStopFilter traces native bpf(2) BPF_PROG_LOAD and BPF_BTF_LOAD, the only
// commands entry and exit act on, with or without bpfCommonAttrs. The kernel
// reads the command as an int, so only the low 32 bits of args[0] count. Every
// other command runs without a stop: the map types, BTF and program info the
// supervisor needs come from its own calls in the stopped target. Compat and
// x32 calls stay allowed: inject-run passes them through without injection anyway.
var bpfStopFilter = []unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 6, K: unix.AUDIT_ARCH_X86_64},
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 4, K: unix.SYS_BPF},
	{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
	{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: ^uint32(bpfCommonAttrs)},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, K: unix.BPF_PROG_LOAD},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.BPF_BTF_LOAD},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_TRACE | seccompDataBPF},
}

// installFilter runs at the exit stop of the target's first syscall, which went
// through the every-syscall path, so no bpf(2) comes before the filter. Where
// the filter cannot be used, the target stays on that path and the log says
// why. It never sets no_new_privs: without CAP_SYS_ADMIN the kernel returns
// EACCES. SPEC_ALLOW keeps
// spec_store_bypass_disable=seccomp from slowing the target.
func (s *supervisor) installFilter(tid, threads int, arch uint32, regs unix.PtraceRegs) error {
	switch regs.Orig_rax {
	case unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_RT_SIGRETURN:
		return nil // these return somewhere other than a SYSCALL instruction
	}
	s.filterPending = false
	if reason := filterUnusable(seccompMode(tid), arch, threads); reason != "" {
		s.log("stopping on every syscall: %s", reason)
		return nil
	}
	r, err := beginRemote(tid, regs, false)
	if err != nil {
		return err
	}
	prog := make([]byte, 0, 8*len(bpfStopFilter))
	for _, f := range bpfStopFilter {
		prog = append(prog, unsafe.Slice((*byte)(unsafe.Pointer(&f)), 8)...)
	}
	progAddr, err := r.alloc(prog)
	if err == nil {
		fprog := make([]byte, 16)
		put32(fprog, 0, uint32(len(bpfStopFilter)))
		put64(fprog, 8, progAddr)
		var addr uint64
		if addr, err = r.alloc(fprog); err == nil {
			var ret int64
			ret, err = r.call(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_SPEC_ALLOW, addr)
			err = syscallError(ret, err)
		}
	}
	if r.broken != nil {
		return r.broken
	}
	if err != nil {
		s.log("stopping on every syscall: %s", seccompRefusal(err))
		return r.finish(int64(regs.Rax))
	}
	s.filtered = true
	flags := unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_EXITKILL |
		unix.PTRACE_O_TRACESECCOMP | unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK
	if err := unix.PtraceSetOptions(tid, flags); err != nil {
		return err
	}
	s.log("stopping only on bpf()")
	return r.finish(int64(regs.Rax))
}

// filterUnusable says why the target cannot take the filter at its first
// syscall, or returns "". mode is the Seccomp field of its status. An inherited
// filter may kill or trap the seccomp call that would add ours, so any filter
// already present means the every-syscall path.
func filterUnusable(mode string, arch uint32, threads int) string {
	switch {
	case mode == "":
		return "cannot read the target's seccomp mode from /proc"
	case mode != "0":
		return "the target already runs under a seccomp filter (Seccomp " + mode + ")"
	case arch != unix.AUDIT_ARCH_X86_64:
		return fmt.Sprintf("the target is not a native x86-64 process (arch %#x)", arch)
	case threads != 1:
		return fmt.Sprintf("the target has %d threads at its first syscall", threads)
	}
	return ""
}

// seccompRefusal explains an error of the seccomp call that installs the filter.
func seccompRefusal(err error) string {
	switch err {
	case unix.EACCES:
		return "seccomp(2) refused the filter: the target lacks CAP_SYS_ADMIN and no_new_privs is not set"
	case unix.ENOSYS, unix.EINVAL:
		return fmt.Sprintf("seccomp(2) failed: %v; the kernel may lack seccomp filter support", err)
	}
	return fmt.Sprintf("cannot install the seccomp filter: %v", err)
}

// seccompStop handles a PTRACE_EVENT_SECCOMP stop. ok is false if the thread
// died in the stop.
func (s *supervisor) seccompStop(tid int, t *thread) (regs unix.PtraceRegs, ok bool, err error) {
	data, err := unix.PtraceGetEventMsg(tid)
	if err == nil {
		err = unix.PtraceGetRegs(tid, &regs)
	}
	if err == unix.ESRCH {
		return regs, false, nil
	}
	if err != nil {
		return regs, false, err
	}
	switch {
	case data != seccompDataBPF:
		// A target filter's own SECCOMP_RET_TRACE: without PTRACE_O_TRACESECCOMP
		// the kernel would fail the call with ENOSYS, so keep that.
		regs.Orig_rax = ^uint64(0)
		regs.Rax = ^uint64(unix.ENOSYS) + 1
		err = unix.PtraceSetRegs(tid, &regs)
	case !t.foreign:
		err = s.entry(tid, t, regs)
	}
	if err == unix.ESRCH {
		return regs, false, nil
	}
	return regs, err == nil, err
}

func threadGroup(tid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, err
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		var group int
		if _, err := fmt.Sscanf(string(line), "Tgid:\t%d", &group); err == nil {
			return group, nil
		}
	}
	return 0, fmt.Errorf("tgid is missing from /proc/%d/status", tid)
}

func (s *supervisor) entry(pid int, t *thread, regs unix.PtraceRegs) error {
	command := uint32(regs.Rdi) &^ bpfCommonAttrs
	if command != unix.BPF_BTF_LOAD && command != unix.BPF_PROG_LOAD {
		return nil
	}
	t.btf, t.refusal = nil, nil
	if regs.Rdx > maxAttr {
		return s.skipEntry(pid, regs, fmt.Errorf("attr exceeds %d bytes", maxAttr))
	}
	attr, err := readMemory(pid, regs.Rsi, regs.Rdx)
	if err != nil {
		return s.skipEntry(pid, regs, err)
	}
	if command == unix.BPF_BTF_LOAD {
		if len(attr) < 20 {
			return s.skipEntry(pid, regs, fmt.Errorf("short BTF_LOAD attr"))
		}
		t.btf, err = readMemory(pid, u64(attr, 0), uint64(u32(attr, 16)))
		if err != nil {
			return s.skipEntry(pid, regs, err)
		}
		return nil
	}
	// The kernel name is available even on old, BTF-less loads. Full function
	// names additionally use the remembered BTF; live fd identity is checked below.
	name := ""
	if len(attr) >= 64 {
		name = cstring(attr[48:64])
	}
	entryName := ""
	// shortcut: full-name preselection needs the original remembered BTF fd;
	// resolve a live BTF ID here before supporting duped or inherited BTF fds.
	if len(attr) >= 92 {
		if remembered, ok := s.btf[u32(attr, 72)]; ok {
			if spec, err := btf.LoadSpecFromReader(bytes.NewReader(remembered.blob)); err == nil {
				entryName, _ = readEntryName(pid, attr, spec)
			}
		}
	}
	rule, err := s.selectRule(name, entryName)
	if err != nil {
		return s.skipMatched(pid, t, regs, Refusal{Program: name, Func: entryName, Reason: err.Error(), Cause: "selector"})
	}
	discover := s.options.OnDiscover != nil && len(attr) >= 4 && inject.ContextType(ebpf.ProgramType(u32(attr, 0))) != ""
	if rule == nil && !discover {
		return nil
	}
	err = parseProgAttr(attr)
	if err == nil && fdArray(attr) != 0 {
		var insns []byte
		if insns, err = readMemory(pid, u64(attr, 8), uint64(u32(attr, 4))*8); err == nil {
			err = fdArrayMapIndex(insns)
		}
	}
	if err != nil {
		if rule == nil {
			s.log("program %q: lookup discovery skipped: %v", name, err)
			return nil
		}
		return s.skipMatched(pid, t, regs, Refusal{Program: name, Func: entryName, Reason: err.Error(), Cause: "transform"})
	}
	r, err := beginRemote(pid, regs, true)
	if err != nil {
		return err
	}
	rounding := s.options.FrameRounding
	stack, stackErr := s.preloadDepths(r, attr, rounding)
	if s.options.preloadError != nil {
		stackErr = s.options.preloadError
	}
	if stackErr != nil {
		stack = inject.StackReport{Source: "unavailable", FrameRounding: rounding, Error: stackErr.Error()}
		s.log("program %q: stack depth unavailable: %v", name, stackErr)
	} else {
		parts := make([]string, 0, len(stack.Functions))
		for _, frame := range stack.Functions {
			switch {
			case frame.Dead:
				parts = append(parts, fmt.Sprintf("%s dead", frame.Name))
			case frame.SkipReason != "":
				parts = append(parts, fmt.Sprintf("%s skipped (%s)", frame.Name, frame.SkipReason))
			default:
				parts = append(parts, fmt.Sprintf("%s %d (verified %d, text %d)", frame.Name, frame.Floor, frame.VerifiedDepth, frame.TextDepth))
			}
		}
		s.log("program %q: stack floor from the verifier: %s", name, strings.Join(parts, ", "))
	}
	if discover {
		if err := s.discover(r, attr, name, stack); err != nil {
			s.log("program %q: lookup discovery failed: %v", name, err)
		}
		if r.broken != nil {
			return r.broken
		}
	}
	if rule == nil {
		// Load the original program unchanged.
		ret, err := r.call(unix.SYS_BPF, regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8)
		if err != nil {
			return err
		}
		return r.finish(ret)
	}
	form := chooseHookForm(rule.StaticUntrusted, s.probeUntrusted)
	if form.Reason == "probe_inconclusive" {
		s.log("global arg:untrusted probe inconclusive: %v", s.probeUntrusted())
	}
	s.log("program %q: untrusted hook form %s (%s)", name, form.Form, form.Reason)
	var ret int64
	var rewrite *transformed
	var entry string
	var injectErr error
	branches := ""
	s.extra = 0
	if stackErr != nil {
		injectErr = fmt.Errorf("stack depth unavailable: %w", stackErr)
	} else {
		ret, rewrite, entry, injectErr = s.transformLoad(r, attr, *rule, form, stack, false)
		if errors.Is(injectErr, errJumpLimit) && r.broken == nil {
			s.log("program %q: %v; retrying with lookup misses first", name, injectErr)
			branches = ", lookup branches miss-first"
			ret, rewrite, entry, injectErr = s.transformLoad(r, attr, *rule, form, stack, true)
		}
	}
	step, cause := stepOriginal, ""
	if injectErr != nil && r.broken == nil {
		failure := loadFailure{err: injectErr, stackErr: stackErr, loaderLog: loaderLog(attr)}
		if step, cause = failedLoad(failure, s.options.FailClosed, *rule); step == stepLogTrial {
			s.log("program %q: %v with the loader's verifier log; trying the rewrite with a log of its own", name, injectErr)
			s.extra++
			trialErr := s.logTrial(r, attr, rule.Program, form, rewrite)
			failure.logTried = true
			if trialErr == nil {
				failure.logPassed = true
				injectErr = fmt.Errorf("%w; the rewrite passes with a log of its own: the loader's verifier log buffer is too small", injectErr)
			} else {
				injectErr = trialErr
			}
			failure.err = injectErr
			step, cause = failedLoad(failure, s.options.FailClosed, *rule)
		}
		if step == stepRetry && r.broken == nil {
			s.log("program %q: %v; retrying with fewer sites", name, injectErr)
			ret, rewrite, injectErr = s.retryLoad(r, attr, *rule, form, stack, rewrite, injectErr)
			if failure.err, failure.retried = injectErr, true; injectErr != nil {
				step, cause = failedLoad(failure, s.options.FailClosed, *rule)
			}
		}
	}
	if r.broken != nil {
		return r.broken
	}
	var result *inject.LookupResultRaw
	summary := ""
	if rewrite != nil {
		result = rewrite.result
		summary = hookSummary(result)
	}
	if injectErr != nil {
		if !errors.Is(injectErr, inject.ErrCheckerNotApplicable) {
			if summary != "" {
				s.log("program %q: injection skipped: %v; attempted %s", name, injectErr, summary)
			} else {
				s.log("program %q: injection skipped: %v", name, injectErr)
			}
		}
		// --fail-closed refuses every load that ends without hooks, whatever
		// step the last decision gave.
		refuse := s.options.FailClosed || step == stepRefuse
		ret, err = retryOriginalOrRefuse(refuse, func() (int64, error) {
			// Substituted attrs and buffers live in scratch memory, so the original
			// registers, attr and input buffers still describe the unchanged load.
			// A verifier attempt may have written the caller-owned log buffer.
			return r.call(unix.SYS_BPF, regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8)
		})
		if err != nil {
			return err
		}
		if s.options.OnRefuse != nil {
			s.options.OnRefuse(Refusal{Program: name, Func: cmp.Or(entry, entryName), Reason: injectErr.Error(),
				Cause: cause, Outcome: refusalOutcome(refuse, ret)})
		}
	} else {
		s.log("program %q: injected %s, tracee fd %d%s", name, summary, ret, branches)
		for _, hook := range result.Hooks {
			if hook.ArgReason != "" {
				s.log("program %q: hook %q observes only the result of %s: %s", name, hook.Name, hook.Call, hook.ArgReason)
			}
		}
		inj := s.injection(name, entry, ebpf.ProgramType(u32(attr, 0)), form, stack, rewrite)
		if s.options.OnInject != nil {
			// bpf_prog_info starts with type, id and the 8-byte tag.
			if info, err := r.info(uint32(ret), 16); err != nil {
				s.log("program %q: cannot query program ID: %v", name, err)
			} else {
				inj.ProgID, inj.Tag = u32(info, 4), hex.EncodeToString(info[8:16])
			}
			if r.broken != nil {
				return r.broken
			}
			s.options.OnInject(inj)
		}
	}
	return r.finish(ret)
}

// injection is the report of the rewrite that loaded for program name, with
// the marks of the original program (outside the premise, not reviewed),
// which it also logs.
func (s *supervisor) injection(name, entry string, typ ebpf.ProgramType, form HookForm, stack inject.StackReport, rewrite *transformed) Injection {
	if len(rewrite.premise) != 0 {
		s.log("program %q: outside the theorem's premise: calls %s", name, strings.Join(rewrite.premise, ", "))
	}
	if len(rewrite.unread) != 0 {
		s.log("program %q: kernel functions without a review record: calls %s", name, strings.Join(rewrite.unread, ", "))
	}
	return Injection{HookForm: form, Program: name, Func: entry, Type: typ, Hooks: rewrite.result.Hooks, Skipped: rewrite.result.Skipped, Stack: stack,
		Build: rewrite.build, Labels: rewrite.labels, OutsidePremise: rewrite.premise, NotReviewed: rewrite.unread}
}

// skipMatched ends a matched load that is not rewritten (skipEntry) and
// reports it (OnRefuse): refused at once with FailClosed, else at its exit
// stop, with the outcome of the unchanged load.
func (s *supervisor) skipMatched(pid int, t *thread, regs unix.PtraceRegs, refusal Refusal) error {
	if err := s.skipEntry(pid, regs, errors.New(refusal.Reason)); err != nil || s.options.OnRefuse == nil {
		return err
	}
	if s.options.FailClosed {
		refusal.Outcome = refusalOutcome(true, 0)
		s.options.OnRefuse(refusal)
		return nil
	}
	t.refusal = &refusal
	return nil
}

func (s *supervisor) skipEntry(pid int, regs unix.PtraceRegs, cause error) error {
	s.log("bpf command %d: injection skipped: %v", uint32(regs.Rdi), cause)
	if !s.options.FailClosed {
		return nil
	}
	r, err := beginRemote(pid, regs, true)
	if err != nil {
		return err
	}
	return r.finish(-int64(unix.EPERM))
}
func (s *supervisor) selectRule(name, entry string) (*Rule, error) {
	var selected *Rule
	for i := range s.options.Rules {
		rule := &s.options.Rules[i]
		if rule.Program != name && rule.Program != entry {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("ambiguous program selectors for %q / %q", name, entry)
		}
		selected = rule
	}
	return selected, nil
}
func readEntryName(pid int, attr []byte, spec *btf.Spec) (string, error) {
	if len(attr) < 92 || u32(attr, 88) == 0 || u32(attr, 76) != 8 {
		return "", fmt.Errorf("entry func_info missing")
	}
	fi, err := readMemory(pid, u64(attr, 80), 8)
	if err != nil {
		return "", err
	}
	if u32(fi, 0) != 0 {
		return "", fmt.Errorf("entry func_info offset is not zero")
	}
	typ, err := spec.TypeByID(btf.TypeID(u32(fi, 4)))
	if err != nil {
		return "", err
	}
	fn, ok := typ.(*btf.Func)
	if !ok {
		return "", fmt.Errorf("entry BTF is not FUNC")
	}
	return fn.Name, nil
}

func (s *supervisor) exit(pid int, t *thread, regs unix.PtraceRegs) error {
	if t.refusal != nil {
		refusal := *t.refusal
		t.refusal = nil
		refusal.Outcome = refusalOutcome(false, int64(regs.Rax))
		s.options.OnRefuse(refusal)
	}
	blob := t.btf
	t.btf = nil
	if uint32(regs.Rdi)&^bpfCommonAttrs != unix.BPF_BTF_LOAD || int64(regs.Rax) < 0 || len(blob) == 0 {
		return nil
	}
	r, err := beginRemote(pid, regs, false)
	if err != nil {
		return err
	}
	info, queryErr := r.info(uint32(regs.Rax), 32)
	if queryErr != nil {
		s.log("BTF fd %d: cannot remember identity: %v", regs.Rax, queryErr)
	} else {
		if s.cacheBytes+len(blob) > scratchSize {
			clear(s.btf)
			s.cacheBytes = 0
		}
		fd := uint32(regs.Rax)
		s.cacheBytes -= len(s.btf[fd].blob)
		s.btf[fd] = rememberedBTF{blob: blob, id: u32(info, 12)}
		s.cacheBytes += len(blob)
	}
	return r.finish(int64(regs.Rax))
}

func kernelBTF(id uint32) (*btf.Spec, error) {
	if id == 0 {
		return nil, fmt.Errorf("object has no BTF")
	}
	h, err := btf.NewHandleFromID(btf.ID(id))
	if err != nil {
		return nil, err
	}
	defer func() { _ = h.Close() }()
	return h.Spec(nil)
}

// transformLoad returns the tracee's PROG_LOAD result, the entry function name
// and, once the transformed PROG_LOAD ran, the transform's result: also when
// that load fails, so the caller can name the hooks it attempted.
// programBTF is the BTF behind the load's prog_btf_fd: the blob the target
// loaded, while the fd still names it, else the kernel's copy.
func (s *supervisor) programBTF(r *remote, attr []byte) (*btf.Spec, error) {
	info, err := r.info(u32(attr, 72), 32)
	if err != nil {
		return nil, err
	}
	if remembered, ok := s.btf[u32(attr, 72)]; ok && remembered.id == u32(info, 12) {
		return btf.LoadSpecFromReader(bytes.NewReader(remembered.blob))
	}
	return kernelBTF(u32(info, 12))
}

func runningKernelInfo() inject.KernelInfo {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return inject.KernelInfo{}
	}
	release := unix.ByteSliceToString(u.Release[:])
	info := inject.KernelInfo{Release: release}
	_, _ = fmt.Sscanf(release, "%d.%d", &info.Major, &info.Minor)
	return info
}

// loadedFunctions names the functions of the loaded program fd from the
// func_info query returns. A failure to reach the tracee's memory or
// descriptor stays the tracee's (errTracee); any other failure is the
// kernel's answer, as no func_info for a loader without CAP_BPF, so the
// audit is unavailable (errAuditUnavailable).
func loadedFunctions(query func(fd uint32) ([]byte, error), fd uint32, spec *btf.Spec) ([]string, error) {
	records, err := query(fd)
	if errors.Is(err, errTracee) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errAuditUnavailable, err)
	}
	return loadedFunctionNames(records, spec)
}

func loadedFunctionNames(records []byte, spec *btf.Spec) ([]string, error) {
	if len(records)%8 != 0 {
		return nil, fmt.Errorf("loaded func_info has %d bytes, not 8-byte records", len(records))
	}
	names := make([]string, 0, len(records)/8)
	for off := 0; off < len(records); off += 8 {
		typ, err := spec.TypeByID(btf.TypeID(u32(records, off+4)))
		if err != nil {
			return nil, fmt.Errorf("loaded func_info type: %w", err)
		}
		fn, ok := typ.(*btf.Func)
		if !ok {
			return nil, fmt.Errorf("loaded func_info type is %T, not FUNC", typ)
		}
		names = append(names, fn.Name)
	}
	return names, nil
}

func withTrialProgram(fd int64, closeFD func(int64) error, work func() error) (err error) {
	defer func() {
		if closeErr := closeFD(fd); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing trial program fd: %w", closeErr))
		}
	}()
	return work()
}

// frameFloors is inject.FrameFloorsRaw with a panic as an error (see guard).
func frameFloors(depths []int, names []string, raw inject.RawProgram, kernel inject.KernelInfo) (report inject.StackReport, err error) {
	err = guard("matching stack depths to functions", func() (err error) {
		report, err = frameFloorsRaw(depths, names, raw, kernel)
		return err
	})
	return report, err
}

// stackDepths parses the stack depths of a verifier stats log
// (inject.ParseStackDepths); a panic in it is an error (see guard).
func stackDepths(log string) (depths []int, err error) {
	err = guard("parsing verifier stats", func() (err error) {
		depths, err = parseStackDepths(log)
		return err
	})
	return depths, err
}

// statsLog points attr's verifier log at a BPF_LOG_STATS buffer of size
// bytes at addr and returns attr. Every other field stays, so a trial is
// bound to the loader's device (prog_flags at 44, prog_ifindex at 64).
func statsLog(attr []byte, size uint32, addr uint64) []byte {
	put32(attr, 24, 4) // BPF_LOG_STATS
	put32(attr, 28, size)
	put64(attr, 32, addr)
	return attr
}

// offloadAudit is the error of a load whose stack the kernel does not
// account locally: an offload request, or an attr too short to tell.
func offloadAudit(attr []byte) error {
	if len(attr) < 68 || offloaded(attr) {
		return fmt.Errorf("%w: offloaded programs do not expose local verifier stack accounting", errAuditUnavailable)
	}
	return nil
}

// trialLoadError is the error of a stack trial the kernel refused with
// loadErr and log. It is errTrialVerifier, and the original then gets the
// kernel's own error and log, when the log has a line other than the
// statistics the kernel prints after every check, refused or not (the
// verifier's reason), whatever the errno (E2BIG for the complexity and frame
// limits, EPERM for a capability the program needs), or for EACCES or EINVAL
// when the log has no line at all (the kernel refused the program before the
// verifier ran, as for a device that is gone). It is errAuditUnavailable when
// the kernel gave no verdict on the program: an errno that carries none
// (noVerdict), whatever the log, a statistics-only log, or an empty log with
// an errno other than EACCES or EINVAL. Its message says so and names the
// errno, because a rule that names a map then refuses the load.
func trialLoadError(loadErr error, log string) error {
	if errors.Is(loadErr, errTracee) {
		return loadErr
	}
	verdict := !noVerdict(loadErr) && !statsOnly(log)
	if strings.TrimSpace(log) == "" {
		verdict = errors.Is(loadErr, unix.EACCES) || errors.Is(loadErr, unix.EINVAL)
	}
	if verdict {
		return fmt.Errorf("%w: %v: %s", errTrialVerifier, loadErr, strings.TrimSpace(log))
	}
	ended := "trial PROG_LOAD ended without a verdict on the program"
	if errno := unix.Errno(0); errors.As(loadErr, &errno) {
		ended += " with " + unix.ErrnoName(errno)
	}
	if log != "" {
		return fmt.Errorf("%w: %s: %w: %s", errAuditUnavailable, ended, loadErr, strings.TrimSpace(log))
	}
	return fmt.Errorf("%w: %s: %w", errAuditUnavailable, ended, loadErr)
}

// noVerdict says whether a trial's errno says nothing of the program: ENOSPC
// and EFAULT, which the log's finalisation returns in place of the verifier's
// verdict, passed or not (bpf_check, bpf_vlog_finalize), and ENOMEM, EAGAIN
// and EBUSY, which a later load need not meet. The errno decides over the
// log: an EFAULT or EBUSY the verifier returns with a reason of its own is
// taken as no verdict as well.
func noVerdict(err error) bool {
	for _, errno := range []unix.Errno{unix.ENOSPC, unix.EFAULT, unix.ENOMEM, unix.EAGAIN, unix.EBUSY} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// statsOnly says whether every line of a verifier log is one of the
// statistics lines print_verification_stats writes with BPF_LOG_STATS.
func statsOnly(log string) bool {
	for line := range strings.Lines(log) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "verification time ") && !strings.HasPrefix(line, "stack depth ") && !strings.HasPrefix(line, "processed ") {
			return false
		}
	}
	return true
}

// readStatsLog reads a trial's verifier log of size bytes at addr in the
// tracee pid; a failed read is the tracee's (traceeError).
func readStatsLog(pid int, addr, size uint64) (string, error) {
	logBytes, err := readMemory(pid, addr, size)
	if err != nil {
		return "", traceeError(fmt.Errorf("reading verifier stats: %w", err))
	}
	return cstring(logBytes), nil
}

func (s *supervisor) preloadDepths(r *remote, attr []byte, rounding int) (report inject.StackReport, err error) {
	if err := offloadAudit(attr); err != nil {
		return report, err
	}
	spec, err := s.programBTF(r, attr)
	if err != nil {
		return report, err
	}
	raw, err := extractRaw(r, attr, spec)
	if err != nil {
		return report, err
	}
	// A successful load binds an instruction array for good, even after the
	// program is closed, so a trial load would make the original load fail.
	if pc, ok := inject.IndirectJump(raw.Instructions); ok {
		return report, fmt.Errorf("%w at instruction %d is unsupported", errIndirectJump, pc)
	}
	const logSize = 64 << 10
	logAddr, err := r.alloc(make([]byte, logSize))
	if err != nil {
		return report, err
	}
	trial := statsLog(bytes.Clone(attr), logSize, logAddr)
	fd, loadErr := r.bpf(unix.BPF_PROG_LOAD, trial)
	readLog := func() (string, error) { return readStatsLog(r.pid, logAddr, logSize) }
	if loadErr != nil {
		log, readErr := readLog()
		if readErr != nil {
			return report, readErr
		}
		return report, trialLoadError(loadErr, log)
	}
	err = withTrialProgram(fd, func(fd int64) error {
		closed, closeErr := r.call(unix.SYS_CLOSE, uint64(fd))
		return syscallError(closed, closeErr)
	}, func() error {
		log, readErr := readLog()
		if readErr != nil {
			return readErr
		}
		depths, parseErr := stackDepths(log)
		if parseErr != nil {
			return parseErr
		}
		names, namesErr := loadedFunctions(r.progFuncInfo, uint32(fd), spec)
		if namesErr != nil {
			return namesErr
		}
		report, parseErr = frameFloors(depths, names, raw, runningKernelInfo())
		report.FrameRounding = rounding
		return parseErr
	})
	return report, err
}

func (s *supervisor) discover(r *remote, attr []byte, name string, stack inject.StackReport) error {
	spec, err := s.programBTF(r, attr)
	if err != nil {
		return err
	}
	entry, err := readEntryName(r.pid, attr, spec)
	if err != nil {
		return err
	}
	raw, err := extractRaw(r, attr, spec)
	if err != nil {
		return err
	}
	raw.Kernel = s.kernel
	raw.Modules, _ = s.programModules(r, attr, raw.Instructions)
	calls, callSites, err := listing(raw)
	if err != nil {
		return err
	}
	d := Discovery{Program: name, Func: entry, Type: raw.Type, Calls: calls, Maps: map[string]ebpf.MapType{}, Stack: stack, CallSites: callSites}
	for _, site := range calls {
		if site.Op == inject.HookLookup {
			d.Lookups = append(d.Lookups, site)
		}
	}
	for _, m := range raw.Maps {
		d.Maps[m.Name] = m.Type
	}
	s.options.OnDiscover(d)
	return nil
}

// transformed is one rewrite of a program load as the load-time check saw
// it. The retry keeps the last one a trial load accepted and loads exactly
// that.
type transformed struct {
	result    *inject.LookupResultRaw
	request   inject.LookupRequestRaw
	original  asm.Instructions
	insns     []byte
	cert      injectcheck.Certificate
	premises  injectcheck.Premises
	check     bool
	missFirst bool
	retry     bool              // a trial of the retry, with its own drop list
	build     string            // the listing fingerprint of the original
	labels    map[uint32]string // the listing's site labels by pc
	premise   []string          // inject.PremiseCalls of the original, named with the load's kernel and module BTF
	unread    []string          // inject.NotReviewed of the original, named the same way
}

// sitesRefusal is a load a rule's sites refused (Sites.drop).
type sitesRefusal struct{ error }

func (e sitesRefusal) Unwrap() error { return e.error }

// programModules returns the module BTFs of insns' kfunc calls when kernel
// BTF loaded (see moduleBTFs).
func (s *supervisor) programModules(r *remote, attr []byte, insns asm.Instructions) (map[int16]*btf.Spec, map[int16]string) {
	if s.kernel == nil {
		return nil, nil
	}
	return s.moduleBTFs(insns, fdArray(attr),
		func(addr, size uint64) ([]byte, error) { return readMemory(r.pid, addr, size) },
		func(fd uint32) ([]byte, error) { return r.info(fd, 32) }, loadModuleBTF)
}

// refusedLoad marks the kernel's refusal of a rewritten program; why is the
// verifier's last log line when a load with a log of its own read it.
type refusedLoad struct {
	error
	why string
}

func (e refusedLoad) Unwrap() error { return e.error }

// transformLoad rewrites the load and loads the rewrite in place of the
// original. It returns the rewrite also when the kernel refused it
// (refusedLoad), for the retry.
func (s *supervisor) transformLoad(r *remote, attr []byte, rule Rule, form HookForm, stack inject.StackReport, missFirst bool) (ret int64, t *transformed, entry string, err error) {
	t, entry, err = s.transform(r, attr, rule, form, stack, missFirst, nil)
	if err != nil {
		return 0, t, entry, err
	}
	ret, _, err = s.load(r, attr, rule.Program, form, t, false)
	return ret, t, entry, err
}

// transform rewrites the load without the sites of drop (see
// inject.LookupRequest.Drop) and without those the rule's sites leave out.
// It lists the load as a listing would, for the hooks file and the sites
// check; a sites rule whose listing differs gets a sitesRefusal.
func (s *supervisor) transform(r *remote, attr []byte, rule Rule, form HookForm, stack inject.StackReport, missFirst bool, drop map[uint32]string) (t *transformed, entry string, err error) {
	spec, err := s.programBTF(r, attr)
	if err != nil {
		return nil, "", err
	}
	entry, err = readEntryName(r.pid, attr, spec)
	if err != nil {
		return nil, "", err
	}
	liveRule, err := s.selectRule(cstring(attr[48:64]), entry)
	if err != nil {
		return nil, "", err
	}
	if liveRule == nil || liveRule.Program != rule.Program {
		return nil, "", fmt.Errorf("BTF fd identity changed; selector no longer matches")
	}
	raw, err := extractRaw(r, attr, spec)
	if err != nil {
		return nil, "", err
	}
	listed := raw
	var homes map[int16]string
	listed.Kernel = s.kernel
	listed.Modules, homes = s.programModules(r, attr, raw.Instructions)
	if len(rule.Calls) > 0 {
		raw.Kernel, raw.Modules = listed.Kernel, listed.Modules // only a rule with calls names kfunc calls and types their arguments
	}
	return s.rewrite(raw, listed, homes, entry, rule, form, stack, missFirst, drop)
}

// rewrite is the part of transform that issues no ptrace call: raw is the
// load as the transform sees it and listed as a listing sees it, homes the
// module names of listed.Modules (moduleBTFs). A panic in it is an error
// (see guard).
func (s *supervisor) rewrite(raw, listed inject.RawProgram, homes map[int16]string, entry string, rule Rule, form HookForm, stack inject.StackReport, missFirst bool, drop map[uint32]string) (t *transformed, _ string, err error) {
	err = guard("rewriting the load", func() (err error) {
		t, entry, err = s.rewriteLoad(raw, listed, homes, entry, rule, form, stack, missFirst, drop)
		return err
	})
	return t, entry, err
}

func (s *supervisor) rewriteLoad(raw, listed inject.RawProgram, homes map[int16]string, entry string, rule Rule, form HookForm, stack inject.StackReport, missFirst bool, drop map[uint32]string) (t *transformed, _ string, err error) {
	mapCalls, list, listErr := listing(listed)
	if listErr != nil && rule.Sites != nil {
		return nil, entry, sitesRefusal{fmt.Errorf("listing the load for the rule's sites: %w", listErr)}
	}
	if listErr != nil && drop == nil {
		s.log("program %q: no site labels: %v", rule.Program, listErr)
	}
	request := rule.request()
	request.Drop = drop
	if rule.Sites != nil {
		selected, err := rule.Sites.drop(list.Fingerprint, slices.Concat(mapCalls, list.Sites, list.TailCalls), list.Labels)
		if err != nil {
			return nil, entry, sitesRefusal{err}
		}
		maps.Copy(selected, drop) // the retry drops only sites the selection kept
		request.Drop = selected
	}
	if err := supplyMapTypes(&raw, rule); err != nil {
		return nil, "", err
	}
	if rule.MapBTF != nil && drop == nil {
		for _, m := range raw.Maps {
			if m.Name == rule.Map && m.Key != nil && m.Value != nil {
				s.log("program %q: map %q types from ELF sha256 %.12s: key %q, value %q", rule.Program, rule.Map, strings.ToLower(rule.MapBTF.SHA256), m.Key.TypeName(), m.Value.TypeName())
			}
		}
	}
	request.StaticUntrusted = form.Form == "static"
	request.MissFirst = missFirst
	request.Stack = inject.StackAudit{Frames: stack.Frames(), Source: stack.Source, FrameRounding: stack.FrameRounding}
	injectcheck.Label(raw.Instructions)
	result, err := transformLookupRaw(raw, request, s.probeTailCallReachability)
	if err != nil {
		return nil, "", err
	}
	t = &transformed{result: result, request: request, original: raw.Instructions, missFirst: missFirst, retry: drop != nil,
		build: list.Fingerprint, labels: list.Labels, premise: inject.PremiseCalls(raw.Instructions, listed.Kernel, listed.Modules),
		unread: inject.NotReviewed(raw.Instructions, listed.Kernel, listed.Modules, homes)}
	t.cert, t.premises, err = loadCheckInputs(raw.Instructions, result, request.Stack, stack)
	if errors.Is(err, inject.ErrCheckerNotApplicable) && drop == nil {
		s.log("program %q: %v; load not validated", rule.Program, err)
	}
	t.check, err = loadCheckPolicy(err, s.options.FailClosed)
	if err != nil {
		return t, entry, err
	}
	var instructions bytes.Buffer
	if err := result.Instructions.Marshal(&instructions, wire); err != nil {
		return nil, "", err
	}
	t.insns = instructions.Bytes()
	return t, entry, nil
}

// load loads t in the tracee in place of the original program. A trial
// load (see retry) carries a log of its own and closes the program it
// loaded; when the kernel refuses it, why is the verifier's last log line.
// The caller's attr and log are untouched. Otherwise the load is the one the
// tracee asked for, and a refusal of a rewrite without dropped sites is
// repeated once to see whether the jump limit caused it (hitJumpLimit). A
// refusal is a refusedLoad.
func (s *supervisor) load(r *remote, attr []byte, name string, form HookForm, t *transformed, trial bool) (ret int64, why string, err error) {
	result := t.result
	// Load BTF inside the tracee. A supervisor-owned fd is not a valid substitute
	// for prog_btf_fd, even when its numeric value happens to match a target fd.
	btfAddr, err := r.alloc(result.BTFBytes)
	if err != nil {
		return 0, "", err
	}
	btfAttr := make([]byte, 32)
	put64(btfAttr, 0, btfAddr)
	put32(btfAttr, 16, uint32(len(result.BTFBytes)))
	fd, err := r.bpf(unix.BPF_BTF_LOAD, btfAttr)
	if err != nil {
		return 0, "", fmt.Errorf("tracee extended BTF load: %w", err)
	}
	defer func() {
		closed, closeErr := r.call(unix.SYS_CLOSE, uint64(fd))
		if closeErr = syscallError(closed, closeErr); closeErr != nil {
			r.broken = fmt.Errorf("close injected BTF fd: %w", closeErr)
			err = r.broken
		}
	}()
	patched := bytes.Clone(attr)
	put32(patched, 72, uint32(fd))
	for _, buffer := range []struct {
		data                            []byte
		ptr, count, sizeOff, recordSize int
	}{
		{t.insns, 8, 4, -1, 8}, {result.FuncInfo, 80, 88, 76, 8}, {result.LineInfo, 96, 104, 92, 16},
	} {
		addr, err := r.alloc(buffer.data)
		if err != nil {
			return 0, "", err
		}
		put64(patched, buffer.ptr, addr)
		put32(patched, buffer.count, uint32(len(buffer.data)/buffer.recordSize))
		if buffer.sizeOff >= 0 {
			put32(patched, buffer.sizeOff, uint32(buffer.recordSize))
		}
	}
	const logSize = 64 << 10
	var logAddr uint64
	if trial {
		if logAddr, err = r.alloc(make([]byte, logSize)); err != nil {
			return 0, "", err
		}
		statsLog(patched, logSize, logAddr) // verifier errors print at any level
	}
	// Preserve kernel output fields (currently log_true_size) in the caller's attr.
	addr, err := r.alloc(patched)
	if err != nil {
		return 0, "", err
	}
	// This checks the bytes read from attr.insns immediately before the traced
	// thread resumes. It neither freezes sibling threads nor proves kernel
	// acceptance, BTF meaning, fd bindings, verifier behavior, or JIT behavior.
	var verdict injectcheck.Verdict
	if t.check {
		encoded, err := readMemory(r.pid, u64(patched, 8), uint64(u32(patched, 4))*8)
		if err != nil {
			return 0, "", checkerRejection{fmt.Errorf("checker rejected the transform: read substituted load stream: %w; probe was not installed", err)}
		}
		verdict, err = checkLoad(t.original, encoded, t.cert, t.premises)
		if err != nil {
			return 0, "", checkerRejection{fmt.Errorf("checker rejected the transform: %w; probe was not installed", err)}
		}
	}
	if trial {
		ret, err = r.call(unix.SYS_BPF, unix.BPF_PROG_LOAD, addr, uint64(len(patched)))
	} else {
		// The original command and common attr keep a 7.3 caller's log request.
		ret, err = r.call(unix.SYS_BPF, r.saved.Rdi, addr, uint64(len(patched)), r.saved.R10, r.saved.R8)
	}
	if err != nil {
		return 0, "", err
	}
	if t.check && !trial {
		s.log("program %q: checker accepted sites=%d hooks=%d floor=%d", name, verdict.Counts.Sites, verdict.Counts.Hooks, verdict.Premises.LowestOffset)
	}
	if len(patched) >= 144 && !trial {
		out, e := readMemory(r.pid, addr+140, 4)
		if e == nil {
			e = writeMemory(r.pid, r.saved.Rsi+140, out)
		}
		if e != nil {
			r.broken = e
			return 0, "", e
		}
	}
	if ret >= 0 && s.options.loadFault != nil {
		if fault := s.options.loadFault(result.Hooks); fault != nil {
			if err := s.closeProgram(r, ret); err != nil {
				return 0, "", err
			}
			ret, why = -int64(unix.EACCES), fault.Error()
		}
	}
	if trial && ret >= 0 {
		return 0, "", s.closeProgram(r, ret)
	}
	if err := syscallError(ret, nil); err != nil {
		if trial {
			if why == "" {
				log, readErr := readMemory(r.pid, logAddr, logSize)
				if readErr != nil {
					return 0, "", fmt.Errorf("reading the trial load's log: %w", readErr)
				}
				why = lastLogLine(cstring(log))
			}
			why = cmp.Or(why, err.Error())
			return 0, why, refusedLoad{fmt.Errorf("trial PROG_LOAD: %w", err), why}
		}
		// Not after the retry: its rewrite is final, and the load would go
		// past the budget.
		if !t.missFirst && !t.retry && missFirstDiffers(t.request, result) {
			s.extra++
			hit, diagnosed := s.hitJumpLimit(r, patched)
			if hit {
				err = fmt.Errorf("%w: %w", errJumpLimit, err)
			}
			why = cmp.Or(why, diagnosed)
		}
		// Carry the summary so the caller can name the attempted hooks, and a
		// hint when an untrusted-pointer ABI mismatch may be the cause.
		return 0, why, refusedLoad{fmt.Errorf("transformed PROG_LOAD: %w%s", err, untrustedHint(form, result, err)), why}
	}
	return ret, "", nil
}

// closeProgram closes the program fd a trial or refused load got.
func (s *supervisor) closeProgram(r *remote, fd int64) error {
	closed, err := r.call(unix.SYS_CLOSE, uint64(fd))
	if err = syscallError(closed, err); err != nil {
		r.broken = fmt.Errorf("close trial program fd: %w", err)
		return r.broken
	}
	return nil
}

// retryLoad looks for a rewrite the kernel accepts after it refused failed
// with cause, dropping sites by trial loads (see degrade), and loads exactly
// the one it keeps. The rewrite it returns lists the dropped sites as
// skipped with their reasons.
func (s *supervisor) retryLoad(r *remote, attr []byte, rule Rule, form HookForm, stack inject.StackReport, failed *transformed, cause error) (int64, *transformed, error) {
	sites := retrySites(failed.result.Hooks, failed.request.Auto)
	trial := func(drop map[uint32]string) (*transformed, bool, string, error) {
		defer func(used uint64) { r.used = used }(r.used) // the scratch a trial used is free again
		t, _, err := s.transform(r, attr, rule, form, stack, failed.missFirst, drop)
		if err != nil {
			if r.broken != nil || !errors.Is(err, inject.ErrRefused) {
				return nil, false, "", err
			}
			return nil, false, err.Error(), nil // nothing to load, as without hooks
		}
		_, why, err := s.load(r, attr, rule.Program, form, t, true)
		if errors.As(err, &refusedLoad{}) {
			return t, false, why, nil
		}
		return t, err == nil, "", err
	}
	why := cause.Error()
	if refused := (refusedLoad{}); errors.As(cause, &refused) && refused.why != "" {
		why = refused.why
	}
	bare := baseHooksNothing(failed.result.Hooks, sites, failed.request.Entry)
	out, ret, err := degrade(sites, why, trialBudget-s.extra, bare, trial, func(t *transformed) (int64, error) {
		ret, _, err := s.load(r, attr, rule.Program, form, t, false)
		return ret, err
	})
	if !out.loaded || err != nil {
		// Neither a trial nor the final load of the kept rewrite passed:
		// the caller loads the original program or refuses the load.
		fallback := "the original program loads"
		if s.options.FailClosed {
			fallback = "the load is refused (--fail-closed)"
		}
		s.log("program %q: %d sites requested, no rewrite loaded after %d trial loads (budget %d, %d used before); %s",
			rule.Program, len(sites), out.trials, trialBudget, s.extra, fallback)
	} else {
		s.log("program %q: %d sites requested, %d kept after %d trial loads (budget %d, %d used before); dropped %s",
			rule.Program, len(sites), len(out.kept), out.trials, trialBudget, s.extra, cmp.Or(droppedSummary(out.dropped), "none"))
	}
	if !out.loaded {
		return 0, failed, fmt.Errorf("%w; %w", cause, err)
	}
	if err != nil {
		return 0, out.art, err
	}
	for i, site := range out.art.result.Skipped {
		if reason, ok := out.dropped[site.SitePC]; ok && !unmatchedMapsName(site) && !inject.UnknownCallsName(site) && !site.KernelAdded {
			out.art.result.Skipped[i].Reason = reason
		}
	}
	return ret, out.art, nil
}

// logTrial loads t once as a trial (load), with a log of the supervisor's
// own; the scratch memory it used is free again.
func (s *supervisor) logTrial(r *remote, attr []byte, name string, form HookForm, t *transformed) error {
	defer func(used uint64) { r.used = used }(r.used)
	_, _, err := s.load(r, attr, name, form, t, true)
	return err
}

// missFirstDiffers reports whether MissFirst would change the rewrite: some
// lookup hook observes hits. A miss-only site is already laid out miss-first.
func missFirstDiffers(request inject.LookupRequestRaw, result *inject.LookupResultRaw) bool {
	if request.Lookups == inject.LookupMiss || request.Lookups == inject.LookupNone {
		return false
	}
	return slices.ContainsFunc(result.Hooks, func(h inject.LookupHook) bool { return h.Kind == inject.HookLookup })
}

// hitJumpLimit repeats a refused load with a log of its own to read why. The
// errno cannot say: it differs across kernels and E2BIG also means the
// instruction limit, and the loader's log may be off or end before the message.
// A refused load binds no map, and this one does not touch the loader's log.
// why is the log's last line (lastLogLine), when the repeated load was
// refused too.
func (s *supervisor) hitJumpLimit(r *remote, attr []byte) (hit bool, why string) {
	const logSize = 64 << 10
	logAddr, err := r.alloc(make([]byte, logSize))
	if err != nil {
		return false, ""
	}
	trial := statsLog(bytes.Clone(attr), logSize, logAddr)
	fd, err := r.bpf(unix.BPF_PROG_LOAD, trial)
	if err == nil {
		closed, closeErr := r.call(unix.SYS_CLOSE, uint64(fd))
		if closeErr = syscallError(closed, closeErr); closeErr != nil {
			r.broken = fmt.Errorf("close repeated load fd: %w", closeErr)
		}
		return false, ""
	}
	log, err := readMemory(r.pid, logAddr, logSize)
	if err != nil {
		return false, ""
	}
	return strings.Contains(cstring(log), "jumps is too complex"), lastLogLine(cstring(log))
}

// untrustedHint explains how to load a program whose hooks take arg:untrusted
// pointers on a kernel without that tag. It is empty unless some hook is
// untrusted and the load failed the way those kernels fail it: EINVAL on 6.1
// and 6.6, EOPNOTSUPP on 6.12 and 6.15, or EACCES. It is also empty unless the
// probe was inconclusive: otherwise it already showed whether the kernel
// accepts the tag.
func untrustedHint(form HookForm, result *inject.LookupResultRaw, err error) string {
	if form.Reason != "probe_inconclusive" {
		return ""
	}
	if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EACCES) {
		return ""
	}
	untrusted, copyHelps := false, false
	for _, hook := range result.Hooks {
		untrusted = untrusted || hook.Untrusted
		copyHelps = copyHelps || copyReadOnlyHelps(hook)
	}
	if !untrusted {
		return ""
	}
	fix := `"static_untrusted": true`
	if copyHelps {
		fix += ` or, for read-only maps, "copy_read_only": true`
	}
	return ` (hooks use arg:untrusted pointers, which kernels 6.15 and older in our CI matrix reject; set ` + fix + ` to load on those kernels)`
}

// copyReadOnlyHelps reports whether copy_read_only would give hook a typed
// hook: an untrusted lookup hook on a read-only map (never the generic hook).
// A hook whose rule cannot also set copy_read_only must be excluded here: a
// dispatch hook, since Validate rejects dispatch with copy_read_only.
func copyReadOnlyHelps(hook inject.LookupHook) bool {
	return hook.Kind == inject.HookLookup && hook.Untrusted && hook.ReadOnly && !hook.Generic && !hook.Dispatch
}

// hookSummary lists each hook as
//
//	hook "NAME" (KIND[ map "MAP"][ generic[ map "MAP"...][ runtime map]][, untrusted pointers][, value copied to stack][, static][, dispatch][, site pc N, N])
//
// separated by ", ", then "; skipped pc N (reason)" for each skipped lookup,
// or "; skipped map "MAP" (reason)" for a Maps name that matches no site,
// "; skipped call "NAME" (reason)" for an unknown Calls name, and
// "; call "NAME" (reason)" for one the kernel may call from code it adds at load.
// A generic hook names each map its sites reference directly, such as a
// sockhash, and says "runtime map" when a site's map is known only at run
// time.
// The launcher log and the integration test look for the leading "hook".
func hookSummary(result *inject.LookupResultRaw) string {
	var b strings.Builder
	for i, hook := range result.Hooks {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "hook %q (%s", hook.Name, hook.Kind)
		if hook.MapName != "" {
			fmt.Fprintf(&b, " map %q", hook.MapName)
		}
		if hook.Generic {
			b.WriteString(" generic")
			var named []string
			atRuntime := false
			for _, site := range hook.Sites {
				if site.MapName == "" {
					atRuntime = true
				} else if !slices.Contains(named, site.MapName) {
					named = append(named, site.MapName)
				}
			}
			for _, name := range named {
				fmt.Fprintf(&b, " map %q", name)
			}
			if atRuntime {
				b.WriteString(" runtime map")
			}
		}
		if hook.Untrusted {
			b.WriteString(", untrusted pointers")
		}
		if hook.Copied {
			b.WriteString(", value copied to stack")
		}
		if hook.Static {
			b.WriteString(", static")
		}
		if hook.Dispatch {
			b.WriteString(", dispatch")
		}
		for j, site := range hook.Sites {
			if j == 0 {
				b.WriteString(", site pc")
			} else {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, " %d", site.SitePC)
		}
		b.WriteByte(')')
	}
	for _, site := range result.Skipped {
		if unmatchedMapsName(site) {
			fmt.Fprintf(&b, "; skipped map %q (%s)", site.MapName, site.Reason)
			continue
		}
		if inject.UnknownCallsName(site) {
			fmt.Fprintf(&b, "; skipped call %q (%s)", site.Call, site.Reason)
			continue
		}
		if site.KernelAdded {
			fmt.Fprintf(&b, "; call %q (%s)", site.Call, site.Reason)
			continue
		}
		fmt.Fprintf(&b, "; skipped pc %d (%s)", site.SitePC, site.Reason)
	}
	return b.String()
}

// unmatchedMapsName reports a skipped entry for a Maps name that matches no
// site (inject.LookupRequest.SkipUnmatchedMaps): it has no op and no pc.
func unmatchedMapsName(site inject.LookupSite) bool {
	return site.Op == "" && site.SitePC == 0 && site.MapName != ""
}

func extractRaw(r *remote, attr []byte, spec *btf.Spec) (inject.RawProgram, error) {
	// TODO: a SEIZE/INTERRUPT launcher must stop all siblings before this snapshot
	// to support concurrent mutation of load buffers or shared fd tables.
	p := inject.RawProgram{Type: ebpf.ProgramType(u32(attr, 0)), BTF: spec, Maps: make(map[int32]inject.RawMap)}
	insns, err := readMemory(r.pid, u64(attr, 8), uint64(u32(attr, 4))*8)
	if err != nil {
		return p, traceeError(err)
	}
	if fdArray(attr) != 0 {
		if err := fdArrayMapIndex(insns); err != nil {
			return p, err
		}
	}
	p.Instructions, err = asm.AppendInstructions(nil, bytes.NewReader(insns), wire, "linux")
	if err != nil {
		return p, err
	}
	p.FuncInfo, err = readMemory(r.pid, u64(attr, 80), uint64(u32(attr, 88))*8)
	if err != nil {
		return p, traceeError(err)
	}
	p.LineInfo, err = readMemory(r.pid, u64(attr, 96), uint64(u32(attr, 104))*16)
	if err != nil {
		return p, traceeError(err)
	}
	for _, ins := range p.Instructions {
		if !ins.IsLoadFromMap() {
			continue
		}
		fd := int32(ins.Constant)
		if _, ok := p.Maps[fd]; ok {
			continue
		}
		info, err := r.info(uint32(fd), 88)
		if err != nil {
			return p, err
		}
		// A map without BTF (often a program array) keeps its identity; the
		// transform skips or refuses lookups that need its types.
		var key, value btf.Type
		if id := u32(info, 64); id != 0 {
			types, err := kernelBTF(id)
			if err != nil {
				return p, fmt.Errorf("map fd %d BTF: %w", fd, err)
			}
			// A zero type id is a side declared only by size; it stays nil.
			if kid := u32(info, 68); kid != 0 {
				if key, err = types.TypeByID(btf.TypeID(kid)); err != nil {
					return p, err
				}
			}
			if vid := u32(info, 72); vid != 0 {
				if value, err = types.TypeByID(btf.TypeID(vid)); err != nil {
					return p, err
				}
			}
		}
		m := inject.RawMap{Name: cstring(info[24:40]), Type: ebpf.MapType(u32(info, 0)), KeySize: u32(info, 8), ValueSize: u32(info, 12), Flags: u32(info, 20), BTFID: btf.ID(u32(info, 64)), Key: key, Value: value}
		if m.Type == ebpf.ArrayOfMaps || m.Type == ebpf.HashOfMaps {
			// The kernel does not report the inner-map template's flags.
			m.InnerFlags = unix.BPF_F_RDONLY_PROG
		}
		p.Maps[fd] = m
	}
	return p, nil
}
