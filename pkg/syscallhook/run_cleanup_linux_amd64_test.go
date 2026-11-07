//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type delayedDoneContext struct {
	context.Context
	entered  chan struct{}
	release  chan struct{}
	canceled chan struct{}
}

func (c *delayedDoneContext) Done() <-chan struct{} {
	close(c.entered)
	<-c.release
	return c.canceled
}

func (c *delayedDoneContext) Err() error { return context.Canceled }

func TestRunJoinsCancellationWorker(t *testing.T) {
	ctx := &delayedDoneContext{
		Context:  context.Background(),
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	close(ctx.canceled)
	type result struct {
		code int
		err  error
	}
	returned := make(chan result, 1)
	go func() {
		code, err := Run(ctx, []string{"/bin/true"}, Options{
			Rules:        []Rule{testRule()},
			EverySyscall: true,
			pidfdOpen: func(pid, flags int) (int, error) {
				fd, err := unix.PidfdOpen(pid, flags)
				if err == nil {
					err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
				}
				return fd, err
			},
		})
		returned <- result{code, err}
	}()
	select {
	case <-ctx.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation worker did not start")
	}

	var got result
	returnedBeforeRelease := false
	select {
	case got = <-returned:
		returnedBeforeRelease = true
	case <-time.After(200 * time.Millisecond):
	}
	close(ctx.release)
	if !returnedBeforeRelease {
		select {
		case got = <-returned:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not return after releasing cancellation worker")
		}
	}
	if returnedBeforeRelease {
		t.Fatal("Run returned before its cancellation worker stopped")
	}
	if got.code != 0 || got.err == nil || !strings.Contains(got.err.Error(), "target did not stop at exec") {
		t.Fatalf("code=%d err=%v, want startup failure", got.code, got.err)
	}
}

func startWaitOwnershipChild(t *testing.T) (*exec.Cmd, func()) {
	t.Helper()
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ready, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("/bin/sh", "-c", "printf R; read line; exit 23")
	child.Stdin = input
	child.Stdout = output
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	_ = output.Close()
	t.Cleanup(func() {
		_ = writer.Close()
		_ = ready.Close()
		_ = child.Process.Kill()
		_ = child.Process.Release()
	})
	var b [1]byte
	if n, err := ready.Read(b[:]); err != nil || n != 1 || b[0] != 'R' {
		t.Fatalf("unrelated child readiness n=%d b=%q err=%v", n, b, err)
	}
	return child, func() {
		_, _ = writer.Write([]byte("release\n"))
		_ = writer.Close()
	}
}

func TestRunLeavesUnrelatedChildWaitable(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unrelated, release := startWaitOwnershipChild(t)
	runReturned := make(chan struct{})
	released := make(chan bool, 1)
	go func() {
		timedOut := false
		select {
		case <-runReturned:
		case <-time.After(2 * time.Second):
			timedOut = true
		}
		release()
		released <- timedOut
	}()

	code, err := Run(context.Background(), []string{"/bin/sh", "-c", "exit 7"}, Options{
		Rules:        []Rule{testRule()},
		EverySyscall: true,
	})
	close(runReturned)
	timedOut := <-released
	otherErr := unrelated.Wait()
	var exitErr *exec.ExitError
	if timedOut {
		t.Fatal("Run waited for an unrelated child")
	}
	if code != 7 || err != nil {
		t.Fatalf("code=%d err=%v, want target exit 7", code, err)
	}
	if !errors.As(otherErr, &exitErr) || exitErr.ExitCode() != 23 {
		t.Fatalf("unrelated child Wait=%v, want exit 23", otherErr)
	}
}

type errorCleanupResult struct {
	blocked       bool
	code          int
	err, otherErr error
}

func errorCleanupError(r errorCleanupResult) error {
	var exitErr *exec.ExitError
	switch {
	case r.blocked:
		return errors.New("Run waited after its tracees exited")
	case r.code != 0:
		return fmt.Errorf("code=%d", r.code)
	case r.err == nil || !strings.Contains(r.err.Error(), "target did not stop at exec"):
		return fmt.Errorf("startup error=%v", r.err)
	case !errors.As(r.otherErr, &exitErr) || exitErr.ExitCode() != 23:
		return fmt.Errorf("unrelated child Wait=%v", r.otherErr)
	default:
		return nil
	}
}

func TestErrorCleanupOracleRejectsFaults(t *testing.T) {
	good := errorCleanupResult{err: errors.New("target did not stop at exec"), otherErr: &exec.ExitError{ProcessState: exitedProcessState(t, 23)}}
	if err := errorCleanupError(good); err != nil {
		t.Fatal(err)
	}
	faults := []func(*errorCleanupResult){
		func(r *errorCleanupResult) { r.blocked = true },
		func(r *errorCleanupResult) { r.code = 1 },
		func(r *errorCleanupResult) { r.err = nil },
		func(r *errorCleanupResult) { r.otherErr = unix.ECHILD },
	}
	for i, fault := range faults {
		mutant := good
		fault(&mutant)
		if errorCleanupError(mutant) == nil {
			t.Fatalf("accepted fault %d", i)
		}
	}
}

func exitedProcessState(t *testing.T, code int) *os.ProcessState {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", code))
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("fixture exit %d: %v", code, err)
	}
	return exitErr.ProcessState
}

func TestRunErrorCleanupLeavesUnrelatedChildWaitable(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unrelated, release := startWaitOwnershipChild(t)
	runReturned := make(chan struct{})
	timedOut := make(chan bool, 1)
	go func() {
		select {
		case <-runReturned:
			timedOut <- false
		case <-time.After(500 * time.Millisecond):
			timedOut <- true
		}
		release()
	}()

	code, err := Run(context.Background(), []string{"/bin/true"}, Options{
		Rules:        []Rule{testRule()},
		EverySyscall: true,
		pidfdOpen: func(pid, flags int) (int, error) {
			fd, err := unix.PidfdOpen(pid, flags)
			if err == nil {
				err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}
			return fd, err
		},
	})
	close(runReturned)
	result := errorCleanupResult{blocked: <-timedOut, code: code, err: err, otherErr: unrelated.Wait()}
	if err := errorCleanupError(result); err != nil {
		t.Fatalf("%v: %+v", err, result)
	}
}

const childPidfdFailureHelper = "SYSCALLHOOK_CHILD_PIDFD_FAILURE_HELPER"

func TestBPFStopsChildPidfdFailureStopsUnregisteredChild(t *testing.T) {
	if os.Getenv(childPidfdFailureHelper) == "1" {
		if seccompMode(os.Getpid()) != "0" {
			t.Fatal("helper requires initial seccomp mode 0")
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		calls := 0
		code, err := Run(context.Background(), []string{"/bin/sh", "-c", "sleep 60 & wait"}, Options{
			Rules: []Rule{testRule()},
			pidfdOpen: func(pid, flags int) (int, error) {
				calls++
				if calls == 1 {
					return unix.PidfdOpen(pid, flags)
				}
				return -1, unix.EMFILE
			},
		})
		if code != 0 || !errors.Is(err, unix.EMFILE) || calls != 2 {
			t.Fatalf("code=%d err=%v pidfd_open calls=%d", code, err, calls)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBPFStopsChildPidfdFailureStopsUnregisteredChild$")
	cmd.Env = append(os.Environ(), childPidfdFailureHelper+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("child pidfd registration failure wedged cleanup: %v\n%s", ctx.Err(), out)
	}
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("helper did not report PASS:\n%s", out)
	}
}

const multipleNewbornFailureHelper = "SYSCALLHOOK_MULTIPLE_NEWBORN_FAILURE_HELPER"

type multipleNewbornResult struct {
	code, calls, parent, first, other int
	err                               error
	record, log                       string
	alive, rescued                    bool
}

func multipleNewbornError(r multipleNewbornResult) error {
	switch {
	case r.code != 0:
		return fmt.Errorf("code=%d", r.code)
	case !errors.Is(r.err, unix.EMFILE):
		return fmt.Errorf("error=%v", r.err)
	case r.calls != 2:
		return fmt.Errorf("pidfd_open calls=%d", r.calls)
	case r.parent <= 0 || r.first <= 0 || r.other <= 0 || r.first == r.other:
		return fmt.Errorf("processes parent=%d first=%d other=%d", r.parent, r.first, r.other)
	case r.record != "":
		return fmt.Errorf("unregistered child ran: %q", r.record)
	case r.alive:
		return errors.New("unregistered child survived cleanup")
	case r.rescued:
		return errors.New("cleanup required an external rescue")
	case r.log != "inject-run: stopping only on bpf()\n":
		return fmt.Errorf("filter log=%q", r.log)
	default:
		return nil
	}
}

func TestMultipleNewbornCleanupOracleRejectsFaults(t *testing.T) {
	good := multipleNewbornResult{err: unix.EMFILE, calls: 2, parent: 1, first: 2, other: 3, log: "inject-run: stopping only on bpf()\n"}
	if err := multipleNewbornError(good); err != nil {
		t.Fatal(err)
	}
	faults := []func(*multipleNewbornResult){
		func(r *multipleNewbornResult) { r.code = 1 },
		func(r *multipleNewbornResult) { r.err = nil },
		func(r *multipleNewbornResult) { r.calls = 3 },
		func(r *multipleNewbornResult) { r.parent = 0 },
		func(r *multipleNewbornResult) { r.other = r.first },
		func(r *multipleNewbornResult) { r.record = "ran\n" },
		func(r *multipleNewbornResult) { r.alive = true },
		func(r *multipleNewbornResult) { r.rescued = true },
		func(r *multipleNewbornResult) { r.log = "" },
	}
	for i, fault := range faults {
		mutant := good
		fault(&mutant)
		if multipleNewbornError(mutant) == nil {
			t.Fatalf("accepted fault %d", i)
		}
	}
}

func TestBPFStopsMultipleNewbornRegistrationFailure(t *testing.T) {
	if os.Getenv(multipleNewbornFailureHelper) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBPFStopsMultipleNewbornRegistrationFailure$")
		cmd.Env = append(os.Environ(), multipleNewbornFailureHelper+"=1")
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("multiple-newborn cleanup timed out: %v\n%s", ctx.Err(), out)
		}
		if err != nil || !strings.Contains(string(out), "PASS") {
			t.Fatalf("helper failed: %v\n%s", err, out)
		}
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if seccompMode(os.Getpid()) != "0" {
		t.Fatal("helper requires initial seccomp mode 0")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "record")
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dirty record path: %v", err)
	}
	var log bytes.Buffer
	runDone := make(chan struct{})
	observed := make(chan struct {
		alive, rescued bool
	}, 1)
	result := multipleNewbornResult{}
	code, runErr := Run(context.Background(), []string{"/bin/sh", "-c",
		`(printf x >> "$1"; exec /bin/sleep 60) & (printf x >> "$1"; exec /bin/sleep 60) & wait`, "sh", marker}, Options{
		Rules: []Rule{testRule()},
		Log:   &log,
		pidfdOpen: func(pid, flags int) (int, error) {
			result.calls++
			if result.calls == 1 {
				result.parent = pid
				return unix.PidfdOpen(pid, flags)
			}
			result.first = pid
			deadline := time.Now().Add(500 * time.Millisecond)
			for time.Now().Before(deadline) && result.other == 0 {
				statuses, err := filepath.Glob("/proc/[0-9]*/status")
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range statuses {
					status, err := os.ReadFile(path)
					if err != nil || !bytes.Contains(status, fmt.Appendf(nil, "TracerPid:\t%d\n", unix.Gettid())) {
						continue
					}
					child, err := strconv.Atoi(filepath.Base(filepath.Dir(path)))
					if err != nil {
						t.Fatal(err)
					}
					if child != pid && child != result.parent {
						result.other = child
						break
					}
				}
				time.Sleep(time.Millisecond)
			}
			if result.other == 0 {
				return -1, unix.EMFILE
			}
			fd, err := unix.PidfdOpen(result.other, 0)
			if err != nil {
				t.Fatal(err)
			}
			status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", result.other))
			if err != nil || !bytes.Contains(status, fmt.Appendf(nil, "TracerPid:\t%d\n", unix.Gettid())) {
				t.Fatalf("second child is not this supervisor's tracee: %s (%v)", status, err)
			}
			go func() {
				defer func() { _ = unix.Close(fd) }()
				rescued := false
				select {
				case <-runDone:
				case <-time.After(time.Second):
					rescued = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0) == nil
				}
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				n, err := unix.Poll(poll, 0)
				if err != nil {
					t.Errorf("pidfd poll: %v", err)
				}
				observed <- struct {
					alive, rescued bool
				}{alive: n == 0 && unix.PidfdSendSignal(fd, 0, nil, 0) == nil, rescued: rescued}
			}()
			return -1, unix.EMFILE
		},
	})
	close(runDone)
	state := <-observed
	result.code, result.err = code, runErr
	result.alive, result.rescued = state.alive, state.rescued
	result.log = log.String()
	if data, err := os.ReadFile(marker); err == nil {
		result.record = string(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if result.other == 0 {
		t.Fatal("second-newborn schedule was not reached")
	}
	if err := multipleNewbornError(result); err != nil {
		t.Fatalf("%v: %+v", err, result)
	}
}
