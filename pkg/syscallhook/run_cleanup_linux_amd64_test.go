//go:build linux && amd64

package syscallhook

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
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
