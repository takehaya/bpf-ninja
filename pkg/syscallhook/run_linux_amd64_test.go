//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func testRule() Rule {
	floor := int16(-8)
	return Rule{Program: "p", Map: "sessions", Hook: "lookup_hook", StackLowestOffset: &floor}
}

func TestLauncher(t *testing.T) {
	if os.Getenv("SYSCALLHOOK_CHILD") == "1" {
		var wg sync.WaitGroup
		for range 6 {
			wg.Go(func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				for range 12 {
					unix.Getpid()
				}
			})
		}
		wg.Wait()
		fmt.Println("threads passed")
		return
	}
	t.Setenv("SYSCALLHOOK_CHILD", "1")
	out, err := os.Create(filepath.Join(t.TempDir(), "child.out"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := Run(ctx, []string{os.Args[0], "-test.run=^TestLauncher$"}, Options{Rules: []Rule{testRule()}, Stdout: out, Stderr: out})
	if err != nil || code != 0 {
		t.Fatalf("Run: status=%d err=%v", code, err)
	}
	data, _ := os.ReadFile(out.Name())
	if !bytes.Contains(data, []byte("threads passed")) {
		t.Fatalf("missing child output: %s", data)
	}
}

func TestFailPolicy(t *testing.T) {
	if mode := os.Getenv("SYSCALLHOOK_POLICY"); mode != "" {
		attr := validAttr()
		// Invalid func_info address: extraction fails before any BPF capability is
		// needed, but only after exercising injected mmap, info query, and munmap.
		put64(attr, 80, 1)
		_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
		if mode == "closed" && errno != unix.EPERM {
			t.Fatalf("closed returned %v", errno)
		}
		if errno == 0 {
			t.Fatal("invalid program loaded")
		}
		fmt.Printf("policy errno=%d\n", errno)
		return
	}
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprint(closed), func(t *testing.T) {
			mode := "open"
			if closed {
				mode = "closed"
			}
			t.Setenv("SYSCALLHOOK_POLICY", mode)
			out, err := os.Create(filepath.Join(t.TempDir(), "child.out"))
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			var log bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			code, err := Run(ctx, []string{os.Args[0], "-test.run=^TestFailPolicy$"}, Options{Rules: []Rule{testRule()}, FailClosed: closed, Stdout: out, Stderr: out, Log: &log})
			data, _ := os.ReadFile(out.Name())
			if err != nil || code != 0 || !strings.Contains(log.String(), "injection skipped") || !bytes.Contains(data, []byte("policy errno=")) {
				t.Fatalf("code=%d err=%v log=%s child=%s", code, err, &log, data)
			}
		})
	}
}

func TestExitStatus(t *testing.T) {
	code, err := Run(context.Background(), []string{"/bin/sh", "-c", "exit 37"}, Options{Rules: []Rule{testRule()}})
	if err != nil || code != 37 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := Run(ctx, []string{"/bin/sleep", "10"}, Options{Rules: []Rule{testRule()}})
	if err != context.DeadlineExceeded {
		t.Fatalf("cancellation: %v", err)
	}
}
