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

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"golang.org/x/sys/unix"
)

func TestHookSummary(t *testing.T) {
	pcs := func(pcs ...uint32) []inject.LookupSite {
		sites := make([]inject.LookupSite, len(pcs))
		for i, pc := range pcs {
			sites[i].SitePC = pc
		}
		return sites
	}
	for _, tc := range []struct {
		name   string
		result inject.LookupResultRaw
		want   string
	}{
		{"auto", inject.LookupResultRaw{
			Hooks: []inject.LookupHook{
				{Name: "obs_sessions", Kind: inject.HookLookup, MapName: "sessions", Sites: pcs(12, 40)},
				{Name: "obs_flows", Kind: inject.HookLookup, MapName: "flows", Untrusted: true, Sites: pcs(18)},
				{Name: "obs_any", Kind: inject.HookLookup, Generic: true, Untrusted: true, Sites: pcs(51)},
				{Name: "obs_entry", Kind: inject.HookEntry},
				{Name: "obs_tail_call", Kind: inject.HookTailCall, Sites: pcs(60)},
			},
			Skipped: []inject.LookupSite{{SitePC: 7, Reason: "lookup is not in the entry function; ctx belongs to another stack frame"}},
		}, `hook "obs_sessions" (lookup map "sessions", site pc 12, 40), hook "obs_flows" (lookup map "flows", untrusted pointers, site pc 18), hook "obs_any" (lookup generic runtime map, untrusted pointers, site pc 51), hook "obs_entry" (entry), hook "obs_tail_call" (tail_call, site pc 60); skipped pc 7 (lookup is not in the entry function; ctx belongs to another stack frame)`},
		{"generic-named", inject.LookupResultRaw{Hooks: []inject.LookupHook{
			{Name: "obs_any_update", Kind: inject.HookUpdate, Generic: true, Static: true,
				Sites: []inject.LookupSite{{SitePC: 9, MapName: "socks"}, {SitePC: 20}, {SitePC: 31, MapName: "socks"}}},
		}}, `hook "obs_any_update" (update generic map "socks" runtime map, static, site pc 9, 20, 31)`},
		{"copy", inject.LookupResultRaw{Hooks: []inject.LookupHook{
			{Name: "obs_flows", Kind: inject.HookLookup, MapName: "flows", Copied: true, Sites: pcs(18)},
		}}, `hook "obs_flows" (lookup map "flows", value copied to stack, site pc 18)`},
		{"dispatch-static", inject.LookupResultRaw{Hooks: []inject.LookupHook{
			{Name: "d", Kind: inject.HookLookup, MapName: "sessions", Static: true, Dispatch: true, Sites: pcs(13)},
			{Name: "d", Kind: inject.HookEntry, Static: true, Dispatch: true},
			{Name: "d", Kind: inject.HookTailCall, Static: true, Dispatch: true, Sites: pcs(20)},
		}}, `hook "d" (lookup map "sessions", static, dispatch, site pc 13), hook "d" (entry, static, dispatch), hook "d" (tail_call, static, dispatch, site pc 20)`},
	} {
		if got := hookSummary(&tc.result); got != tc.want {
			t.Fatalf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
	// The launcher logs "injected " + summary, which the integration test
	// matches as "injected hook".
	if !strings.HasPrefix(hookSummary(&inject.LookupResultRaw{Hooks: []inject.LookupHook{{Name: "h", Kind: inject.HookEntry}}}), "hook ") {
		t.Fatal("summary does not start with hook")
	}
}

// The hint names copy_read_only only for an untrusted hook on a read-only
// map whose rule may set it (not a dispatch rule), and fires only for an untrusted hook and an errno the kernels without
// arg:untrusted return.
func TestUntrustedHint(t *testing.T) {
	hint := func(err error, hooks ...inject.LookupHook) string {
		return untrustedHint(&inject.LookupResultRaw{Hooks: hooks}, err)
	}
	readOnly := inject.LookupHook{Name: "a", Kind: inject.HookLookup, Untrusted: true, ReadOnly: true}
	writeOnly := inject.LookupHook{Name: "b", Kind: inject.HookLookup, Untrusted: true}
	generic := inject.LookupHook{Name: "c", Kind: inject.HookLookup, Untrusted: true, Generic: true}
	dispatch := inject.LookupHook{Name: "d", Kind: inject.HookLookup, Untrusted: true, ReadOnly: true, Dispatch: true}
	for _, errno := range []unix.Errno{unix.EINVAL, unix.EOPNOTSUPP, unix.EACCES} {
		h := hint(errno, writeOnly, readOnly)
		if !strings.Contains(h, `"static_untrusted": true`) || !strings.Contains(h, "copy_read_only") || !strings.Contains(h, "6.15 and older in our CI matrix reject") {
			t.Fatalf("%v read-only hint: %q", errno, h)
		}
	}
	for name, h := range map[string]string{
		"write-only": hint(unix.EINVAL, writeOnly),
		"generic":    hint(unix.EINVAL, generic),
		"dispatch":   hint(unix.EINVAL, dispatch),
	} {
		if !strings.Contains(h, "static_untrusted") || strings.Contains(h, "copy_read_only") {
			t.Fatalf("%s hint: %q", name, h)
		}
	}
	for name, h := range map[string]string{
		"E2BIG":  hint(unix.E2BIG, readOnly),
		"static": hint(unix.EINVAL, inject.LookupHook{Name: "a", Kind: inject.HookLookup, Static: true, ReadOnly: true}),
		"typed":  hint(unix.EINVAL, inject.LookupHook{Name: "a", Kind: inject.HookLookup}),
	} {
		if h != "" {
			t.Fatalf("%s hint not empty: %q", name, h)
		}
	}
}

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
	defer func() { _ = out.Close() }()
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
			defer func() { _ = out.Close() }()
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

// A load too short to name its program type is left to the kernel, which
// rejects it, even while discovery is on.
func TestShortDiscoveryAttr(t *testing.T) {
	if os.Getenv("SYSCALLHOOK_SHORT") == "1" {
		attr := []byte{byte(ebpf.XDP)}
		_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
		if errno == 0 {
			t.Fatal("short attr loaded")
		}
		fmt.Println("short attr rejected")
		return
	}
	t.Setenv("SYSCALLHOOK_SHORT", "1")
	out, err := os.Create(filepath.Join(t.TempDir(), "child.out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := Run(ctx, []string{os.Args[0], "-test.run=^TestShortDiscoveryAttr$"}, Options{OnDiscover: func(Discovery) {}, Stdout: out, Stderr: out})
	data, _ := os.ReadFile(out.Name())
	if err != nil || code != 0 || !bytes.Contains(data, []byte("short attr rejected")) {
		t.Fatalf("code=%d err=%v child=%s", code, err, data)
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
