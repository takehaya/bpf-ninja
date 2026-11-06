//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// SYSCALLHOOK_TEST_EVERY_SYSCALL=1 runs every other test of the package on the every-syscall path.
func init() {
	testEverySyscall = os.Getenv("SYSCALLHOOK_TEST_EVERY_SYSCALL") == "1"
	if os.Getenv(stopsChildEnv) == "leader-exit" {
		leaderExit()
	}
}

// leaderExit runs in init, on the main thread, which is the thread group
// leader. It ends that thread alone. Another thread starts a child process,
// checks that it still runs after the leader is gone, and exits the process.
func leaderExit() {
	go func() {
		child := exec.Command("/bin/sleep", "30")
		if err := child.Start(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
		leader := statusField(fmt.Sprintf("/proc/%d/status", os.Getpid()), "State")
		fmt.Printf("child %d alive=%t leader=%s\n", child.Process.Pid, unix.Kill(child.Process.Pid, 0) == nil, leader[:1])
		os.Exit(4)
	}()
	// Syscall, not RawSyscall: the runtime sees this thread in a syscall and
	// does not wait for it.
	_, _, _ = unix.Syscall(unix.SYS_EXIT, 0, 0, 0)
}

const stopsChildEnv = "SYSCALLHOOK_STOPS_CHILD"

// mapCreateAttr is a static array-map attr, for use in a raw fork child.
var mapCreateAttr = [20]byte{0: 2 /* array */, 4: 4 /* key */, 8: 4 /* value */, 12: 1 /* entries */}

func rawMapCreate() (uintptr, unix.Errno) {
	fd, _, errno := unix.RawSyscall(unix.SYS_BPF, unix.BPF_MAP_CREATE, uintptr(unsafe.Pointer(&mapCreateAttr)), uintptr(len(mapCreateAttr)))
	return fd, errno
}

func installOwnFilter(t *testing.T, action uint32, nr uint32) {
	t.Helper()
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: nr},
		{Code: unix.BPF_RET | unix.BPF_K, K: action},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		t.Fatalf("seccomp: %v", errno)
	}
}

func printMapCreate(what string) {
	_, errno := rawMapCreate()
	fmt.Printf("%s errno=%d\n", what, int(errno))
}

func statusField(path, field string) string {
	data, _ := os.ReadFile(path)
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, field+":\t"); ok {
			return v
		}
	}
	return "?"
}

// stopsChild is the target. Its stdout is what the two paths must agree on.
func stopsChild(t *testing.T, mode string) {
	runtime.LockOSThread()
	switch mode {
	case "status":
		fmt.Printf("seccomp=%s nnp=%s\n", statusField("/proc/self/status", "Seccomp"), statusField("/proc/self/status", "NoNewPrivs"))
	case "getppid":
		for range 2000 {
			unix.Getppid()
		}
	case "mapupdate":
		fd, errno := rawMapCreate()
		if errno != 0 {
			t.Fatal(errno)
		}
		var key uint32
		var value [4]byte
		attr := [32]byte{}
		*(*uint32)(unsafe.Pointer(&attr[0])) = uint32(fd)
		*(*uint64)(unsafe.Pointer(&attr[8])) = uint64(uintptr(unsafe.Pointer(&key)))
		*(*uint64)(unsafe.Pointer(&attr[16])) = uint64(uintptr(unsafe.Pointer(&value)))
		for range 1000 {
			if _, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_UPDATE_ELEM, uintptr(unsafe.Pointer(&attr)), uintptr(len(attr))); errno != 0 {
				t.Fatal(errno)
			}
		}
		fmt.Println("updates ok")
	case "thread-bpf":
		done := make(chan unix.Errno)
		for range 4 {
			go func() {
				runtime.LockOSThread()
				_, errno := rawMapCreate()
				done <- errno
			}()
		}
		for range 4 {
			fmt.Printf("thread errno=%d\n", int(<-done))
		}
	case "exec-bpf":
		if os.Getenv("SYSCALLHOOK_STOPS_EXECED") == "" {
			env := append(os.Environ(), "SYSCALLHOOK_STOPS_EXECED=1")
			if err := syscall.Exec(os.Args[0], os.Args, env); err != nil {
				t.Fatal(err)
			}
		}
		printMapCreate("after exec")
	case "exec-from-thread":
		if os.Getenv("SYSCALLHOOK_STOPS_EXECED") != "" {
			printMapCreate("after thread exec")
			return
		}
		go func() {
			runtime.LockOSThread()
			env := append(os.Environ(), "SYSCALLHOOK_STOPS_EXECED=1")
			if err := syscall.Exec(os.Args[0], os.Args, env); err != nil {
				fmt.Println(err)
			}
		}()
		time.Sleep(10 * time.Second)
	case "fork-bpf":
		// A raw fork: the child runs only raw syscalls.
		pid, _, errno := unix.RawSyscall(unix.SYS_FORK, 0, 0, 0)
		if errno != 0 {
			t.Fatal(errno)
		}
		if pid == 0 {
			_, errno := rawMapCreate()
			_, _, _ = unix.RawSyscall(unix.SYS_EXIT_GROUP, uintptr(errno), 0, 0)
		}
		var status unix.WaitStatus
		_, err := unix.Wait4(int(pid), &status, 0, nil)
		fmt.Printf("fork child errno=%d err=%v\n", status.ExitStatus(), err)
	case "clone-bpf":
		// clone with no CLONE_THREAD and an exit signal other than SIGCHLD:
		// PTRACE_O_TRACECLONE reports it and the old path detaches it.
		pid, _, errno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGUSR2), 0, 0, 0, 0, 0)
		if errno != 0 {
			t.Fatal(errno)
		}
		if pid == 0 {
			_, errno := rawMapCreate()
			_, _, _ = unix.RawSyscall(unix.SYS_EXIT_GROUP, uintptr(errno), 0, 0)
		}
		var status unix.WaitStatus
		_, err := unix.Wait4(int(pid), &status, unix.WALL, nil)
		fmt.Printf("clone child errno=%d err=%v\n", status.ExitStatus(), err)
	case "vfork-exec-bpf", "tracer-pid":
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Env = append(os.Environ(), stopsChildEnv+"="+map[string]string{"vfork-exec-bpf": "bpf-only", "tracer-pid": "print-tracer"}[mode])
		out, err := cmd.CombinedOutput()
		fmt.Printf("%s err=%v\n", bytes.TrimSuffix(out, []byte("\n")), err)
	case "bpf-only":
		printMapCreate("execed child")
		os.Exit(0)
	case "print-tracer":
		fmt.Printf("child traced=%t\n", statusField("/proc/self/status", "TracerPid") != "0")
		os.Exit(0)
	case "own-errno":
		installOwnFilter(t, unix.SECCOMP_RET_ERRNO|uint32(unix.EACCES), unix.SYS_BPF)
		printMapCreate("own errno")
	case "own-trace-other":
		installOwnFilter(t, unix.SECCOMP_RET_TRACE|7, unix.SYS_GETPPID)
		_, _, errno := unix.Syscall(unix.SYS_GETPPID, 0, 0, 0)
		fmt.Printf("getppid errno=%d\n", int(errno))
		printMapCreate("bpf")
	case "own-trace-bpf":
		installOwnFilter(t, unix.SECCOMP_RET_TRACE|7, unix.SYS_BPF)
		printMapCreate("traced bpf")
	case "own-allow":
		installOwnFilter(t, unix.SECCOMP_RET_ALLOW, unix.SYS_BPF)
		printMapCreate("after own filter")
	case "own-kill":
		installOwnFilter(t, unix.SECCOMP_RET_KILL_PROCESS, unix.SYS_BPF)
		printMapCreate("not reached")
	case "common-attrs":
		// An attr over maxAttr makes entry refuse the load under fail-closed,
		// before it reads anything, so the kernel's answer never shows.
		attr := make([]byte, maxAttr+1)
		for _, cmd := range []uintptr{unix.BPF_PROG_LOAD, unix.BPF_BTF_LOAD} {
			_, _, errno := unix.Syscall6(unix.SYS_BPF, cmd|bpfCommonAttrs, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)), 0, 0, 0)
			fmt.Printf("cmd %d errno=%d\n", cmd, int(errno))
		}
	case "signal":
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGUSR1)
		if err := unix.Kill(os.Getpid(), unix.SIGUSR1); err != nil {
			t.Fatal(err)
		}
		fmt.Println("got", <-ch)
		printMapCreate("after signal")
	case "group-stop":
		// Does a child of the target stop on SIGSTOP, as an untraced process does?
		cmd := exec.Command("/bin/sleep", "30")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Kill() }()
		time.Sleep(200 * time.Millisecond)
		stopped, continued := stopAndContinue(cmd.Process.Pid)
		fmt.Printf("child stopped=%t continued=%t\n", stopped, continued)
	case "group-stop-self":
		// A helper stops and continues the target itself.
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Env = append(os.Environ(), stopsChildEnv+"=stop-parent")
		out, err := cmd.CombinedOutput()
		fmt.Printf("%s err=%v\n", bytes.TrimSuffix(out, []byte("\n")), err)
	case "stop-parent":
		stopped, continued := stopAndContinue(os.Getppid())
		fmt.Printf("target stopped=%t continued=%t\n", stopped, continued)
		os.Exit(0)
	default:
		t.Fatalf("unknown child mode %q", mode)
	}
}

// stopAndContinue reports whether pid stops on SIGSTOP and runs again on
// SIGCONT. A group stop under a tracer shows as "t" in State, else as "T".
func stopAndContinue(pid int) (stopped, continued bool) {
	stoppedState := func() bool {
		return strings.ContainsAny(statusField(fmt.Sprintf("/proc/%d/status", pid), "State")[:1], "tT")
	}
	_ = unix.Kill(pid, unix.SIGSTOP)
	time.Sleep(300 * time.Millisecond)
	stopped = stoppedState()
	_ = unix.Kill(pid, unix.SIGCONT)
	time.Sleep(300 * time.Millisecond)
	return stopped, !stoppedState()
}

func runStops(t *testing.T, mode string, filtered bool, extra ...func(*Options)) (code int, stdout, log string, stops int, err error) {
	t.Helper()
	t.Setenv(stopsChildEnv, mode)
	out, cerr := os.Create(filepath.Join(t.TempDir(), "child.out"))
	if cerr != nil {
		t.Fatal(cerr)
	}
	defer func() { _ = out.Close() }()
	var logs bytes.Buffer
	opts := Options{Stdout: out, Stderr: out, Log: &logs, EverySyscall: !filtered, stops: &stops, Rules: []Rule{testRule()}}
	for _, f := range extra {
		f(&opts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	code, err = Run(ctx, []string{os.Args[0], "-test.run=^TestBPFStopsBehaviour$"}, opts)
	data, _ := os.ReadFile(out.Name())
	// go test appends its own lines; only the child's own results matter.
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && line != "PASS" {
			kept = append(kept, line)
		}
	}
	return code, strings.Join(kept, "\n"), logs.String(), stops, err
}

// Each mode runs on both paths; want is the target's output, which must not
// depend on the path unless wantFiltered says how it does.
func TestBPFStopsBehaviour(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if mode := os.Getenv(stopsChildEnv); mode != "" {
		stopsChild(t, mode)
		return
	}
	thread := strings.Repeat("thread errno=0\n", 4)
	for _, tc := range []struct {
		mode, want, wantFiltered string
		code                     int
	}{
		{mode: "status", want: "seccomp=0 nnp=0", wantFiltered: "seccomp=2 nnp=0"},
		{mode: "thread-bpf", want: strings.TrimSuffix(thread, "\n")},
		{mode: "exec-bpf", want: "after exec errno=0"},
		{mode: "exec-from-thread", want: "after thread exec errno=0"},
		{mode: "fork-bpf", want: "fork child errno=0 err=<nil>"},
		{mode: "clone-bpf", want: "clone child errno=0 err=<nil>"},
		{mode: "vfork-exec-bpf", want: "execed child errno=0 err=<nil>"},
		{mode: "tracer-pid", want: "child traced=false err=<nil>", wantFiltered: "child traced=true err=<nil>"},
		{mode: "own-errno", want: fmt.Sprintf("own errno errno=%d", int(unix.EACCES))},
		{mode: "own-trace-other", want: fmt.Sprintf("getppid errno=%d\nbpf errno=0", int(unix.ENOSYS))},
		{mode: "own-trace-bpf", want: fmt.Sprintf("traced bpf errno=%d", int(unix.ENOSYS))},
		{mode: "own-allow", want: "after own filter errno=0"},
		{mode: "own-kill", want: "", code: 128 + int(unix.SIGSYS)},
		{mode: "signal", want: "got user defined signal 1\nafter signal errno=0"},
		// The followed child and the target stay in a group stop until SIGCONT.
		{mode: "group-stop", want: "child stopped=true continued=true"},
		{mode: "group-stop-self", want: "target stopped=true continued=true err=<nil>"},
	} {
		for _, filtered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", tc.mode, filtered), func(t *testing.T) {
				code, out, log, _, err := runStops(t, tc.mode, filtered)
				want := tc.want
				if filtered && tc.wantFiltered != "" {
					want = tc.wantFiltered
				}
				if err != nil || code != tc.code || out != want {
					t.Fatalf("code=%d (want %d) err=%v\n got %q\nwant %q\nlog: %s", code, tc.code, err, out, want, log)
				}
				if on := strings.Contains(log, "stopping only on bpf()"); on != filtered {
					t.Fatalf("filter line present=%t\n%s", on, log)
				}
				// seccomp(2) and prctl(PR_SET_SECCOMP) are not traced, so nothing is logged for them.
				if strings.Contains(log, "target installs a seccomp filter") {
					t.Fatalf("own-filter log line present:\n%s", log)
				}
				// Neither the default nor the override falls back here.
				if strings.Contains(log, "stopping on every syscall") {
					t.Fatalf("fallback line present:\n%s", log)
				}
			})
		}
	}
}

// The stop count is what the filter is for. The bounds leave room for the
// test binary's start; the old path needs at least two stops per call.
func TestBPFStopsCount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	for _, tc := range []struct {
		mode     string
		filtered bool
		min, max int
	}{
		{"getppid", false, 4000, 1 << 30},
		{"getppid", true, 0, 500},
		{"mapupdate", false, 2000, 1 << 30},
		// Map operations do not stop at all: only loads are traced.
		{"mapupdate", true, 0, 500},
	} {
		code, _, log, n, err := runStops(t, tc.mode, tc.filtered, func(o *Options) { o.Rules = nil; o.OnDiscover = func(Discovery) {} })
		t.Logf("%s filtered=%t: %d stops", tc.mode, tc.filtered, n)
		if err != nil || code != 0 || n < tc.min || n > tc.max {
			t.Fatalf("%s filtered=%t: %d stops, want %d..%d; code=%d err=%v\n%s", tc.mode, tc.filtered, n, tc.min, tc.max, code, err, log)
		}
	}
}

// Run with no options installs the filter. Self-contained, so it also runs
// against trees where every-syscall stops are the only path.
func TestBPFStopsDefault(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	var logs bytes.Buffer
	code, err := Run(context.Background(), []string{"/bin/sh", "-c", `grep '^Seccomp:' /proc/$$/status`},
		Options{Stdout: out, Stderr: out, Log: &logs, Rules: []Rule{testRule()}})
	data, _ := os.ReadFile(out.Name())
	if err != nil || code != 0 || string(data) != "Seccomp:\t2\n" || !strings.Contains(logs.String(), "stopping only on bpf()") {
		t.Fatalf("code=%d err=%v target %q\n%s", code, err, data, &logs)
	}
}

// Where the filter cannot be installed, the target runs on the every-syscall
// path, the log says why in one line, and a matched load is still instrumented.
// The supervisor is a child whose locked thread starts the target, so the
// filter or dropped capability reaches only that case's target. It checks the
// loaded program itself, since a loader without CAP_SYS_ADMIN cannot read the
// program BTF, and reports its stops, which the parent compares with a run
// that takes the filter.
func TestBPFStopsFallback(t *testing.T) {
	how := os.Getenv("SYSCALLHOOK_FALLBACK")
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if how != "" {
		runtime.LockOSThread()
		loader := "hook"
		switch how {
		case "inherited":
			// A parent filter that refuses seccomp(2) with EPERM.
			installOwnFilter(t, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM), unix.SYS_SECCOMP)
		case "no-cap-sys-admin":
			// The target loses CAP_SYS_ADMIN at exec; this thread keeps it.
			if err := unix.Prctl(unix.PR_CAPBSET_DROP, unix.CAP_SYS_ADMIN, 0, 0, 0); err != nil {
				t.Fatal(err)
			}
			hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
			var data [2]unix.CapUserData
			if err := unix.Capget(&hdr, &data[0]); err != nil {
				t.Fatal(err)
			}
			data[0].Inheritable &^= 1 << unix.CAP_SYS_ADMIN
			if err := unix.Capset(&hdr, &data[0]); err != nil {
				t.Fatal(err)
			}
			loader = "hook-nocap"
		}
		t.Setenv("SYSCALLHOOK_INTEGRATION_CHILD", loader)
		var stops int
		var hooks []string
		code, err := Run(context.Background(), []string{os.Args[0], "-test.run=^TestIntegrationLoader$"},
			Options{Log: os.Stdout, Rules: []Rule{testRule()}, stops: &stops, OnInject: func(inj Injection) {
				hooks = append(hooks, loadedHook(inj.ProgID))
			}})
		fmt.Printf("code=%d err=%v hooks=%v\nstops=%d\n", code, err, hooks, stops)
		return
	}
	run := func(t *testing.T, how, line string) (stops int) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestBPFStopsFallback$")
		cmd.Env = append(os.Environ(), "SYSCALLHOOK_FALLBACK="+how)
		out, err := cmd.CombinedOutput()
		got := string(out)
		_, serr := fmt.Sscanf(got[strings.LastIndex(got, "stops="):], "stops=%d", &stops)
		if err != nil || serr != nil || strings.Count(got, line) != 1 || strings.Count(got, "inject-run: stopping ") != 1 ||
			!strings.Contains(got, "code=0 err=<nil> hooks=[hook=true action=2]") {
			t.Fatalf("err=%v\n%s", err, got)
		}
		t.Logf("%s: %d stops", how, stops)
		return stops
	}
	filtered := run(t, "default", "inject-run: stopping only on bpf()\n")
	for _, tc := range []struct{ how, line string }{
		{"inherited", "inject-run: stopping on every syscall: the target already runs under a seccomp filter (Seccomp 2)\n"},
		{"no-cap-sys-admin", "inject-run: stopping on every syscall: seccomp(2) refused the filter: the target lacks CAP_SYS_ADMIN and no_new_privs is not set\n"},
	} {
		t.Run(tc.how, func(t *testing.T) {
			// The loader's own syscalls now stop twice each.
			if stops := run(t, tc.how, tc.line); stops < 2*filtered {
				t.Fatalf("%d stops, want at least twice the %d of the filtered run", stops, filtered)
			}
		})
	}
}

// loadedHook reports whether the program has an injected hook in its
// func_info, and what it returns for a test packet.
func loadedHook(id uint32) string {
	p, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return err.Error()
	}
	defer func() { _ = p.Close() }()
	info, err := p.Info()
	if err != nil {
		return err.Error()
	}
	funcs, err := info.FuncInfos()
	if err != nil {
		return err.Error()
	}
	found := false
	for _, f := range funcs {
		found = found || strings.HasPrefix(f.Func.Name, "lookup_hook")
	}
	action, _, err := p.Test(make([]byte, 64))
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("hook=%t action=%d", found, action)
}

// When the target exits, Run kills the followed children and returns its exit
// code at once. The old path neither follows nor waits for them.
func TestBPFStopsOutlivingChild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	file := filepath.Join(t.TempDir(), "late")
	script := fmt.Sprintf(`(sleep 1; SYSCALLHOOK_STOPS_CHILD=bpf-only %s -test.run=^TestBPFStopsBehaviour$ > %s) & exit 3`, os.Args[0], file)
	for _, filtered := range []bool{false, true} {
		_ = os.Remove(file)
		start := time.Now()
		code, err := Run(context.Background(), []string{"/bin/sh", "-c", script}, Options{EverySyscall: !filtered, Rules: []Rule{testRule()}})
		took := time.Since(start)
		if err != nil || code != 3 || took >= time.Second {
			t.Fatalf("filtered=%t code=%d err=%v after %v", filtered, code, err, took)
		}
		time.Sleep(1500 * time.Millisecond)
		data, _ := os.ReadFile(file)
		if ran := strings.Contains(string(data), "execed child errno=0"); ran == filtered {
			t.Fatalf("filtered=%t late child ran=%t: %q", filtered, ran, data)
		}
	}
}

// The leader thread can exit before the process does. That is not the end of
// the target: its child keeps running until the process exits.
func TestBPFStopsLeaderExit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	for _, filtered := range []bool{false, true} {
		start := time.Now()
		code, out, log, _, err := runStops(t, "leader-exit", filtered)
		took := time.Since(start)
		var child int
		var alive bool
		var leader string
		if _, serr := fmt.Sscanf(out, "child %d alive=%t leader=%s", &child, &alive, &leader); serr != nil || err != nil || code != 4 || !alive || leader != "Z" || took > 10*time.Second {
			t.Fatalf("filtered=%t code=%d err=%v after %v: %q\n%s", filtered, code, err, took, out, log)
		}
		time.Sleep(100 * time.Millisecond)
		running := unix.Kill(child, 0) == nil && !strings.HasPrefix(statusField(fmt.Sprintf("/proc/%d/status", child), "State"), "Z")
		_ = unix.Kill(child, unix.SIGKILL)
		if running == filtered {
			t.Fatalf("filtered=%t: child running=%t after the target exited", filtered, running)
		}
	}
}

// Cancellation ends a followed child too; the old path leaves it running.
func TestBPFStopsCancelEndsChild(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pid")
	script := fmt.Sprintf(`sleep 60 & echo $! > %s; wait`, file)
	for _, filtered := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(500*time.Millisecond, cancel)
		start := time.Now()
		_, err := Run(ctx, []string{"/bin/sh", "-c", script}, Options{EverySyscall: !filtered, Rules: []Rule{testRule()}})
		cancel()
		if err != context.Canceled || time.Since(start) > 10*time.Second {
			t.Fatalf("filtered=%t: %v after %v", filtered, err, time.Since(start))
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		time.Sleep(100 * time.Millisecond)
		alive := unix.Kill(pid, 0) == nil && !strings.HasPrefix(statusField(fmt.Sprintf("/proc/%d/status", pid), "State"), "Z")
		if alive == filtered {
			t.Fatalf("filtered=%t: child alive=%t", filtered, alive)
		}
		_ = unix.Kill(pid, unix.SIGKILL)
	}
}

// A followed child is only kept running: a load matching a rule stays as it is.
func TestBPFStopsChildNotInstrumented(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if os.Getenv("SYSCALLHOOK_FOLLOWED_LOADER") == "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestIntegrationLoader$")
		cmd.Env = append(os.Environ(), "SYSCALLHOOK_INTEGRATION_CHILD=plain")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Setenv("SYSCALLHOOK_FOLLOWED_LOADER", "1")
	var logs bytes.Buffer
	var injected int
	out := filepath.Join(t.TempDir(), "out")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	code, err := Run(context.Background(), []string{os.Args[0], "-test.run=^TestBPFStopsChildNotInstrumented$"},
		Options{Rules: []Rule{testRule()}, Stdout: f, Stderr: f, Log: &logs, OnInject: func(Injection) { injected++ }})
	data, _ := os.ReadFile(out)
	if err != nil || code != 0 || injected != 0 || !strings.Contains(logs.String(), "stopping only on bpf()") {
		t.Fatalf("code=%d err=%v injected=%d\n%s\n%s", code, err, injected, &logs, data)
	}
}

// A target's user-notify filter outranks SECCOMP_RET_TRACE, so with a listener
// that continues the call, the load reaches the kernel unseen and uninstrumented.
// The every-syscall path is not run here: it sees the load and deadlocks, since
// replaying it waits on the loading thread while the listener sits in an
// unresumed stop, and cancelling does not end that wait.
func TestBPFStopsTargetListener(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if os.Getenv("SYSCALLHOOK_LISTENER") == "1" {
		filter := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_BPF},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		}
		prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		flags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH)
		listener, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&prog)))
		if errno != 0 {
			t.Fatal(errno)
		}
		go func() {
			for {
				var notif [80]byte
				if _, _, errno := unix.Syscall(unix.SYS_IOCTL, listener, 0xc0502100, uintptr(unsafe.Pointer(&notif))); errno != 0 {
					continue
				}
				var resp [24]byte
				copy(resp[:8], notif[:8])
				resp[20] = 1 // SECCOMP_USER_NOTIF_FLAG_CONTINUE
				_, _, _ = unix.Syscall(unix.SYS_IOCTL, listener, 0xc0182101, uintptr(unsafe.Pointer(&resp)))
			}
		}()
		loadIntegrationProgram(t, "plain")
		return
	}
	t.Setenv("SYSCALLHOOK_LISTENER", "1")
	var logs bytes.Buffer
	var injected int
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	code, err := Run(ctx, []string{os.Args[0], "-test.run=^TestBPFStopsTargetListener$"},
		Options{Rules: []Rule{testRule()}, Stdout: out, Stderr: out, Log: &logs, OnInject: func(Injection) { injected++ }})
	if err != nil || code != 0 || injected != 0 || !strings.Contains(logs.String(), "stopping only on bpf()") {
		t.Fatalf("code=%d err=%v injected=%d\n%s", code, err, injected, &logs)
	}
}

// Entry strips BPF_COMMON_ATTRS before it compares the command, and the filter
// traces such a load, so under fail-closed it is refused like any other.
func TestBPFStopsCommonAttrs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	want := fmt.Sprintf("cmd %d errno=%d\ncmd %d errno=%d", unix.BPF_PROG_LOAD, int(unix.EPERM), unix.BPF_BTF_LOAD, int(unix.EPERM))
	for _, filtered := range []bool{false, true} {
		code, out, log, _, err := runStops(t, "common-attrs", filtered, func(o *Options) { o.FailClosed = true })
		if err != nil || code != 0 || out != want {
			t.Fatalf("filtered=%t code=%d err=%v\n got %q\nwant %q\nlog: %s", filtered, code, err, out, want, log)
		}
		for _, cmd := range []int{unix.BPF_PROG_LOAD, unix.BPF_BTF_LOAD} {
			if line := fmt.Sprintf("bpf command %d: injection skipped: attr exceeds", cmd|bpfCommonAttrs); !strings.Contains(log, line) {
				t.Fatalf("filtered=%t: no %q in\n%s", filtered, line, log)
			}
		}
	}
}
