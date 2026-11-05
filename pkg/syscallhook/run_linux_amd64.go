//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"

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
	// transformed program replaced, before the target sees the new fd. It must
	// not wait on the target.
	OnInject func(Injection)
	// OnDiscover, if set, is called on the tracing thread for every XDP or tc
	// program load whose attr carries BTF, whether or not a rule selects it,
	// before any transform. Rules may then be empty. It must not wait on the
	// target.
	OnDiscover func(Discovery)
}

// Discovery lists the lookups of one program load (see
// inject.DiscoverLookupsRaw), all its map calls with lookups among them
// (inject.DiscoverMapCallsRaw), and the kinds of the maps it references, by
// kernel map name. Program is the kernel program name and Func the entry
// function.
type Discovery struct {
	Program, Func string
	Type          ebpf.ProgramType
	Lookups       []inject.LookupSite
	Calls         []inject.LookupSite
	Maps          map[string]ebpf.MapType
	Stack         inject.StackReport
}

// Injection describes one successful injected load. Program is the kernel
// program name and Func the entry function. ProgID is the loaded program's
// kernel ID, zero if the tracee could not query it. Hooks and Skipped are
// the transform's (see inject.LookupResult).
type Injection struct {
	HookForm      HookForm
	Program, Func string
	Type          ebpf.ProgramType
	ProgID        uint32
	Hooks         []inject.LookupHook
	Skipped       []inject.LookupSite
	Stack         inject.StackReport
}

type rememberedBTF struct {
	blob []byte
	id   uint32
}
type thread struct {
	btf     []byte
	newborn bool
}
type supervisor struct {
	probeUntrusted            func() error
	probeTailCallReachability func() error
	options                   Options
	btf                       map[uint32]rememberedBTF
	cacheBytes                int
}

var errTrialVerifier = errors.New("trial load was rejected by the verifier")

var errIndirectJump = errors.New("indirect jump")

func (s *supervisor) log(format string, args ...any) {
	_, _ = fmt.Fprintf(s.options.Log, "inject-run: "+format+"\n", args...)
}

func retryOriginalOrRefuse(failClosed bool, retry func() (int64, error)) (int64, error) {
	if failClosed {
		return -int64(unix.EPERM), nil
	}
	return retry()
}

// Run starts argv with PTRACE_TRACEME and returns the child's exit status (or
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
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = unix.Kill(pid, unix.SIGKILL)
		case <-done:
		}
	}()
	threads := map[int]*thread{pid: {}}
	finished := false
	defer func() {
		if finished {
			return
		}
		_ = unix.Kill(pid, unix.SIGKILL)
		// Reap any thread first: waiting for the leader before its dying siblings
		// can deadlock because Linux delays the leader's final wait notification.
		for {
			var status unix.WaitStatus
			tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOTHREAD, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				break
			}
			if status.Stopped() {
				_ = unix.PtraceCont(tid, int(unix.SIGKILL))
			}
		}
	}()
	status, err := waitThread(pid)
	if err != nil {
		return 0, err
	}
	if !status.Stopped() {
		return 0, fmt.Errorf("target did not stop at exec: %#x", uint32(status))
	}
	// TODO: follow FORK/VFORK with per-process caches before supporting loaders
	// which delegate BPF loads to child processes.
	flags := unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_EXITKILL
	if err := unix.PtraceSetOptions(pid, flags); err != nil {
		return 0, err
	}
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		return 0, err
	}
	s := supervisor{probeUntrusted: sync.OnceValue(probeUntrusted), probeTailCallReachability: sync.OnceValue(probeTailCallReachability),
		options: opts, btf: make(map[uint32]rememberedBTF)}
	exitCode := 0
	for len(threads) > 0 {
		tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOTHREAD, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		t := threads[tid]
		if t == nil {
			t = &thread{newborn: true}
			threads[tid] = t
		}
		if status.Exited() || status.Signaled() {
			delete(threads, tid)
			if tid == pid {
				if status.Exited() {
					exitCode = status.ExitStatus()
				} else {
					exitCode = 128 + int(status.Signal())
				}
			}
			continue
		}
		if !status.Stopped() {
			continue
		}
		sig := int(status.StopSignal())
		event := status.TrapCause()
		switch {
		case event == unix.PTRACE_EVENT_CLONE:
			child, err := unix.PtraceGetEventMsg(tid)
			if err == unix.ESRCH {
				continue
			}
			if err != nil {
				return 0, err
			}
			if threads[int(child)] == nil {
				threads[int(child)] = &thread{newborn: true}
			}
			sig = 0
		case event == unix.PTRACE_EVENT_EXEC:
			// exec from a nonleader changes its tid to pid and destroys other threads.
			threads = map[int]*thread{pid: {}}
			s.btf = make(map[uint32]rememberedBTF)
			s.cacheBytes = 0
			sig = 0
		case t.newborn && status.StopSignal() == unix.SIGSTOP:
			t.newborn = false
			// TRACECLONE can also report clone without CLONE_THREAD. Those separate
			// processes are outside this prototype; detach without changing them.
			if !sameThreadGroup(pid, tid) {
				if err := unix.PtraceDetach(tid); err != nil {
					return 0, err
				}
				delete(threads, tid)
				continue
			}
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
			sig = 0
		}
		if err := unix.PtraceSyscall(tid, sig); err != nil && err != unix.ESRCH {
			return 0, err
		}
	}
	finished = true
	if ctx.Err() != nil {
		return exitCode, ctx.Err()
	}
	return exitCode, nil
}

func sameThreadGroup(pid, tid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return false
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		var group int
		if _, err := fmt.Sscanf(string(line), "Tgid:\t%d", &group); err == nil {
			return group == pid
		}
	}
	return false
}

func (s *supervisor) entry(pid int, t *thread, regs unix.PtraceRegs) error {
	command := uint32(regs.Rdi)
	if command != unix.BPF_BTF_LOAD && command != unix.BPF_PROG_LOAD {
		return nil
	}
	t.btf = nil
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
		return s.skipEntry(pid, regs, err)
	}
	discover := s.options.OnDiscover != nil && len(attr) >= 4 && inject.ContextType(ebpf.ProgramType(u32(attr, 0))) != ""
	if rule == nil && !discover {
		return nil
	}
	if err := parseProgAttr(attr); err != nil {
		if rule == nil {
			s.log("program %q: lookup discovery skipped: %v", name, err)
			return nil
		}
		return s.skipEntry(pid, regs, err)
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
		ret, err := r.call(unix.SYS_BPF, regs.Rdi, regs.Rsi, regs.Rdx)
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
	var result *inject.LookupResultRaw
	var entry string
	var injectErr error
	if stackErr != nil {
		injectErr = fmt.Errorf("stack depth unavailable: %w", stackErr)
	} else {
		ret, result, entry, injectErr = s.transformLoad(r, attr, *rule, form, stack)
	}
	if r.broken != nil {
		return r.broken
	}
	summary := ""
	if result != nil {
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
		refuse := s.options.FailClosed || stackErr != nil && !rule.Auto && !errors.Is(stackErr, errTrialVerifier) && !errors.Is(stackErr, errIndirectJump)
		ret, err = retryOriginalOrRefuse(refuse, func() (int64, error) {
			// Substituted attrs and buffers live in scratch memory, so the original
			// registers, attr and input buffers still describe the unchanged load.
			// A verifier attempt may have written the caller-owned log buffer.
			return r.call(unix.SYS_BPF, regs.Rdi, regs.Rsi, regs.Rdx)
		})
		if err != nil {
			return err
		}
	} else {
		s.log("program %q: injected %s, tracee fd %d", name, summary, ret)
		if s.options.OnInject != nil {
			inj := Injection{HookForm: form, Program: name, Func: entry, Type: ebpf.ProgramType(u32(attr, 0)), Hooks: result.Hooks, Skipped: result.Skipped, Stack: stack}
			// bpf_prog_info starts with type and id.
			if info, err := r.info(uint32(ret), 8); err != nil {
				s.log("program %q: cannot query program ID: %v", name, err)
			} else {
				inj.ProgID = u32(info, 4)
			}
			if r.broken != nil {
				return r.broken
			}
			s.options.OnInject(inj)
		}
	}
	return r.finish(ret)
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
	blob := t.btf
	t.btf = nil
	if uint32(regs.Rdi) != unix.BPF_BTF_LOAD || int64(regs.Rax) < 0 || len(blob) == 0 {
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

func (s *supervisor) preloadDepths(r *remote, attr []byte, rounding int) (report inject.StackReport, err error) {
	if len(attr) < 68 || u32(attr, 64) != 0 {
		return report, fmt.Errorf("offloaded programs do not expose local verifier stack accounting")
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
	trial := bytes.Clone(attr)
	put32(trial, 24, 4) // BPF_LOG_STATS
	put32(trial, 28, logSize)
	put64(trial, 32, logAddr)
	fd, loadErr := r.bpf(unix.BPF_PROG_LOAD, trial)
	readLog := func() (string, error) {
		logBytes, readErr := readMemory(r.pid, logAddr, logSize)
		if readErr != nil {
			return "", fmt.Errorf("reading verifier stats: %w", readErr)
		}
		return cstring(logBytes), nil
	}
	if loadErr != nil {
		log, readErr := readLog()
		if readErr != nil {
			return report, readErr
		}
		if (errors.Is(loadErr, unix.EACCES) || errors.Is(loadErr, unix.EINVAL)) && !strings.Contains(log, "processed") {
			return report, fmt.Errorf("%w: %v: %s", errTrialVerifier, loadErr, strings.TrimSpace(log))
		}
		if log != "" {
			return report, fmt.Errorf("trial PROG_LOAD: %w: %s", loadErr, strings.TrimSpace(log))
		}
		return report, fmt.Errorf("trial PROG_LOAD: %w", loadErr)
	}
	err = withTrialProgram(fd, func(fd int64) error {
		closed, closeErr := r.call(unix.SYS_CLOSE, uint64(fd))
		return syscallError(closed, closeErr)
	}, func() error {
		log, readErr := readLog()
		if readErr != nil {
			return readErr
		}
		depths, parseErr := inject.ParseStackDepths(log)
		if parseErr != nil {
			return parseErr
		}
		records, infoErr := r.progFuncInfo(uint32(fd))
		if infoErr != nil {
			return infoErr
		}
		names, namesErr := loadedFunctionNames(records, spec)
		if namesErr != nil {
			return namesErr
		}
		report, parseErr = inject.FrameFloorsRaw(depths, names, raw, runningKernelInfo())
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
	calls, err := inject.DiscoverMapCallsRaw(raw)
	if err != nil {
		return err
	}
	d := Discovery{Program: name, Func: entry, Type: raw.Type, Calls: calls, Maps: map[string]ebpf.MapType{}, Stack: stack}
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

func (s *supervisor) transformLoad(r *remote, attr []byte, rule Rule, form HookForm, stack inject.StackReport) (ret int64, result *inject.LookupResultRaw, entry string, err error) {
	spec, err := s.programBTF(r, attr)
	if err != nil {
		return 0, nil, "", err
	}
	entry, err = readEntryName(r.pid, attr, spec)
	if err != nil {
		return 0, nil, "", err
	}
	liveRule, err := s.selectRule(cstring(attr[48:64]), entry)
	if err != nil {
		return 0, nil, "", err
	}
	if liveRule == nil || liveRule.Program != rule.Program {
		return 0, nil, "", fmt.Errorf("BTF fd identity changed; selector no longer matches")
	}
	raw, err := extractRaw(r, attr, spec)
	if err != nil {
		return 0, nil, "", err
	}
	if err := supplyMapTypes(&raw, rule); err != nil {
		return 0, nil, "", err
	}
	if rule.MapBTF != nil {
		for _, m := range raw.Maps {
			if m.Name == rule.Map && m.Key != nil && m.Value != nil {
				s.log("program %q: map %q types from ELF sha256 %.12s: key %q, value %q", rule.Program, rule.Map, strings.ToLower(rule.MapBTF.SHA256), m.Key.TypeName(), m.Value.TypeName())
			}
		}
	}
	request := rule.request()
	request.StaticUntrusted = form.Form == "static"
	request.Stack = inject.StackAudit{Frames: stack.Frames(), Source: stack.Source, FrameRounding: stack.FrameRounding}
	injectcheck.Label(raw.Instructions)
	result, err = inject.TransformLookupRawGuarded(raw, request, s.probeTailCallReachability)
	if err != nil {
		return 0, nil, "", err
	}
	cert, premises, err := loadCheckInputs(raw.Instructions, result, request.Stack, stack)
	if errors.Is(err, inject.ErrCheckerNotApplicable) {
		s.log("program %q: %v; load not validated", rule.Program, err)
	}
	check, err := loadCheckPolicy(err, s.options.FailClosed)
	if err != nil {
		return 0, result, entry, err
	}
	var instructions bytes.Buffer
	if err := result.Instructions.Marshal(&instructions, wire); err != nil {
		return 0, nil, "", err
	}
	// Load BTF inside the tracee. A supervisor-owned fd is not a valid substitute
	// for prog_btf_fd, even when its numeric value happens to match a target fd.
	btfAddr, err := r.alloc(result.BTFBytes)
	if err != nil {
		return 0, nil, "", err
	}
	btfAttr := make([]byte, 32)
	put64(btfAttr, 0, btfAddr)
	put32(btfAttr, 16, uint32(len(result.BTFBytes)))
	fd, err := r.bpf(unix.BPF_BTF_LOAD, btfAttr)
	if err != nil {
		return 0, nil, "", fmt.Errorf("tracee extended BTF load: %w", err)
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
		{instructions.Bytes(), 8, 4, -1, 8}, {result.FuncInfo, 80, 88, 76, 8}, {result.LineInfo, 96, 104, 92, 16},
	} {
		addr, err := r.alloc(buffer.data)
		if err != nil {
			return 0, nil, "", err
		}
		put64(patched, buffer.ptr, addr)
		put32(patched, buffer.count, uint32(len(buffer.data)/buffer.recordSize))
		if buffer.sizeOff >= 0 {
			put32(patched, buffer.sizeOff, uint32(buffer.recordSize))
		}
	}
	// Preserve kernel output fields (currently log_true_size) in the caller's attr.
	addr, err := r.alloc(patched)
	if err != nil {
		return 0, nil, "", err
	}
	// This checks the bytes read from attr.insns immediately before the traced
	// thread resumes. It neither freezes sibling threads nor proves kernel
	// acceptance, BTF meaning, fd bindings, verifier behavior, or JIT behavior.
	var verdict injectcheck.Verdict
	if check {
		encoded, err := readMemory(r.pid, u64(patched, 8), uint64(u32(patched, 4))*8)
		if err != nil {
			return 0, result, entry, fmt.Errorf("checker rejected the transform: read substituted load stream: %w; probe was not installed", err)
		}
		verdict, err = checkLoad(raw.Instructions, encoded, cert, premises)
		if err != nil {
			return 0, result, entry, fmt.Errorf("checker rejected the transform: %w; probe was not installed", err)
		}
	}
	ret, err = r.call(unix.SYS_BPF, unix.BPF_PROG_LOAD, addr, uint64(len(patched)))
	if err != nil {
		return 0, nil, "", err
	}
	if check {
		s.log("program %q: checker accepted sites=%d hooks=%d floor=%d", rule.Program, verdict.Counts.Sites, verdict.Counts.Hooks, verdict.Premises.LowestOffset)
	}
	if len(patched) >= 144 {
		out, e := readMemory(r.pid, addr+140, 4)
		if e == nil {
			e = writeMemory(r.pid, r.saved.Rsi+140, out)
		}
		if e != nil {
			r.broken = e
			return 0, nil, "", e
		}
	}
	if err := syscallError(ret, nil); err != nil {
		// Carry the summary so the caller can name the attempted hooks, and a
		// hint when an untrusted-pointer ABI mismatch may be the cause.
		return 0, result, entry, fmt.Errorf("transformed PROG_LOAD: %w%s", err, untrustedHint(form, result, err))
	}
	return ret, result, entry, nil
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
// separated by ", ", then "; skipped pc N (reason)" for each skipped lookup.
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
		fmt.Fprintf(&b, "; skipped pc %d (%s)", site.SitePC, site.Reason)
	}
	return b.String()
}

func extractRaw(r *remote, attr []byte, spec *btf.Spec) (inject.RawProgram, error) {
	// TODO: a SEIZE/INTERRUPT launcher must stop all siblings before this snapshot
	// to support concurrent mutation of load buffers or shared fd tables.
	p := inject.RawProgram{Type: ebpf.ProgramType(u32(attr, 0)), BTF: spec, Maps: make(map[int32]inject.RawMap)}
	insns, err := readMemory(r.pid, u64(attr, 8), uint64(u32(attr, 4))*8)
	if err != nil {
		return p, err
	}
	p.Instructions, err = asm.AppendInstructions(nil, bytes.NewReader(insns), wire, "linux")
	if err != nil {
		return p, err
	}
	p.FuncInfo, err = readMemory(r.pid, u64(attr, 80), uint64(u32(attr, 88))*8)
	if err != nil {
		return p, err
	}
	p.LineInfo, err = readMemory(r.pid, u64(attr, 96), uint64(u32(attr, 104))*16)
	if err != nil {
		return p, err
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
