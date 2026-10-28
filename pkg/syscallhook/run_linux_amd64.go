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
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
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
}

// Injection describes one successful injected load. Program is the kernel
// program name and Func the entry function. ProgID is the loaded program's
// kernel ID, zero if the tracee could not query it. Hooks and Skipped are
// the transform's (see inject.LookupResult).
type Injection struct {
	Program, Func string
	Type          ebpf.ProgramType
	ProgID        uint32
	Hooks         []inject.LookupHook
	Skipped       []inject.LookupSite
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
	options    Options
	btf        map[uint32]rememberedBTF
	cacheBytes int
}

func (s *supervisor) log(format string, args ...any) {
	_, _ = fmt.Fprintf(s.options.Log, "inject-run: "+format+"\n", args...)
}

// Run starts argv with PTRACE_TRACEME and returns the child's exit status (or
// 128+signal). A supervisor error terminates the tracee: resuming with uncertain
// registers is unsafe even in fail-open mode. No network attachments are made.
func Run(ctx context.Context, argv []string, opts Options) (int, error) {
	if len(argv) == 0 {
		return 0, fmt.Errorf("target command is required after --")
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
	s := supervisor{options: opts, btf: make(map[uint32]rememberedBTF)}
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
	if discover {
		if err := s.discover(r, attr, name); err != nil {
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
	ret, result, entry, injectErr := s.transformLoad(r, attr, *rule)
	if r.broken != nil {
		return r.broken
	}
	summary := ""
	if result != nil {
		summary = hookSummary(result)
	}
	if injectErr != nil {
		if summary != "" {
			s.log("program %q: injection skipped: %v; attempted %s", name, injectErr, summary)
		} else {
			s.log("program %q: injection skipped: %v", name, injectErr)
		}
		if s.options.FailClosed {
			ret = -int64(unix.EPERM)
		} else {
			// Original registers and all input buffers are unchanged. The verifier's
			// caller-owned log buffer may have been written by the attempted load.
			ret, err = r.call(unix.SYS_BPF, regs.Rdi, regs.Rsi, regs.Rdx)
			if err != nil {
				return err
			}
		}
	} else {
		s.log("program %q: injected %s, tracee fd %d", name, summary, ret)
		if s.options.OnInject != nil {
			inj := Injection{Program: name, Func: entry, Type: ebpf.ProgramType(u32(attr, 0)), Hooks: result.Hooks, Skipped: result.Skipped}
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

func (s *supervisor) discover(r *remote, attr []byte, name string) error {
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
	d := Discovery{Program: name, Func: entry, Type: raw.Type, Calls: calls, Maps: map[string]ebpf.MapType{}}
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

func (s *supervisor) transformLoad(r *remote, attr []byte, rule Rule) (ret int64, result *inject.LookupResultRaw, entry string, err error) {
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
	result, err = inject.TransformLookupRaw(raw, rule.request())
	if err != nil {
		return 0, nil, "", err
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
	ret, err = r.call(unix.SYS_BPF, unix.BPF_PROG_LOAD, addr, uint64(len(patched)))
	if err != nil {
		return 0, nil, "", err
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
		return 0, result, entry, fmt.Errorf("transformed PROG_LOAD: %w%s", err, untrustedHint(result, err))
	}
	return ret, result, entry, nil
}

// untrustedHint explains how to load a program whose hooks take arg:untrusted
// pointers on a kernel without that tag. It is empty unless some hook is
// untrusted and the load failed the way those kernels fail it: EINVAL on 6.1
// and 6.6, EOPNOTSUPP on 6.12 and 6.15, or EACCES.
func untrustedHint(result *inject.LookupResultRaw, err error) string {
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
		p.Maps[fd] = inject.RawMap{Name: cstring(info[24:40]), Type: ebpf.MapType(u32(info, 0)), KeySize: u32(info, 8), ValueSize: u32(info, 12), Flags: u32(info, 20), Key: key, Value: value}
	}
	return p, nil
}
