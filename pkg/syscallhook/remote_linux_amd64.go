//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func readMemory(pid int, addr uint64, size uint64) ([]byte, error) {
	if size > maxBuffer || addr+size < addr {
		return nil, fmt.Errorf("invalid tracee memory range")
	}
	b := make([]byte, int(size))
	if size == 0 {
		return b, nil
	}
	n, err := unix.PtracePeekData(pid, uintptr(addr), b)
	if err != nil {
		return nil, fmt.Errorf("read tracee memory: %w", err)
	}
	if n != len(b) {
		return nil, fmt.Errorf("short tracee memory read")
	}
	return b, nil
}
func writeMemory(pid int, addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	n, err := unix.PtracePokeData(pid, uintptr(addr), b)
	if err != nil {
		return fmt.Errorf("write tracee memory: %w", err)
	}
	if n != len(b) {
		return fmt.Errorf("short tracee memory write")
	}
	return nil
}

// syscallStop uses the kernel's entry/exit discriminator, not a toggle which
// would drift at clone, exec, signals, or restarted syscalls. Linux >= 5.3.
func syscallStop(pid int) (op byte, arch uint32, err error) {
	var b [88]byte
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GET_SYSCALL_INFO, uintptr(pid), uintptr(len(b)), uintptr(unsafe.Pointer(&b[0])), 0, 0)
	if errno != 0 {
		return 0, 0, errno
	}
	return b[0], u32(b[:], 4), nil
}

func signalMask(pid int, request uintptr, mask *uint64) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, request, uintptr(pid), 8, uintptr(unsafe.Pointer(mask)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func waitThread(pid int) (unix.WaitStatus, error) {
	var status unix.WaitStatus
	for {
		_, err := unix.Wait4(pid, &status, unix.WALL, nil)
		if err == unix.EINTR {
			continue
		}
		return status, err
	}
}

// remote operates from a syscall-exit stop. Calls replay the actual x86 SYSCALL
// instruction at RIP-2; executable memory and the tracee's stack are untouched.
// Ptrace failures lose the stop invariant: callers must terminate, not resume.
type remote struct {
	pid        int
	saved      unix.PtraceRegs
	mask       uint64
	base, used uint64
	broken     error
}

const scratchSize = 64 << 20

func beginRemote(pid int, regs unix.PtraceRegs, entry bool) (*remote, error) {
	code, err := readMemory(pid, regs.Rip-2, 2)
	if err != nil || !bytes.Equal(code, []byte{0x0f, 0x05}) {
		return nil, fmt.Errorf("not stopped after a native x86-64 SYSCALL: %v", err)
	}
	r := &remote{pid: pid, saved: regs}
	if err := signalMask(pid, unix.PTRACE_GETSIGMASK, &r.mask); err != nil {
		return nil, err
	}
	blocked := ^uint64(0)
	if err := signalMask(pid, unix.PTRACE_SETSIGMASK, &blocked); err != nil {
		return nil, err
	}
	if entry {
		skipped := regs
		skipped.Orig_rax = ^uint64(0)
		if err := unix.PtraceSetRegs(pid, &skipped); err != nil {
			return nil, err
		}
		if err := r.step(2); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *remote) step(want byte) error {
	if err := unix.PtraceSyscall(r.pid, 0); err != nil {
		r.broken = err
		return err
	}
	status, err := waitThread(r.pid)
	if err == nil && (!status.Stopped() || status.StopSignal() != unix.SIGTRAP|0x80) {
		err = fmt.Errorf("unexpected stop during injected syscall: %#x", uint32(status))
	}
	if err == nil {
		var op byte
		op, _, err = syscallStop(r.pid)
		if err == nil && op != want {
			err = fmt.Errorf("injected syscall stop %d, expected %d", op, want)
		}
	}
	if err != nil {
		r.broken = err
	}
	return err
}

func (r *remote) call(nr uint64, args ...uint64) (int64, error) {
	if r.broken != nil {
		return 0, r.broken
	}
	regs := r.saved
	regs.Rip -= 2
	regs.Rax, regs.Orig_rax = nr, nr
	slots := []*uint64{&regs.Rdi, &regs.Rsi, &regs.Rdx, &regs.R10, &regs.R8, &regs.R9}
	for i, p := range slots {
		*p = 0
		if i < len(args) {
			*p = args[i]
		}
	}
	if err := unix.PtraceSetRegs(r.pid, &regs); err != nil {
		r.broken = err
		return 0, err
	}
	if err := r.step(1); err != nil {
		return 0, err
	}
	if err := r.step(2); err != nil {
		return 0, err
	}
	if err := unix.PtraceGetRegs(r.pid, &regs); err != nil {
		r.broken = err
		return 0, err
	}
	return int64(regs.Rax), nil
}
func syscallError(ret int64, err error) error {
	if err != nil {
		return err
	}
	if ret < 0 && ret >= -4095 {
		return unix.Errno(-ret)
	}
	return nil
}
func (r *remote) alloc(b []byte) (uint64, error) {
	if r.base == 0 {
		ret, err := r.call(unix.SYS_MMAP, 0, scratchSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
		if err = syscallError(ret, err); err != nil {
			return 0, fmt.Errorf("tracee mmap: %w", err)
		}
		r.base = uint64(ret)
	}
	size := (uint64(len(b)) + 7) &^ 7
	if size > scratchSize-r.used {
		return 0, fmt.Errorf("scratch arena exhausted")
	}
	addr := r.base + r.used
	r.used += size
	return addr, writeMemory(r.pid, addr, b)
}
func (r *remote) bpf(command uint64, attr []byte) (int64, error) {
	addr, err := r.alloc(attr)
	if err != nil {
		return 0, err
	}
	ret, err := r.call(unix.SYS_BPF, command, addr, uint64(len(attr)))
	return ret, syscallError(ret, err)
}
func (r *remote) info(fd uint32, size int) ([]byte, error) {
	addr, err := r.alloc(make([]byte, size))
	if err != nil {
		return nil, err
	}
	attr := make([]byte, 16)
	put32(attr, 0, fd)
	put32(attr, 4, uint32(size))
	put64(attr, 8, addr)
	if _, err := r.bpf(unix.BPF_OBJ_GET_INFO_BY_FD, attr); err != nil {
		return nil, fmt.Errorf("tracee object info fd %d: %w", fd, err)
	}
	return readMemory(r.pid, addr, uint64(size))
}
func (r *remote) finish(ret int64) error {
	if r.broken != nil {
		return r.broken
	}
	if r.base != 0 {
		result, err := r.call(unix.SYS_MUNMAP, r.base, scratchSize)
		if err = syscallError(result, err); err != nil {
			return fmt.Errorf("tracee munmap: %w", err)
		}
	}
	regs := r.saved
	regs.Rax = uint64(ret)
	if err := unix.PtraceSetRegs(r.pid, &regs); err != nil {
		return err
	}
	return signalMask(r.pid, unix.PTRACE_SETSIGMASK, &r.mask)
}
