package program

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// Linux 7.0 rejects a second fentry/fexit attach to an XDP program that
// performs a tail call: the attach returns EBUSY, and releasing the
// first link can then fail its trampoline unlink
// (WARN_ON_ONCE in bpf_tracing_link_release), after which the next
// execution of the target faults in __bpf_prog_enter_recur. That took
// the lab host down on 2026-09-21 and is reproducible in a VM on 7.0
// and 7.2-rc2; 6.6, 6.12 and 6.18 attach both probes fine. A gated
// capture always needs two attaches, so refuse it up front on an
// affected kernel rather than walk into the failure.
const tailCallGuardMinMajor = 7

// leadingInt reads the digits at the start of s ("2" from "2-rc2",
// "0" from "0-btf-fixed+"). ok is false when there are none.
func leadingInt(s string) (int, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	return n, err == nil
}

// kernelAtLeast reports whether the running kernel is at least
// major.minor. The release comes from uname(2), so a restricted /proc
// cannot hide it, and each component is read as its leading digits so
// a suffix like "7.2-rc2" still compares. A release it cannot parse
// reads as affected: this gates a check whose failure mode is a kernel
// panic, so an unknown version refuses rather than proceeds.
func kernelAtLeast(major, minor int) bool {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return true
	}
	release := unix.ByteSliceToString(u.Release[:])
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return true
	}
	gotMajor, ok1 := leadingInt(parts[0])
	gotMinor, ok2 := leadingInt(parts[1])
	if !ok1 || !ok2 {
		return true
	}
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}

// performsTailCall reports whether prog can reach a bpf_tail_call. It
// reads the translated instructions when the kernel exposes them
// (subprograms included) and otherwise falls back to "holds a
// PROG_ARRAY", the map a tail call needs. Errors read as "no": the
// guard must not turn a permission problem into a refused capture.
func performsTailCall(prog *ebpf.Program) bool {
	info, err := prog.Info()
	if err != nil {
		return false
	}
	if insns, err := info.Instructions(); err == nil {
		for i := range insns {
			if insns[i].IsBuiltinCall() && asm.BuiltinFunc(insns[i].Constant) == asm.FnTailCall {
				return true
			}
		}
		return false
	}
	// kptr_restrict and friends hide the instructions; fall back to the
	// map, which over-refuses a program that holds a prog array without
	// ever calling into it.
	ids, ok := info.MapIDs()
	if !ok {
		return false
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		mi, err := m.Info()
		_ = m.Close()
		if err == nil && mi.Type == ebpf.ProgramArray {
			return true
		}
	}
	return false
}

// checkGatedTailCallTarget refuses a gated capture whose target can
// tail-call on a kernel where the second attach is rejected.
func checkGatedTailCallTarget(prog *ebpf.Program, funcName string) error {
	if !kernelAtLeast(tailCallGuardMinMajor, 0) || !performsTailCall(prog) {
		return nil
	}
	return fmt.Errorf("%s performs tail calls, and this kernel (or one whose version could not be read) rejects the second fentry/fexit attach such a program needs for a gated (entry + exit) capture; "+
		"the failure can leave the trampoline inconsistent and panic the machine, so bpf-ninja stops here. "+
		"Capture one point at a time (a single --mode), or run the gated capture on a kernel up to 6.18", funcName)
}
