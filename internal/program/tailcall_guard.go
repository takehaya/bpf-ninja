package program

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// On an affected kernel a second fentry/fexit attach to an XDP program
// that performs a tail call returns EBUSY, and releasing the first link
// then fails its trampoline unlink (WARN_ON_ONCE in
// bpf_tracing_link_release), after which the next execution of the
// target faults in __bpf_prog_enter_recur. That took a lab host down on
// 2026-09-21 and reproduces in a VM on 7.0 and 7.2-rc2; 6.6, 6.12 and
// 6.18 attach both probes fine.
//
// Upstream is CVE-2026-92485: the verifier assigned
// tr->flags = BPF_TRAMP_F_TAIL_CALL_CTX without preserving
// BPF_TRAMP_F_CALL_ORIG, so the trampoline poked the target's nop with
// a jmp instead of a call and could not restore it. Fixed in 7.2.6 and
// 7.3-rc1 (48a0209d8da0, 61aaa8782bec).
//
// A gated capture always needs two attaches, so refuse it up front on
// an affected kernel rather than walk into the failure.

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

// kernelVersion returns the running kernel's major, minor and patch.
// The release comes from uname(2), so a restricted /proc cannot hide
// it, and each component is read as its leading digits so a suffix
// like "7.2-rc2" or "7.2.0-rc2-btf-fixed+" still parses. ok is false
// when the release cannot be read or parsed.
func kernelVersion() (major, minor, patch int, ok bool) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return 0, 0, 0, false
	}
	parts := strings.SplitN(unix.ByteSliceToString(u.Release[:]), ".", 3)
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	major, ok1 := leadingInt(parts[0])
	minor, ok2 := leadingInt(parts[1])
	if !ok1 || !ok2 {
		return 0, 0, 0, false
	}
	if len(parts) > 2 {
		patch, _ = leadingInt(parts[2]) // absent or odd reads as 0
	}
	return major, minor, patch, true
}

// kernelHasTailCallAttachBug reports whether the running kernel carries
// CVE-2026-92485. The window is 7.0 up to the 7.2.6 / 7.3-rc1 fix:
// below 7.0 both attaches were measured to work, and a release that
// cannot be parsed counts as affected, since the failure mode here is a
// kernel panic.
func kernelHasTailCallAttachBug() bool {
	return tailCallAttachBugIn(kernelVersion())
}

// tailCallAttachBugIn is the version test, split out so it can be
// checked without the kernel it runs on.
func tailCallAttachBugIn(major, minor, patch int, ok bool) bool {
	switch {
	case !ok:
		return true
	case major < 7:
		return false
	case major > 7, minor > 2:
		return false // 7.3-rc1 and later carry the fix
	case minor == 2 && patch >= 6:
		return false // 7.2.6 and later carry the fix
	default:
		return true // 7.0, 7.1, 7.2.0 .. 7.2.5
	}
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
	if !kernelHasTailCallAttachBug() || !performsTailCall(prog) {
		return nil
	}
	return fmt.Errorf("%s performs tail calls, and this kernel rejects the second fentry/fexit attach such a program needs for a gated (entry + exit) capture (CVE-2026-92485, fixed in 7.2.6 and 7.3-rc1); "+
		"the failure can leave the trampoline inconsistent and panic the machine, so bpf-ninja stops here. "+
		"Capture one point at a time (a single --mode), or use a kernel that carries the fix", funcName)
}
