package program

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
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
//
// ponytail: the target is judged by "references a PROG_ARRAY", which
// is what the kernel's tail-call machinery needs but does not prove a
// tail call is reachable. A program that holds a prog array and never
// calls into it is refused too; narrow this by walking the
// instructions if that ever matters.
const tailCallGuardMinMajor = 7

// kernelAtLeast reports whether the running kernel is at least
// major.minor. An unparsable release reads as "older" so the guard
// never blocks a capture on a version it cannot judge.
func kernelAtLeast(major, minor int) bool {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	parts := strings.SplitN(strings.TrimSpace(string(b)), ".", 3)
	if len(parts) < 2 {
		return false
	}
	gotMajor, err1 := strconv.Atoi(parts[0])
	gotMinor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}

// referencesProgArray reports whether prog holds a PROG_ARRAY, i.e. it
// can tail-call. Errors read as "no": the guard must not turn a
// permission problem into a refused capture.
func referencesProgArray(prog *ebpf.Program) bool {
	info, err := prog.Info()
	if err != nil {
		return false
	}
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
	if !kernelAtLeast(tailCallGuardMinMajor, 0) || !referencesProgArray(prog) {
		return nil
	}
	return fmt.Errorf("%s performs tail calls, and this kernel rejects the second fentry/fexit attach such a program needs for a gated (entry + exit) capture; "+
		"the failure can leave the trampoline inconsistent and panic the machine, so bpf-ninja stops here. "+
		"Capture one point at a time (a single --mode), or run the gated capture on a kernel up to 6.18", funcName)
}
