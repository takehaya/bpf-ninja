package inject

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// KernelFrameRounding returns the StackAudit.FrameRounding a kernel with the
// given release and bpf_jit_enable value uses: 16 for a JIT kernel at 6.9 or
// later, otherwise 32.
func KernelFrameRounding(release, jit string, readErr error) int {
	if readErr != nil || strings.TrimSpace(jit) != "1" && strings.TrimSpace(jit) != "2" {
		return 32
	}
	var major, minor int
	if n, _ := fmt.Sscanf(release, "%d.%d", &major, &minor); n != 2 || major < 6 || major == 6 && minor < 9 {
		return 32
	}
	return 16
}

// RunningKernelFrameRounding returns KernelFrameRounding for the running kernel.
func RunningKernelFrameRounding() int {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return 32
	}
	jit, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable")
	return KernelFrameRounding(unix.ByteSliceToString(u.Release[:]), string(jit), err)
}
