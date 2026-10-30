package program

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// selectRunTracking is independent of host state so version and refusal policy
// can be tested without privileges. An override never bypasses scope checks.
func selectRunTracking(request string, major, minor int, known, rt bool, pt ebpf.ProgramType) (string, string, error) {
	if request != "auto" && request != "percpu" && request != "ctx" {
		return "", "", fmt.Errorf("--run-tracking must be auto, percpu or ctx")
	}
	if rt {
		return "", "", fmt.Errorf("hook capture does not support PREEMPT_RT")
	}
	if pt != ebpf.XDP && pt != ebpf.SchedCLS {
		return "", "", fmt.Errorf("hook capture requires XDP or SchedCLS")
	}
	if request == "percpu" && !known {
		return "", "", fmt.Errorf("--run-tracking=percpu requires a known kernel version; use --run-tracking=ctx")
	}
	if request != "auto" {
		return request, "explicit --run-tracking=" + request, nil
	}
	if !known {
		return "ctx", "kernel version unknown; using context tracking", nil
	}
	if major < 6 || major == 6 && minor < 3 {
		return "ctx", "kernel before 6.3 allows normal test-run interleaving", nil
	}
	return "percpu", "kernel 6.3 or newer protects normal test-run with BH", nil
}

func positiveRT(realtime, version, config string) bool {
	if strings.TrimSpace(realtime) == "1" || strings.Contains(version, "PREEMPT_RT") {
		return true
	}
	for _, line := range strings.Split(config, "\n") {
		if strings.TrimSpace(line) == "CONFIG_PREEMPT_RT=y" {
			return true
		}
	}
	return false
}

func kernelRT() bool {
	rt, _ := os.ReadFile("/sys/kernel/realtime")
	var u unix.Utsname
	_ = unix.Uname(&u)
	version, release := unix.ByteSliceToString(u.Version[:]), unix.ByteSliceToString(u.Release[:])
	if positiveRT(string(rt), version, "") {
		return true
	}
	config, _ := os.ReadFile("/boot/config-" + release)
	if positiveRT("", "", string(config)) {
		return true
	}
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer func() { _ = gz.Close() }()
	config, _ = io.ReadAll(gz)
	return positiveRT("", "", string(config))
}
