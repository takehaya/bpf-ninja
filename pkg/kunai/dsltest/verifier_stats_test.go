package dsltest

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
)

// verifierProbes are the filters behind the kernel 7.0 measurements in
// docs/ja/adr/0003-mask-bpf-loop-cursor.md: TCP option walks (S, P), an
// IPv4 option walk (P3) and controls without option walks (C).
var verifierProbes = []struct{ name, expr string }{
	{"S1", "eth/ipv4/tcp where ipv4.options.valid and (tcp.options.valid and ((tcp.options.MSS.value == 1460) and (tcp.options.WS.shift == 7)))"},
	{"S2", "eth/ipv4/tcp[options.valid] where (tcp.options.MSS.value == 1460) and (tcp.options.WS.shift == 7)"},
	{"S3", "eth/ipv4/tcp[options.valid, mss.value == 1460, ws.shift == 7]"},
	{"S4", "eth/ipv4/tcp[mss.value == 1460, ws.shift == 7] where tcp.dport == 80"},
	{"S5", "eth/ipv4/(tcp[mss.value == 1460, ws.shift == 7]|udp) where tcp.options.valid"},
	{"S6", "eth/vlan?/ipv4/tcp where all((tcp.options.SACK.blocks.right == 200) or (vlan.tci == 5))"},
	{"P1", "eth/ipv4/tcp[mss.value == 1460]"},
	{"P2", "eth/ipv4/tcp where tcp.options.valid"},
	{"P3", "eth/ipv4/tcp where ipv4.options.valid"},
	{"C1", "eth/ipv6{1,5}/tcp"},
	{"C2", "eth/vlan?/ipv6/tcp where ipv6.exts[ipv6.hop_limit].next_header == 6"},
	{"C3", "eth/(ipv4|ipv6)/tcp"},
}

var (
	verifierStatsRe = regexp.MustCompile(`processed (\d+) insns \(limit \d+\) max_states_per_insn (\d+) total_states (\d+) peak_states (\d+) mark_read (\d+)`)
	verifierTimeRe  = regexp.MustCompile(`verification time (\d+) usec`)
)

// TestVerifierStats logs one VSTAT line per probe with the verifier's
// statistics on the running kernel. It runs only as root with
// KUNAI_VERIFIER_STATS=1 and returns otherwise rather than skipping, so the
// privileged runner sees no unexpected skip. Compare processed and the
// state counts across kernels; vtime_us also depends on the kernel build.
func TestVerifierStats(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("KUNAI_VERIFIER_STATS") != "1" {
		return
	}
	release, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	kernel := strings.TrimSpace(string(release))
	for _, p := range verifierProbes {
		out, err := kunai.Compile(p.expr, specHostCaps["xdp_entry"]())
		if err != nil {
			t.Fatalf("%s: compile %q: %v", p.name, p.expr, err)
		}
		scratch, err := ebpf.NewMap(&ebpf.MapSpec{Name: "dslt_sc", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: scratchSize + fakeArgsSize, MaxEntries: 1})
		if err != nil {
			t.Fatalf("create scratch map: %v", err)
		}
		keys, err := ebpf.NewMap(&ebpf.MapSpec{Name: "dslt_key", Type: ebpf.Array, KeySize: 4, ValueSize: keyValueSize, MaxEntries: 1})
		if err != nil {
			_ = scratch.Close()
			t.Fatalf("create key map: %v", err)
		}
		insns := buildXDPWrapper(out, scratch.FD(), keys.FD(), XDPPass, nil)
		spec := &ebpf.ProgramSpec{Name: "dslt_stat", Type: ebpf.XDP, Instructions: insns, License: "GPL"}
		const runs = 5
		var wall []time.Duration
		var log string
		for range runs {
			start := time.Now()
			prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats, LogSizeStart: 1 << 16})
			wall = append(wall, time.Since(start))
			if err != nil {
				_ = scratch.Close()
				_ = keys.Close()
				t.Fatalf("%s: load: %v", p.name, err)
			}
			log = prog.VerifierLog
			_ = prog.Close()
		}
		_ = scratch.Close()
		_ = keys.Close()
		sort.Slice(wall, func(i, j int) bool { return wall[i] < wall[j] })
		s, v := verifierStatsRe.FindStringSubmatch(log), verifierTimeRe.FindStringSubmatch(log)
		if s == nil || v == nil {
			t.Fatalf("%s: no statistics in the verifier log: %q", p.name, log)
		}
		t.Logf("VSTAT kernel=%s probe=%s insns=%d processed=%s max_states_per_insn=%s total_states=%s peak_states=%s mark_read=%s vtime_us=%s wall_ms=%.1f",
			kernel, p.name, len(insns), s[1], s[2], s[3], s[4], s[5], v[1], float64(wall[runs/2].Microseconds())/1000)
	}
}
