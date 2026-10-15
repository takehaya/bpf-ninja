package dsltest

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

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

// verifierBaseline holds the processed insns of each probe on the
// ghcr.io/cilium/ci-kernels images, keyed by kernelKey. Refresh a row by
// pasting the VSTAT-BASELINE line that TestVerifierStats logs.
var verifierBaseline = map[string]map[string]int{
	"6.1":  {"S1": 2563, "S2": 1319, "S3": 1317, "S4": 1292, "S5": 1299, "S6": 3990, "P1": 1540, "P2": 997, "P3": 962, "C1": 11112, "C2": 3131, "C3": 1316},
	"6.6":  {"S1": 6621, "S2": 3085, "S3": 3083, "S4": 3053, "S5": 3045, "S6": 7449, "P1": 3316, "P2": 1544, "P3": 1634, "C1": 18177, "C2": 7511, "C3": 1868},
	"6.12": {"S1": 9066, "S2": 4373, "S3": 4371, "S4": 4294, "S5": 4233, "S6": 14921, "P1": 7002, "P2": 2543, "P3": 1543, "C1": 9872, "C2": 9175, "C3": 2139},
	"6.15": {"S1": 9089, "S2": 4352, "S3": 4350, "S4": 4294, "S5": 4244, "S6": 14656, "P1": 6882, "P2": 2557, "P3": 1539, "C1": 9867, "C2": 9152, "C3": 2194},
	"6.18": {"S1": 9051, "S2": 4332, "S3": 4330, "S4": 4303, "S5": 4228, "S6": 14931, "P1": 6997, "P2": 2537, "P3": 1539, "C1": 8383, "C2": 7540, "C3": 1794},
	"7.0":  {"S1": 27916, "S2": 13914, "S3": 13912, "S4": 13705, "S5": 13497, "S6": 20415, "P1": 9737, "P2": 3177, "P3": 1711, "C1": 8483, "C2": 7832, "C3": 1814},
	"7.1":  {"S1": 11928, "S2": 5541, "S3": 5539, "S4": 5554, "S5": 5577, "S6": 16761, "P1": 7926, "P2": 2620, "P3": 1611, "C1": 8323, "C2": 7608, "C3": 1794},
	"7.2":  {"S1": 11928, "S2": 5541, "S3": 5539, "S4": 5554, "S5": 5577, "S6": 16761, "P1": 7926, "P2": 2620, "P3": 1611, "C1": 8323, "C2": 7608, "C3": 1794},
	"7.3":  {"S1": 11928, "S2": 5541, "S3": 5539, "S4": 5554, "S5": 5577, "S6": 16761, "P1": 7926, "P2": 2620, "P3": 1611, "C1": 8323, "C2": 7608, "C3": 1794},
}

// verifierHeadroom scales a baseline into the budget. Point releases move
// processed by a few percent; the regressions this guards against were 2-4x.
const verifierHeadroom = 1.5

var (
	verifierStatsRe = regexp.MustCompile(`processed (\d+) insns \(limit \d+\) max_states_per_insn (\d+) total_states (\d+) peak_states (\d+) mark_read (\d+)`)
	verifierTimeRe  = regexp.MustCompile(`verification time (\d+) usec`)
)

// kernelKey reduces a kernel release such as "7.3.0-rc4" to "7.3", so a
// point release or an rc-to-GA move keeps its baseline row.
func kernelKey(release string) string {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return release
	}
	return parts[0] + "." + parts[1]
}

// TestVerifierStats logs one VSTAT line per probe with the verifier's
// statistics on the running kernel, then a VSTAT-BASELINE line in the shape
// of a verifierBaseline row. It runs only as root and returns otherwise
// rather than skipping, so the privileged runner sees no unexpected skip.
// With KUNAI_VERIFIER_STRICT=1, which privileged.py --kernel sets, a probe
// whose processed exceeds its baseline times verifierHeadroom fails, and so
// does a kernel or probe without a baseline. Without it, the same findings
// are only logged, so a developer host kernel never fails. vtime_us depends
// on the kernel build; compare only processed and the state counts.
func TestVerifierStats(t *testing.T) {
	if os.Getuid() != 0 {
		return
	}
	strict := os.Getenv("KUNAI_VERIFIER_STRICT") == "1"
	report := t.Logf
	if strict {
		report = t.Errorf
	}
	release, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	kernel := strings.TrimSpace(string(release))
	key := kernelKey(kernel)
	processed := make(map[string]int, len(verifierProbes))
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
		prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats, LogSizeStart: 1 << 16})
		_ = scratch.Close()
		_ = keys.Close()
		if err != nil {
			t.Fatalf("%s: load: %v", p.name, err)
		}
		log := prog.VerifierLog
		_ = prog.Close()
		s, v := verifierStatsRe.FindStringSubmatch(log), verifierTimeRe.FindStringSubmatch(log)
		if s == nil || v == nil {
			t.Fatalf("%s: no statistics in the verifier log: %q", p.name, log)
		}
		n, err := strconv.Atoi(s[1])
		if err != nil {
			t.Fatalf("%s: parse processed %q: %v", p.name, s[1], err)
		}
		processed[p.name] = n
		t.Logf("VSTAT kernel=%s probe=%s insns=%d processed=%s max_states_per_insn=%s total_states=%s peak_states=%s mark_read=%s vtime_us=%s",
			kernel, p.name, len(insns), s[1], s[2], s[3], s[4], s[5], v[1])
	}

	var row strings.Builder
	fmt.Fprintf(&row, "VSTAT-BASELINE %q: {", key)
	for i, p := range verifierProbes {
		if i > 0 {
			row.WriteString(", ")
		}
		fmt.Fprintf(&row, "%q: %d", p.name, processed[p.name])
	}
	row.WriteString("},")
	t.Logf("%s strict=%v", row.String(), strict)

	base, ok := verifierBaseline[key]
	if !ok {
		if strict {
			t.Errorf("no verifier baseline for kernel %s (%s); add the VSTAT-BASELINE line above to verifierBaseline", key, kernel)
		} else {
			t.Logf("no verifier baseline for kernel %s (%s); the table covers the ci-kernels images only", key, kernel)
		}
		return
	}
	for _, p := range verifierProbes {
		b, ok := base[p.name]
		if !ok {
			report("%s: no verifier baseline on kernel %s; refresh the row from the VSTAT-BASELINE line above", p.name, key)
			continue
		}
		budget := int(float64(b) * verifierHeadroom)
		switch got := processed[p.name]; {
		case got > budget:
			report("%s: processed %d exceeds budget %d (baseline %d x %.1f) on kernel %s", p.name, got, budget, b, verifierHeadroom, key)
		case float64(got) < float64(b)/verifierHeadroom:
			t.Logf("%s: processed %d is well below baseline %d on kernel %s; refresh the row", p.name, got, b, key)
		}
	}
}
