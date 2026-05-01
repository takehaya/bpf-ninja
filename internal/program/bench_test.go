package program

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// Compile benchmarks that compare the cbpfc and DSL paths on
// equivalent filter expressions. These are *Go-side* measurements —
// they tell you how long compileFilter takes and how many BPF
// instructions each path emits, not how fast the resulting program
// runs in the kernel. For runtime PPS comparisons see
// docs/ja/dsl-benchmark.md (kernel + traffic generator workflow).
//
// Run:
//
//	go test -bench==BenchmarkCompile -benchmem -benchtime==1s ./internal/program/...
//
// Each result reports a custom `insns/op` metric so one row of `go
// test -bench` output captures both compile time and emitted size.

type compileBench struct {
	name        string
	cbpfcExpr   string // empty when no cbpfc equivalent exists
	dslExpr     string // empty when no DSL equivalent exists
}

var compileBenches = []compileBench{
	{
		name:      "ICMP",
		cbpfcExpr: "icmp",
		dslExpr:   "eth/ipv4/icmp",
	},
	{
		name:      "TCP_443",
		cbpfcExpr: "tcp port 443",
		dslExpr:   "eth/ipv4/tcp[dport==443]",
	},
	{
		name:      "TCP_or_UDP",
		cbpfcExpr: "tcp or udp",
		dslExpr:   "eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80",
	},
	{
		// No cbpfc equivalent — DSL is the only path.
		name:    "VLAN_chain",
		dslExpr: "eth/vlan{1,3}/ipv4/tcp",
	},
	{
		name:    "MPLS_plus",
		dslExpr: "eth/mpls+/ipv4/tcp",
	},
	{
		name:    "VXLAN_inner",
		dslExpr: "eth/ipv4/udp/vxlan/eth/ipv4/tcp",
	},
	{
		name:    "Capture_headers_plus_64",
		dslExpr: "eth/ipv4/tcp capture headers+64",
	},
}

func BenchmarkCompile(b *testing.B) {
	for _, tc := range compileBenches {
		if tc.cbpfcExpr != "" {
			b.Run("cbpfc/"+tc.name, func(b *testing.B) {
				benchmarkCompile(b, tc.cbpfcExpr, false)
			})
		}
		if tc.dslExpr != "" {
			b.Run("dsl/"+tc.name, func(b *testing.B) {
				benchmarkCompile(b, tc.dslExpr, true)
			})
		}
	}
}

func benchmarkCompile(b *testing.B, expr string, useDSL bool) {
	b.Helper()
	// Warm the vocab / first-call paths so the steady-state numbers
	// are not skewed by sync.Once-style one-time work.
	if _, err := compileFilter(expr, useDSL, false); err != nil {
		b.Fatalf("compileFilter(%q): %v", expr, err)
	}

	var lastInsns int
	b.ResetTimer()
	for range b.N {
		out, err := compileFilter(expr, useDSL, false)
		if err != nil {
			b.Fatalf("compileFilter(%q): %v", expr, err)
		}
		lastInsns = countRawInsns(out.Main, out.Callbacks)
	}
	b.StopTimer()
	b.ReportMetric(float64(lastInsns), "insns/op")
}

// countRawInsns counts asm.Instructions across main + callbacks
// using the raw-instruction expansion (DWord loads cost two slots),
// which matches what the verifier actually counts.
func countRawInsns(streams ...asm.Instructions) int {
	total := 0
	for _, s := range streams {
		for _, ins := range s {
			total += int(ins.Size() / asm.InstructionSize)
		}
	}
	return total
}
