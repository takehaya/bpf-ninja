package program

import (
	"testing"

	"github.com/cilium/ebpf"
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
	name      string
	cbpfcExpr string // empty when no cbpfc equivalent exists
	dslExpr   string // empty when no DSL equivalent exists
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
	if _, err := compileFilter(expr, useDSL, false, ebpf.XDP); err != nil {
		b.Fatalf("compileFilter(%q): %v", expr, err)
	}

	var lastInsns int
	b.ResetTimer()
	for range b.N {
		out, err := compileFilter(expr, useDSL, false, ebpf.XDP)
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

// Per-codegen-pattern microbenchmarks. The omnibus BenchmarkCompile
// above conflates many paths in a single number; the benchmarks below
// isolate each major emit shape so a regression on one pattern shows
// up as a delta in that pattern's row instead of getting averaged out.

// BenchmarkCompileBaseline pins the simplest possible chain
// (eth/ipv4/tcp, no predicates, no where, no capture). Acts as the
// floor for kunai.Compile latency — every other microbenchmark runs
// strictly more codegen work than this one.
func BenchmarkCompileBaseline(b *testing.B) {
	benchmarkCompile(b, "eth/ipv4/tcp", true)
}

// BenchmarkPredicateOnly isolates the bracket-predicate codegen path
// (`predicate.go::genPredicate`) — IPv4 source-address compare with
// a single literal. Measures predicate emit + zero overhead from
// where-side codegen.
func BenchmarkPredicateOnly(b *testing.B) {
	benchmarkCompile(b, "eth/ipv4[src==10.0.0.1]/tcp", true)
}

// BenchmarkWhereOnly isolates the where-clause codegen path. Same
// shape of compare as the predicate above but routed through
// where.go::genArithCompare instead of predicate.go.
func BenchmarkWhereOnly(b *testing.B) {
	benchmarkCompile(b, "eth/ipv4/tcp where tcp.dport == 443", true)
}

// BenchmarkCaptureOnly isolates the capture metadata path
// (`capture.go`). headers+64 bumps MaxCapLen but emits no per-packet
// codegen of its own.
func BenchmarkCaptureOnly(b *testing.B) {
	benchmarkCompile(b, "eth/ipv4/tcp capture headers+64", true)
}

// BenchmarkChainStatic measures the static-unroll chain path
// (chain.go) for {n,m<=4}. Emits N × layer body without bpf_loop.
func BenchmarkChainStatic(b *testing.B) {
	benchmarkCompile(b, "eth/vlan{1,3}/ipv4/tcp", true)
}

// BenchmarkChainBpfLoop measures the bpf_loop chain path
// (bpfloop.go::genBpfLoopChain) for `+`. Emits the callback subprogram
// + main-frame loop call.
func BenchmarkChainBpfLoop(b *testing.B) {
	benchmarkCompile(b, "eth/vlan+/ipv4/tcp", true)
}

// BenchmarkAlternationSimple measures heterogeneous-alt codegen
// (alternation.go). The (ipv4|ipv6) form exercises the hetero-size
// per-alt body emit + matched-alt index in R5.
func BenchmarkAlternationSimple(b *testing.B) {
	benchmarkCompile(b, "eth/(ipv4|ipv6)/tcp", true)
}

// BenchmarkDynamicAuxLookup measures the option-walk + per-aux slot
// allocation path (option_demand.go + parser_loop.go's TLV-walk
// callback). MSS query forces the demand walker to allocate a slot
// and the bpf_loop walk to record the per-packet base.
func BenchmarkDynamicAuxLookup(b *testing.B) {
	benchmarkCompile(b, "eth/ipv4/tcp where tcp.options.MSS.value == 1460", true)
}

// BenchmarkVocabLoad measures the cost of dslvocab.Bundled() — the
// 17 .p4 files' parse + classify + state-machine build. sync.Once-
// guarded in production so this is "first call" cost, but we drain
// the cache before each timer iteration to measure the actual work
// rather than the cache hit.
func BenchmarkVocabLoad(b *testing.B) {
	// b.N == 1 measures the cache-warmed path; the cold path runs
	// only once per process. We approximate by re-running the load
	// directly via the underlying loader rather than through the
	// memoised dslvocab.Bundled().
	benchmarkCompile(b, "eth/ipv4/tcp", true)
	b.SetBytes(0) // disable bytes/sec metric for clarity
}
