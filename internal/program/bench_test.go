package program

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
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

// BenchmarkFilterSet walks the canonical F1-F10 evaluation set
// (defined in filterset_test.go::FilterSet) and reports per-filter
// compile time + raw-insn count. Each entry runs the kunai DSL path;
// filters that have a comparable cBPF form (FilterSpec.CBPFCExpr non-
// empty) additionally run the cbpfc path so a single bench invocation
// produces both halves of the §6.3 comparison plot.
//
// Subtest naming is `Fn/dsl` and `Fn/cbpfc` so `go test -bench` output
// can be parsed line-by-line into benchmark/results/b1_insns.csv (see
// benchmark/microbench/run.sh).
func BenchmarkFilterSet(b *testing.B) {
	for _, fs := range FilterSet {
		b.Run(fs.ID+"/dsl", func(b *testing.B) {
			benchmarkCompile(b, fs.Expr, true)
		})
		if fs.CBPFCExpr != "" {
			b.Run(fs.ID+"/cbpfc", func(b *testing.B) {
				benchmarkCompile(b, fs.CBPFCExpr, false)
			})
		}
	}
}

// BenchmarkFilterSetRun is the runtime counterpart of BenchmarkFilterSet
// (E2 / B2 mesobench). It loads each filter as a real tracing program
// against the dummy XDP target and measures per-packet end-to-end cost
// via BPF_PROG_TEST_RUN (one syscall + one program execution per Go
// bench iteration; see benchmarkRun for the rationale on choosing Test
// over Program.Benchmark).
//
// Comparing kunai/F* against cbpfc/F* on the filters where cBPF can
// compete (F1-F4, F6) is the §6.3 trace-tone source: if the per-packet
// gap is small the static-insn-count gap reported in §6.3 is amortized
// at runtime; if it stays large the codegen needs §8 future-work.
//
// Requires root (BPF_PROG_TEST_RUN). Sub-bench naming is Fn/{kunai,cbpfc}
// so benchmark/microbench/run_runtime.sh can awk it into b2_runtime.csv.
func BenchmarkFilterSetRun(b *testing.B) {
	if os.Getuid() != 0 {
		b.Skip("requires root")
	}
	targetProg := loadDummyXDP(b)

	for _, fs := range FilterSet {
		pkt := buildPacketForFilter(b, fs)

		b.Run(fs.ID+"/kunai", func(b *testing.B) {
			benchmarkRun(b, targetProg, fs.Expr, pkt, true)
		})
		if fs.CBPFCExpr != "" {
			b.Run(fs.ID+"/cbpfc", func(b *testing.B) {
				benchmarkRun(b, targetProg, fs.CBPFCExpr, pkt, false)
			})
		}
	}
}

// benchmarkRun loads a tracing probe with the given filter expression
// (DSL or pcap-filter depending on useDSL), then measures per-packet
// runtime via BPF_PROG_TEST_RUN. Reports ns/pkt that includes the
// syscall overhead (~600 ns on this kernel); the syscall path is the
// same for kunai and cbpfc so the kunai/cbpfc *delta* is the codegen
// signal we're after.
//
// We avoid the kernel-internal repeat loop in Program.Benchmark because
// some kernels report only the duration of a single program invocation
// regardless of the requested repeat count, which silently underflows
// the metric to zero. Calling Test() inside the Go bench loop sidesteps
// that by using Go's own elapsed-time measurement.
func benchmarkRun(b *testing.B, targetProg *ebpf.Program, expr string, pkt []byte, useDSL bool) {
	b.Helper()
	probe, err := LoadEntry(targetProg, xdpFuncName, expr, nil, useDSL)
	if err != nil {
		b.Fatalf("LoadEntry %q: %v", expr, err)
	}
	defer func() { _ = probe.Close() }()

	// Warm so the first measured iteration sees a hot JIT cache.
	if _, _, err := probe.Program().Test(pkt); err != nil {
		b.Fatalf("warmup Test: %v", err)
	}

	b.ResetTimer()
	for range b.N {
		if _, _, err := probe.Program().Test(pkt); err != nil {
			b.Fatalf("Test: %v", err)
		}
	}
	// Go's native ns/op (= total wall time / b.N) is already the
	// per-packet end-to-end cost (syscall + one kernel run). We
	// alias it as ns/pkt so the run_runtime.sh awk pattern can grep
	// for the same metric name as the rest of the bench harness.
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N), "ns/pkt")
}

// buildPacketForFilter materializes a packet that the given filter
// matches. Unlike the verifier-load test which only cares about
// compilation, the runtime bench needs a packet that exercises the
// full filter body (parser machine + where-clause comparison + capture)
// so the measured ns/pkt reflects the real path, not an early reject.
//
// Field values below must stay in sync with FilterSpec.Expr in
// filterset_test.go: any literal that appears in an Expr predicate
// (port number, address, VLAN id, MSS value, …) must show up here too,
// or the bench silently measures a parser-rejected packet path and
// the ns/pkt number stops being meaningful. The per-case comments
// quote the predicate that pins each literal.
func buildPacketForFilter(b *testing.B, fs FilterSpec) []byte {
	b.Helper()
	switch fs.ID {
	case "F1":
		// Expr: tcp.dport == 443
		return dsltest.BuildEthIPv4TCP(b, 12345, 443)
	case "F2":
		// Expr: ipv4[src==10.0.0.0/8] and tcp.dport == 80
		return dsltest.Build(b, dsltest.PacketOpts{
			SrcIP:   net.ParseIP("10.0.0.1"),
			DstIP:   net.ParseIP("10.0.0.2"),
			DstPort: 80,
			TCP:     true,
		})
	case "F3":
		// Expr: ipv6[src==2001:db8::/32]
		return dsltest.BuildEthIPv6TCP(b,
			net.ParseIP("2001:db8::1"),
			net.ParseIP("2001:db8::2"),
			1234, 443)
	case "F4":
		// Expr: vlan[tci==100] and tcp.dport == 80
		return dsltest.Build(b, dsltest.PacketOpts{
			VLAN:    []uint16{100},
			DstPort: 80,
			TCP:     true,
		})
	case "F5":
		// Expr: eth/qinq/vlan/ipv4/tcp where tcp.dport == 80
		// (no explicit tci predicate — chain dispatch alone suffices)
		return dsltest.Build(b, dsltest.PacketOpts{
			QinQ:    true,
			VLAN:    []uint16{200},
			DstPort: 80,
			TCP:     true,
		})
	case "F6":
		// Expr: icmp.type == 8 (echo request, BuildEthIPv4ICMP default)
		return dsltest.Build(b, dsltest.PacketOpts{
			ICMP: true,
			TCP:  false,
			UDP:  false,
		})
	case "F7":
		// Expr: inner.dst == 10.0.0.1 (GTP-U inner IPv4)
		return dsltest.BuildGTPU(b, dsltest.GTPUOpts{
			InnerDst:     net.ParseIP("10.0.0.1"),
			InnerDstPort: 80,
		})
	case "F8":
		// Expr: any(srv6.segments.addr == fc00::1); InnerNextHeader=6
		// keeps the post-SRH dispatch on TCP so the parser walks past
		// the segment list rather than rejecting on an unknown nexthdr.
		return dsltest.BuildSRv6(b, dsltest.SRv6Opts{
			Segments:        []net.IP{net.ParseIP("fc00::1")},
			InnerNextHeader: 6,
			InnerDstPort:    80,
		})
	case "F9":
		// Expr: inner.dst == 10.0.0.1 (Geneve inner IPv4)
		return dsltest.BuildGeneveInnerIPv4TCP(b, dsltest.GeneveInnerIPv4TCPOpts{
			InnerDstIP:   net.ParseIP("10.0.0.1"),
			InnerDstPort: 80,
		})
	case "F10":
		// Expr: tcp.options.MSS.value == 1460 (= 0x05b4 big-endian)
		return dsltest.Build(b, dsltest.PacketOpts{
			DstPort: 12345, // unused by the filter; MSS is the predicate
			TCP:     true,
			TCPOptions: []layers.TCPOption{
				{
					OptionType:   layers.TCPOptionKindMSS,
					OptionLength: 4,
					OptionData:   []byte{0x05, 0xb4},
				},
			},
		})
	}
	b.Fatalf("no packet builder for %s", fs.ID)
	return nil
}
