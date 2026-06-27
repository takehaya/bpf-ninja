package program

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

// FilterSpec is one row of the paper's evaluation matrix
// (docs/paper/filter-set.md). Keep this list in sync with
// benchmark/filters/kunai/F*.kunai and the §6.2 scoreboard.
//
// WantInsns pins the raw-insn count (countRawInsns expands DWord loads
// into two verifier slots, matching what the kernel verifier counts) so
// a codegen regression surfaces as a test failure. Refresh this number
// together with docs/paper/filter-set.md and the §6.3 prelim numbers in
// paper/sections/06_evaluation.tex when a real codegen change shifts a
// filter's count.
//
// CBPFCExpr is the equivalent pcap-filter expression for cBPF/cbpfc
// comparison benchmarks; empty means cBPF cannot express the filter
// (F5 is fragile in pcap-filter, F7-F10 are kunai-only by design).
type FilterSpec struct {
	ID        string
	Expr      string
	CBPFCExpr string // pcap-filter equivalent; "" when cBPF cannot express
	WantInsns int    // entry-mode XDP host raw-insn count (tc emits the same body)
	Notes     string // short rationale; surfaces in test output
	// TCUnsupported marks filters the tc host rejects at compile time.
	// The kernel extracts the outer VLAN tag into skb metadata before
	// the tc program runs, so vlan/qinq layers are not in packet bytes
	// (see codegen.Capabilities.VlanInMetadata). These compile and load
	// on XDP, where VLAN is in-band.
	TCUnsupported bool
}

// FilterSet is the canonical F1-F10 used across the paper's expressiveness
// (E1), microbench (E2), and verifier-matrix (E4) evaluations. Bench /
// load tests in this package read from here so a syntax change shows up
// as one diff in one place. Captured 2026-05-06.
var FilterSet = []FilterSpec{
	{ID: "F1", Expr: "eth/ipv4/tcp where tcp.dport == 443",
		CBPFCExpr: "tcp dst port 443",
		WantInsns: 199, Notes: "TCP dst port baseline"},
	{ID: "F2", Expr: "eth/ipv4[src==10.0.0.0/8]/tcp where tcp.dport == 80",
		CBPFCExpr: "src net 10.0.0.0/8 and tcp dst port 80",
		WantInsns: 209, Notes: "IPv4 source CIDR via bracket predicate"},
	{ID: "F3", Expr: "eth/ipv6[src==2001:db8::/32]/tcp",
		CBPFCExpr: "src net 2001:db8::/32 and tcp",
		WantInsns: 338, Notes: "IPv6 source CIDR via bracket predicate"},
	{ID: "F4", Expr: "eth/vlan[tci==100]/ipv4/tcp where tcp.dport == 80",
		CBPFCExpr: "vlan 100 and tcp dst port 80",
		WantInsns: 215, Notes: "VLAN tag (TCI=100) + TCP dst", TCUnsupported: true},
	{ID: "F5", Expr: "eth/ipv4/icmp where icmp.type == 8",
		CBPFCExpr: "icmp[icmptype]==8",
		WantInsns: 85, Notes: "ICMP echo request"},
	{ID: "F6", Expr: "eth/qinq/vlan/ipv4/tcp where tcp.dport == 80",
		// pcap "vlan 100 and vlan 200" is kernel/NIC dependent; intentionally
		// omitted so the bench does not pretend the comparison is meaningful.
		WantInsns: 217, Notes: "QinQ S-VLAN + inner C-VLAN via chain", TCUnsupported: true},
	{ID: "F7", Expr: "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where inner.dst == 10.0.0.1",
		WantInsns: 405, Notes: "GTP-U inner IPv4 dst (5G core)"},
	{ID: "F8", Expr: "eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)",
		WantInsns: 332, Notes: "SRv6 segment-list any-quantifier (5G/SDN); element-driven segment walk (count = last_entry+1, derived) + post-walk R4 re-anchor to next-header at (last_entry+1)*16 from the same count (no annotations), any() read lowered to a bpf_loop callback"},
	{ID: "F9", Expr: "eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp where inner.dst == 10.0.0.1",
		WantInsns: 351, Notes: "Geneve inner IPv4 dst (Cilium overlay / cloud VPC); inner offset resolved past the opt_len*4 options section via the counter-driven bulk-advance fallback"},
	{ID: "F10", Expr: "eth/ipv4/tcp where tcp.options.MSS.value == 1460",
		WantInsns: 231, Notes: "TCP option MSS via parser-counter walk"},
}

// TestFilterSetCompiles confirms every paper filter compiles end-to-end
// against both the XDP and tc hosts. Runs without root (no BPF load),
// so it's gated behind `make test` and protects the syntax used in
// docs/paper/filter-set.md and paper/sections/06_evaluation.tex from
// drifting silently.
func TestFilterSetCompiles(t *testing.T) {
	hosts := []struct {
		name     string
		progType ebpf.ProgramType
	}{
		{"XDP", ebpf.XDP},
		{"tc", ebpf.SchedCLS},
	}

	for _, fs := range FilterSet {
		for _, h := range hosts {
			t.Run(fs.ID+"/"+h.name, func(t *testing.T) {
				if fs.TCUnsupported && h.progType != ebpf.XDP {
					_, err := compileFilter(fs.Expr, true /*useDSL*/, false /*isFexit*/, h.progType)
					if !errors.Is(err, codegen.ErrNotImplemented) {
						t.Fatalf("compile %s (%s): expected tc rejection with ErrNotImplemented (VLAN in skb metadata), got %v\n  expr: %s", fs.ID, fs.Notes, err, fs.Expr)
					}
					t.Logf("rejected on %s as expected: %v", h.name, err)
					return
				}
				out, err := compileFilter(fs.Expr, true /*useDSL*/, false /*isFexit*/, h.progType)
				if err != nil {
					t.Fatalf("compile %s (%s): %v\n  expr: %s", fs.ID, fs.Notes, err, fs.Expr)
				}
				t.Logf("insns=%d  %s",
					countRawInsns(out.Main, out.Callbacks), fs.Notes)
			})
		}
	}
}

// TestFilterSetCounts pins each filter's raw-insn count so an accidental
// codegen blow-up surfaces as a test failure rather than a quiet drift in
// the paper's §6.3 numbers. Compiles independently of TestFilterSetCompiles
// so that "this expression no longer parses/compiles" and "this expression
// emits a different number of instructions" remain separately diagnosable.
func TestFilterSetCounts(t *testing.T) {
	for _, fs := range FilterSet {
		t.Run(fs.ID, func(t *testing.T) {
			out, err := compileFilter(fs.Expr, true /*useDSL*/, false /*isFexit*/, ebpf.XDP)
			if err != nil {
				t.Fatalf("compile %s: %v", fs.ID, err)
			}
			got := countRawInsns(out.Main, out.Callbacks)
			if got != fs.WantInsns {
				t.Errorf("%s: insns drifted: got %d, want %d (%s)\n  expr: %s",
					fs.ID, got, fs.WantInsns, fs.Notes, fs.Expr)
			}
		})
	}
}
