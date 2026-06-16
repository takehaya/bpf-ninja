package program

// Packet-level correctness for the VerifierCorpus.
//
// filterset_corpus_test.go asserts every corpus expression compiles and
// loads on the verifier. That is the *load* path only: a filter can load
// yet read the wrong bytes (e.g. the historical Geneve opt_len mis-read).
// This file closes that gap by running each corpus expression through the
// dsltest BPF_PROG_TEST_RUN harness against hand-built packets and
// asserting match / reject, so corpus coverage is correctness, not just
// loadability.
//
// The corpus expression strings stay single-sourced in VerifierCorpus;
// entries here are keyed by ID and supply only the packets. A drift guard
// at the end forces every corpus ID into exactly one of: a correctness
// case, a documented load-only reason, or a test failure.
//
// Root only (BPF_PROG_TEST_RUN needs CAP_SYS_ADMIN); runs under
// `make test-bpf` via the TestBpf prefix.

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket/layers"

	dt "github.com/takehaya/xdp-ninja/pkg/kunai/dsltest"
)

type pktFn = func(testing.TB) []byte

// cp builds a packet from dsltest.Defaults() with mut applied.
func cp(mut func(o *dt.PacketOpts)) pktFn {
	return func(t testing.TB) []byte {
		o := dt.Defaults()
		if mut != nil {
			mut(&o)
		}
		return dt.Build(t, o)
	}
}

func pks(fs ...pktFn) []pktFn { return fs }

// asUDP / asICMP swap the default TCP L4 for the chain-shape match/reject
// cases. Each sets all three L4 flags so the selection is unambiguous even
// if a mutation composes them (buildL3L4 picks UDP before ICMP before TCP).
var (
	asUDP  = func(o *dt.PacketOpts) { o.TCP, o.UDP, o.ICMP = false, true, false }
	asICMP = func(o *dt.PacketOpts) { o.TCP, o.UDP, o.ICMP = false, false, true }
)

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// v6 turns a default packet into an Ethernet/IPv6/TCP frame with the
// given addresses (callers override ports/L4 as needed afterwards).
func v6(src, dst string) func(o *dt.PacketOpts) {
	return func(o *dt.PacketOpts) {
		o.SrcIP = net.ParseIP(src)
		o.DstIP = net.ParseIP(dst)
	}
}

type corpusCase struct {
	match  []pktFn // every packet here MUST match
	reject []pktFn // every packet here MUST reject
}

// corpusCorrectness maps corpus ID -> expected packets. The expression is
// looked up from VerifierCorpus by ID. A nil/empty match or reject list is
// allowed for one-sided predicates (where true / where false).
var corpusCorrectness = map[string]corpusCase{
	// --- basic chains: match the chain's L4, reject a different one ---
	"C01": {pks(cp(nil)), pks(cp(asUDP))},
	"C02": {pks(cp(asUDP)), pks(cp(nil))},
	"C03": {pks(cp(v6("fe80::1", "fe80::2"))), pks(cp(nil))},
	"C04": {pks(cp(func(o *dt.PacketOpts) { v6("fe80::1", "fe80::2")(o); asUDP(o) })),
		pks(cp(v6("fe80::1", "fe80::2")))},
	"C05": {pks(cp(asICMP)), pks(cp(nil))},
	"C06": {pks(cp(func(o *dt.PacketOpts) { v6("fe80::1", "fe80::2")(o); asICMP(o) })),
		pks(cp(v6("fe80::1", "fe80::2")))},

	// --- bracket predicates: integer ---
	"C10": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 443 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 }))},
	"C11": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 443 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 }))},
	"C12": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 443 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 22 }))},
	"C13": {pks(cp(nil)), pks(cp(func(o *dt.PacketOpts) { o.TTL = 63 }))}, // default TTL 64 matches

	// --- bracket predicates: IPv4 host / prefix ---
	"C20": {pks(cp(nil)), pks(cp(func(o *dt.PacketOpts) { o.SrcIP = net.ParseIP("10.0.0.9") }))}, // default src 10.0.0.1
	"C21": {pks(cp(func(o *dt.PacketOpts) { o.DstIP = net.ParseIP("192.168.1.42") })), pks(cp(nil))},
	"C22": {pks(cp(nil)), pks(cp(func(o *dt.PacketOpts) { o.DstIP = net.ParseIP("192.168.1.1") }))}, // default dst 10.0.0.2 in 10/8
	"C23": {
		pks(cp(func(o *dt.PacketOpts) { o.SrcIP = net.ParseIP("192.168.1.1"); o.DstPort = 443 })),
		pks(
			cp(func(o *dt.PacketOpts) { o.SrcIP = net.ParseIP("10.0.0.1"); o.DstPort = 443 }),   // src out of /16
			cp(func(o *dt.PacketOpts) { o.SrcIP = net.ParseIP("192.168.1.1"); o.DstPort = 80 }), // dport mismatch
		),
	},

	// --- bracket predicates: IPv6 host / prefix ---
	"C30": {pks(cp(v6("fe80::1", "fe80::2"))), pks(cp(v6("fe80::2", "fe80::2")))},
	"C31": {pks(cp(v6("fe80::1", "::1"))), pks(cp(v6("fe80::1", "::2")))},
	"C32": {pks(cp(v6("fe80::1", "fe80::2"))), pks(cp(v6("2001:db8::1", "fe80::2")))},
	"C33": {pks(cp(v6("fe80::1", "2001:db8::1"))), pks(cp(v6("fe80::1", "fe80::2")))},
	"C34": {pks(cp(v6("2001:db8::1", "fe80::2"))), pks(cp(v6("2001:db8::2", "fe80::2")))},
	"C35": {pks(cp(v6("fe80::2", "fe80::2"))), pks(cp(v6("fe80::1", "fe80::2")))},

	// --- bracket predicates: MAC ---
	"C40": {pks(cp(func(o *dt.PacketOpts) { o.DstMAC = mac("de:ad:be:ef:00:01") })), pks(cp(nil))},
	"C41": {pks(cp(nil)), pks(cp(func(o *dt.PacketOpts) { o.SrcMAC = mac("00:11:22:33:44:55") }))},

	// --- where-clause: comparison ---
	"C50": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 443 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 }))},
	"C51": {
		pks(cp(func(o *dt.PacketOpts) { o.DstPort = 443 }), cp(func(o *dt.PacketOpts) { o.DstPort = 80 })),
		pks(cp(func(o *dt.PacketOpts) { o.DstPort = 22 })),
	},
	"C52": {pks(cp(func(o *dt.PacketOpts) { o.Payload = make([]byte, 60) })), pks(cp(nil))}, // 20+20+60 = 100
	"C53": {
		pks(cp(nil)), // sport 12345 > 1024, dport 80
		pks(
			cp(func(o *dt.PacketOpts) { o.SrcPort = 500 }), // sport not > 1024
			cp(func(o *dt.PacketOpts) { o.DstPort = 22 }),  // dport in neither
		),
	},
	"C54": {pks(cp(nil)), nil}, // where true: match only
	"C55": {nil, pks(cp(nil))}, // where false: reject only
	"C56": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 0 }))},
	"C57": { // (dport==443)==(sport==443): bool-eq is XNOR — match when both bools agree
		pks(
			cp(func(o *dt.PacketOpts) { o.DstPort, o.SrcPort = 443, 443 }),  // T == T
			cp(func(o *dt.PacketOpts) { o.DstPort, o.SrcPort = 80, 12345 }), // F == F
		),
		pks(
			cp(func(o *dt.PacketOpts) { o.DstPort, o.SrcPort = 443, 12345 }), // T == F
			cp(func(o *dt.PacketOpts) { o.DstPort, o.SrcPort = 80, 443 }),    // F == T
		),
	},

	// --- where-clause: bitwise / shift, (a OP b) binds tighter than == ---
	"C60": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 81 }))},
	"C61": {pks(cp(func(o *dt.PacketOpts) { o.TTL = 65 })), pks(cp(func(o *dt.PacketOpts) { o.TTL = 64 }))},         // 64&0x0f==0
	"C62": {nil, pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 }))},                                                // (dport|0x80)>=128, never ==80
	"C63": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 81 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 }))}, // 81^1==80
	"C64": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 8 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 }))},  // 8>>4==0
	"C65": {pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 })), pks(cp(func(o *dt.PacketOpts) { o.DstPort = 81 }))}, // 80<<1==160

	// --- where-clause: IPv6 bit-slice ---
	"C70": {pks(cp(v6("2001:db8::1", "fe80::2"))), pks(cp(v6("fe80::1", "fe80::2")))},
	"C71": {pks(cp(v6("2001:db8::1234:5678", "fe80::1234:5678"))), pks(cp(v6("2001:db8::1234:5678", "fe80::1234:5679")))},
	"C72": {pks(cp(v6("2001:db8::1:2:3:4", "fe80::1:2:3:4"))), pks(cp(v6("2001:db8::1:2:3:4", "fe80::1:2:3:5")))},
	"C73": {pks(cp(v6("2001:db8::1", "fe80::1"))), pks(cp(v6("2001:db8::1", "2001:db8::2")))}, // != on /64
	"C74": {pks(cp(v6("2001:db8::1", "fe80::2"))), pks(cp(v6("fe80::1", "fe80::2")))},

	// --- where-clause: literal LHS ---
	"C80": {pks(cp(func(o *dt.PacketOpts) { o.DstIP = net.ParseIP("10.0.0.1") })), pks(cp(nil))}, // default dst 10.0.0.2
	"C81": {pks(cp(func(o *dt.PacketOpts) { o.DstIP = net.ParseIP("192.168.1.1") })), pks(cp(nil))},
	"C82": {pks(cp(func(o *dt.PacketOpts) { o.DstMAC = mac("aa:bb:cc:dd:ee:ff") })), pks(cp(nil))},

	// --- where-clause: field-vs-field 128-bit ---
	"C90": {pks(cp(v6("2001:db8::1", "2001:db8::1"))), pks(cp(v6("2001:db8::1", "2001:db8::2")))},
	"C91": {pks(cp(v6("::1", "::2"))), pks(cp(v6("::2", "::1")))},

	// --- quantified layers ---
	"D00": { // vlan? — match with and without a tag
		pks(cp(nil), cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{100} })),
		pks(cp(asUDP)),
	},
	"D01": {
		pks(cp(nil), cp(func(o *dt.PacketOpts) { o.QinQ = true; o.VLAN = []uint16{100, 200} })),
		pks(cp(asUDP)),
	},
	"D02": { // mpls+ — 1 or more labels (1 and 2 both match)
		pks(
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16} }),
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16, 17} }),
		),
		pks(cp(nil)),
	},
	"D03": { // mpls* — 0 or more labels (0, 1, 2 all match)
		pks(
			cp(nil),
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16} }),
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16, 17} }),
		),
		pks(cp(asUDP)),
	},
	"D04": { // vlan{1,3}
		pks(cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{100} }), cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{100, 200, 300} })),
		pks(cp(nil)),
	},
	"D05": { // mpls{1,4}: 1-4 labels match; 0 and 5+ reject (s-bit chain-end termination)
		pks(
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16} }),
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16, 17} }),
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16, 17, 18} }),
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16, 17, 18, 19} }),
		),
		pks(
			cp(nil), // 0 labels
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16, 17, 18, 19, 20} }), // 5 > max 4
		),
	},
	"D06": { // mpls{2,2}: exactly 2 labels match; 1 (under-run), 3 (over-run), 0 all reject on the s-bit
		pks(cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16, 17} })),
		pks(
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16} }),         // 1 < min 2 (under-run)
			cp(func(o *dt.PacketOpts) { o.MPLS = []uint32{16, 17, 18} }), // 3 > max 2 (over-run)
			cp(nil), // 0 labels
		),
	},
	"D07": {
		pks(cp(func(o *dt.PacketOpts) { o.DstPort = 443 }), cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{100}; o.DstPort = 443 })),
		pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 })),
	},

	// --- heterogeneous-size alternation ---
	"E00": {
		pks(cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{100} }), cp(func(o *dt.PacketOpts) { o.QinQ = true; o.VLAN = []uint16{100} })),
		pks(cp(nil)),
	},
	"E01": {
		pks(cp(nil), cp(v6("fe80::1", "fe80::2"))),
		pks(cp(asUDP)),
	},
	"E02": {
		pks(cp(func(o *dt.PacketOpts) { o.DstPort = 443 }), cp(func(o *dt.PacketOpts) { v6("fe80::1", "fe80::2")(o); o.DstPort = 443 })),
		pks(cp(func(o *dt.PacketOpts) { o.DstPort = 80 })),
	},
	"E03": {
		pks(cp(nil), cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{100} }), cp(func(o *dt.PacketOpts) { o.QinQ = true; o.VLAN = []uint16{100} })),
		pks(cp(v6("fe80::1", "fe80::2"))),
	},

	// --- @label multi-encap: inner.dst / inner port ---
	"F00": {pks(func(t testing.TB) []byte { return dt.BuildVXLANInnerIPv4TCP(t, net.IPv4(10, 0, 0, 1), 80) }),
		pks(func(t testing.TB) []byte { return dt.BuildVXLANInnerIPv4TCP(t, net.IPv4(10, 0, 0, 2), 80) })},
	"F01": {pks(func(t testing.TB) []byte {
		return dt.BuildGeneveInnerIPv4TCP(t, dt.GeneveInnerIPv4TCPOpts{InnerDstIP: net.IPv4(10, 0, 0, 1)})
	}), pks(func(t testing.TB) []byte {
		return dt.BuildGeneveInnerIPv4TCP(t, dt.GeneveInnerIPv4TCPOpts{InnerDstIP: net.IPv4(10, 0, 0, 2)})
	})},
	"F02": {pks(func(t testing.TB) []byte {
		return dt.BuildGTPU(t, dt.GTPUOpts{InnerDst: net.IPv4(10, 0, 0, 1)})
	}), pks(func(t testing.TB) []byte {
		return dt.BuildGTPU(t, dt.GTPUOpts{InnerDst: net.IPv4(10, 0, 0, 2)})
	})},
	"F03": {pks(func(t testing.TB) []byte { return dt.BuildVXLANInnerIPv4TCP(t, net.IPv4(10, 0, 0, 1), 80) }),
		pks(func(t testing.TB) []byte { return dt.BuildVXLANInnerIPv4TCP(t, net.IPv4(10, 0, 0, 1), 443) })},

	// --- aux-walk: any() over segments / TCP options ---
	"G00": {pks(func(t testing.TB) []byte {
		return dt.BuildSRv6(t, dt.SRv6Opts{Segments: []net.IP{net.ParseIP("fc00::3"), net.ParseIP("fc00::2"), net.ParseIP("fc00::1")}})
	}), pks(func(t testing.TB) []byte {
		return dt.BuildSRv6(t, dt.SRv6Opts{Segments: []net.IP{net.ParseIP("fc00::3"), net.ParseIP("fc00::2"), net.ParseIP("fc00::9")}})
	})},
	"G01": {pks(func(t testing.TB) []byte {
		return dt.BuildSRv6(t, dt.SRv6Opts{Segments: []net.IP{net.ParseIP("fc00::1"), net.ParseIP("2001:db8::5")}})
	}), pks(func(t testing.TB) []byte {
		return dt.BuildSRv6(t, dt.SRv6Opts{Segments: []net.IP{net.ParseIP("fc00::1"), net.ParseIP("fc00::2")}})
	})},
	"G02": {
		pks(cp(func(o *dt.PacketOpts) { o.TCPOptions = mssOption(1460) })),
		pks(cp(func(o *dt.PacketOpts) { o.TCPOptions = mssOption(1400) })),
	},
}

func mssOption(v uint16) []layers.TCPOption {
	return []layers.TCPOption{{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{byte(v >> 8), byte(v)},
	}}
}

// corpusLoadOnly documents IDs whose match/reject verdict is out of this
// suite's scope: the verdict is trivial or the intended semantics are
// genuinely unclear, so there is no confident oracle to assert.
var corpusLoadOnly = map[string]string{
	"H00": "capture clause: changes captured output bytes, not the match/reject verdict (which equals eth/ipv4/tcp); capture-byte correctness needs a separate oracle",
	"H01": "capture clause (capture all): same as H00",
	"H03": "capture clause (capture absolute 96): same as H00",
}

func TestBpfFilterCorpusCorrectness(t *testing.T) {
	exprByID := make(map[string]string, len(VerifierCorpus))
	covered := make(map[string]bool, len(corpusCorrectness))
	for _, c := range VerifierCorpus {
		exprByID[c.ID] = c.Expr
		cc, ok := corpusCorrectness[c.ID]
		if !ok {
			continue
		}
		covered[c.ID] = true
		c := c
		t.Run(c.ID, func(t *testing.T) {
			r := dt.New(t, c.Expr) // skips when not root
			for i, mk := range cc.match {
				r.MustMatch(t, mk(t), fmt.Sprintf("%s match #%d (%s)", c.ID, i, c.Expr))
			}
			for i, rk := range cc.reject {
				r.MustReject(t, rk(t), fmt.Sprintf("%s reject #%d (%s)", c.ID, i, c.Expr))
			}
		})
	}

	// drift guard: every corpus ID must be correctness-covered or documented
	// load-only. Forces a decision as the corpus grows.
	for _, c := range VerifierCorpus {
		if covered[c.ID] {
			continue
		}
		if _, ok := corpusLoadOnly[c.ID]; !ok {
			t.Errorf("corpus %s (%q): classify it in corpusCorrectness or corpusLoadOnly", c.ID, c.Expr)
		}
	}
	// other direction: no stale IDs in either map.
	for id := range corpusCorrectness {
		if _, ok := exprByID[id]; !ok {
			t.Errorf("corpusCorrectness has %s which is not in VerifierCorpus", id)
		}
		// "exactly one of" — an ID in both maps would be silently treated as
		// covered above, leaving a dead load-only reason. Reject it.
		if _, both := corpusLoadOnly[id]; both {
			t.Errorf("corpus %s is in both corpusCorrectness and corpusLoadOnly; it must be in exactly one", id)
		}
	}
	for id := range corpusLoadOnly {
		if _, ok := exprByID[id]; !ok {
			t.Errorf("corpusLoadOnly has %s which is not in VerifierCorpus", id)
		}
	}
}
