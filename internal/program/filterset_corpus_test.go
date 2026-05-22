package program

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// exprHasVlanLayer reports whether a corpus expression carries a
// vlan/qinq layer. The tc host rejects these at compile time because
// the kernel extracts the outer VLAN tag into skb metadata before the
// program runs (codegen.Capabilities.VlanInMetadata); they compile and
// load only on XDP, where VLAN is in-band. No corpus field is named
// "vlan"/"qinq", so a substring match is sufficient and self-contained.
func exprHasVlanLayer(expr string) bool {
	return strings.Contains(expr, "vlan") || strings.Contains(expr, "qinq")
}

// VerifierCorpus is a curated set of well-typed kunai expressions that
// extends the F1-F10 set with broader language coverage. Every entry
// must (i) compile (parse + resolve + codegen) and (ii) load on the
// kernel verifier; both are asserted below. The set strengthens the
// §4 verifier-safety claim of paper/sections/04_kunai_dsl.tex from
// "10 hand-picked filters pass" to "N curated filters pass". Selection
// rule: each entry must already be exercised by an upstream unit test
// (compile_test.go / parser_test.go / dsltest) so adding it here only
// changes coverage of the *load* path, not of the compile path.
var VerifierCorpus = []struct {
	ID   string
	Expr string
}{
	// Basic chains — minimal shapes.
	{"C01", "eth/ipv4/tcp"},
	{"C02", "eth/ipv4/udp"},
	{"C03", "eth/ipv6/tcp"},
	{"C04", "eth/ipv6/udp"},
	{"C05", "eth/ipv4/icmp"},
	{"C06", "eth/ipv6/icmp6"},

	// Bracket predicates — integer equality and inequality.
	{"C10", "eth/ipv4/tcp[dport==443]"},
	{"C11", "eth/ipv4/tcp[dport!=80]"},
	{"C12", "eth/ipv4/tcp[dport in [80, 443, 8080, 8443]]"},
	{"C13", "eth/ipv4[ttl==64]/tcp"},

	// Bracket predicates — IPv4 host and prefix.
	{"C20", "eth/ipv4[src==10.0.0.1]/tcp"},
	{"C21", "eth/ipv4[dst==192.168.1.42]/tcp"},
	{"C22", "eth/ipv4[dst==10.0.0.0/8]/tcp"},
	{"C23", "eth/ipv4[src==192.168.0.0/16]/tcp[dport==443]"},

	// Bracket predicates — IPv6 host and prefix.
	{"C30", "eth/ipv6[src==fe80::1]/tcp"},
	{"C31", "eth/ipv6[dst==::1]/tcp"},
	{"C32", "eth/ipv6[src==fe80::/10]/tcp"},
	{"C33", "eth/ipv6[dst==2001:db8::/32]/tcp"},
	{"C34", "eth/ipv6[src==2001:db8::1/128]/tcp"},
	{"C35", "eth/ipv6[src!=fe80::1]/tcp"},

	// Bracket predicates — MAC address.
	{"C40", "eth[dst==de:ad:be:ef:00:01]/ipv4/tcp"},
	{"C41", "eth[src!=00:11:22:33:44:55]/ipv4/tcp"},

	// where-clause — boolean / integer / comparison.
	{"C50", "eth/ipv4/tcp where tcp.dport == 443"},
	{"C51", "eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80"},
	{"C52", "eth/ipv4/tcp where ipv4.total_length == 100"},
	{"C53", "eth/ipv4/tcp where (tcp.dport == 80 or tcp.dport == 443) and tcp.sport > 1024"},
	{"C54", "eth/ipv4/tcp where true"},
	{"C55", "eth/ipv4/tcp where false"},
	{"C56", "eth/ipv4/tcp where tcp.dport"},
	{"C57", "eth/ipv4/tcp where (tcp.dport == 443) == (tcp.sport == 443)"},

	// where-clause — bitwise and shift on field × literal.
	{"C60", "eth/ipv4/tcp where tcp.dport & 0xff == 80"},
	{"C61", "eth/ipv4/tcp where ipv4.ttl & 0x0f != 0"},
	{"C62", "eth/ipv4/tcp where tcp.dport | 0x80 == 80"},
	{"C63", "eth/ipv4/tcp where tcp.dport ^ 0x01 == 80"},
	{"C64", "eth/ipv4/tcp where tcp.dport >> 4 == 0"},
	{"C65", "eth/ipv4/tcp where tcp.dport << 1 == 160"},

	// where-clause — IPv6 bit-slice (high half, low half, prefix).
	{"C70", "eth/ipv6/tcp where ipv6.src[0:32] == 0x20010db8"},
	{"C71", "eth/ipv6/tcp where ipv6.src[96:128] == ipv6.dst[96:128]"},
	{"C72", "eth/ipv6/tcp where ipv6.src[64:128] == ipv6.dst[64:128]"},
	{"C73", "eth/ipv6/tcp where ipv6.src[0:64] != ipv6.dst[0:64]"},
	{"C74", "eth/ipv6[src[0:32]==0x20010db8]/tcp"},

	// where-clause — literal on the left-hand side.
	{"C80", "eth/ipv4/tcp where 10.0.0.1 == ipv4.dst"},
	{"C81", "eth/ipv4/tcp where 10.0.0.0/8 != ipv4.dst"},
	{"C82", "eth/ipv4/tcp where aa:bb:cc:dd:ee:ff == eth.dst"},

	// where-clause — field-vs-field on 128-bit IPv6.
	{"C90", "eth/ipv6/tcp where ipv6.src == ipv6.dst"},
	{"C91", "eth/ipv6/tcp where ipv6.src < ipv6.dst"},

	// Quantified layers — ?, +, *, {n,m}.
	{"D00", "eth/vlan?/ipv4/tcp"},
	{"D01", "eth/qinq?/vlan?/ipv4/tcp"},
	{"D02", "eth/mpls+/ipv4/tcp"},
	{"D03", "eth/mpls*/ipv4/tcp"},
	{"D04", "eth/vlan{1,3}/ipv4/tcp"},
	{"D05", "eth/mpls{1,4}/ipv4/tcp"},
	{"D06", "eth/mpls{2,2}/ipv4/tcp"},
	{"D07", "eth/vlan?/ipv4/tcp[dport==443]"},

	// Heterogeneous-size alternation.
	{"E00", "eth/(vlan|qinq)/ipv4/tcp"},
	{"E01", "eth/(ipv4|ipv6)/tcp"},
	{"E02", "eth/(ipv4|ipv6)/tcp[dport==443]"},
	{"E03", "eth/((vlan|qinq)|ipv4)"},

	// @label disambiguation in multi-encap chains.
	{"F00", "eth/ipv4@outer/udp/vxlan/ipv4@inner/tcp where inner.dst == 10.0.0.1"},
	{"F01", "eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp where inner.dst == 10.0.0.1"},
	{"F02", "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where inner.dst == 10.0.0.1"},
	{"F03", "eth/ipv4@outer/udp/vxlan/ipv4@inner/tcp[dport==80]"},

	// SRv6 / TCP options aux-walk — quantifier-bearing structures.
	{"G00", "eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)"},
	{"G01", "eth/ipv6/srv6 where any(srv6.segments.addr == 2001:db8::/32)"},
	{"G02", "eth/ipv4/tcp where tcp.options.MSS.value == 1460"},

	// Capture clauses — exercise output-shape parser, not just chain.
	{"H00", "eth/ipv4/tcp capture headers+64"},
	{"H01", "eth/ipv4/tcp capture all"},
	{"H03", "eth/ipv4/tcp capture absolute 96"},
}

// TestFilterCorpusCompiles is the no-root sister of TestFilterSetCompiles:
// every entry in VerifierCorpus must successfully compile against both
// XDP and tc hosts. Drift here means a kunai change has broken language
// coverage that downstream tests (and the paper) rely on.
func TestFilterCorpusCompiles(t *testing.T) {
	hosts := []struct {
		name     string
		progType ebpf.ProgramType
	}{
		{"XDP", ebpf.XDP},
		{"tc", ebpf.SchedCLS},
	}

	for _, c := range VerifierCorpus {
		for _, h := range hosts {
			t.Run(c.ID+"/"+h.name, func(t *testing.T) {
				tcVlan := h.progType != ebpf.XDP && exprHasVlanLayer(c.Expr)
				_, err := compileFilter(c.Expr, true /*useDSL*/, false /*isFexit*/, h.progType)
				if tcVlan {
					if err == nil {
						t.Fatalf("compile %s (%s): expected tc rejection (VLAN in skb metadata), got success", c.ID, h.name)
					}
					return
				}
				if err != nil {
					t.Fatalf("compile %s (%s): %v", c.ID, h.name, err)
				}
			})
		}
	}
}

// TestBpfFilterCorpusXDP is the corpus counterpart of TestBpfFilterSetXDP.
// Each entry is loaded against the kernel verifier on the XDP host; any
// rejection fails the corresponding subtest. Sudo-gated through
// loadDummyXDP (testutil.SkipIfNotRoot). CI runs this through vimto on
// every kernel in .github/workflows/bpf_load_test.yaml, so a regression
// is caught across the 5-kernel matrix.
func TestBpfFilterCorpusXDP(t *testing.T) {
	runFilterCorpusMatrix(t, loadDummyXDP(t), xdpFuncName)
}

// TestBpfFilterCorpusTC mirrors the XDP variant on the tc clsact host.
func TestBpfFilterCorpusTC(t *testing.T) {
	runFilterCorpusMatrix(t, loadDummyTC(t), tcFuncName)
}

func runFilterCorpusMatrix(t *testing.T, hostProg *ebpf.Program, funcName string) {
	t.Helper()
	isTC := funcName == tcFuncName
	for _, c := range VerifierCorpus {
		t.Run(c.ID, func(t *testing.T) {
			if isTC && exprHasVlanLayer(c.Expr) {
				t.Skipf("%s carries a vlan/qinq layer; the tc host extracts the outer VLAN tag into skb metadata, so it is rejected at compile time (not loadable)", c.ID)
			}
			loadProbeOrFail(t, hostProg, funcName, c.Expr, false /*exit*/, true /*useDSL*/)
		})
	}
}
