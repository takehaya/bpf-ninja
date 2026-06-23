package program

// Differential correctness for the pcap-expressible filters (F1-F4, F6).
//
// filterset_corpus_correctness_test.go asserts match/reject against
// hand-written expectations: the oracle is the author's own intent, so a
// protocol misunderstanding baked into both the .p4 definition and the
// test packet would agree and pass undetected. This file removes that
// self-judged circularity for the filters that pcap-filter can also
// express. It compiles the equivalent pcap-filter to cBPF with libpcap
// (the filter engine behind tcpdump) and runs it on the same packets
// through an x/net/bpf VM, an implementation that shares no code with
// kunai's eBPF backend. The two engines must agree on every packet;
// agreement is corroboration that does not depend on hand-built
// expectations.
//
// Root only (kunai side needs BPF_PROG_TEST_RUN / CAP_SYS_ADMIN); runs
// under `make test-bpf` via the TestBpf prefix.

import (
	"net"
	"os"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"

	dt "github.com/takehaya/xdp-ninja/pkg/kunai/dsltest"
)

// compilePcapVM compiles a pcap-filter expression to cBPF via libpcap
// and returns an independent x/net/bpf interpreter for it. This is the
// same pcap -> cBPF path the paper's pcap-filter baseline uses
// (internal/program/program.go), evaluated here in a pure-Go VM so the
// reference verdict never touches kunai's compiler.
func compilePcapVM(t *testing.T, expr string) *bpf.VM {
	t.Helper()
	raw, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, expr)
	if err != nil {
		t.Fatalf("pcap.CompileBPFFilter(%q): %v", expr, err)
	}
	insns := make([]bpf.Instruction, len(raw))
	for i, in := range raw {
		insns[i] = bpf.RawInstruction{Op: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}.Disassemble()
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("bpf.NewVM(%q): %v", expr, err)
	}
	return vm
}

// diffPackets returns a diverse packet set for a filter, chosen to
// straddle the filter's discriminating field so the differential sees
// both a match and a reject. The packets carry no expected verdict: the
// two engines supply each other's oracle.
func diffPackets(t *testing.T, id string) [][]byte {
	t.Helper()
	switch id {
	case "F1": // eth/ipv4/tcp where tcp.dport == 443  |  tcp dst port 443
		return [][]byte{
			cp(func(o *dt.PacketOpts) { o.DstPort = 443 })(t),           // match
			cp(func(o *dt.PacketOpts) { o.DstPort = 80 })(t),            // reject: dport
			cp(func(o *dt.PacketOpts) { o.DstPort = 443; asUDP(o) })(t), // reject: not tcp
		}
	case "F2": // src net 10.0.0.0/8 and tcp dst port 80
		return [][]byte{
			cp(func(o *dt.PacketOpts) { o.SrcIP = net.ParseIP("10.9.9.9"); o.DstPort = 80 })(t),    // match
			cp(func(o *dt.PacketOpts) { o.SrcIP = net.ParseIP("192.168.1.1"); o.DstPort = 80 })(t), // reject: src out of /8
			cp(func(o *dt.PacketOpts) { o.SrcIP = net.ParseIP("10.9.9.9"); o.DstPort = 8080 })(t),  // reject: dport
		}
	case "F3": // src net 2001:db8::/32 and tcp
		return [][]byte{
			cp(v6("2001:db8::1", "2001:db8::2"))(t),                                         // match
			cp(v6("2001:dead::1", "2001:db8::2"))(t),                                        // reject: src out of /32
			cp(func(o *dt.PacketOpts) { v6("2001:db8::1", "2001:db8::2")(o); asUDP(o) })(t), // reject: not tcp
		}
	case "F4": // vlan 100 and tcp dst port 80
		return [][]byte{
			cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{100}; o.DstPort = 80 })(t),   // match
			cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{100}; o.DstPort = 8080 })(t), // reject: dport
			cp(func(o *dt.PacketOpts) { o.VLAN = []uint16{200}; o.DstPort = 80 })(t),   // reject: vlan tag
			cp(func(o *dt.PacketOpts) { o.DstPort = 80 })(t),                           // reject: no tag
		}
	case "F6": // icmp[icmptype] == 8
		// The builder always emits ICMP echo request (type 8). Patch the
		// type byte for a reject case. Frame is eth(14)/ipv4 ihl=5(20)/icmp,
		// so the ICMP type is at offset 34; neither engine checks the ICMP
		// checksum, so the in-place edit is sufficient.
		const icmpTypeOff = 14 + 20
		reply := cp(asICMP)(t)
		if len(reply) <= icmpTypeOff {
			t.Fatalf("F6: packet is %d bytes, too short for the ICMP type at offset %d (builder/offset drift)", len(reply), icmpTypeOff)
		}
		if reply[icmpTypeOff] != 8 {
			t.Fatalf("F6: expected ICMP type 8 at offset %d, got %d (builder/offset drift)", icmpTypeOff, reply[icmpTypeOff])
		}
		reply[icmpTypeOff] = 0 // echo reply
		return [][]byte{
			cp(asICMP)(t), // match: type 8
			reply,         // reject: type 0
			cp(nil)(t),    // reject: tcp, not icmp
		}
	}
	t.Fatalf("no differential packet set defined for %s", id)
	return nil
}

// TestBpfFilterSetDifferential cross-checks every pcap-expressible filter
// (F1-F4, F6) against libpcap on the same packets, giving an independent
// reference beyond the hand-built expectations of the corpus suite.
func TestBpfFilterSetDifferential(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("differential checks need root (BPF_PROG_TEST_RUN)")
	}
	for _, fs := range FilterSet {
		if fs.CBPFCExpr == "" {
			continue // F5, F7-F10: pcap-filter cannot express these
		}
		fs := fs
		t.Run(fs.ID, func(t *testing.T) {
			r := dt.New(t, fs.Expr)
			vm := compilePcapVM(t, fs.CBPFCExpr)
			pkts := diffPackets(t, fs.ID)

			var nMatch, nReject int
			for i, pkt := range pkts {
				kunaiV := r.Match(t, pkt)
				n, err := vm.Run(pkt)
				if err != nil {
					t.Fatalf("%s pkt#%d: libpcap vm.Run: %v", fs.ID, i, err)
				}
				pcapV := n > 0
				if kunaiV != pcapV {
					t.Errorf("%s pkt#%d verdict mismatch: kunai=%v libpcap=%v\n  kunai: %s\n  pcap : %s",
						fs.ID, i, kunaiV, pcapV, fs.Expr, fs.CBPFCExpr)
				}
				if kunaiV {
					nMatch++
				} else {
					nReject++
				}
			}
			// Guard against a vacuous pass where every packet rejects on
			// both engines: the set must exercise both verdicts.
			if nMatch == 0 || nReject == 0 {
				t.Fatalf("%s: differential is vacuous (match=%d reject=%d); packet set must straddle the filter",
					fs.ID, nMatch, nReject)
			}
		})
	}
}
