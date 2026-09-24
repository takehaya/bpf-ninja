package dsltest

import "testing"

func TestWhereIntegerGrouping(t *testing.T) {
	for _, expr := range []string{
		"tcp.dport == 443", "(tcp.dport) == 443", "((tcp.dport)) == (443)",
		"(tcp.dport + 1) == 444", "(tcp.dport) + 1 == 444",
		"(tcp.dport + 1) > 443 and (tcp.dport) < 444",
		"not ((tcp.dport) != 443)", "((tcp.dport) == 443) == true",
		"true == ((tcp.dport) == 443)",
	} {
		t.Run(expr, func(t *testing.T) {
			r := New(t, "eth/ipv4/tcp where "+expr)
			for _, port := range []uint16{0, 80, 443, 65535} {
				if got := r.Match(t, BuildEthIPv4TCP(t, 12345, port)); got != (port == 443) {
					t.Errorf("port %d: match=%t, want %t", port, got, port == 443)
				}
			}
		})
	}
}

func TestWhereExistsEquality(t *testing.T) {
	for _, expr := range []string{"gtp.opt.exists", "gtp.opt.exists == true", "true == gtp.opt.exists", "(gtp.opt.exists) == true", "gtp.opt.exists != false"} {
		t.Run(expr, func(t *testing.T) {
			r := New(t, gtpChain+" where "+expr)
			r.MustMatch(t, BuildGTPU(t, GTPUOpts{Flags: 0x32, MsgType: 255, TEID: 1, Opt: &GTPOpt{Seq: 1}, InnerDstPort: 443}), "optional block present")
			r.MustReject(t, BuildGTPU(t, GTPUOpts{Flags: 0x30, MsgType: 255, TEID: 1, InnerDstPort: 443}), "optional block absent")
		})
	}
}
