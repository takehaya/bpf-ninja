package dsltest

import (
	"github.com/google/gopacket/layers"
	"testing"
)

func TestWhereIntegerGrouping(t *testing.T) {
	for _, expr := range []string{
		"tcp.dport == 443", "(tcp.dport) == 443", "((tcp.dport)) == (443)",
		"(tcp.dport + 1) == 444", "(tcp.dport) + 1 == 444",
		"(tcp.dport + 1) > 443 and (tcp.dport) < 444",
		"not ((tcp.dport) != 443)", "((tcp.dport) == 443) == true",
		"true == ((tcp.dport) == 443)",
		"((tcp.dport) == 443) == (not false)",
		"(not true) != (tcp.dport == 443)",
		"(true and true) == (tcp.dport == 443)",
		"(tcp.dport == 443) == (true or false)",
		"false or tcp.dport == 443", "tcp.dport == 443 and true",
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

func TestWhereCompositeConstants(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{"not false", true}, {"not true", false}, {"true or tcp.dport == 80", true},
		{"false and tcp.dport == 80", false}, {"not (false or false)", true},
		{"(true and false) == (not true)", true}, {"(true or false) != true", false},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			r := New(t, "eth/ipv4/tcp where "+tc.expr)
			for _, port := range []uint16{80, 443} {
				if got := r.Match(t, BuildEthIPv4TCP(t, 1234, port)); got != tc.want {
					t.Fatalf("port %d: got %v want %v", port, got, tc.want)
				}
			}
		})
	}
}

func TestWhereQuantifierCompositeConstants(t *testing.T) {
	for _, quant := range []string{"any", "all"} {
		for _, constant := range []bool{false, true} {
			expr := "(false != false) and tcp.options.SACK.blocks.left == 256"
			if constant {
				expr = "(true == true) or tcp.options.SACK.blocks.left == 256"
			}
			t.Run(quant+"/"+expr, func(t *testing.T) {
				r := New(t, "eth/ipv4/tcp where "+quant+"("+expr+")")
				for _, present := range []bool{false, true} {
					o := Defaults()
					if present {
						o.TCPOptions = []layers.TCPOption{sackOption([2]uint32{1, 2})}
					}
					want := constant
					if !present {
						want = quant == "all"
					}
					if got := r.Match(t, Build(t, o)); got != want {
						t.Fatalf("present=%v: got %v want %v", present, got, want)
					}
				}
			})
		}
	}
}
