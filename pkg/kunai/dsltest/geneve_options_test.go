package dsltest

// Packet-level checks for the Geneve option-TLV walk, dispatched on the
// 24-bit option class+type discriminator. Two widely-deployed classes
// are exercised: OVN (OpenStack Neutron / OVN-Kubernetes, class 0x0102)
// and AWS Gateway Load Balancer (class 0x0108).

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// ovnPortsValue packs the OVN option's 32-bit value: rsv(1) +
// ingress(15) + egress(16), big-endian.
func ovnPortsValue(ingress, egress uint16) []byte {
	v := (uint32(ingress&0x7fff) << 16) | uint32(egress)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// ovnValue is ovnPortsValue with the rsv bit set when rsv is true.
func ovnValue(rsv bool, ingress, egress uint16) []byte {
	b := ovnPortsValue(ingress, egress)
	if rsv {
		b[0] |= 0x80
	}
	return b
}

// gwlbCookieValue packs the AWS GWLB 32-bit flow cookie big-endian.
func gwlbCookieValue(cookie uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, cookie)
	return b
}

// TestGeneveOptionOVNEgressPort filters on the OVN logical egress port
// carried in the Geneve option (class 0x0102, type 0x80).
func TestGeneveOptionOVNEgressPort(t *testing.T) {
	r := New(t, "eth/ipv4/udp/geneve where geneve.options.OVN.egress_port == 42")

	ovn42 := GeneveOptionTLV(t, 0x0102, 0x80, ovnPortsValue(7, 42))
	r.MustMatch(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, ovn42), "OVN egress_port == 42")

	ovn99 := GeneveOptionTLV(t, 0x0102, 0x80, ovnPortsValue(7, 99))
	r.MustReject(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, ovn99), "OVN egress_port == 99 (!= 42)")
}

// TestGeneveOptionGWLBFlowCookie filters on the 32-bit AWS GWLB flow
// cookie (class 0x0108, type 3).
func TestGeneveOptionGWLBFlowCookie(t *testing.T) {
	r := New(t, "eth/ipv4/udp/geneve where geneve.options.GWLB.flow_cookie == 0x12345678")

	gwlb := GeneveOptionTLV(t, 0x0108, 0x03, gwlbCookieValue(0x12345678))
	r.MustMatch(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, gwlb), "GWLB flow_cookie matches")

	other := GeneveOptionTLV(t, 0x0108, 0x03, gwlbCookieValue(0x0badf00d))
	r.MustReject(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, other), "GWLB flow_cookie differs")
}

// TestGeneveOptionMultiCase walks past one known option to reach a
// second — exercising the 24-bit multi-case dispatch and the
// counter-driven loop across more than one option.
func TestGeneveOptionMultiCase(t *testing.T) {
	r := New(t, "eth/ipv4/udp/geneve where geneve.options.GWLB.flow_cookie == 0x55667788")

	ovn := GeneveOptionTLV(t, 0x0102, 0x80, ovnPortsValue(1, 2))
	gwlb := GeneveOptionTLV(t, 0x0108, 0x03, gwlbCookieValue(0x55667788))
	// OVN first, then GWLB: the walk must extract OVN, decrement, and
	// dispatch GWLB on the next iteration.
	r.MustMatch(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, ovn, gwlb), "GWLBE after OVN")
}

// TestGeneveOptionOVNIngressPort reads the OVN option's ingress port,
// bits 33..48 of the option (off a byte boundary), and its 1-bit rsv:
// each is narrowed out of the bytes it shares with the other, through
// the where clause, a bracket, a slice, ordering, an integer list, and
// arithmetic.
func TestGeneveOptionOVNIngressPort(t *testing.T) {
	opt := func(rsv bool, ingress uint16) []byte {
		return BuildEthIPv4UDPGeneveOpts(t, 0x123456, GeneveOptionTLV(t, 0x0102, 0x80, ovnValue(rsv, ingress, 0xffff)))
	}
	gwlb := GeneveOptionTLV(t, 0x0108, 0x03, gwlbCookieValue(7))
	behindGWLB := BuildEthIPv4UDPGeneveOpts(t, 0x123456, gwlb, GeneveOptionTLV(t, 0x0102, 0x80, ovnValue(true, 7, 0)))
	noOVN := BuildEthIPv4UDPGeneveOpts(t, 0x123456, gwlb)
	for _, tc := range []struct {
		expr          string
		match, reject [][]byte
	}{
		{"eth/ipv4/udp/geneve where geneve.options.OVN.ingress_port == 7",
			[][]byte{opt(true, 7), opt(false, 7), behindGWLB}, [][]byte{opt(true, 8), opt(false, 0x4007), noOVN}},
		{"eth/ipv4/udp/geneve[ovn.ingress_port == 0x7fff]",
			[][]byte{opt(false, 0x7fff), opt(true, 0x7fff)}, [][]byte{opt(true, 0x7ffe), noOVN}},
		{"eth/ipv4/udp/geneve[ovn.rsv == 1]",
			[][]byte{opt(true, 0), behindGWLB}, [][]byte{opt(false, 0x7fff), noOVN}},
		{"eth/ipv4/udp/geneve[ovn.ingress_port != 7]",
			[][]byte{opt(true, 6)}, [][]byte{opt(true, 7), noOVN}},
		{"eth/ipv4/udp/geneve[ovn.ingress_port in [1, 7]]",
			[][]byte{opt(true, 1), behindGWLB}, [][]byte{opt(true, 2), noOVN}},
		{"eth/ipv4/udp/geneve where geneve.options.OVN.ingress_port > 0x4000",
			[][]byte{opt(false, 0x4001)}, [][]byte{opt(true, 0x4000), opt(true, 1)}},
		{"eth/ipv4/udp/geneve where geneve.options.OVN.ingress_port[0:7] == 0x40",
			[][]byte{opt(true, 0x4000), opt(false, 0x40ff)}, [][]byte{opt(true, 0x3f80), opt(true, 7)}},
		{"eth/ipv4/udp/geneve where geneve.options.OVN.ingress_port + 1 == 8",
			[][]byte{opt(true, 7)}, [][]byte{opt(true, 8), noOVN}},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			r := New(t, tc.expr)
			for i, p := range tc.match {
				r.MustMatch(t, p, fmt.Sprintf("match #%d", i))
			}
			for i, p := range tc.reject {
				r.MustReject(t, p, fmt.Sprintf("reject #%d", i))
			}
		})
	}
}
