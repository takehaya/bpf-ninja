package dsltest

// Packet-level checks for the Geneve option-TLV walk, dispatched on the
// 24-bit option class+type discriminator. Two widely-deployed classes
// are exercised: OVN (OpenStack Neutron / OVN-Kubernetes, class 0x0102)
// and AWS Gateway Load Balancer (class 0x0108).

import (
	"encoding/binary"
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
