package dsltest

// Packet-level behaviour of the tag-flexible optional-VLAN forms that
// the tc host accepts. These run on the XDP harness, but the kunai
// filter bytecode is host-agnostic, so the byte layouts here are the
// same ones the identical bytecode sees at the tc skb window — in
// particular an untagged frame is exactly the post-untag layout the
// kernel hands a tc program for a singly-tagged frame
// (vlan_untag_datapath_test.go confirms that on a live veth).

import (
	"net"
	"testing"
)

// qinq?/vlan? is the recommended tag-flexible pattern: it matches every
// realistic L2 tagging shape on Ethernet.
func TestQinqVlanOptionalAllShapes(t *testing.T) {
	r := New(t, "eth/qinq?/vlan?/ipv4/tcp")

	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "untagged (= tc post-untag of a single tag)")

	single := Defaults()
	single.VLAN = []uint16{100}
	r.MustMatch(t, Build(t, single), "single C-tag")

	qinq := Defaults()
	qinq.VLAN = []uint16{100}
	qinq.QinQ = true
	r.MustMatch(t, Build(t, qinq), "double-tagged QinQ (S-tag + C-tag)")

	// A non-IP ethertype with no tag must still reject.
	v6 := Defaults()
	v6.SrcIP = net.ParseIP("fe80::1")
	v6.DstIP = net.ParseIP("fe80::2")
	r.MustReject(t, Build(t, v6), "ipv6 ethertype, no tag")
}

// `vlan[tci==100]?` is the "if a tag is present, require tci==100; else
// pass through" form (predicate before quantifier). On full packet
// bytes it tests the tag only when present.
func TestVlanOptionalPredicateSemantics(t *testing.T) {
	r := New(t, "eth/vlan[tci==100]?/ipv4/tcp")

	r.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "no tag -> skip -> pass through")

	ok := Defaults()
	ok.VLAN = []uint16{100}
	r.MustMatch(t, Build(t, ok), "tag tci=100 -> predicate passes")

	bad := Defaults()
	bad.VLAN = []uint16{200}
	r.MustReject(t, Build(t, bad), "tag tci=200 -> predicate fails")
}
