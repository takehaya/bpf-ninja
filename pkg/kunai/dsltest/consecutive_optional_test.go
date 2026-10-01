package dsltest

import (
	"net"
	"testing"
)

// TestConsecutiveOptionalsRuntimeParent pins D-034 for a run of optional
// layers whose dispatches differ: `eth/vlan?/mpls?/ipv4/tcp` dispatches
// ipv4 against whichever of vlan, mpls or eth actually precedes it.
func TestConsecutiveOptionalsRuntimeParent(t *testing.T) {
	build := func(vlan bool, mpls bool) []byte {
		o := Defaults()
		if vlan {
			o.VLAN = []uint16{100}
		}
		if mpls {
			o.MPLS = []uint32{16}
		}
		return Build(t, o)
	}
	r := New(t, "eth/vlan?/mpls?/ipv4/tcp")
	r.MustMatch(t, build(false, false), "plain ipv4: eth.ethertype")
	r.MustMatch(t, build(true, false), "vlan only: vlan.ethertype")
	r.MustMatch(t, build(false, true), "mpls only: self-validating under mpls")
	r.MustMatch(t, build(true, true), "vlan and mpls")

	v6 := Defaults()
	v6.VLAN = []uint16{100}
	v6.SrcIP, v6.DstIP = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	r.MustReject(t, Build(t, v6), "vlan then ipv6: vlan.ethertype is not ipv4")
}
