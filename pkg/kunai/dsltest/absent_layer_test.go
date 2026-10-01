package dsltest

import "testing"

// Packet-level checks for where clauses on optional and repeated layers
// (spec D-003 / D-013 / D-018): a field of a skipped layer makes its atom
// false, `not` of it true, layers after the optional one read at their
// runtime offset, and a label on a repeated layer names the last header.

func vlanTagged(t testing.TB, tci uint16) []byte {
	o := Defaults()
	o.VLAN = []uint16{tci}
	return Build(t, o)
}

func TestWhereOnOptionalVlan(t *testing.T) {
	untagged := Build(t, Defaults())

	eq := New(t, "eth/vlan?/ipv4/tcp where vlan.tci == 100")
	eq.MustMatch(t, vlanTagged(t, 100), "tagged 100")
	eq.MustReject(t, vlanTagged(t, 200), "tagged 200")
	eq.MustReject(t, untagged, "untagged: the atom is false (D-003)")

	ne := New(t, "eth/vlan?/ipv4/tcp where vlan.tci != 100")
	ne.MustMatch(t, vlanTagged(t, 200), "tagged 200")
	ne.MustReject(t, untagged, "untagged: != is false on an absent layer too")

	not := New(t, "eth/vlan?/ipv4/tcp where not (vlan.tci == 100)")
	not.MustMatch(t, untagged, "untagged: not(false)")
	not.MustReject(t, vlanTagged(t, 100), "tagged 100")
	not.MustMatch(t, vlanTagged(t, 200), "tagged 200")

	after := New(t, "eth/vlan?/ipv4/tcp where ipv4.ttl == 64")
	after.MustMatch(t, vlanTagged(t, 100), "tagged: ipv4 at its runtime offset")
	after.MustMatch(t, untagged, "untagged: ipv4 at its static offset")
}

func TestWhereOnLabelledRepeatedMpls(t *testing.T) {
	mpls := func(labels ...uint32) []byte {
		o := Defaults()
		o.MPLS = labels
		return Build(t, o)
	}
	for _, expr := range []string{"eth/mpls@m{1,3}/ipv4/tcp where m.label == 18", "eth/mpls@m{1,8}/ipv4/tcp where m.label == 18"} {
		r := New(t, expr)
		r.MustMatch(t, mpls(16, 17, 18), expr+": last label 18")
		r.MustReject(t, mpls(18, 17, 16), expr+": last label 16")
		r.MustMatch(t, mpls(18), expr+": single label")
	}
	star := New(t, "eth/mpls@m*/ipv4/tcp where m.label == 16")
	star.MustMatch(t, mpls(16), "one label")
	star.MustReject(t, mpls(), "no labels: absent")
	starNot := New(t, "eth/mpls@m*/ipv4/tcp where not (m.label == 16)")
	starNot.MustMatch(t, mpls(), "no labels: not(false)")
	starNot.MustReject(t, mpls(16), "one label 16")
}
