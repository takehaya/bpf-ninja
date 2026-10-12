package dsltest

import "testing"

// TestStaticChainPredicatePerHeader runs a bracket `in` list on an
// unrolled chain: every header checks the list with its own labels, which
// the loader refused as duplicate symbols when one emission was reused.
func TestStaticChainPredicatePerHeader(t *testing.T) {
	build := func(labels ...uint32) []byte {
		o := Defaults()
		o.MPLS = labels
		return Build(t, o)
	}
	r := New(t, "eth/mpls[label in [1..5, 100]]{1,3}/ipv4")
	r.MustMatch(t, build(3), "one header in the range")
	r.MustMatch(t, build(100), "one header on the single value")
	r.MustMatch(t, build(3, 100, 5), "three headers, each in the list")
	r.MustReject(t, build(50), "one header outside the list")
	r.MustReject(t, build(3, 50), "second header outside the list")
	r.MustReject(t, build(3, 4, 50), "third header outside the list")
	r.MustReject(t, build(1, 2, 3, 4), "four headers exceed the quantifier")

	// `+` walks the stack in a bpf_loop callback, which replays the
	// predicates with labels of its own.
	r = New(t, "eth/mpls[label in [1..5, 100]]+/ipv4")
	r.MustMatch(t, build(3, 100, 5, 1), "four headers, each in the list")
	r.MustReject(t, build(3, 100, 50), "third header outside the list")
}
