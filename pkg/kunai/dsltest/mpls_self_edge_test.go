package dsltest

import "testing"

// TestMplsOptionalSelfEdge pins the optional continuation of an MPLS
// stack (`mpls/mpls?`, `mpls/mpls*`): the previous label's s bit decides
// whether the optional layer is present, so a one-label stack skips it
// and deeper stacks consume it.
func TestMplsOptionalSelfEdge(t *testing.T) {
	mpls := func(labels ...uint32) []byte {
		o := Defaults()
		o.MPLS = labels
		return Build(t, o)
	}
	opt := New(t, "eth/mpls/mpls?/ipv4/tcp")
	opt.MustMatch(t, mpls(16), "one label: the optional is absent")
	opt.MustMatch(t, mpls(16, 17), "two labels")
	opt.MustReject(t, mpls(16, 17, 18), "three labels: the second must end the stack")

	star := New(t, "eth/mpls/mpls*/ipv4/tcp")
	star.MustMatch(t, mpls(16), "one label")
	star.MustMatch(t, mpls(16, 17, 18, 19), "four labels")
	star.MustReject(t, mpls(), "no label: the mandatory first one is missing")
}
