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

	rng := New(t, "eth/mpls/mpls{0,3}/ipv4/tcp")
	rng.MustMatch(t, mpls(16), "one label: zero optional labels")
	rng.MustMatch(t, mpls(16, 17), "two labels")
	rng.MustMatch(t, mpls(16, 17, 18, 19), "four labels: three optional")
	rng.MustReject(t, mpls(16, 17, 18, 19, 20), "five labels: over-run")

	// Each `mpls?` is "zero or one label ending the stack" (D-024): a
	// label it consumes must carry the s bit, so three labels over-run
	// the first optional even though a second optional follows.
	two := New(t, "eth/mpls/mpls?/mpls?/ipv4/tcp")
	two.MustMatch(t, mpls(16), "one label: both optionals read the first label's s bit")
	two.MustMatch(t, mpls(16, 17), "two labels")
	two.MustReject(t, mpls(16, 17, 18), "three labels: the first optional's label does not end the stack")

	// A mandatory self edge misses too once the previous label ended the
	// stack: `mpls/mpls` needs two labels (spec parent_dispatch).
	mandatory := New(t, "eth/mpls/mpls/ipv4/tcp")
	mandatory.MustMatch(t, mpls(16, 17), "two labels")
	mandatory.MustReject(t, mpls(16), "one label: the second mpls has no label to match")
}
