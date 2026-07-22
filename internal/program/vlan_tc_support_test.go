package program

// tc-host VLAN support: an optional, predicate-free vlan/qinq layer is
// matchable at the tc attach point (the kernel moves the outer tag into
// skb metadata, and the byte parser takes the layer's skip path), while
// a mandatory tag, a field-reading predicate, or a tag inside an
// alternation stays rejected at compile time. The datapath rationale is
// confirmed end-to-end in vlan_untag_datapath_test.go.

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// tcAcceptedVlanExprs load & verify at the tc clsact host.
var tcAcceptedVlanExprs = []string{
	"eth/vlan?/ipv4/tcp",             // optional single tag
	"eth/qinq?/vlan?/ipv4/tcp",       // recommended tag-flexible pattern
	"eth/vlan*/ipv4/tcp",             // zero-or-more (bpf_loop)
	"eth/vlan?/ipv4/tcp[dport==443]", // optional tag + predicate on a later layer
}

// tcRejectedVlanExprs reject at compile time on the tc host: they read a
// tag the kernel stripped into skb metadata.
var tcRejectedVlanExprs = []string{
	"eth/vlan/ipv4/tcp",            // mandatory tag, no skip path
	"eth/vlan{1,3}/ipv4/tcp",       // mandatory (RangeMin>=1)
	"eth/qinq/vlan/ipv4/tcp",       // mandatory QinQ stack
	"eth/vlan[tci==100]/ipv4/tcp",  // mandatory + reads tci
	"eth/vlan[tci==100]?/ipv4/tcp", // optional but reads tci (predicate before quant)
	"eth/(vlan|qinq)/ipv4/tcp",     // tag inside an alternation
}

func TestVlanTCOptionalLoads(t *testing.T) {
	hostProg := loadDummyTC(t) // skips when not root
	for _, expr := range tcAcceptedVlanExprs {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, hostProg, tcFuncName, expr, false /*exit*/, true /*useDSL*/)
		})
	}
}

func TestVlanTCFieldReadingRejects(t *testing.T) {
	for _, expr := range tcRejectedVlanExprs {
		t.Run(expr, func(t *testing.T) {
			_, err := compileFilter(expr, true /*useDSL*/, false /*isFexit*/, ebpf.SchedCLS)
			if !errors.Is(err, codegen.ErrNotImplemented) {
				t.Fatalf("expected tc ErrNotImplemented for %q, got %v", expr, err)
			}
		})
	}
}
