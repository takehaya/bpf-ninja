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
// tag the kernel stripped into skb metadata. A mandatory tag layer is a
// type error; a predicate on an optional tag is not implemented.
var tcRejectedVlanExprs = []struct {
	expr string
	want error
}{
	{"eth/vlan/ipv4/tcp", codegen.ErrVlanInMetadata},            // mandatory tag, no skip path
	{"eth/vlan{1,3}/ipv4/tcp", codegen.ErrVlanInMetadata},       // mandatory (RangeMin>=1)
	{"eth/qinq/vlan/ipv4/tcp", codegen.ErrVlanInMetadata},       // mandatory QinQ stack
	{"eth/vlan[tci==100]/ipv4/tcp", codegen.ErrVlanInMetadata},  // mandatory + reads tci
	{"eth/(vlan|qinq)/ipv4/tcp", codegen.ErrVlanInMetadata},     // tag inside an alternation
	{"eth/qinq/vlan?/ipv4/tcp", codegen.ErrVlanInMetadata},      // mandatory outer tag
	{"eth/vlan[tci==100]?/ipv4/tcp", codegen.ErrNotImplemented}, // optional but reads tci (predicate before quant)
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
	for _, c := range tcRejectedVlanExprs {
		t.Run(c.expr, func(t *testing.T) {
			_, err := compileFilter(c.expr, true /*useDSL*/, false /*isFexit*/, ebpf.SchedCLS)
			if !errors.Is(err, c.want) {
				t.Fatalf("expected tc rejection %q for %q, got %v", c.want, c.expr, err)
			}
		})
	}
}

// withTCVlanReinsert turns program.TCVlanReinsert on for the test.
func withTCVlanReinsert(t *testing.T) {
	t.Helper()
	TCVlanReinsert = true
	t.Cleanup(func() { TCVlanReinsert = false })
}

// tcWireVlanExprs: with TCVlanReinsert every vlan / qinq shape compiles
// at tc, including the ones the default rejects.
var tcWireVlanExprs = append(append([]string{}, tcAcceptedVlanExprs...),
	"eth/vlan/ipv4/tcp",
	"eth/vlan{1,3}/ipv4/tcp",
	"eth/qinq/vlan/ipv4/tcp",
	"eth/vlan[tci==100]/ipv4/tcp",
	"eth/(vlan|qinq)/ipv4/tcp",
	"eth/qinq/vlan?/ipv4/tcp",
	"eth/vlan[tci==100]?/ipv4/tcp",
	"eth/vlan?/ipv4/tcp where vlan.tci == 100",
	"eth/vlan?/ipv4/tcp capture vlan",
)

// TestBpfVlanTCWireLoads loads the wire-frame copy through the verifier
// (the kernel matrix runs it, so the pre-6.2 vlan_present branch too).
func TestBpfVlanTCWireLoads(t *testing.T) {
	hostProg := loadDummyTC(t) // skips when not root
	withTCVlanReinsert(t)
	for _, expr := range tcWireVlanExprs {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, hostProg, tcFuncName, expr, false /*exit*/, true /*useDSL*/)
		})
	}
}

func TestVlanTCWireCompiles(t *testing.T) {
	// Default: the filter reads the bytes as the kernel holds them.
	if out, err := compileFilter("eth/ipv4/tcp", true, false, ebpf.SchedCLS); err != nil || out.WireFrame {
		t.Fatalf("default tc: WireFrame=%v err=%v; want false, nil", out.WireFrame, err)
	}
	withTCVlanReinsert(t)
	for _, expr := range tcWireVlanExprs {
		for _, isFexit := range []bool{false, true} {
			out, err := compileFilter(expr, true /*useDSL*/, isFexit, ebpf.SchedCLS)
			if err != nil {
				t.Fatalf("compile %q at tc (fexit=%v): %v", expr, isFexit, err)
			}
			if !out.WireFrame {
				t.Fatalf("compile %q at tc (fexit=%v): the filter does not expect the wire frame", expr, isFexit)
			}
		}
	}
	// A pcap filter reads the bytes as the kernel holds them either way.
	if out, err := compileFilter("tcp dst port 80", false /*useDSL*/, false, ebpf.SchedCLS); err != nil || out.WireFrame {
		t.Fatalf("pcap filter at tc: WireFrame=%v err=%v; want false, nil", out.WireFrame, err)
	}
	// XDP has no metadata tag: the option changes nothing there.
	if out, err := compileFilter("eth/vlan/ipv4/tcp", true, false, ebpf.XDP); err != nil || !out.WireFrame {
		t.Fatalf("xdp: WireFrame=%v err=%v; want true, nil", out.WireFrame, err)
	}
}
