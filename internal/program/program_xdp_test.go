package program

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// xdpNativeCBPFExprs and xdpNativeDSLExprs cover the cbpfc and kunai
// shapes the XDP-native wrapper must load cleanly. The filter runs on
// the packet pointer there (PTR_TO_PACKET), where every variable-offset
// access needs an end-pointer check on the very pointer it uses; the
// tracing hosts run on a 512-byte map value whose size alone bounds a
// scalar offset, so a shape can pass dsltest and still fail here. The
// DSL list is the coverage statement: a shape rejected on the packet
// pointer is named in the note at its end.
var (
	xdpNativeCBPFExprs = []string{
		"arp",
		"icmp",
		"tcp port 80",
		"host 10.0.0.1",
	}

	xdpNativeDSLExprs = []string{
		// fixed-offset chains
		"eth/ipv4/udp",
		"eth/ipv4/tcp",
		// IHL × 4 dynamic offset
		"eth/ipv4/tcp[dport==443]",
		"eth/ipv4/tcp where tcp.dport == 443",
		// IPv6 ext header walking via bpf_loop callback
		"eth/ipv6/tcp",
		"eth/ipv6/udp",
		"eth/ipv6/tcp where ipv6.src == ipv6.dst",
		// aux stack indexes bounded by the header's count byte (D-031):
		// dynamic in a where clause, static in a bracket predicate.
		"eth/ipv6/srv6/tcp where srv6.segments[srv6.segments_left].addr == fc00::1",
		"eth/ipv6/srv6[segments[1].addr != fc00::1]/tcp",
		// alternation (both IPv4 + IPv6 paths must verify)
		"eth/(ipv4|ipv6)/tcp",
		// optional + range quantifiers
		"eth/vlan?/ipv4/tcp",
		"eth/vlan{1,3}/ipv4/tcp",
		// capture clause
		"eth/ipv4/tcp capture headers+64",
		"eth/ipv6/tcp capture headers+64",
		// repeated variable-length layers: the layer after the chain
		// dispatches against a range-valued entry (bounded idiom), and
		// iterations >= 2 read the previous header through one too.
		"eth/ipv4{1,2}/tcp",
		"eth/ipv4{2,2}/tcp",
		"eth/ipv4{1,4}/tcp",
		"eth/ipv4/ipv4{0,2}/tcp",
		"eth/vlan/ipv4{1,2}/tcp",
		"eth/ipv4[options.valid]{1,4}/tcp",
		"eth/ipv4@o{1,2}/tcp where o.options.RR.kind == 7",
		"eth/ipv4{1,2}/tcp where tcp.dport == 443",
		"eth/ipv4{1,2}/udp",
		// flag-gated optional words (gre's C/K/S) read the flag byte
		// back through the range-valued R4 left by ipv4's IHL.
		"eth/ipv4/gre/ipv4/tcp",
		"eth/ipv4/gre?/ipv4/tcp",
		"eth/ipv4{1,2}/gre?/ipv4/tcp",
		// Not here: an ipv6 whose entry is a range (`eth/ipv6/ipv6/tcp`,
		// `eth/ipv4/ipv6/tcp`, so `ipv6{1,2}` too) stores the extension
		// chain's next_header back into the ipv6 header through an
		// unbounded packet pointer and is rejected on the packet pointer
		// today.
	}
)

// TestBpfXDPNativeLoad verifies the XDP-native wrapper passes the
// verifier with a representative spread of cbpfc + DSL filters. No
// attach: we only build and load, exercising the program shape.
func TestBpfXDPNativeLoad(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	t.Run("no_filter", func(t *testing.T) { loadXDPNativeOrFail(t, "", false) })
	t.Run("cbpfc", func(t *testing.T) {
		for _, expr := range xdpNativeCBPFExprs {
			t.Run(expr, func(t *testing.T) { loadXDPNativeOrFail(t, expr, false) })
		}
	})
	t.Run("DSL", func(t *testing.T) {
		for _, expr := range xdpNativeDSLExprs {
			t.Run(expr, func(t *testing.T) { loadXDPNativeOrFail(t, expr, true) })
		}
	})
}

// loadXDPNativeOrFail compiles the filter, builds the XDP-native
// wrapper with a real events map (placeholder fd=0 trips the verifier
// on capture-side LoadMapPtr), and loads it through the verifier.
// Mirrors loadProbeOrFail but skips the attach step.
func loadXDPNativeOrFail(t *testing.T, expr string, useDSL bool) {
	t.Helper()
	out, err := compileFilter(expr, useDSL, false, ebpf.XDP)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}

	innerSpec := &ebpf.MapSpec{
		Name: "ninja_xdp_test_rb", Type: ebpf.RingBuf, MaxEntries: 65536,
	}
	innerMap, err := ebpf.NewMap(innerSpec)
	if err != nil {
		t.Fatalf("creating inner ringbuf: %v", err)
	}
	t.Cleanup(func() { _ = innerMap.Close() })
	outerMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "ninja_xdp_test_outer", Type: ebpf.ArrayOfMaps,
		KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: innerSpec,
	})
	if err != nil {
		t.Fatalf("creating outer array_of_maps: %v", err)
	}
	t.Cleanup(func() { _ = outerMap.Close() })
	if err := outerMap.Put(uint32(0), innerMap); err != nil {
		t.Fatalf("populating outer map: %v", err)
	}

	insns := buildXDPNativeInsns(out, outerMap.FD(), nil, 0, 0)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "bpfninja_ntvtst",
		Type:         ebpf.XDP,
		Instructions: insns,
		License:      "GPL",
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			dumpVerifierStats(t, expr, ve)
			t.Fatalf("verifier rejected %q:\n%+v", expr, ve)
		}
		t.Fatalf("loading XDP-native program for %q: %v", expr, err)
	}
	t.Cleanup(func() { _ = prog.Close() })
}
