package program

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// xdpNativeFilterExprs covers the kunai/cbpfc shapes the XDP-native
// wrapper needs to load cleanly.
//
// cbpfc filters all pass the verifier: cbpfc emits packet-pointer-safe
// bound checks on every variable-offset access.
//
// DSL filters are partial in v1: simple chains like eth/ipv4/udp work
// because UDP's fixed 8-byte header keeps every access within a
// statically-known offset range. Chains that walk through IPv4 to a
// variable-offset L4 header (TCP, where the inner offset depends on
// IHL*4) currently fail to load: kunai's bound-check emit was tuned
// for the tracing path's PTR_TO_MAP_VALUE access (where the verifier
// trusts the proven map size for any in-bounds offset), and is too
// loose for PTR_TO_PACKET access. See dsl-followups for "kunai
// packet-pointer codegen".
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
		// alternation (both IPv4 + IPv6 paths must verify)
		"eth/(ipv4|ipv6)/tcp",
		// optional + range quantifiers
		"eth/vlan?/ipv4/tcp",
		"eth/vlan{1,3}/ipv4/tcp",
		// capture clause
		"eth/ipv4/tcp capture headers+64",
		"eth/ipv6/tcp capture headers+64",
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

	insns := buildXDPNativeInsns(out, outerMap.FD())
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "xdp_ninja_native_test",
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
