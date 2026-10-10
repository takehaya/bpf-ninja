package program

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
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
		// ipv6 whose entry is a range: the extension chain's next_header
		// used to be written back into the packet through an unbounded
		// pointer; it lives in a stack slot now, which the next layer's
		// dispatch and the field reads use.
		"eth/ipv6/ipv6/tcp",
		"eth/ipv4/ipv6/tcp",
		"eth/ipv6{1,2}/tcp",
		"eth/ipv6/tcp where ipv6.next_header == 6",
		"eth/ipv6[next_header == 6]/tcp",
		"eth/(ipv4|ipv6)/tcp where ipv6.next_header == 6",
		"eth/vlan?/ipv6/tcp capture headers+64",
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
	_, _, _ = loadXDPNative(t, expr, useDSL)
}

// TestBpfXDPNativePacketUnchanged runs the native program on a frame with
// an IPv6 extension header through BPF_PROG_TEST_RUN and requires the
// frame back unchanged, both the frame the program passes on (DataOut)
// and the capture record it wrote to the ring. The filter runs on the
// live packet here, and the extension walk used to write the chain's
// final next_header into the IPv6 header (byte 20 became 6 on this frame)
// before passing it on and before copying it into the record; the value
// lives in a stack slot now (D-032 overlay) and the record holds the wire
// bytes, as the spec's evalCapture does.
func TestBpfXDPNativePacketUnchanged(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	// One extension (walked inline) and two (the second in the bpf_loop
	// callback, whose store goes through the ctx pointer).
	frames := map[string][]byte{
		"hbh": dsltest.BuildIPv6WithExts(t, dsltest.IPv6WithExtsOpts{
			FirstNextHeader: 0, // Hop-by-Hop
			Exts:            []dsltest.IPv6Ext{{}},
			FinalNextHeader: 6,
		}),
		"hbh-dstopts": dsltest.BuildIPv6WithExts(t, dsltest.IPv6WithExtsOpts{
			FirstNextHeader: 0,
			Exts:            []dsltest.IPv6Ext{{NextHeader: 60}, {}},
			FinalNextHeader: 6,
		}),
	}
	for _, expr := range []string{
		"eth/ipv6/tcp",
		"eth/ipv6/tcp where ipv6.next_header == 6",
		"eth/ipv6[next_header == 6]/tcp",
		// `capture headers` is bounded by the chain's primary headers
		// (14 + 40 + 20 = 74 here): the record is that prefix of the frame.
		"eth/ipv6/tcp capture headers",
	} {
		for name, in := range frames {
			t.Run(expr+"/"+name, func(t *testing.T) {
				prog, ring, maxCapLen := loadXDPNative(t, expr, true)
				rd, err := ringbuf.NewReader(ring)
				if err != nil {
					t.Fatalf("ringbuf reader: %v", err)
				}
				defer func() { _ = rd.Close() }()
				out := make([]byte, len(in)+64)
				ret, outLen, err := runXDPOnce(prog, in, out)
				if err != nil {
					t.Fatalf("test run: %v", err)
				}
				if ret != 2 { // XDP_PASS
					t.Fatalf("return value %d, want XDP_PASS (2)", ret)
				}
				// Errorf, not Fatalf: the record check below is the other
				// witness of a packet write and should report in the same run.
				if !bytes.Equal(out[:outLen], in) {
					t.Errorf("the program changed the frame (ipv6 byte 20 is %#x, wire %#x):\n got %x\nwant %x", out[20], in[20], out[:outLen], in)
				}
				// The record the program wrote: a deadline means the filter
				// missed or the per-CPU ring lookup failed.
				rd.SetDeadline(time.Now().Add(time.Second))
				rec, err := rd.Read()
				if err != nil {
					t.Fatalf("no capture record (filter miss or ring lookup miss): %v", err)
				}
				pkt, err := capture.ParseRawSample(rec.RawSample)
				if err != nil {
					t.Fatalf("parse record: %v", err)
				}
				// The record is the frame clamped to the filter's capture
				// length (0 = the host default, longer than these frames).
				want := len(in)
				if maxCapLen != 0 && maxCapLen < want {
					want = maxCapLen
				}
				if len(pkt.Data) != want {
					t.Fatalf("capture record length %d, want %d (MaxCapLen %d, frame %d)", len(pkt.Data), want, maxCapLen, len(in))
				}
				if !bytes.Equal(pkt.Data, in[:len(pkt.Data)]) {
					t.Fatalf("the capture record differs from the wire (ipv6 byte 20 is %#x, wire %#x, caplen %d):\n got %x\nwant %x", pkt.Data[20], in[20], pkt.CapLen, pkt.Data, in[:len(pkt.Data)])
				}
			})
		}
	}
}

// runXDPOnce runs prog once on data through BPF_PROG_TEST_RUN and returns
// the verdict and the bytes the program left in dataOut.
func runXDPOnce(prog *ebpf.Program, data, dataOut []byte) (uint32, int, error) {
	opts := ebpf.RunOptions{Data: data, DataOut: dataOut, Repeat: 1}
	ret, err := prog.Run(&opts)
	if err != nil {
		return 0, 0, err
	}
	return ret, len(opts.DataOut), nil
}

// loadXDPNative is loadXDPNativeOrFail returning the loaded program, the
// ring it captures into and the filter's capture length (0 = host
// default). The program picks the ring by CPU id from the outer map
// (captureXDPNative), so every possible CPU index points at the one
// ring and a test run on any CPU finds it; a test only exercises the CPU
// it happens to run on, so a fixture regression to fewer slots would show
// up as a scheduler-dependent failure rather than a sure one.
func loadXDPNative(t *testing.T, expr string, useDSL bool) (*ebpf.Program, *ebpf.Map, int) {
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
	slots, err := possibleCPUSlots()
	if err != nil {
		t.Fatalf("possible CPUs: %v", err)
	}
	outerMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "ninja_xdp_test_outer", Type: ebpf.ArrayOfMaps,
		KeySize: 4, ValueSize: 4, MaxEntries: uint32(slots), InnerMap: innerSpec,
	})
	if err != nil {
		t.Fatalf("creating outer array_of_maps: %v", err)
	}
	t.Cleanup(func() { _ = outerMap.Close() })
	for cpu := 0; cpu < slots; cpu++ {
		if err := outerMap.Put(uint32(cpu), innerMap); err != nil {
			t.Fatalf("populating outer map slot %d: %v", cpu, err)
		}
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
	return prog, innerMap, out.Capture.MaxCapLen
}
