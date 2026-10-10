package dsltest

import (
	"fmt"
	"net"
	"testing"
)

// hbhTCP is Ethernet/IPv6/Hop-by-Hop/TCP: ipv6.next_header on the wire
// is 0 (HBH), the extension's next_header is 6 (TCP).
func hbhTCP(t testing.TB, dport uint16) []byte {
	return BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0,
		Exts:            []IPv6Ext{{}},
		FinalNextHeader: 6,
		DstPort:         dport,
	})
}

// ipv6InIPv6 wraps the frame `inner` (Ethernet/IPv6/...) in an outer
// IPv6 header carrying one Hop-by-Hop extension whose next_header is 41
// (IPv6): both ipv6 layers hold their final protocol in the write-back.
func ipv6InIPv6(t testing.TB, inner []byte) []byte {
	t.Helper()
	outer := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		Src:             net.ParseIP("fe80::aa"),
		Dst:             net.ParseIP("fe80::bb"),
		FirstNextHeader: 0,
		Exts:            []IPv6Ext{{}},
		FinalNextHeader: 41,
	})
	// Keep eth + ipv6 + the 8-byte extension, drop the builder's TCP.
	outer = outer[:ethIPv6PrefixSize+8]
	innerIP := inner[ethHeaderSize:]
	patchIPv6NextHeaderAndLen(outer, 0, 8+len(innerIP))
	return append(outer, innerIP...)
}

// TestIPv6WriteBackSlotDispatch pins the next layer's dispatch after an
// extension chain. The chain's final next_header is kept in the layer's
// write-back slot, never written into the packet (the native XDP host
// runs on the live frame; the spec models the write-back as an overlay,
// D-032): tcp dispatches on the slot and udp misses on it.
func TestIPv6WriteBackSlotDispatch(t *testing.T) {
	pkt := hbhTCP(t, 80)
	New(t, "eth/ipv6/tcp").MustMatch(t, pkt, "HBH then TCP: the dispatch reads the written-back next_header")
	New(t, "eth/ipv6/udp").MustReject(t, pkt, "HBH then TCP is not udp")
	New(t, "eth/ipv6/tcp where tcp.dport == 80").MustMatch(t, pkt, "tcp fields after the chain")
	plain := BuildEthIPv6TCP(t, net.ParseIP("fe80::1"), net.ParseIP("fe80::2"), 1234, 80)
	New(t, "eth/ipv6/tcp").MustMatch(t, plain, "no extension: the slot holds the header's own byte")
	New(t, "eth/ipv6/udp").MustReject(t, plain, "no extension, not udp")
}

// TestIPv6WriteBackSlotReads pins the where and bracket reads of
// ipv6.next_header after a chain: both see the written-back value (6),
// not the wire byte (0), and the layer's other fields keep reading the
// packet.
func TestIPv6WriteBackSlotReads(t *testing.T) {
	pkt := hbhTCP(t, 80)
	New(t, "eth/ipv6/tcp where ipv6.next_header == 6").MustMatch(t, pkt, "where: written-back value")
	New(t, "eth/ipv6/tcp where ipv6.next_header == 0").MustReject(t, pkt, "where: not the wire byte")
	New(t, "eth/ipv6/tcp where ipv6.next_header != 0").MustMatch(t, pkt, "where: != on the slot")
	New(t, "eth/ipv6[next_header == 6]/tcp").MustMatch(t, pkt, "bracket: written-back value (D-032)")
	New(t, "eth/ipv6[next_header == 0]/tcp").MustReject(t, pkt, "bracket: not the wire byte")
	New(t, "eth/ipv6/tcp where ipv6.next_header == 17 or ipv6.next_header == 6").MustMatch(t, pkt, "where or-chain on the slot")
	New(t, "eth/ipv6/tcp where ipv6.hop_limit == 64").MustMatch(t, pkt, "the next byte still comes from the packet")
	New(t, fmt.Sprintf("eth/ipv6/tcp where ipv6.payload_length == %d", len(pkt)-ethIPv6PrefixSize)).MustMatch(t, pkt, "the previous bytes still come from the packet")
	New(t, "eth/ipv6/tcp where ipv6.exts[0].next_header == 6").MustMatch(t, pkt, "the extension's own byte is unchanged")

	// Two extensions (HBH, Destination Options): the second is walked by
	// the bpf_loop callback, whose store goes through the ctx pointer.
	two := BuildIPv6WithExts(t, IPv6WithExtsOpts{
		FirstNextHeader: 0,
		Exts:            []IPv6Ext{{NextHeader: 60}, {}},
		FinalNextHeader: 6,
	})
	New(t, "eth/ipv6/tcp").MustMatch(t, two, "two extensions: dispatch on the callback's value")
	New(t, "eth/ipv6/udp").MustReject(t, two, "two extensions: not udp")
	New(t, "eth/ipv6/tcp where ipv6.next_header == 6").MustMatch(t, two, "two extensions: where sees the last value")
	New(t, "eth/ipv6/tcp where ipv6.next_header == 60").MustReject(t, two, "two extensions: not the intermediate value")
	New(t, "eth/ipv6[next_header == 6]/tcp").MustMatch(t, two, "two extensions: bracket sees the last value")
}

// TestIPv6WriteBackSlotPerInstance pins one slot per ipv6 instance: the
// outer chain ends in 41 and the inner in 6, each read by its own
// dispatch and where reference; the alternation member and the repeated
// layer share the lowering.
func TestIPv6WriteBackSlotPerInstance(t *testing.T) {
	inner := hbhTCP(t, 80)
	pkt := ipv6InIPv6(t, inner)
	New(t, "eth/ipv6/ipv6/tcp").MustMatch(t, pkt, "both chains dispatch on their slots")
	New(t, "eth/ipv6@o/ipv6@i/tcp where o.next_header == 41 and i.next_header == 6").MustMatch(t, pkt, "per-instance values")
	New(t, "eth/ipv6@o/ipv6@i/tcp where o.next_header == 6").MustReject(t, pkt, "the outer slot is not the inner value")
	New(t, "eth/ipv6{1,2}/tcp").MustMatch(t, pkt, "repeated layer: the second instance dispatches on the first's slot")
	New(t, "eth/ipv6{1,2}/tcp").MustMatch(t, inner, "repeated layer: one instance")
	New(t, "eth/ipv6@o{1,2}/tcp where o.next_header == 6").MustMatch(t, pkt, "where reads the last instance")
	New(t, "eth/(ipv4|ipv6)/tcp where ipv6.next_header == 6").MustMatch(t, inner, "alternation member keeps its slot")
	New(t, "eth/(ipv4|ipv6)/tcp").MustMatch(t, inner, "alternation member dispatches on its slot")
	New(t, "eth/(ipv4|ipv6)/udp").MustReject(t, inner, "alternation member: HBH then TCP is not udp")
	New(t, "eth/(ipv4|ipv6)/tcp").MustMatch(t, BuildEthIPv4TCP(t, 1234, 80), "the ipv4 member is unaffected")
}
