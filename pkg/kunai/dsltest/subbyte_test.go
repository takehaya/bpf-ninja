package dsltest

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet-level correctness for non-byte-aligned / sub-byte-sized
// primary field reads (TCP flags / data_offset, IPv4 version / ihl /
// flags / frag_offset, IPv6 traffic_class). The bit-extraction math is
// pinned in codegen/slice_test.go; here we prove the generated
// bytecode loads, passes the verifier, and matches/rejects real frames
// the way pcap-filter's `tcp[13]&2` etc. would. Requires root (New
// skips otherwise).

// serialize composes a layer stack into wire bytes with checksums and
// lengths fixed, matching how Build emits frames.
func serialize(t testing.TB, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func ethIPv4() *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       mustMAC("aa:bb:cc:dd:ee:01"),
		DstMAC:       mustMAC("aa:bb:cc:dd:ee:02"),
		EthernetType: layers.EthernetTypeIPv4,
	}
}

// v4tcpFrame builds an eth/ipv4/tcp frame, letting the caller mutate
// the IPv4 and TCP layers (flags, options, frag) before serialization.
func v4tcpFrame(t testing.TB, mut func(ip *layers.IPv4, tcp *layers.TCP)) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, Window: 65535, Seq: 1}
	if mut != nil {
		mut(ip, tcp)
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	return serialize(t, ethIPv4(), ip, tcp, gopacket.Payload([]byte("hello")))
}

func TestSubByteTCPFlagsSYN(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.flags & 0x02 != 0")
	r.MustMatch(t, v4tcpFrame(t, func(_ *layers.IPv4, tcp *layers.TCP) { tcp.SYN = true }),
		"SYN set")
	r.MustReject(t, v4tcpFrame(t, func(_ *layers.IPv4, tcp *layers.TCP) { tcp.SYN, tcp.ACK = false, true }),
		"SYN clear (ACK only)")
	// FIN+PSH set but not SYN — adjacent bits must not leak in.
	r.MustReject(t, v4tcpFrame(t, func(_ *layers.IPv4, tcp *layers.TCP) {
		tcp.SYN, tcp.FIN, tcp.PSH = false, true, true
	}), "FIN+PSH, no SYN")
}

func TestSubByteTCPDataOffset(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.data_offset == 5")
	r.MustMatch(t, v4tcpFrame(t, nil), "no TCP options → data_offset 5")
	r.MustReject(t, v4tcpFrame(t, func(_ *layers.IPv4, tcp *layers.TCP) {
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		}
	}), "MSS option → data_offset 6")
}

func TestSubByteIPv4Version(t *testing.T) {
	frame := v4tcpFrame(t, nil)
	New(t, "eth/ipv4/tcp where ipv4.version == 4").MustMatch(t, frame, "IPv4 version 4")
	// Same v4 frame against ==6 must reject: proves the nibble read
	// returns 4, not a stray adjacent value.
	New(t, "eth/ipv4/tcp where ipv4.version == 6").MustReject(t, frame, "v4 frame, version!=6")
}

func TestSubByteIPv4IHL(t *testing.T) {
	noOpts := v4tcpFrame(t, nil)
	withOpts := v4tcpFrame(t, func(ip *layers.IPv4, _ *layers.TCP) {
		ip.Options = []layers.IPv4Option{{OptionType: 148, OptionLength: 4, OptionData: []byte{0, 0}}}
	})
	r5 := New(t, "eth/ipv4[ihl==5]/tcp")
	r5.MustMatch(t, noOpts, "IHL=5, no options")
	r5.MustReject(t, withOpts, "IHL=6, Router Alert")
	r6 := New(t, "eth/ipv4[ihl==6]/tcp")
	r6.MustMatch(t, withOpts, "IHL=6, Router Alert")
	r6.MustReject(t, noOpts, "IHL=5, no options")
}

func TestSubByteIPv4DontFragment(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where ipv4.flags & 0x2 != 0") // DF = 0x2 of the 3-bit flags
	r.MustMatch(t, v4tcpFrame(t, func(ip *layers.IPv4, _ *layers.TCP) {
		ip.Flags = layers.IPv4DontFragment
	}), "DF set")
	r.MustReject(t, v4tcpFrame(t, nil), "DF clear")
}

func TestSubByteIPv4FragOffset(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where ipv4.frag_offset == 0")
	r.MustMatch(t, v4tcpFrame(t, nil), "frag_offset 0")
	r.MustReject(t, v4tcpFrame(t, func(ip *layers.IPv4, _ *layers.TCP) {
		ip.Flags = layers.IPv4MoreFragments
		ip.FragOffset = 100
	}), "frag_offset 100")
}

func TestSubByteIPv6TrafficClass(t *testing.T) {
	build := func(tc uint8) []byte {
		ip := &layers.IPv6{
			Version: 6, TrafficClass: tc, HopLimit: 64,
			SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
			NextHeader: layers.IPProtocolTCP,
		}
		tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, Window: 65535, Seq: 1, SYN: true}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		eth := &layers.Ethernet{
			SrcMAC: mustMAC("aa:bb:cc:dd:ee:01"), DstMAC: mustMAC("aa:bb:cc:dd:ee:02"),
			EthernetType: layers.EthernetTypeIPv6,
		}
		return serialize(t, eth, ip, tcp, gopacket.Payload([]byte("hello")))
	}
	r := New(t, "eth/ipv6/tcp where ipv6.traffic_class == 0")
	r.MustMatch(t, build(0), "traffic_class 0")
	r.MustReject(t, build(5), "traffic_class 5")
	// DSCP-style high bits set: traffic_class spans the version/flow
	// boundary, so a wrong shift would misread it.
	r.MustReject(t, build(0xb8), "traffic_class 0xb8 (EF)")
}
