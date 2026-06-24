package dsltest

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketOpts configures a single packet built by Build. Zero values
// are filled in with deterministic defaults so callers only set the
// fields the test cares about. Each helper composes the layers with
// gopacket.SerializeOptions{ComputeChecksums: true, FixLengths:
// true} so the resulting bytes are byte-for-byte identical to a
// real frame on the wire.
type PacketOpts struct {
	// Ethernet
	SrcMAC, DstMAC net.HardwareAddr
	EthType        layers.EthernetType // overridden by upper layer when zero

	// VLAN tags (outer first). Zero-length means no tag.
	VLAN []uint16
	// QinQ outer ethertype: 0x88a8 (default 0x8100 when QinQ true).
	QinQ bool

	// MPLS labels (outer first). Zero-length means no MPLS.
	MPLS []uint32

	// IP layer: SrcIP / DstIP (v4 or v6). When both are nil, no IP.
	SrcIP, DstIP net.IP
	IPProto      uint8 // overridden by upper layer when zero
	// TTL sets the IPv4 TTL (and is ignored for IPv6, which uses a
	// fixed HopLimit). Zero means the default 64, so predicates like
	// `ipv4[ttl==64]` match out of the box and a reject case sets a
	// different value.
	TTL uint8

	// L4
	SrcPort, DstPort uint16
	TCP              bool
	UDP              bool
	ICMP             bool

	// IPv4 options. When non-empty, gopacket lifts ihl past 5 and
	// emits the option bytes — exercises the IPv4 HDRLEN advance.
	IPv4Options []layers.IPv4Option
	// TCP options. Same idea for data_offset > 5.
	TCPOptions []layers.TCPOption

	// Payload
	Payload []byte
}

// Defaults returns a PacketOpts with sensible defaults so tests can
// override individual fields. Two layers worth of "valid filler"
// (Ethernet+IPv4+TCP/80) so the resulting bytes match
// `eth/ipv4/tcp` out of the box.
func Defaults() PacketOpts {
	return PacketOpts{
		SrcMAC:  mustMAC("aa:bb:cc:dd:ee:01"),
		DstMAC:  mustMAC("aa:bb:cc:dd:ee:02"),
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
		TCP:     true,
		Payload: []byte("hello"),
	}
}

// BuildEthIPv4TCP returns a serialized Ethernet/IPv4/TCP frame with
// the requested ports. Convenience wrapper for the most common
// chain shape.
func BuildEthIPv4TCP(t testing.TB, srcPort, dstPort uint16) []byte {
	t.Helper()
	o := Defaults()
	o.SrcPort, o.DstPort = srcPort, dstPort
	return Build(t, o)
}

// BuildEthIPv4UDP returns a serialized Ethernet/IPv4/UDP frame.
func BuildEthIPv4UDP(t testing.TB, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	o := Defaults()
	o.TCP, o.UDP = false, true
	o.SrcPort, o.DstPort = srcPort, dstPort
	if payload != nil {
		o.Payload = payload
	}
	return Build(t, o)
}

// BuildEthIPv6TCP returns a serialized Ethernet/IPv6/TCP frame.
func BuildEthIPv6TCP(t testing.TB, src, dst net.IP, srcPort, dstPort uint16) []byte {
	t.Helper()
	o := Defaults()
	o.SrcIP, o.DstIP = src, dst
	o.SrcPort, o.DstPort = srcPort, dstPort
	return Build(t, o)
}

// Build serializes the packet described by opts. The function picks
// the right gopacket layer combination from the flags + which
// IP/MAC fields are populated; tests should call Defaults() and
// override only what they need.
func Build(t testing.TB, opts PacketOpts) []byte {
	t.Helper()

	if opts.SrcMAC == nil {
		opts.SrcMAC = mustMAC("aa:bb:cc:dd:ee:01")
	}
	if opts.DstMAC == nil {
		opts.DstMAC = mustMAC("aa:bb:cc:dd:ee:02")
	}

	isV6 := opts.SrcIP != nil && opts.SrcIP.To4() == nil
	if opts.EthType == 0 {
		switch {
		case len(opts.MPLS) > 0:
			opts.EthType = layers.EthernetTypeMPLSUnicast
		case isV6:
			opts.EthType = layers.EthernetTypeIPv6
		case opts.SrcIP != nil:
			opts.EthType = layers.EthernetTypeIPv4
		default:
			opts.EthType = layers.EthernetTypeIPv4
		}
	}
	if len(opts.VLAN) > 0 {
		if opts.QinQ {
			opts.EthType = layers.EthernetTypeQinQ
		} else {
			opts.EthType = layers.EthernetTypeDot1Q
		}
	}

	eth := &layers.Ethernet{
		SrcMAC:       opts.SrcMAC,
		DstMAC:       opts.DstMAC,
		EthernetType: opts.EthType,
	}

	stack := []gopacket.SerializableLayer{eth}

	for i, vid := range opts.VLAN {
		next := layers.EthernetTypeDot1Q
		if i == len(opts.VLAN)-1 {
			switch {
			case len(opts.MPLS) > 0:
				next = layers.EthernetTypeMPLSUnicast
			case isV6:
				next = layers.EthernetTypeIPv6
			default:
				next = layers.EthernetTypeIPv4
			}
		}
		stack = append(stack, &layers.Dot1Q{
			VLANIdentifier: vid,
			Type:           next,
		})
	}

	for i, label := range opts.MPLS {
		stack = append(stack, &layers.MPLS{
			Label:        label,
			TrafficClass: 0,
			StackBottom:  i == len(opts.MPLS)-1,
			TTL:          64,
		})
	}

	upper, payload := buildL3L4(t, &opts, isV6)
	stack = append(stack, upper...)
	if payload != nil {
		stack = append(stack, gopacket.Payload(payload))
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}, stack...); err != nil {
		t.Fatalf("gopacket.SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

func buildL3L4(t testing.TB, o *PacketOpts, isV6 bool) ([]gopacket.SerializableLayer, []byte) {
	t.Helper()
	var ip gopacket.SerializableLayer
	var netLayer gopacket.NetworkLayer
	if o.SrcIP == nil {
		return nil, o.Payload
	}
	switch {
	case isV6:
		v6 := &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			SrcIP:      o.SrcIP,
			DstIP:      o.DstIP,
			NextHeader: layers.IPProtocolTCP,
		}
		switch {
		case o.UDP:
			v6.NextHeader = layers.IPProtocolUDP
		case o.ICMP:
			v6.NextHeader = layers.IPProtocolICMPv6
		}
		ip, netLayer = v6, v6
	default:
		ttl := o.TTL
		if ttl == 0 {
			ttl = 64
		}
		v4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      ttl,
			SrcIP:    o.SrcIP.To4(),
			DstIP:    o.DstIP.To4(),
			Protocol: layers.IPProtocolTCP,
			Options:  o.IPv4Options,
		}
		switch {
		case o.UDP:
			v4.Protocol = layers.IPProtocolUDP
		case o.ICMP:
			v4.Protocol = layers.IPProtocolICMPv4
		}
		ip, netLayer = v4, v4
	}

	var upper []gopacket.SerializableLayer
	upper = append(upper, ip)

	switch {
	case o.UDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(o.SrcPort),
			DstPort: layers.UDPPort(o.DstPort),
		}
		_ = udp.SetNetworkLayerForChecksum(netLayer)
		upper = append(upper, udp)
	case o.ICMP:
		if isV6 {
			icmp6 := &layers.ICMPv6{
				TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
			}
			_ = icmp6.SetNetworkLayerForChecksum(netLayer)
			upper = append(upper, icmp6)
		} else {
			upper = append(upper, &layers.ICMPv4{
				TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			})
		}
	default:
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(o.SrcPort),
			DstPort: layers.TCPPort(o.DstPort),
			Window:  65535,
			SYN:     true,
			Seq:     1,
			Options: o.TCPOptions,
		}
		_ = tcp.SetNetworkLayerForChecksum(netLayer)
		upper = append(upper, tcp)
	}

	return upper, o.Payload
}

// BuildGTPU constructs an Ethernet/IPv4/UDP/GTP-U/IPv4/TCP frame.
// `flags` is the GTP byte 0 (version|pt|reserved|e|s|pn). When any
// of the lower three flag bits are set, opts.Opt populates the
// optional 4-byte block; opts.Exts populates the extension-header
// chain (terminated implicitly by next_ext == 0).
type GTPUOpts struct {
	TEID    uint32
	Flags   uint8 // version<<5 | pt<<4 | reserved<<3 | e<<2 | s<<1 | pn<<0; default 0x30 (v1, pt=1)
	MsgType uint8 // GTP message type; default 0xff (T-PDU)
	Opt     *GTPOpt
	Exts    []GTPExt
	// Inner IPv4/TCP ports.
	InnerSrc, InnerDst net.IP
	InnerSrcPort       uint16
	InnerDstPort       uint16
}

// GTPOpt is the optional 4-byte block present when E|S|PN is set.
// Layout: seq(16) | npdu(8) | next_ext(8).
type GTPOpt struct {
	Seq           uint16
	NPDU, NextExt uint8
}

// GTPExt is one 4-byte extension header; the terminating ext should
// have NextExt == 0.
type GTPExt struct {
	ExtLength uint8
	ExtType   uint16 // payload of ext (any 16-bit value)
	NextExt   uint8
}

// BuildGTPU serializes a GTP-U frame as described by opts.
func BuildGTPU(t testing.TB, opts GTPUOpts) []byte {
	t.Helper()

	flags := opts.Flags
	if flags == 0 {
		flags = 0x30 // version 1, pt 1
	}
	msgType := opts.MsgType
	if msgType == 0 {
		msgType = 0xff
	}
	if opts.InnerSrc == nil {
		opts.InnerSrc = net.ParseIP("192.168.1.1")
	}
	if opts.InnerDst == nil {
		opts.InnerDst = net.ParseIP("192.168.1.2")
	}
	if opts.InnerSrcPort == 0 {
		opts.InnerSrcPort = 4444
	}
	if opts.InnerDstPort == 0 {
		opts.InnerDstPort = 5555
	}

	// Build inner IPv4/TCP first.
	innerOpts := Defaults()
	innerOpts.SrcIP, innerOpts.DstIP = opts.InnerSrc, opts.InnerDst
	innerOpts.SrcPort, innerOpts.DstPort = opts.InnerSrcPort, opts.InnerDstPort
	innerBytes := Build(t, innerOpts)
	// Strip the outer eth (14 bytes); GTP-U payload starts at IP.
	innerIP := innerBytes[14:]

	// Assemble the GTP payload: gtp_h (8) + opt (4) + exts (4N) + innerIP.
	gtp := make([]byte, 0, 8+4+4*len(opts.Exts)+len(innerIP))
	gtp = append(gtp,
		flags, msgType,
		0, 0, // length placeholder (filled below)
		byte(opts.TEID>>24), byte(opts.TEID>>16), byte(opts.TEID>>8), byte(opts.TEID),
	)
	if opts.Opt != nil {
		gtp = append(gtp, 0, 0, opts.Opt.NPDU, opts.Opt.NextExt)
		// `seq` is the first 16 bits but we kept order simple; rewrite seq below.
		gtp[len(gtp)-4] = byte(opts.Opt.Seq >> 8)
		gtp[len(gtp)-3] = byte(opts.Opt.Seq)
	}
	for _, ext := range opts.Exts {
		gtp = append(gtp,
			ext.ExtLength,
			byte(ext.ExtType>>8), byte(ext.ExtType),
			ext.NextExt,
		)
	}
	gtp = append(gtp, innerIP...)

	// Fill the GTP length field (offset 2, 16 bits, big-endian).
	// Length = bytes after the fixed 8-byte header (per TS 29.281).
	tail := len(gtp) - 8
	gtp[2] = byte(tail >> 8)
	gtp[3] = byte(tail)

	// Wrap in eth/ipv4/udp(2152).
	udpOpts := Defaults()
	udpOpts.TCP, udpOpts.UDP = false, true
	udpOpts.SrcPort, udpOpts.DstPort = 2152, 2152
	udpOpts.Payload = gtp
	return Build(t, udpOpts)
}

func mustMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

// bytes16 returns a fixed-width 16-byte buffer for HBH/DestOpt
// option payloads. Padding lets gopacket-built frames carry a
// realistic fingerprint without the test caring about byte values.
func bytes16(seed string) []byte {
	out := make([]byte, 16)
	copy(out, seed)
	return out
}

// Common in-frame offsets shared by IPv6-suffix builders (BuildIPv6WithExts,
// BuildSRv6). Naming the magic numbers keeps the builders auditable.
const (
	ethHeaderSize     = 14
	ipv6HeaderSize    = 40
	ipv6PayloadLenOff = 4 // bytes 4-5 of ipv6_h (big-endian u16)
	ipv6NextHeaderOff = 6 // byte 6 of ipv6_h
	ethIPv6PrefixSize = ethHeaderSize + ipv6HeaderSize
)

// buildEthIPv6Prefix returns the eth(14)+ipv6(40) bytes for a frame
// that will carry custom variable+inner payload past the IPv6 base
// header. The caller patches ipv6.next_header to the first chained
// header type and ipv6.payload_length to len(variable)+len(inner)
// after concatenation. Both BuildIPv6WithExts and BuildSRv6 use it
// to avoid duplicating the strip-and-patch dance.
func buildEthIPv6Prefix(t testing.TB, src, dst net.IP) []byte {
	t.Helper()
	o := Defaults()
	o.SrcIP, o.DstIP = src, dst
	o.TCP = false
	o.UDP = true
	o.Payload = nil
	frame := Build(t, o)
	out := make([]byte, ethIPv6PrefixSize)
	copy(out, frame[:ethIPv6PrefixSize])
	return out
}

// patchIPv6NextHeaderAndLen rewrites the just-built eth+ipv6 prefix
// to advertise nextHeader and a payload_length covering the
// concatenation of the trailing bytes (variable + inner) the caller
// is about to append.
func patchIPv6NextHeaderAndLen(prefix []byte, nextHeader uint8, payloadLen int) {
	prefix[ethHeaderSize+ipv6NextHeaderOff] = nextHeader
	prefix[ethHeaderSize+ipv6PayloadLenOff] = byte(payloadLen >> 8)
	prefix[ethHeaderSize+ipv6PayloadLenOff+1] = byte(payloadLen)
}

// stripToTCPSegment builds a stock IPv4/TCP frame and strips the
// outer eth(14)+ipv4(20) so callers can splice the bare TCP segment
// past their own IPv6+ext chain or SRH.
func stripToTCPSegment(t testing.TB, src, dst net.IP, srcPort, dstPort uint16) []byte {
	t.Helper()
	tcpInner := Defaults()
	tcpInner.SrcIP, tcpInner.DstIP = src, dst
	tcpInner.SrcPort, tcpInner.DstPort = srcPort, dstPort
	tcpBytes := Build(t, tcpInner)
	return tcpBytes[ethHeaderSize+20:]
}

// SRv6Opts describes an Ethernet/IPv6/SRH/<inner> frame.
type SRv6Opts struct {
	Src, Dst        net.IP
	Segments        []net.IP // segment list (last_entry+1 entries); first is innermost
	InnerNextHeader uint8    // protocol for SRH.next_header (e.g. 6=TCP)
	InnerSrcPort    uint16
	InnerDstPort    uint16
	// TrailingTLVBytes are optional bytes appended after the segment
	// list inside the SRH variable region (TLVs). Length MUST be a
	// multiple of 8 so hdr_ext_len stays whole; the explicit segment
	// walk in srv6.p4 reaches the next header by consuming the whole
	// variable region (hdr_ext_len*8 bytes), so trailing TLVs that are
	// a multiple of 16 bytes are walked as opaque chunks without
	// desyncing R4 from the next-header position.
	TrailingTLVBytes []byte
}

// BuildSRv6 builds Ethernet+IPv6(NH=43)+SRH+inner-TCP. The number
// of segments = len(opts.Segments); SRH.last_entry = N-1. The SRH
// variable region after the fixed 8 bytes is N*16 segment bytes plus
// any opts.TrailingTLVBytes; hdr_ext_len = (region bytes)/8. The
// explicit segment walk in srv6.p4 consumes the whole region so the
// inner layer lands at SRH+8 + hdr_ext_len*8.
func BuildSRv6(t testing.TB, opts SRv6Opts) []byte {
	t.Helper()
	if opts.Src == nil {
		opts.Src = net.ParseIP("fe80::1")
	}
	if opts.Dst == nil {
		opts.Dst = net.ParseIP("fe80::2")
	}
	if len(opts.Segments) == 0 {
		opts.Segments = []net.IP{net.ParseIP("fe80::dead")}
	}
	if opts.InnerNextHeader == 0 {
		opts.InnerNextHeader = 6 // TCP
	}
	if opts.InnerSrcPort == 0 {
		opts.InnerSrcPort = 1234
	}
	if opts.InnerDstPort == 0 {
		opts.InnerDstPort = 80
	}
	if len(opts.TrailingTLVBytes)%8 != 0 {
		t.Fatalf("BuildSRv6: TrailingTLVBytes length %d is not a multiple of 8", len(opts.TrailingTLVBytes))
	}

	tcpSeg := stripToTCPSegment(t, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), opts.InnerSrcPort, opts.InnerDstPort)

	n := len(opts.Segments)
	region := n*16 + len(opts.TrailingTLVBytes)
	srh := make([]byte, 8+region)
	srh[0] = opts.InnerNextHeader
	srh[1] = uint8(region / 8) // hdr_ext_len in 8-byte units
	srh[2] = 4                 // routing_type = SRH
	srh[3] = uint8(n - 1)      // segments_left
	srh[4] = uint8(n - 1)      // last_entry
	for i, seg := range opts.Segments {
		copy(srh[8+i*16:8+(i+1)*16], seg.To16())
	}
	copy(srh[8+n*16:], opts.TrailingTLVBytes)

	out := buildEthIPv6Prefix(t, opts.Src, opts.Dst)
	patchIPv6NextHeaderAndLen(out, 43, len(srh)+len(tcpSeg))
	out = append(out, srh...)
	out = append(out, tcpSeg...)
	return out
}

// BuildEthIPv4UDPVXLAN returns Ethernet/IPv4/UDP(dport=4789)/VXLAN
// without an inner payload. The vxlan vocab's parser is
// `extract; transition accept` so this exercises dispatch + extract;
// inner Ethernet support is not declared in the vocab.
func BuildEthIPv4UDPVXLAN(t testing.TB, vni uint32) []byte {
	t.Helper()
	d := Defaults()
	eth := &layers.Ethernet{SrcMAC: d.SrcMAC, DstMAC: d.DstMAC, EthernetType: layers.EthernetTypeIPv4}
	v4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP:    d.SrcIP.To4(),
		DstIP:    d.DstIP.To4(),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 4789}
	_ = udp.SetNetworkLayerForChecksum(v4)
	vx := &layers.VXLAN{ValidIDFlag: true, VNI: vni}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true, FixLengths: true,
	}, eth, v4, udp, vx); err != nil {
		t.Fatalf("gopacket.SerializeLayers (vxlan): %v", err)
	}
	return buf.Bytes()
}

// BuildVXLANInnerIPv4TCP builds eth/ipv4/udp(4789)/VXLAN/ipv4/tcp.
// The vxlan vocab parser extracts the fixed 8-byte header and accepts,
// transitioning straight to the next network header (no inner
// Ethernet), so the inner IPv4/TCP sits immediately after the VXLAN
// header. innerDst and innerDstPort drive the fields the F00/F03
// corpus filters read; nil/zero fall back to 10.0.0.1 / port 80.
func BuildVXLANInnerIPv4TCP(t testing.TB, innerDst net.IP, innerDstPort uint16) []byte {
	t.Helper()
	if innerDst == nil {
		innerDst = net.IPv4(10, 0, 0, 1)
	}
	innerDst4 := innerDst.To4()
	if innerDst4 == nil {
		t.Fatalf("BuildVXLANInnerIPv4TCP: innerDst %v is not an IPv4 address", innerDst)
	}
	if innerDstPort == 0 {
		innerDstPort = 80
	}
	d := Defaults()
	eth := &layers.Ethernet{SrcMAC: d.SrcMAC, DstMAC: d.DstMAC, EthernetType: layers.EthernetTypeIPv4}
	outer := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: d.SrcIP.To4(), DstIP: d.DstIP.To4(),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 4789}
	_ = udp.SetNetworkLayerForChecksum(outer)
	vx := &layers.VXLAN{ValidIDFlag: true, VNI: 100}
	inner := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: net.IPv4(192, 168, 0, 1).To4(), DstIP: innerDst4,
		Protocol: layers.IPProtocolTCP,
	}
	itcp := &layers.TCP{
		SrcPort: 1024, DstPort: layers.TCPPort(innerDstPort),
		Window: 65535, SYN: true, Seq: 1,
	}
	_ = itcp.SetNetworkLayerForChecksum(inner)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true, FixLengths: true,
	}, eth, outer, udp, vx, inner, itcp); err != nil {
		t.Fatalf("gopacket.SerializeLayers (vxlan inner): %v", err)
	}
	return buf.Bytes()
}

// geneveHeader returns the 8-byte Geneve fixed header (RFC 8926):
//
//	[0]     ver(2) | opt_len(6)   — 0 = v0, no options
//	[1]     O(1) | C(1) | rsvd(6) — 0
//	[2..3]  protocol_type (BE16)
//	[4..6]  VNI (BE24)
//	[7]     reserved              — 0
//
// gopacket's Geneve type is non-serializable, so callers hand-roll
// the bytes via this helper. Used by both BuildEthIPv4UDPGeneve
// (protocol_type = IPv4) and BuildGeneveInnerIPv4TCP (protocol_type =
// TransparentEthernetBridging).
func geneveHeader(vni uint32, protocolType layers.EthernetType) []byte {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(protocolType))
	hdr[4] = byte(vni >> 16)
	hdr[5] = byte(vni >> 8)
	hdr[6] = byte(vni)
	return hdr
}

// GeneveInnerIPv4TCPOpts describes an Ethernet/IPv4/UDP(6081)/Geneve/
// Ethernet/IPv4/TCP frame for testing F9-style filters that chain past
// Geneve into the inner Ethernet ("eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp").
// Geneve's protocol_type is set to TransparentEthernetBridging (RFC 5694)
// so the payload is a full inner Ethernet frame; eth.p4 declares
// KUNAI_ETH_GENEVE_NO_CHECK so the kunai parser accepts the chain
// without a dispatch constant check.
type GeneveInnerIPv4TCPOpts struct {
	VNI                        uint32
	OuterSrcIP, OuterDstIP     net.IP
	InnerSrcMAC, InnerDstMAC   net.HardwareAddr
	InnerSrcIP, InnerDstIP     net.IP
	InnerSrcPort, InnerDstPort uint16
	// OptLenWords sets the Geneve opt_len field (count of 4-byte option
	// words after the fixed 8-byte header). Zero = no options. The
	// builder writes opt_len into the header and inserts OptLenWords*4
	// filler option bytes so the inner Ethernet frame sits at the offset
	// opt_len implies — exercising the parser's option-skip advance.
	OptLenWords int
}

// BuildGeneveInnerIPv4TCP serializes the Geneve-tunneled frame described
// above. Defaults: outer 10.0.0.1 -> 10.0.0.2, inner 192.168.1.1 ->
// 192.168.1.2, inner ports 4444 -> 5555, vni 0x123456.
func BuildGeneveInnerIPv4TCP(t testing.TB, opts GeneveInnerIPv4TCPOpts) []byte {
	t.Helper()

	if opts.VNI == 0 {
		opts.VNI = 0x123456
	}
	if opts.OuterSrcIP == nil {
		opts.OuterSrcIP = net.ParseIP("10.0.0.1")
	}
	if opts.OuterDstIP == nil {
		opts.OuterDstIP = net.ParseIP("10.0.0.2")
	}
	if opts.InnerSrcIP == nil {
		opts.InnerSrcIP = net.ParseIP("192.168.1.1")
	}
	if opts.InnerDstIP == nil {
		opts.InnerDstIP = net.ParseIP("192.168.1.2")
	}
	if opts.InnerSrcPort == 0 {
		opts.InnerSrcPort = 4444
	}
	if opts.InnerDstPort == 0 {
		opts.InnerDstPort = 5555
	}

	innerInputs := Defaults()
	if opts.InnerSrcMAC != nil {
		innerInputs.SrcMAC = opts.InnerSrcMAC
	}
	if opts.InnerDstMAC != nil {
		innerInputs.DstMAC = opts.InnerDstMAC
	}
	innerInputs.SrcIP, innerInputs.DstIP = opts.InnerSrcIP, opts.InnerDstIP
	innerInputs.SrcPort, innerInputs.DstPort = opts.InnerSrcPort, opts.InnerDstPort
	innerFrame := Build(t, innerInputs)

	d := Defaults()
	eth := &layers.Ethernet{SrcMAC: d.SrcMAC, DstMAC: d.DstMAC, EthernetType: layers.EthernetTypeIPv4}
	v4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP:    opts.OuterSrcIP.To4(),
		DstIP:    opts.OuterDstIP.To4(),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 6081}
	_ = udp.SetNetworkLayerForChecksum(v4)

	geneve := geneveHeader(opts.VNI, layers.EthernetTypeTransparentEthernetBridging)
	if opts.OptLenWords < 0 || opts.OptLenWords > 0x3F {
		t.Fatalf("OptLenWords=%d out of range (Geneve opt_len is 6 bits, 0..63)", opts.OptLenWords)
	}
	// opt_len occupies the low 6 bits of byte 0 (version stays 0); append
	// the matching opt_len*4 filler bytes so the inner frame sits past
	// them. OptLenWords==0 leaves the header untouched (no-op append).
	geneve[0] = byte(opts.OptLenWords)
	geneve = append(geneve, make([]byte, opts.OptLenWords*4)...)
	payload := append(geneve, innerFrame...)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true, FixLengths: true,
	}, eth, v4, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("gopacket.SerializeLayers (geneve-inner): %v", err)
	}
	return buf.Bytes()
}

// BuildEthIPv4UDPGeneve returns Ethernet/IPv4/UDP(dport=6081)/Geneve
// (no options, protocol_type=IPv4). The 8-byte Geneve header layout
// is documented on geneveHeader above.
func BuildEthIPv4UDPGeneve(t testing.TB, vni uint32) []byte {
	t.Helper()
	d := Defaults()
	eth := &layers.Ethernet{SrcMAC: d.SrcMAC, DstMAC: d.DstMAC, EthernetType: layers.EthernetTypeIPv4}
	v4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP:    d.SrcIP.To4(),
		DstIP:    d.DstIP.To4(),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 6081}
	_ = udp.SetNetworkLayerForChecksum(v4)

	geneve := geneveHeader(vni, layers.EthernetTypeIPv4)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true, FixLengths: true,
	}, eth, v4, udp, gopacket.Payload(geneve)); err != nil {
		t.Fatalf("gopacket.SerializeLayers (geneve): %v", err)
	}
	return buf.Bytes()
}

// GeneveOptionTLV builds one Geneve option TLV (RFC 8926): a 4-byte
// header (option_class BE16, type, R(3)+opt_data_len(5)) followed by
// data. data must be a whole number of 4-byte words; opt_data_len is
// derived as len(data)/4.
func GeneveOptionTLV(t testing.TB, optClass uint16, optType uint8, data []byte) []byte {
	t.Helper()
	if len(data)%4 != 0 {
		t.Fatalf("GeneveOptionTLV: data len %d is not a multiple of 4", len(data))
	}
	tlv := make([]byte, 4)
	binary.BigEndian.PutUint16(tlv[0:2], optClass)
	tlv[2] = optType
	tlv[3] = byte(len(data) / 4) // R bits stay 0
	return append(tlv, data...)
}

// BuildEthIPv4UDPGeneveOpts returns Ethernet/IPv4/UDP(6081)/Geneve
// carrying the concatenated option TLVs. opt_len is set from the total
// option byte length (which must be a multiple of 4). Used by tests
// that filter on geneve.options.<NAME>.<field>.
func BuildEthIPv4UDPGeneveOpts(t testing.TB, vni uint32, opts ...[]byte) []byte {
	t.Helper()
	var optBytes []byte
	for _, o := range opts {
		optBytes = append(optBytes, o...)
	}
	if len(optBytes)%4 != 0 {
		t.Fatalf("geneve options total %d bytes is not a multiple of 4", len(optBytes))
	}
	words := len(optBytes) / 4
	if words > 0x3F {
		t.Fatalf("geneve opt_len %d words exceeds the 6-bit field", words)
	}

	d := Defaults()
	eth := &layers.Ethernet{SrcMAC: d.SrcMAC, DstMAC: d.DstMAC, EthernetType: layers.EthernetTypeIPv4}
	v4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP:    d.SrcIP.To4(),
		DstIP:    d.DstIP.To4(),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 6081}
	_ = udp.SetNetworkLayerForChecksum(v4)

	geneve := geneveHeader(vni, layers.EthernetTypeIPv4)
	geneve[0] = byte(words) // version 0, opt_len = words
	geneve = append(geneve, optBytes...)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true, FixLengths: true,
	}, eth, v4, udp, gopacket.Payload(geneve)); err != nil {
		t.Fatalf("gopacket.SerializeLayers (geneve-opts): %v", err)
	}
	return buf.Bytes()
}

// IPIPOpts describes an Ethernet/IPv4(outer, proto=IPIP)/IPv4(inner)/
// TCP frame. InnerOptions populate the inner IPv4 header's options
// (lifting its IHL past 5) so tests can confirm the layered chain
// `eth/ipv4/ipv4/tcp` correctly handles inner IPv4 with options —
// which is the use case the chain-quantifier `ipv4+` cannot handle.
type IPIPOpts struct {
	InnerOptions []layers.IPv4Option
}

// BuildEthIPIPTCP serializes Ethernet/IPv4(outer, proto=IPIP)/IPv4
// (inner)/TCP. Each ipv4 layer runs its own parser machine when
// matched against `eth/ipv4/ipv4/tcp`, so the inner can carry options
// (IHL>5) and still match — the parser's IHL-driven trailer skip
// advances R4 correctly per layer.
func BuildEthIPIPTCP(t testing.TB, opts IPIPOpts) []byte {
	t.Helper()
	innerInputs := Defaults()
	innerInputs.IPv4Options = opts.InnerOptions
	innerBytes := Build(t, innerInputs)
	innerIP := innerBytes[ethHeaderSize:] // strip inner eth

	d := Defaults()
	eth := &layers.Ethernet{
		SrcMAC:       d.SrcMAC,
		DstMAC:       d.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	outer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP("203.0.113.1").To4(),
		DstIP:    net.ParseIP("203.0.113.2").To4(),
		Protocol: layers.IPProtocolIPv4, // IANA "IPIP"
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}, eth, outer, gopacket.Payload(innerIP)); err != nil {
		t.Fatalf("gopacket.SerializeLayers (ipip): %v", err)
	}
	return buf.Bytes()
}

// BuildEthIPv6inIPv6TCP serializes Ethernet/IPv6(outer, next_header=IPv6)/
// IPv6(inner)/TCP. Mirrors BuildEthIPIPTCP for the v6-in-v6 layered
// chain (`eth/ipv6/ipv6/tcp`).
func BuildEthIPv6inIPv6TCP(t testing.TB) []byte {
	t.Helper()
	o := Defaults()
	o.SrcIP = net.ParseIP("2001:db8::1")
	o.DstIP = net.ParseIP("2001:db8::2")
	innerBytes := Build(t, o)
	innerIP := innerBytes[ethHeaderSize:]

	d := Defaults()
	eth := &layers.Ethernet{
		SrcMAC:       d.SrcMAC,
		DstMAC:       d.DstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	outer := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8:f00::1"),
		DstIP:      net.ParseIP("2001:db8:f00::2"),
		NextHeader: layers.IPProtocolIPv6,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}, eth, outer, gopacket.Payload(innerIP)); err != nil {
		t.Fatalf("gopacket.SerializeLayers (ipv6-in-ipv6): %v", err)
	}
	return buf.Bytes()
}

// GREOpts describes an Ethernet/IPv4/GRE/IPv4/TCP frame. Each
// Checksum/Key/Sequence flag adds a 4-byte block past the fixed GRE
// header — codegen advances R4 via the OPT_TRIGGER/OPT_LEN const
// pairs in gre.p4.
type GREOpts struct {
	HasChecksum bool
	HasKey      bool
	HasSequence bool
	Key         uint32
	Sequence    uint32
	// Inner IPv4/TCP ports.
	InnerSrcPort, InnerDstPort uint16
}

// BuildGRE serializes Ethernet/IPv4/GRE/<inner IPv4/TCP> with the
// requested optional sub-headers enabled. The outer IPv4 carries
// protocol=47 (GRE); inner ports default to 4444 → 5555.
func BuildGRE(t testing.TB, opts GREOpts) []byte {
	t.Helper()
	if opts.InnerSrcPort == 0 {
		opts.InnerSrcPort = 4444
	}
	if opts.InnerDstPort == 0 {
		opts.InnerDstPort = 5555
	}

	innerOpts := Defaults()
	innerOpts.SrcIP = net.ParseIP("192.168.10.1")
	innerOpts.DstIP = net.ParseIP("192.168.10.2")
	innerOpts.SrcPort, innerOpts.DstPort = opts.InnerSrcPort, opts.InnerDstPort
	innerBytes := Build(t, innerOpts)
	innerIP := innerBytes[ethHeaderSize:] // strip outer eth

	gre := &layers.GRE{
		Protocol:        layers.EthernetTypeIPv4,
		Version:         0,
		ChecksumPresent: opts.HasChecksum,
		KeyPresent:      opts.HasKey,
		SeqPresent:      opts.HasSequence,
		Key:             opts.Key,
		Seq:             opts.Sequence,
	}

	d := Defaults()
	eth := &layers.Ethernet{
		SrcMAC:       d.SrcMAC,
		DstMAC:       d.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	v4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.ParseIP("10.1.0.1").To4(),
		DstIP:    net.ParseIP("10.1.0.2").To4(),
		Protocol: layers.IPProtocolGRE,
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}, eth, v4, gre, gopacket.Payload(innerIP)); err != nil {
		t.Fatalf("gopacket.SerializeLayers (gre): %v", err)
	}
	return buf.Bytes()
}

// BuildEthIPv4ESP returns an Ethernet/IPv4/ESP frame with the given
// SPI and sequence number. The 8-byte ESP fixed header is plaintext
// (kunai matches on it); the appended 16 opaque bytes simulate the
// encrypted payload that kunai cannot inspect — testing here pins
// that the chain match succeeds despite the inner being unreadable.
func BuildEthIPv4ESP(t testing.TB, spi, seq uint32) []byte {
	t.Helper()
	o := Defaults()
	o.UDP = true // any IPv4 child is fine; we patch the protocol byte after build
	o.TCP = false
	o.Payload = espPayload(spi, seq)
	pkt := Build(t, o)
	patchIPv4Protocol(pkt, 50) // IPPROTO_ESP
	return pkt
}

// BuildEthIPv6ESP returns an Ethernet/IPv6/ESP frame.
func BuildEthIPv6ESP(t testing.TB, src, dst net.IP, spi, seq uint32) []byte {
	t.Helper()
	out := buildEthIPv6Prefix(t, src, dst)
	body := espPayload(spi, seq)
	patchIPv6NextHeaderAndLen(out, 50, len(body))
	return append(out, body...)
}

// espPayload synthesises the 8-byte ESP fixed header (SPI + seq)
// plus 16 placeholder bytes representing the encrypted payload.
func espPayload(spi, seq uint32) []byte {
	out := make([]byte, 8+16)
	out[0], out[1], out[2], out[3] = byte(spi>>24), byte(spi>>16), byte(spi>>8), byte(spi)
	out[4], out[5], out[6], out[7] = byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
	copy(out[8:], "encrypted-bytes-")
	return out
}

// patchIPv4Protocol overrides the IPv4 protocol byte at offset 14+9
// in a just-built frame and recomputes the IPv4 header checksum.
// Used when we need a frame for an L4 protocol gopacket does not
// model directly (e.g. ESP).
func patchIPv4Protocol(pkt []byte, proto uint8) {
	pkt[ethHeaderSize+9] = proto
	pkt[ethHeaderSize+10] = 0
	pkt[ethHeaderSize+11] = 0
	var sum uint32
	for i := ethHeaderSize; i < ethHeaderSize+20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	pkt[ethHeaderSize+10] = byte(cs >> 8)
	pkt[ethHeaderSize+11] = byte(cs)
}

// IPv6Ext is one chained IPv6 extension header (RFC 8200). HdrExtLen
// is in 8-byte units NOT including the first 8 bytes (i.e. 0 means
// the ext header is exactly 8 bytes total).
type IPv6Ext struct {
	NextHeader uint8
	HdrExtLen  uint8
	Options    []byte // arbitrary options payload, padded to fit the declared length
}

// IPv6WithExts constructs Ethernet/IPv6/<ext-chain>/TCP frames so
// tests can drive the ipv6 parser machine through HBH/Fragment/
// DestOpt iterations. firstNextHeader is the value the IPv6 base
// header puts in next_header; the chain ends when the most recent
// ext header carries a non-ext next_header (e.g. IPPROTO_TCP=6).
type IPv6WithExtsOpts struct {
	Src, Dst         net.IP
	SrcPort, DstPort uint16
	FirstNextHeader  uint8 // base ipv6.next_header — value of the *first* ext, or final L4 if no exts
	Exts             []IPv6Ext
	FinalNextHeader  uint8 // protocol for the last ext header's next_header (e.g. 6 for TCP)
}

// BuildIPv6WithExts serializes Ethernet/IPv6/<ext chain>/TCP. The
// caller picks the chain shape via opts.Exts (each entry's HdrExtLen
// is in 8-byte units; 0 means an 8-byte ext header). The base
// header's next_header points at the first ext type, each ext's
// next_header points at the next ext (or FinalNextHeader on the
// last ext).
func BuildIPv6WithExts(t testing.TB, opts IPv6WithExtsOpts) []byte {
	t.Helper()
	if opts.Src == nil {
		opts.Src = net.ParseIP("fe80::1")
	}
	if opts.Dst == nil {
		opts.Dst = net.ParseIP("fe80::2")
	}
	if opts.SrcPort == 0 {
		opts.SrcPort = 1234
	}
	if opts.DstPort == 0 {
		opts.DstPort = 80
	}
	if opts.FinalNextHeader == 0 {
		opts.FinalNextHeader = 6 // TCP
	}

	tcpSeg := stripToTCPSegment(t, net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), opts.SrcPort, opts.DstPort)

	var extPayload []byte
	for i, ex := range opts.Exts {
		nh := opts.FinalNextHeader
		if i+1 < len(opts.Exts) {
			nh = opts.Exts[i+1].NextHeader
		}
		extLen := int(ex.HdrExtLen)*8 + 8
		buf := make([]byte, extLen)
		buf[0] = nh
		buf[1] = ex.HdrExtLen
		if extLen > 8 {
			copy(buf[8:], ex.Options)
		}
		extPayload = append(extPayload, buf...)
	}

	out := buildEthIPv6Prefix(t, opts.Src, opts.Dst)
	patchIPv6NextHeaderAndLen(out, opts.FirstNextHeader, len(extPayload)+len(tcpSeg))
	out = append(out, extPayload...)
	out = append(out, tcpSeg...)
	return out
}
