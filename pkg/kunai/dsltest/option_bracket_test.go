package dsltest

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

// buildTCPWithOptions is an Ethernet/IPv4/TCP frame carrying opts.
func buildTCPWithOptions(t *testing.T, opts ...layers.TCPOption) []byte {
	t.Helper()
	o := Defaults()
	o.TCPOptions = opts
	return Build(t, o)
}

func mssOption(v uint16) layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{byte(v >> 8), byte(v)}}
}

func tsOption(tsval uint32) layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: []byte{
		byte(tsval >> 24), byte(tsval >> 16), byte(tsval >> 8), byte(tsval), 0, 0, 0, 0,
	}}
}

var wsOption = layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}

// TestBracketTCPOption: a bracket predicate on an option the walk locates
// reads the option where the walk found it, after the walk: behind another
// option, absent (false, D-027), inside a malformed region (no options,
// D-029), for every predicate kind.
func TestBracketTCPOption(t *testing.T) {
	t.Run("eq", func(t *testing.T) {
		r := New(t, "eth/ipv4/tcp[mss.value == 1460]")
		r.MustMatch(t, buildTCPWithOptions(t, mssOption(1460)), "MSS 1460")
		r.MustMatch(t, buildTCPWithOptions(t, wsOption, mssOption(1460)), "MSS behind WS")
		r.MustReject(t, buildTCPWithOptions(t, mssOption(1400)), "MSS 1400")
		r.MustReject(t, buildTCPWithOptions(t, wsOption), "no MSS")
		r.MustReject(t, BuildEthIPv4TCP(t, 12345, 80), "no options")
		r.MustReject(t, tcpWithRawOptions(t, 7, []byte{2, 4, 5, 180, 99, 1, 0, 0}, nil), "MSS before a malformed TLV")
	})
	t.Run("ne", func(t *testing.T) {
		r := New(t, "eth/ipv4/tcp[mss.value != 1460]")
		r.MustMatch(t, buildTCPWithOptions(t, mssOption(1400)), "MSS 1400")
		r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "MSS 1460")
		r.MustReject(t, buildTCPWithOptions(t, wsOption), "no MSS: != is false too")
	})
	t.Run("in-list", func(t *testing.T) {
		r := New(t, "eth/ipv4/tcp[mss.value in [1400, 1460, 9000..9100]]")
		r.MustMatch(t, buildTCPWithOptions(t, mssOption(1400)), "1400")
		r.MustMatch(t, buildTCPWithOptions(t, mssOption(9050)), "in range")
		r.MustReject(t, buildTCPWithOptions(t, mssOption(1500)), "1500")
		r.MustReject(t, buildTCPWithOptions(t, wsOption), "no MSS")
	})
	t.Run("ordered", func(t *testing.T) {
		r := New(t, "eth/ipv4/tcp[ts.tsval > 0x01000000]")
		r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x01000001)), "above")
		r.MustReject(t, buildTCPWithOptions(t, tsOption(0x01000000)), "equal")
		r.MustReject(t, buildTCPWithOptions(t, tsOption(0x00ffffff)), "below, larger low byte")
		r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "no TS")
	})
	t.Run("slice", func(t *testing.T) {
		r := New(t, "eth/ipv4/tcp[ts.tsval[24:32] == 1]")
		r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x0a000101)), "low byte 1")
		r.MustReject(t, buildTCPWithOptions(t, tsOption(0x00000100)), "low byte 0")
	})
	t.Run("ipv4-literal", func(t *testing.T) {
		r := New(t, "eth/ipv4/tcp[ts.tsval in [10.0.0.0/8, 192.168.0.1]]")
		r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x0a010203)), "in 10/8")
		r.MustMatch(t, buildTCPWithOptions(t, tsOption(0xc0a80001)), "192.168.0.1")
		r.MustReject(t, buildTCPWithOptions(t, tsOption(0x0b000001)), "11.0.0.1")
		r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "no TS")
	})
}

// TestWhereTCPOptionLiteralAndSlice pins two where reads of an option the
// walk locates that used to address the primary header or ignore the
// slice: an IPv4 literal compare and a bit slice.
func TestWhereTCPOptionLiteralAndSlice(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.ts.tsval == 10.0.0.1")
	r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x0a000001)), "tsval 10.0.0.1")
	r.MustReject(t, buildTCPWithOptions(t, tsOption(0x0a000002)), "tsval 10.0.0.2")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "no TS")

	r = New(t, "eth/ipv4/tcp where tcp.ts.tsval != 10.0.0.1")
	r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x0a000002)), "tsval 10.0.0.2")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "no TS: != is false too")

	r = New(t, "eth/ipv4/tcp where tcp.ts.tsval[24:32] == 1")
	r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x0a000101)), "low byte 1")
	r.MustReject(t, buildTCPWithOptions(t, tsOption(0x00000100)), "low byte 0")
}

// TestBracketOptionRepeatedLayer: on a repeated machine layer every
// instance reads its own option slot, refreshed for each header.
func TestBracketOptionRepeatedLayer(t *testing.T) {
	rr := func(ptr byte) []layers.IPv4Option {
		return []layers.IPv4Option{{OptionType: 7, OptionLength: 4, OptionData: []byte{ptr, 0}}}
	}
	r := New(t, "eth/ipv4[rr.pointer == 4]{1,2}/tcp")
	r.MustMatch(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: rr(4), InnerOptions: rr(4)}), "both RR pointers 4")
	r.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: rr(4), InnerOptions: rr(8)}), "inner RR pointer 8")
	r.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: rr(4)}), "inner without RR")
	r.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{InnerOptions: rr(4)}), "outer without RR")
}

func rrOpt(ptr byte) layers.IPv4Option {
	return layers.IPv4Option{OptionType: 7, OptionLength: 4, OptionData: []byte{ptr, 0}}
}

// An absent option makes `!=` and an ordered compare against a network
// literal false too: the option slot's sentinel is checked before the
// literal compare.
func TestBracketOptionLiteralNeAbsent(t *testing.T) {
	r := New(t, "eth/ipv4/tcp[ts.tsval != 10.0.0.1]")
	r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x0a000002)), "tsval 10.0.0.2")
	r.MustReject(t, buildTCPWithOptions(t, tsOption(0x0a000001)), "tsval 10.0.0.1")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "no TS: != false")
}

func TestBracketOptionLiteralEq(t *testing.T) {
	r := New(t, "eth/ipv4/tcp[ts.tsval == 10.0.0.1]")
	r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x0a000001)), "hit")
	r.MustMatch(t, buildTCPWithOptions(t, wsOption, tsOption(0x0a000001)), "hit behind ws")
	r.MustReject(t, buildTCPWithOptions(t, tsOption(0x0a000002)), "miss")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "absent")
}

func TestBracketOptionLiteralOrdered(t *testing.T) {
	r := New(t, "eth/ipv4/tcp[ts.tsval > 10.0.0.1]")
	r.MustMatch(t, buildTCPWithOptions(t, tsOption(0x0a000002)), "above")
	r.MustReject(t, buildTCPWithOptions(t, tsOption(0x0a000001)), "equal")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "absent")
}

// The geneve walk is counter-driven (opt_len); a bracket reads its
// option the same way.
func TestBracketGeneveOption(t *testing.T) {
	r := New(t, "eth/ipv4/udp/geneve[ovn.egress_port == 42]")
	ovn42 := GeneveOptionTLV(t, 0x0102, 0x80, ovnPortsValue(7, 42))
	ovn99 := GeneveOptionTLV(t, 0x0102, 0x80, ovnPortsValue(7, 99))
	gwlb := GeneveOptionTLV(t, 0x0108, 0x03, gwlbCookieValue(42))
	r.MustMatch(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, ovn42), "ovn 42")
	r.MustMatch(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, gwlb, ovn42), "ovn 42 behind gwlb")
	r.MustReject(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, ovn99), "ovn 99")
	r.MustReject(t, BuildEthIPv4UDPGeneveOpts(t, 0x123456, gwlb), "no ovn")
	r.MustReject(t, BuildEthIPv4UDPGeneve(t, 0x123456), "no options")
}

func TestBracketOptionAltMember(t *testing.T) {
	r := New(t, "eth/ipv4/(tcp[mss.value == 1460]|udp)")
	r.MustMatch(t, buildTCPWithOptions(t, mssOption(1460)), "tcp mss 1460")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1400)), "tcp mss 1400")
	r.MustReject(t, buildTCPWithOptions(t, wsOption), "tcp no mss")
	r.MustMatch(t, BuildEthIPv4UDP(t, 1, 2, []byte("x")), "udp")
}

func TestBracketOptionUnderIPv6(t *testing.T) {
	r := New(t, "eth/(ipv4|ipv6)/tcp[mss.value in [1400..1460]]")
	o := Defaults()
	o.SrcIP, o.DstIP = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	o.TCPOptions = []layers.TCPOption{mssOption(1420)}
	r.MustMatch(t, Build(t, o), "v6 mss 1420")
	o.TCPOptions = []layers.TCPOption{wsOption, mssOption(1500)}
	r.MustReject(t, Build(t, o), "v6 mss 1500")
	o.TCPOptions = []layers.TCPOption{wsOption}
	r.MustReject(t, Build(t, o), "v6 no mss")
	r.MustMatch(t, buildTCPWithOptions(t, mssOption(1460)), "v4 mss 1460")
}

func TestBracketAndWhereSameOption(t *testing.T) {
	r := New(t, "eth/ipv4/tcp[mss.value == 1460] where tcp.mss.value == 1460")
	r.MustMatch(t, buildTCPWithOptions(t, mssOption(1460)), "1460")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1400)), "1400")
	r.MustReject(t, buildTCPWithOptions(t, wsOption), "absent")
	r = New(t, "eth/ipv4/tcp[mss.value == 1460] where tcp.mss.value != 1460")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "contradiction 1460")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1400)), "contradiction 1400")
	r = New(t, "eth/ipv4/tcp[mss.value == 1460] where tcp.dport == 80 or tcp.mss.value == 1")
	r.MustMatch(t, buildTCPWithOptions(t, mssOption(1460)), "mss + dport 80")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1)), "where true but bracket false")
}

// An RR option before a malformed one is not there (D-029).
func TestBracketIPv4RRMalformed(t *testing.T) {
	r := New(t, "eth/ipv4[rr.pointer == 4]/tcp")
	o := Defaults()
	o.IPv4Options = []layers.IPv4Option{rrOpt(4)}
	r.MustMatch(t, Build(t, o), "rr 4")
	o.IPv4Options = []layers.IPv4Option{{OptionType: 1}, {OptionType: 1}, {OptionType: 1}, {OptionType: 1}, rrOpt(4)}
	r.MustMatch(t, Build(t, o), "rr behind 4 NOPs")
	o.IPv4Options = []layers.IPv4Option{rrOpt(8)}
	r.MustReject(t, Build(t, o), "rr 8")
	o.IPv4Options = []layers.IPv4Option{rrOpt(4), {OptionType: 99, OptionLength: 4, OptionData: []byte{0, 0}}}
	pkt := Build(t, o)
	pkt[14+20+4+1] = 1 // malformed length
	r.MustReject(t, pkt, "rr before malformed (D-029)")
}

func TestBracketOptionPlus(t *testing.T) {
	r := New(t, "eth/ipv4[rr.pointer == 4]+/tcp")
	r.MustMatch(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: []layers.IPv4Option{rrOpt(4)}, InnerOptions: []layers.IPv4Option{rrOpt(4)}}), "both 4")
	r.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: []layers.IPv4Option{rrOpt(4)}, InnerOptions: []layers.IPv4Option{rrOpt(8)}}), "inner 8")
	r.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: []layers.IPv4Option{rrOpt(4)}}), "inner absent")
	r.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{InnerOptions: []layers.IPv4Option{rrOpt(4)}}), "outer absent")
	o := Defaults()
	o.IPv4Options = []layers.IPv4Option{rrOpt(4)}
	r.MustMatch(t, Build(t, o), "single 4")
	r.MustMatch(t, BuildEthIPIPTCP(t, IPIPOpts{Depth: 3, OuterOptions: []layers.IPv4Option{rrOpt(4)}, InnerOptions: []layers.IPv4Option{rrOpt(4)}}), "depth3 all 4")
}
