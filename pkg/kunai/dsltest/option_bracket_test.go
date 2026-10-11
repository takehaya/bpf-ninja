package dsltest

import (
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
