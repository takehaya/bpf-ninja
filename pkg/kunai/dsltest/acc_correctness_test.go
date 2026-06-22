package dsltest

import (
	"testing"

	"github.com/google/gopacket/layers"
)

// TestTCPMultiOptionAccumulator verifies the two-option accumulator
// lowering produces correct verdicts. `MSS.value == 1460 and
// WS.shift == 7` compiles to a single bpf_loop that ORs one result bit
// per option into a single accumulator slot, then accepts iff
// (acc & mask) == mask. The semantics must match a conjunction: accept
// only when both options are present AND both fields match; an absent
// option leaves its bit 0, so the AND fails (reject). Walk order must
// not matter.
func TestTCPMultiOptionAccumulator(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7")

	mss := func(b0, b1 byte) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{b0, b1}}
	}
	ws := func(s byte) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{s}}
	}

	both := Defaults()
	both.TCPOptions = []layers.TCPOption{mss(0x05, 0xb4), ws(7)} // MSS=1460, WS=7
	r.MustMatch(t, Build(t, both), "MSS=1460 AND WS=7")

	swapped := Defaults()
	swapped.TCPOptions = []layers.TCPOption{ws(7), mss(0x05, 0xb4)} // order must not matter
	r.MustMatch(t, Build(t, swapped), "WS before MSS, both match")

	wsBad := Defaults()
	wsBad.TCPOptions = []layers.TCPOption{mss(0x05, 0xb4), ws(8)}
	r.MustReject(t, Build(t, wsBad), "WS=8 mismatch")

	mssBad := Defaults()
	mssBad.TCPOptions = []layers.TCPOption{mss(0x05, 0xa0), ws(7)} // MSS=1440
	r.MustReject(t, Build(t, mssBad), "MSS=1440 mismatch")

	noWS := Defaults()
	noWS.TCPOptions = []layers.TCPOption{mss(0x05, 0xb4)}
	r.MustReject(t, Build(t, noWS), "WS absent — bit stays 0, AND fails")

	noMSS := Defaults()
	noMSS.TCPOptions = []layers.TCPOption{ws(7)}
	r.MustReject(t, Build(t, noMSS), "MSS absent — bit stays 0, AND fails")

	none := Defaults()
	r.MustReject(t, Build(t, none), "neither option present")
}
