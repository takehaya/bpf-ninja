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

// TestTCPThreeOptionAccumulator checks the cap-limit case (three option
// equalities), which only loads thanks to the cursor-forget convergence
// trick. Verifies the forget preserves runtime verdicts: accept iff all
// three options are present and match.
func TestTCPThreeOptionAccumulator(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7 and tcp.options.SACK_PERM.kind == 4")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := func(s byte) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{s}}
	}
	sackPerm := layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}

	all := Defaults()
	all.TCPOptions = []layers.TCPOption{mss, ws(7), sackPerm}
	r.MustMatch(t, Build(t, all), "MSS=1460 AND WS=7 AND SACK_PERM present")

	// reordered, still all present
	reordered := Defaults()
	reordered.TCPOptions = []layers.TCPOption{sackPerm, ws(7), mss}
	r.MustMatch(t, Build(t, reordered), "reordered, all match")

	noSackPerm := Defaults()
	noSackPerm.TCPOptions = []layers.TCPOption{mss, ws(7)}
	r.MustReject(t, Build(t, noSackPerm), "SACK_PERM absent — bit 2 stays 0")

	wsBad := Defaults()
	wsBad.TCPOptions = []layers.TCPOption{mss, ws(9), sackPerm}
	r.MustReject(t, Build(t, wsBad), "WS mismatch")
}

// TestTCPFourOptionAccumulator checks four option equalities lowered into
// the one combined accumulator loop (cursor + accumulator forgets keep it
// converging). Verifies the forgets preserve runtime verdicts: accept iff
// all four options are present and match.
func TestTCPFourOptionAccumulator(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7 and tcp.options.SACK_PERM.kind == 4 and tcp.options.TS.tsval == 1")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := func(s byte) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{s}}
	}
	sackPerm := layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
	ts := func(tsval uint32) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: []byte{
			byte(tsval >> 24), byte(tsval >> 16), byte(tsval >> 8), byte(tsval), 0, 0, 0, 0,
		}}
	}

	all := Defaults()
	all.TCPOptions = []layers.TCPOption{mss, ws(7), sackPerm, ts(1)}
	r.MustMatch(t, Build(t, all), "all four present and match")

	reordered := Defaults()
	reordered.TCPOptions = []layers.TCPOption{ts(1), sackPerm, ws(7), mss}
	r.MustMatch(t, Build(t, reordered), "reordered, all match")

	noTS := Defaults()
	noTS.TCPOptions = []layers.TCPOption{mss, ws(7), sackPerm}
	r.MustReject(t, Build(t, noTS), "TS absent — bit 3 stays 0")

	tsBad := Defaults()
	tsBad.TCPOptions = []layers.TCPOption{mss, ws(7), sackPerm, ts(2)}
	r.MustReject(t, Build(t, tsBad), "TS tsval mismatch")
}

// TestTCPEightOptionAccumulator checks eight atoms (two fields on each of
// the four option types) in the one combined accumulator loop. Verifies
// verdicts stay correct as the atom count and accumulator bit width grow.
func TestTCPEightOptionAccumulator(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where "+
		"tcp.options.MSS.value == 1460 and tcp.options.MSS.length == 4 "+
		"and tcp.options.WS.shift == 7 and tcp.options.WS.length == 3 "+
		"and tcp.options.SACK_PERM.kind == 4 and tcp.options.SACK_PERM.length == 2 "+
		"and tcp.options.TS.tsval == 1 and tcp.options.TS.tsecr == 2")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}
	sackPerm := layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
	ts := func(tsval, tsecr uint32) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: []byte{
			byte(tsval >> 24), byte(tsval >> 16), byte(tsval >> 8), byte(tsval),
			byte(tsecr >> 24), byte(tsecr >> 16), byte(tsecr >> 8), byte(tsecr),
		}}
	}

	all := Defaults()
	all.TCPOptions = []layers.TCPOption{mss, ws, sackPerm, ts(1, 2)}
	r.MustMatch(t, Build(t, all), "all eight field equalities hold")

	tsecrBad := Defaults()
	tsecrBad.TCPOptions = []layers.TCPOption{mss, ws, sackPerm, ts(1, 9)}
	r.MustReject(t, Build(t, tsecrBad), "TS tsecr mismatch — its bit stays 0")
}

// TestTCPTwelveOptionAccumulator exercises twelve atoms (every field of
// MSS/WS/TS plus SACK_PERM), which only verify because the per-iteration
// accumulator forget uses a u64 salt — a narrower salt would leave the
// high result bits' history precise and explode on 6.18/7.0. Confirms the
// wide-salt canonicalization still preserves verdicts.
func TestTCPTwelveOptionAccumulator(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where "+
		"tcp.options.MSS.kind == 2 and tcp.options.MSS.length == 4 and tcp.options.MSS.value == 1460 "+
		"and tcp.options.WS.kind == 3 and tcp.options.WS.length == 3 and tcp.options.WS.shift == 7 "+
		"and tcp.options.TS.kind == 8 and tcp.options.TS.length == 10 and tcp.options.TS.tsval == 1 and tcp.options.TS.tsecr == 2 "+
		"and tcp.options.SACK_PERM.kind == 4 and tcp.options.SACK_PERM.length == 2")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}
	sackPerm := layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
	ts := func(tsval, tsecr uint32) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: []byte{
			byte(tsval >> 24), byte(tsval >> 16), byte(tsval >> 8), byte(tsval),
			byte(tsecr >> 24), byte(tsecr >> 16), byte(tsecr >> 8), byte(tsecr),
		}}
	}

	all := Defaults()
	all.TCPOptions = []layers.TCPOption{mss, ws, sackPerm, ts(1, 2)}
	r.MustMatch(t, Build(t, all), "all twelve field equalities hold")

	tsecrBad := Defaults()
	tsecrBad.TCPOptions = []layers.TCPOption{mss, ws, sackPerm, ts(1, 9)}
	r.MustReject(t, Build(t, tsecrBad), "high-bit (tsecr) mismatch — confirms u64-salt forget did not corrupt bit 11")
}

// TestTCPAccumulatorLeafForms checks the two operand-shape normalizations
// in eqLeafToAtom keep the right verdict: a constant on the LHS of a leaf
// (`1460 == field`) and a negative literal narrowed to the field width
// (`WS.shift == -1` means shift == 0xff).
func TestTCPAccumulatorLeafForms(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where 1460 == tcp.options.MSS.value and tcp.options.WS.shift == -1")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := func(s byte) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{s}}
	}

	match := Defaults()
	match.TCPOptions = []layers.TCPOption{mss, ws(0xff)}
	r.MustMatch(t, Build(t, match), "MSS=1460 (const on left) AND shift=0xff (== -1)")

	wrongShift := Defaults()
	wrongShift.TCPOptions = []layers.TCPOption{mss, ws(7)}
	r.MustReject(t, Build(t, wrongShift), "shift=7 != 0xff, so the -1 leaf fails")
}
