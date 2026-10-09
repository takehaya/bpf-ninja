package dsltest

import (
	"net"
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

// TestTCPAccumulatorInAlternation checks the accumulator threaded through an
// alternation member. The non-matching branch (udp) never runs the tcp
// option walk, so the acc slot must be zeroed before the alternation for the
// post-layer mask check to reject it cleanly.
func TestTCPAccumulatorInAlternation(t *testing.T) {
	r := New(t, "eth/ipv4/(tcp|udp) where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := func(s byte) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{s}}
	}

	match := Defaults()
	match.TCPOptions = []layers.TCPOption{mss, ws(7)}
	r.MustMatch(t, Build(t, match), "tcp branch: MSS=1460 AND WS=7")

	wsBad := Defaults()
	wsBad.TCPOptions = []layers.TCPOption{mss, ws(9)}
	r.MustReject(t, Build(t, wsBad), "tcp branch: WS mismatch")

	// udp branch: the tcp option walk never runs, so the acc slot keeps its
	// pre-alternation zero and the mask check rejects.
	r.MustReject(t, BuildEthIPv4UDP(t, 1234, 5678, []byte{0xde, 0xad}), "udp branch: no tcp options")
}

// TestTCPAccumulatorWideLiteralNeverHolds checks a pair whose first leaf
// compares the 16-bit MSS against an int<128>(…) above 2^64. No MSS can
// hold that value, so the conjunction is false for every packet (D-035
// compares values, not bit patterns): the plan rejects outright, even
// the packet whose WS leaf matches.
func TestTCPAccumulatorWideLiteralNeverHolds(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == int<128>(18446744073709553076) and tcp.options.WS.shift == 7")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}

	both := Defaults()
	both.TCPOptions = []layers.TCPOption{mss, ws}
	r.MustReject(t, Build(t, both), "MSS=1460 is not 2^64+1460; WS=7 cannot rescue the AND")

	none := Defaults()
	r.MustReject(t, Build(t, none), "no options")

	// A never atom carries no comparison value: an MSS of 0 must not be
	// mistaken for a match against a degenerate constant.
	zeroMSS := Defaults()
	zeroMSS.TCPOptions = []layers.TCPOption{mss0(), ws}
	r.MustReject(t, Build(t, zeroMSS), "MSS=0 and WS=7: the never leaf stays false")

	// The same value written as a small int<128>(…) fits and matches.
	small := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == int<128>(1460) and tcp.options.WS.shift == 7")
	small.MustMatch(t, Build(t, both), "int<128>(1460) fits the field")

	// A value that fits 64 bits but not the 16-bit field is never too:
	// 70000 is not narrowed to 70000 mod 2^16 (= 4464).
	fits64 := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == int<128>(70000) and tcp.options.WS.shift == 7")
	narrowed := Defaults()
	narrowed.TCPOptions = []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x11, 0x70}}, ws}
	fits64.MustReject(t, Build(t, narrowed), "MSS=4464 is not 70000")
	fits64.MustReject(t, Build(t, both), "MSS=1460 is not 70000")

	// The 4-byte sibling: 2^32 fits 64 bits, not the 32-bit tsval.
	ts32 := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.TS.tsval == int<128>(4294967296)")
	tsZero := Defaults()
	tsZero.TCPOptions = []layers.TCPOption{mss, {OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)}}
	ts32.MustReject(t, Build(t, tsZero), "tsval=0 is not 2^32")
}

func mss0() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0, 0}}
}

// TestTCPAccumulatorHighBitConst checks a 4-byte constant with the high
// bit set (0x80000000): the prelude compares it from a register because
// JNE.Imm would sign-extend the immediate to 0xffffffff80000000.
func TestTCPAccumulatorHighBitConst(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.TS.tsval == 0x80000000")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ts := func(tsval uint32) layers.TCPOption {
		d := make([]byte, 8)
		d[0], d[1], d[2], d[3] = byte(tsval>>24), byte(tsval>>16), byte(tsval>>8), byte(tsval)
		return layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: d}
	}

	match := Defaults()
	match.TCPOptions = []layers.TCPOption{mss, ts(0x80000000)}
	r.MustMatch(t, Build(t, match), "tsval == 0x80000000")

	below := Defaults()
	below.TCPOptions = []layers.TCPOption{mss, ts(0x7fffffff)}
	r.MustReject(t, Build(t, below), "tsval == 0x7fffffff")

	zero := Defaults()
	zero.TCPOptions = []layers.TCPOption{mss, ts(0)}
	r.MustReject(t, Build(t, zero), "tsval == 0 (a truncated constant would match)")
}

// TestTCPAccumulatorOtherLayerValid checks `ipv4.options.valid` ANDed
// with a two-option TCP plan. The ipv4 flag comes from ipv4's own walk,
// so it is checked after the accumulator's mask: a malformed ipv4 option
// region (D-029) rejects even when both TCP options match.
func TestTCPAccumulatorOtherLayerValid(t *testing.T) {
	r := New(t, "eth/ipv4/tcp where ipv4.options.valid and tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := func(s byte) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{s}}
	}

	plain := Defaults()
	plain.TCPOptions = []layers.TCPOption{mss, ws(7)}
	r.MustMatch(t, Build(t, plain), "ipv4 without options is valid; MSS=1460 AND WS=7")

	withOpt := Defaults()
	withOpt.IPv4Options = []layers.IPv4Option{{OptionType: 7, OptionLength: 4, OptionData: []byte{0, 0}}}
	withOpt.TCPOptions = []layers.TCPOption{mss, ws(7)}
	r.MustMatch(t, Build(t, withOpt), "a well-formed RR option keeps ipv4 valid")

	// An unknown ipv4 option kind faults the walk: ipv4 has no options
	// and is not valid (D-029), whatever the TCP options say.
	bad := Defaults()
	bad.IPv4Options = []layers.IPv4Option{{OptionType: 0x99, OptionLength: 4, OptionData: []byte{0, 0}}}
	bad.TCPOptions = []layers.TCPOption{mss, ws(7)}
	r.MustReject(t, Build(t, bad), "malformed ipv4 options: the residual flag check rejects")

	wsBad := Defaults()
	wsBad.TCPOptions = []layers.TCPOption{mss, ws(8)}
	r.MustReject(t, Build(t, wsBad), "ipv4 valid but WS=8: the mask check rejects")
}

// TestTCPAccumulatorOtherLayerValidAbsent checks the residual atom on an
// alternation member that did not match: `ipv4.options.valid` is false
// when ipv6 was taken (D-003), so the filter rejects even though the TCP
// plan is satisfied.
func TestTCPAccumulatorOtherLayerValidAbsent(t *testing.T) {
	r := New(t, "eth/(ipv4|ipv6)/tcp where ipv4.options.valid and tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7")

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}

	v4 := Defaults()
	v4.TCPOptions = []layers.TCPOption{mss, ws}
	r.MustMatch(t, Build(t, v4), "ipv4 member matched and valid")

	v6 := Defaults()
	v6.SrcIP, v6.DstIP = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	v6.TCPOptions = []layers.TCPOption{mss, ws}
	r.MustReject(t, Build(t, v6), "ipv6 member matched: ipv4 is absent, its flag reads false")
}

// TestTCPAccumulatorOtherLayerValidWhereOnlyGroup checks the residual
// atom on a member of an alternation that only the where clause tells
// apart (both members are ipv4). The member guard reads the group's
// matched-member slot, which the plan must therefore keep (it drops the
// where-only slots when nothing else reads them). The first member wins
// the dispatch, so `a` is present and `b` absent.
func TestTCPAccumulatorOtherLayerValidWhereOnlyGroup(t *testing.T) {
	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}
	ws := layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}}
	pkt := Defaults()
	pkt.TCPOptions = []layers.TCPOption{mss, ws}

	a := New(t, "eth/(ipv4@a|ipv4@b)/tcp where a.options.valid and tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7")
	a.MustMatch(t, Build(t, pkt), "a matched and is valid")

	b := New(t, "eth/(ipv4@a|ipv4@b)/tcp where b.options.valid and tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7")
	b.MustReject(t, Build(t, pkt), "b did not match: its flag reads false")
}
