package dsltest

import (
	"testing"

	"github.com/google/gopacket/layers"
)

// TestBracketNestedOptionPath: `<option_segment>.<NAME>.<field>` and
// `<option_segment>.<NAME>.<stack>[N].<field>` in a bracket read the
// option the walk located, the second one entry of a stack inside it; an
// entry past the option's length is absent (D-031).
func TestBracketNestedOptionPath(t *testing.T) {
	r := New(t, "eth/ipv4/tcp[options.MSS.value == 1460]")
	r.MustMatch(t, buildTCPWithOptions(t, wsOption, mssOption(1460)), "MSS 1460 behind WS")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1400)), "MSS 1400")
	r.MustReject(t, buildTCPWithOptions(t, wsOption), "no MSS")

	nop := layers.TCPOption{OptionType: layers.TCPOptionKindNop}
	oneBlock := buildTCPWithOptions(t, nop, nop, sackOption([2]uint32{5, 9}))
	twoBlocks := buildTCPWithOptions(t, nop, nop, sackOption([2]uint32{5, 9}, [2]uint32{20, 30}))
	r = New(t, "eth/ipv4/tcp[options.SACK.blocks[0].left == 5]")
	r.MustMatch(t, oneBlock, "block 0 left 5")
	r.MustReject(t, buildTCPWithOptions(t, nop, nop, sackOption([2]uint32{6, 9})), "block 0 left 6")
	r.MustReject(t, buildTCPWithOptions(t, mssOption(1460)), "no SACK")
	r = New(t, "eth/ipv4/tcp[options.SACK.blocks[1].right > 25]")
	r.MustMatch(t, twoBlocks, "block 1 right 30")
	r.MustReject(t, oneBlock, "no block 1")

	rr := func(addrs ...byte) []layers.IPv4Option {
		data := []byte{4}
		for _, a := range addrs {
			data = append(data, 10, 0, 0, a)
		}
		return []layers.IPv4Option{{OptionType: 7, OptionLength: uint8(2 + len(data)), OptionData: data}, {OptionType: 0}}
	}
	o := Defaults()
	r = New(t, "eth/ipv4[options.RR.addrs[1].addr in [10.0.0.0/24, 192.168.0.1]]/tcp")
	o.IPv4Options = rr(1, 2)
	r.MustMatch(t, Build(t, o), "addr 1 is 10.0.0.2")
	o.IPv4Options = rr(1)
	r.MustReject(t, Build(t, o), "one address only")
}
