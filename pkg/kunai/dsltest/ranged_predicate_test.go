package dsltest

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestIPv4OptionsWithTransportPredicate(t *testing.T) {
	r := New(t, "eth/ipv4/tcp[dport==80] where ipv4.options.ROUTER_ALERT.value == 0")
	for _, port := range []uint16{80, 443} {
		for _, value := range []byte{0, 1} {
			o := Defaults()
			o.DstPort = port
			o.IPv4Options = []layers.IPv4Option{{OptionType: 148, OptionLength: 4, OptionData: []byte{0, value}}}
			pkt := Build(t, o)
			if got := r.Match(t, pkt); got != (port == 80 && value == 0) {
				t.Errorf("port=%d value=%d: match=%t", port, value, got)
			}
			r.MustReject(t, pkt[:14+24+3], "truncated TCP predicate field")
		}
	}
}
