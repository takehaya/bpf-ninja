package dsltest

import (
	"fmt"
	"testing"
)

func TestIPv6ExtensionLengthBoundary(t *testing.T) {
	r := New(t, "eth/ipv6/tcp[dport==80]")
	for _, length := range []uint8{0, 3, 4, 5, 7, 8} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			for _, port := range []uint16{80, 443} {
				pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{FirstNextHeader: 0, FinalNextHeader: 6, DstPort: port, Exts: []IPv6Ext{{HdrExtLen: length}}})
				if got := r.Match(t, pkt); got != (port == 80) {
					t.Errorf("length=%d port=%d: match=%t", length, port, got)
				}
			}
		})
	}
	options := make([]byte, 32)
	options[3], options[12] = 80, 0x50
	r.MustReject(t, BuildIPv6WithExts(t, IPv6WithExtsOpts{FirstNextHeader: 0, FinalNextHeader: 6, DstPort: 443, Exts: []IPv6Ext{{HdrExtLen: 4, Options: options}}}), "TCP-like option bytes are not the transport header")
	r.MustMatch(t, BuildIPv6WithExts(t, IPv6WithExtsOpts{FirstNextHeader: 0, FinalNextHeader: 6, Exts: []IPv6Ext{{HdrExtLen: 4}, {HdrExtLen: 5}}}), "multiple long extension headers")
	for _, length := range []uint8{4, 8, 255} {
		pkt := BuildIPv6WithExts(t, IPv6WithExtsOpts{FirstNextHeader: 0, FinalNextHeader: 6, Exts: []IPv6Ext{{HdrExtLen: 0}}})
		pkt[ethIPv6PrefixSize+1] = length
		r.MustReject(t, pkt, "declared extension length exceeds packet")
	}
	r.MustReject(t, BuildIPv6WithExts(t, IPv6WithExtsOpts{FirstNextHeader: 0, FinalNextHeader: 6, Exts: []IPv6Ext{{HdrExtLen: 255}}}), "transport header beyond scratch window")
}
