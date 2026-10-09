package dsltest

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

// Repeated variable-length layers (`ipv4{n,m}`, genStaticMachineChain):
// one parser machine per instance, the self edge (protocol == 4) read
// from the previous header. Packets are eth/ipv4^k/tcp built by
// BuildEthIPIPTCP (Depth k).

func ipipDepth(t *testing.T, depth int) []byte {
	return BuildEthIPIPTCP(t, IPIPOpts{Depth: depth})
}

// rrOption is a well-formed Record Route option (kind 7, length 4).
var rrOption = layers.IPv4Option{OptionType: 7, OptionLength: 4, OptionData: []byte{0, 0}}

// badOption has an unknown kind: the option walk faults and the header
// has no options and is not valid (D-029).
var badOption = layers.IPv4Option{OptionType: 0x99, OptionLength: 4, OptionData: []byte{0, 0}}

func TestMachineChainRange(t *testing.T) {
	one := BuildEthIPv4TCP(t, 12345, 80)
	two := ipipDepth(t, 2)
	three := ipipDepth(t, 3)
	udp := BuildEthIPv4UDP(t, 1234, 5678, []byte{1, 2})

	r12 := New(t, "eth/ipv4{1,2}/tcp")
	r12.MustMatch(t, one, "one header")
	r12.MustMatch(t, two, "two headers")
	r12.MustReject(t, three, "three headers: the third is not tcp")
	r12.MustReject(t, udp, "udp after one header")

	r22 := New(t, "eth/ipv4{2,2}/tcp")
	r22.MustReject(t, one, "one header: under-run, the second dispatch misses")
	r22.MustMatch(t, two, "two headers")
	r22.MustReject(t, three, "three headers")

	r02 := New(t, "eth/ipv4/ipv4{0,2}/tcp")
	r02.MustMatch(t, one, "no inner header: tcp follows the first ipv4")
	r02.MustMatch(t, two, "one inner header")
	r02.MustMatch(t, three, "two inner headers")
	r02.MustReject(t, ipipDepth(t, 4), "three inner headers")
	r02.MustReject(t, udp, "udp after the outer header")

	r14 := New(t, "eth/ipv4{1,4}/tcp")
	r14.MustMatch(t, one, "one header")
	r14.MustMatch(t, ipipDepth(t, 4), "four headers")
}

// TestMachineChainBracket checks that every instance runs the bracket
// predicates (spec `iterate`): a predicate failing on the second header
// rejects even though the first one passed, and an option region that
// faults on either header makes `[options.valid]` reject.
func TestMachineChainBracket(t *testing.T) {
	ttl := New(t, "eth/ipv4[ttl==64]{1,2}/tcp")
	ttl.MustMatch(t, ipipDepth(t, 2), "both headers have ttl 64")
	ttl.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterTTL: 63}), "outer ttl 63: the first instance fails")
	ttl.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{InnerTTL: 63}), "inner ttl 63: the second instance fails")

	valid := New(t, "eth/ipv4[options.valid]{1,2}/tcp")
	valid.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "one header, no options")
	valid.MustMatch(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: []layers.IPv4Option{rrOption}, InnerOptions: []layers.IPv4Option{rrOption}}), "RR on both headers")
	valid.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: []layers.IPv4Option{badOption}}), "outer option region faults")
	valid.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{InnerOptions: []layers.IPv4Option{badOption}}), "inner option region faults")

	notValid := New(t, "eth/ipv4@o{1,2}/tcp where not o.options.valid")
	notValid.MustReject(t, ipipDepth(t, 2), "both regions well formed")
	notValid.MustMatch(t, BuildEthIPIPTCP(t, IPIPOpts{InnerOptions: []layers.IPv4Option{badOption}}), "the last instance's region faults")
	notValid.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: []layers.IPv4Option{badOption}}), "only the first instance's region faults: the reference is to the last")
}

// TestMachineChainWhereLast checks that a where reference to the
// repeated layer reads the last matched instance, and that a miss of a
// later iteration leaves that instance's slots in place.
func TestMachineChainWhereLast(t *testing.T) {
	r := New(t, "eth/ipv4@o{1,2}/tcp where o.ttl == 63")
	inner63 := BuildEthIPIPTCP(t, IPIPOpts{OuterTTL: 64, InnerTTL: 63})
	r.MustMatch(t, inner63, "inner (last) ttl 63")
	r.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterTTL: 63}), "outer ttl 63 but the inner (last) is 64")
	one63 := Defaults()
	one63.TTL = 63
	r.MustMatch(t, Build(t, one63), "one header with ttl 63: the second iteration missed")

	opt := New(t, "eth/ipv4@o{1,2}/tcp where o.options.RR.kind == 7")
	opt.MustMatch(t, BuildEthIPIPTCP(t, IPIPOpts{InnerOptions: []layers.IPv4Option{rrOption}}), "RR on the last instance")
	opt.MustReject(t, BuildEthIPIPTCP(t, IPIPOpts{OuterOptions: []layers.IPv4Option{rrOption}}), "RR only on the first instance")
	single := Defaults()
	single.IPv4Options = []layers.IPv4Option{rrOption}
	opt.MustMatch(t, Build(t, single), "one header with RR: the miss of the second iteration keeps its slots")

	after := New(t, "eth/ipv4{1,2}/tcp where tcp.dport == 80")
	after.MustMatch(t, ipipDepth(t, 2), "tcp after two headers")
	after.MustMatch(t, BuildEthIPv4TCP(t, 12345, 80), "tcp after one header")
	after.MustReject(t, BuildEthIPv4TCP(t, 12345, 81), "tcp dport 81")
}

// TestMachineChainIPv6 is the IPv6 shape: the extension-header walk of
// each instance is its own, and the self edge is next_header == 41.
func TestMachineChainIPv6(t *testing.T) {
	one := BuildEthIPv6TCP(t, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 1234, 80)
	two := BuildEthIPv6inIPv6TCP(t)

	r12 := New(t, "eth/ipv6{1,2}/tcp")
	r12.MustMatch(t, one, "one header")
	r12.MustMatch(t, two, "ipv6 in ipv6")

	r22 := New(t, "eth/ipv6{2,2}/tcp")
	r22.MustReject(t, one, "one header: under-run")
	r22.MustMatch(t, two, "two headers")

	// An extension header on the last instance only; the bracket form
	// checks every instance.
	ext := BuildIPv6WithExts(t, IPv6WithExtsOpts{FirstNextHeader: 0, FinalNextHeader: 6, Exts: []IPv6Ext{{HdrExtLen: 0}}})
	last := New(t, "eth/ipv6@o{1,2}/tcp where o.exts[0].next_header == 6")
	last.MustMatch(t, ext, "one header with a hop-by-hop ext: the second iteration misses, the slots stay")
	last.MustReject(t, two, "no ext on the last instance: index past the count is false (D-031)")
	br := New(t, "eth/ipv6[exts[0].next_header == 6]{1,2}/tcp")
	br.MustMatch(t, ext, "one header with ext")
	br.MustReject(t, two, "neither header has an ext")
}
