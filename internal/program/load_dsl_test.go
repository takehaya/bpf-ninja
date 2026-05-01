package program

import "testing"

// DSL verifier-load coverage. Each case goes through kunai.Compile and
// must pass the kernel BPF verifier. Chains requiring PR 5c codegen
// (`+/*/{n,m}`) or alternation are deliberately absent — they land
// with those commits.

var dslEntryExprs = []string{
	"eth/ipv4/tcp",
	"eth/ipv4/udp",
	"eth/ipv4/icmp",
	"eth/ipv6/tcp",
	"eth/ipv6/icmp6",
	"eth/vlan?/ipv4/tcp",
	"eth/vlan{1,3}/ipv4/tcp",
	"eth/vlan{3,3}/ipv4/tcp",
	"eth/mpls{1,4}/ipv4/tcp",
	"eth/mpls{2,2}/ipv4/tcp",
	"eth/vlan+/ipv4/tcp",
	"eth/mpls+/ipv4/tcp",
	"eth/vlan{1,8}/ipv4/tcp",
	"eth/vlan*/ipv4/tcp",
	"eth/mpls*/ipv4/tcp",
	"eth/(vlan|qinq)",
	"eth/(vlan|qinq)/ipv4/tcp",
	"eth/ipv4/tcp[dport==443]",
	"eth/ipv4[src==10.0.0.1]/tcp",
	"eth/ipv4[dst==10.0.0.0/8]/tcp",
	"eth/ipv4[src==192.168.0.0/16]/tcp[dport==443]",
	"eth/ipv6[src==fe80::1]/tcp",
	"eth/ipv6[dst==2001:db8::/32]/tcp",
	"eth/ipv6[src!=fe80::1]/tcp",
	"eth/ipv6[dst!=2001:db8::/32]/tcp",
	"eth[dst==de:ad:be:ef:00:01]/ipv4/tcp",
	"eth[dst!=de:ad:be:ef:00:01]/ipv4/tcp",
	"eth/ipv4/tcp where tcp.dport == 443",
	"eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80",
	"eth/ipv4/tcp where ipv4.total_length > 100",
	"eth/ipv4/tcp capture headers+64",
	"eth/ipv4/tcp capture headers+64 where tcp.dport > 1024",
	// Parser machine: GTP-U with optional + extension-header chain.
	"eth/ipv4/udp/gtp/ipv4/tcp",
	// Flag-triggered optional sub-headers: GRE C/K/S advance.
	"eth/ipv4/gre/ipv4/tcp",
	// Capture: layer-targeted slicing (label, proto name, absolute).
	"eth/ipv4@outer/udp/gtp/ipv4@inner/tcp capture inner+8",
	"eth/ipv4/tcp capture ipv4",
	"eth/ipv4/tcp capture absolute 96",
}

// dslExitExprs covers fexit-specific constructs (action atoms) plus a
// basic chain to confirm the exit side still accepts simple DSL.
var dslExitExprs = []string{
	"eth/ipv4/tcp",
	"eth/ipv4/tcp where action == XDP_DROP",
	"eth/ipv4/tcp where action == XDP_PASS or action == XDP_TX",
}

func TestBpfEntryWithDSLFilter(t *testing.T) {
	runFilterMatrix(t, loadDummyXDP(t), xdpFuncName, dslEntryExprs, false, true)
}

func TestBpfExitWithDSLFilter(t *testing.T) {
	runFilterMatrix(t, loadDummyXDP(t), xdpFuncName, dslExitExprs, true, true)
}
