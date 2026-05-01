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
	// Aux header predicate (gtp.opt.next_ext): reads a field of an
	// auxiliary header gated by the parser's E|S|PN tuple-select
	// (= opt is only extracted when any of those flags is set).
	"eth/ipv4/udp/gtp[opt.next_ext==0]/ipv4/tcp",
	"eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.next_ext == 0",
	// Aux header stack static index access: read N-th element's field.
	// gtp.exts is a fixed 4B-per-entry stack; ipv6.exts is a variable
	// per-entry stack but [0].next_header still lands at a fixed byte
	// (= start of first ext immediately after ipv6_h).
	"eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts[0].ext_type == 0",
	"eth/ipv6/tcp where ipv6.exts[0].next_header == 6",
	// SRv6 segment list address access via aux header stack:
	// static index (final destination = wire-order [0]) and
	// dynamic index from a parent field (next hop = [last_entry]).
	"eth/ipv6/srv6/tcp where srv6.segments[0].addr == fc00::1",
	"eth/ipv6/srv6/tcp where srv6.segments[srv6.last_entry].addr == fc00::1",
	// any/all quantifiers over an aux header stack: static unrolls
	// 8 iters (= capacity), each guarded by srv6.last_entry+1.
	"eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)",
	"eth/ipv6/srv6/tcp where all(srv6.segments.addr == fc00::1)",
	// TCP option lookup: walk options area searching for kind=2 (MSS),
	// read 16-bit value field, compare. Static unroll capped at 20
	// iters (= 40-byte options / 1-byte minimum option = 20 max).
	"eth/ipv4/tcp where tcp.options.MSS.value == 1460",
	// Flag-triggered optional sub-headers: GRE C/K/S advance.
	"eth/ipv4/gre/ipv4/tcp",
	// Capture: layer-targeted slicing (label, proto name, absolute).
	"eth/ipv4@outer/udp/gtp/ipv4@inner/tcp capture inner+8",
	"eth/ipv4/tcp capture ipv4",
	"eth/ipv4/tcp capture absolute 96",
	// Bool literal: `where true` is identity (no-op condition); the
	// `where false` counterpart compiles fine but is excluded from
	// the verifier-load matrix because the always-reject pattern
	// surfaces a kernel-side corner case unrelated to the type
	// system (the spec allows it; we just don't load it in CI).
	// dsl-types.md §4.6.
	"eth/ipv4/tcp where true",
	// Bare aux-exists: `where gtp.opt.exists` desugars in the resolver
	// to the aux-gating emit path (no field load, just the gate).
	"eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.exists",
	// Int<N> -> Bool decay: `where tcp.dport` is `tcp.dport != 0`
	// (always true on real TCP frames, but exercises the §5.4 path).
	"eth/ipv4/tcp where tcp.dport",
	// Bool == Bool (iff): a parens-grouped sub-condition feeds a
	// WAtomBoolEq desugared into and/or/not via dsl-types.md §6.2.
	"eth/ipv4/tcp where (tcp.dport == 443) == (tcp.sport == 443)",
	// Negative integer literal (where & bracket forms). 2's-complement
	// narrow per dsl-types.md §4.1: -1 against bit<16> binds to 0xffff.
	"eth/ipv4/tcp where tcp.dport == -1",
	"eth/ipv4/tcp[dport==-1]",
	// LHS network literal symmetry per dsl-types.md §6.2: literal on
	// either side resolves to the same WAtomLiteralCmp IR.
	"eth/ipv4/tcp where 10.0.0.1 == ipv4.dst",
	"eth/ipv4/tcp where 10.0.0.0/8 != ipv4.dst",
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
