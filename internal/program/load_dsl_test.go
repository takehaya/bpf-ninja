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
	// MPLS under QinQ — relies on MPLS_QINQ_ETHERTYPE = 0x8847 in
	// mpls.p4 (parallel to the eth and vlan ethertypes; MPLS rides
	// every L2 carrier with the same payload-protocol code).
	"eth/qinq/mpls{1,2}/ipv4/tcp",
	"eth/qinq/mpls+/ipv4/tcp",
	// P3-12 alt with diverged size + diverged dispatch. (ipv4|ipv6)
	// differs in both header size (20 vs 40) and the field tcp/udp
	// dispatches off (protocol byte 9 vs next_header byte 6). The alt
	// block emits per-alt advance + matched-alt index in R5; the next
	// layer's dispatch reads R5 and JNEs into a per-alt check.
	"eth/(ipv4|ipv6)/tcp",
	"eth/(ipv4|ipv6)/udp",
	// Bracket predicate inside post-alt layer rides on R4-relative
	// addressing — agnostic to which alt's primary header size R4
	// got advanced past.
	"eth/(ipv4|ipv6)/tcp[dport==443]",
	// P3-13: nested alt groups are flattened in the resolver, so
	// `((a|b)|c)` ends up identical to `(a|b|c)` for codegen.
	// We pick a 3-way alt without ipv6 to keep the bpf_loop callback
	// out of this test — kernel 6.6's verifier loses bpf_loop ctx
	// spill bounds when the callback sits behind several preceding
	// alt dispatches, so the ipv6-bearing 4-way variant is exercised
	// in compile_test only (TestCompileNestedAlternationFlattens).
	"eth/((vlan|qinq)|ipv4)",
	// PR-A/PR-B: where past het-alt — uses per-layer entry slot to
	// recover tcp.dport's runtime address. The alt block stores R4
	// to slot at layer entry; tcp's where load reads the slot back.
	"eth/(ipv4|ipv6)/tcp where tcp.dport == 443",
	"eth/(ipv4|ipv6)/tcp where tcp.dport > 1024",
	// Capture past het-alt — uses max-alt rounding for MaxCapLen.
	"eth/(ipv4|ipv6)/tcp capture headers+64",
	// Option lookup past het-alt — option-walk loop's per-iter R2
	// compute switches between abs / slot anchor based on layer mark.
	"eth/(ipv4|ipv6)/tcp where tcp.options.MSS.value == 1460",
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
	// IPIP / 6-in-6 tunneling expressed as explicit two-layer chain
	// rather than a `+` quantifier — each ipv4/ipv6 layer runs its
	// own parser machine, so options/ext-headers on either layer are
	// handled correctly. Backed by IPV4_IPV4_PROTOCOL / IPV6_IPV6_NEXT_HEADER.
	"eth/ipv4/ipv4/tcp",
	"eth/ipv6/ipv6/tcp",
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
	// Bool literal: `where true` is identity (no-op condition);
	// `where false` short-circuits in Gen to a minimal always-reject
	// program (codegen.go::isConstantFalseCondition), so the chain
	// emit's bounds-check side effects don't dangle as dead code.
	// dsl-types.md §4.6 / §15.4.
	"eth/ipv4/tcp where true",
	"eth/ipv4/tcp where false",
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
	// F7 (`field in [...]`) — integer alternatives reach codegen as
	// an OR-chain of JEq jumps, with no overall packet-state delta
	// versus the equivalent `dport == 80 or dport == 443`.
	"eth/ipv4/tcp[dport in [80, 443]]",
	"eth/ipv4/tcp[dport in [80, 443, 8080, 8443]]",
	// F6 bitwise op set — `&`, `<<`, `>>` at mul/div precedence,
	// `|`, `^` at add/sub. The classic flag/mask + shift idioms
	// reach codegen as plain BPF ALU ops.
	"eth/ipv4/tcp where tcp.dport & 0xff == 80",
	"eth/ipv4/tcp where tcp.dport | 0x80 == 80",
	"eth/ipv4/tcp where tcp.dport ^ 0x01 == 80",
	"eth/ipv4/tcp where tcp.dport >> 4 == 0",
	"eth/ipv4/tcp where tcp.dport << 1 == 160",
	// F3 IPv6 ordered cmp — lexicographic comparison emitted as
	// high-half decision + low-half fall-through.
	"eth/ipv6[dst < fe80::ffff]/tcp",
	"eth/ipv6[dst >= ::1]/tcp",
	// F4 Int<128> arith in the where path. The carry/borrow plumbing
	// is now ABI-clean (no R6/R7/R8 use), so plain cmp, field + const
	// / field - const, and field + field / field - field all
	// verifier-load. Mul stays staged via F5 (bit-slice covers the
	// IPv6 manipulation cases that mattered).
	"eth/ipv6/tcp where ipv6.src == ipv6.dst",
	"eth/ipv6/tcp where ipv6.src + 1 == ipv6.dst",
	"eth/ipv6/tcp where ipv6.dst - 1 == ipv6.src",
	"eth/ipv6/tcp where ipv6.src + ipv6.dst == ipv6.src",
	"eth/ipv6/tcp where ipv6.src - ipv6.dst == ipv6.src",
	// 128-bit cmp + capture combo — this is the shape that caught
	// the earlier R8/R9 ABI leak: filter clobbered R9 (host pkt_len)
	// and captureWithXdpOutput's `Mov R3, R9` after filter then read
	// a stale value, silently truncating MaxCapLen. ABI-clean fix
	// (slot 2 routing in genArithCompare128) is pinned by both
	// TestZeroCapsIsHostAgnostic and this verifier-load case.
	"eth/ipv6/tcp where ipv6.src == ipv6.dst capture headers+64",
	// F3 where-arith Int<128> ordered cmp — same lex compare shape
	// as the bracket path, lifted into where via genArithCompare128
	// so `where ipv6.src < ipv6.dst` etc. now load.
	"eth/ipv6/tcp where ipv6.src < ipv6.dst",
	"eth/ipv6/tcp where ipv6.src >= ipv6.dst",
	// `field[lo:hi]` bit-slice — narrows a wide field down to a
	// single LDX-sized window, or sugar for the full-field cmp at
	// width 128. Replaces the F5 multiplication path nobody wanted.
	"eth/ipv6/tcp where ipv6.src[0:32] == 0x20010db8",
	"eth/ipv6/tcp where ipv6.src[64:128] == ipv6.dst[64:128]",
	"eth/ipv6/tcp where ipv6.src[0:128] == ipv6.dst[0:128]",
	"eth/ipv6[src[0:32]==0x20010db8]/tcp",
	// F12 mid-width slice cmp — resolver desugars into AND-chain
	// of LDX-aligned sub-cmps. 96bit (= 8+4 split) is the typical
	// IPv4-mapped-prefix shape.
	"eth/ipv6/tcp where ipv6.src[0:96] == ipv6.dst[0:96]",
	// F13 non-aligned bit-slice — codegen loads pow2-byte cover and
	// applies shift+mask after bswap to extract the actual slice bits.
	"eth/ipv6/tcp where ipv6.src[3:9] == 1",
	"eth/ipv6/tcp where ipv6.src[4:12] == 0xff",
}

// dslExitExprs covers fexit-specific constructs (action atoms) plus a
// basic chain to confirm the exit side still accepts simple DSL.
var dslExitExprs = []string{
	"eth/ipv4/tcp",
	"eth/ipv4/tcp where action == XDP_DROP",
	"eth/ipv4/tcp where action == XDP_PASS or action == XDP_TX",
}

// dslTCEntryExprs is the tc clsact fentry-side DSL matrix. A subset
// of dslEntryExprs broad enough to pin the kunai-host-agnostic
// codegen on the tc context-loading path (skb->data / data_end /
// len via runtime BTF resolve).
var dslTCEntryExprs = []string{
	"eth/ipv4/tcp",
	"eth/ipv4/udp",
	"eth/ipv6/tcp",
	"eth/ipv4/tcp[dport==443]",
	"eth/ipv4/tcp where tcp.dport == 443",
	"eth/ipv4/tcp capture headers+64",
	"eth/(ipv4|ipv6)/tcp",
	// mpls+ (not vlan+) pins the `+` quantifier / bpf_loop path on the
	// tc context: the kernel strips the outer VLAN tag into skb
	// metadata before tc, so vlan/qinq layers are rejected there.
	"eth/mpls+/ipv4/tcp",
	"eth/ipv4/ipv4/tcp",
	// Parser-machine paths: GTP-U with optional + ext-header chain,
	// SRv6 segments, IPv6 ext walk. These exercise the bpf_loop
	// callback subprograms under tc-style tracing context.
	"eth/ipv4/udp/gtp/ipv4/tcp",
	"eth/ipv6/srv6/tcp",
	// Aux predicate (option-walk + slot prelude) under tc.
	"eth/ipv4/tcp where tcp.options.MSS.value == 1460",
	// Owner-bound array (TCP SACK addrs[N] static index + any/all
	// quantifier).
	"eth/ipv4/tcp where any(ipv4.options.RR.addrs.addr == 192.168.0.0/16)",
}

// dslTCExitExprs covers tc clsact fexit-side action atoms. Every
// distinct verdict shape used by the project should compile + load:
// positive verdicts (TC_ACT_OK/SHOT/REDIRECT), pipe/continue
// (TC_ACT_PIPE), and the only signed verdict (TC_ACT_UNSPEC = -1)
// which previously broke silently due to JNE.Imm sign-extension —
// pinned here as a regression test for the JNE.Imm32 fix.
var dslTCExitExprs = []string{
	"eth/ipv4/tcp",
	"eth/ipv4/tcp where action == TC_ACT_SHOT",
	"eth/ipv4/tcp where action == TC_ACT_OK or action == TC_ACT_REDIRECT",
	"eth/ipv4/tcp where action == TC_ACT_PIPE",
	"eth/ipv4/tcp where action == TC_ACT_UNSPEC",
}

func TestBpfEntryWithDSLFilter(t *testing.T) {
	runFilterMatrix(t, loadDummyXDP(t), xdpFuncName, dslEntryExprs, false, true)
}

func TestBpfExitWithDSLFilter(t *testing.T) {
	runFilterMatrix(t, loadDummyXDP(t), xdpFuncName, dslExitExprs, true, true)
}

func TestBpfEntryWithDSLFilterTC(t *testing.T) {
	runFilterMatrix(t, loadDummyTC(t), tcFuncName, dslTCEntryExprs, false, true)
}

func TestBpfExitWithDSLFilterTC(t *testing.T) {
	runFilterMatrix(t, loadDummyTC(t), tcFuncName, dslTCExitExprs, true, true)
}

// dslCgroupSKBEntryExprs is the cgroup-skb fentry-side DSL matrix.
// The packet window starts at the network header (no Ethernet framing),
// so chains root at ipv4/ipv6. The context-loading path is the same
// skb prologue as tc (runtime BTF-resolved sk_buff offsets); the
// matrix pins the L3-rooted chain shapes on it, including a
// parser-machine (bpf_loop) path and an option-walk predicate.
var dslCgroupSKBEntryExprs = []string{
	"ipv4/tcp",
	"ipv4/udp",
	"ipv6/tcp",
	"ipv4/tcp[dport==443]",
	"ipv4/tcp where tcp.dport == 443",
	"ipv4/tcp capture headers+64",
	"ipv4/udp/gtp/ipv4/tcp",
	"ipv6/srv6/tcp",
	"ipv4/tcp where tcp.options.MSS.value == 1460",
}

// dslCgroupSKBExitExprs covers the cgroup-skb fexit-side action atoms
// (SK_DROP=0 / SK_PASS=1).
var dslCgroupSKBExitExprs = []string{
	"ipv4/tcp",
	"ipv4/tcp where action == SK_DROP",
	"ipv4/tcp where action == SK_PASS or action == SK_DROP",
}

func TestBpfEntryWithDSLFilterCgroupSKB(t *testing.T) {
	runFilterMatrix(t, loadDummyCgroupSKB(t), cgroupSKBFuncName, dslCgroupSKBEntryExprs, false, true)
}

func TestBpfExitWithDSLFilterCgroupSKB(t *testing.T) {
	runFilterMatrix(t, loadDummyCgroupSKB(t), cgroupSKBFuncName, dslCgroupSKBExitExprs, true, true)
}
