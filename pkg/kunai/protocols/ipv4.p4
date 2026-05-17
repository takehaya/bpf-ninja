// IPv4 base header.
header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_length;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

// Router Alert (RFC 2113, kind 148, length 4): 16-bit value telling
// routers along the path whether to examine the packet (well-known
// values: 0 = MLD, 1 = RSVP, 2 = AGGR). The fixed 4-byte shape makes
// this the simplest IPv4 option to extract.
header ipv4_opt_router_alert_h {
    bit<8>  kind;
    bit<8>  length;
    bit<16> value;
}

// Record Route (RFC 791 §3.1, kind 7): variable-size option whose
// length byte covers the full kind+length+pointer header (3 bytes)
// plus 1..9 IPv4 addresses (4 bytes each). pointer (octet 3) is the
// 1-indexed byte offset of the next-empty slot inside the option;
// codegen exposes it as ipv4.options.RR.pointer for inspection.
header ipv4_opt_rr_h {
    bit<8> kind;
    bit<8> length;
    bit<8> pointer;
}

// One IPv4 address slot inside a Record Route option. Addresses are
// reached at predicate time via the owner-bound stack
// `ipv4.options.RR.addrs[N].addr`; the parser block does not extract
// individual entries (the slot prelude records the option base before
// dispatch and per-element offsets fold in at where-time).
header ipv4_rr_addr_h {
    bit<32> addr;
}

// Ethernet/VLAN/QinQ select ipv4 via the ethertype.
const bit<16> IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> IPV4_VLAN_ETHERTYPE = 0x0800;
const bit<16> IPV4_QINQ_ETHERTYPE = 0x0800;

// SRv6 transports IPv4-in-IPv6 (SRv6 → IPv4 inner): the SRH
// next_header byte uses IANA protocol number 4 (IPIP).
const bit<8>  IPV4_SRV6_NEXT_HEADER = 4;

// IPv4-in-IPv4 tunneling (IPIP, RFC 2003): the outer ipv4's protocol
// byte is 4 (IANA "IPIP"). Lets users write `eth/ipv4/ipv4/tcp` to
// match IPIP frames without resorting to a chain quantifier — each
// ipv4 layer runs its own parser machine, so IHL>5 / options on the
// inner ipv4 are handled correctly.
const bit<8>  IPV4_IPV4_PROTOCOL = 4;

// Under GRE, the protocol_type field carries the EtherType of the
// payload — IPv4 uses the well-known 0x0800.
const bit<16> IPV4_GRE_PROTOCOL_TYPE = 0x0800;

// Option-walk loop bound: worst-case trailer is 40 bytes (IHL=15)
// of NOPs (kind=1, single byte), so up to 40 iterations would drain
// the trailer fully. We leave the bound at codegen's default 8
// iterations (see vocab/loader.go classifyConsts MAX_DEPTH path).
// Mixed real-world options (Router Alert at 4 B/iter, Record Route
// at 4 B/entry) hit the cap far sooner; 8 is adequate for every
// well-formed IPv4 packet observed in the wild.
//
// A previous declaration named `IPV4_PARSER_MAX_DEPTH = 32` was
// silently misclassified by the loader as a `<SELF>_<PARENT>_<FIELD>`
// dispatch const with a phantom parent named "parser"; the intended
// 32-iter cap was never applied. Removed to eliminate the
// source/impl drift. The loader's MAX_DEPTH path matches the exact
// name `<SELF>_MAX_DEPTH` only — declare `IPV4_MAX_DEPTH = N` (and
// verify on every supported kernel) if a higher cap is needed.
//
// The bound is only consulted when codegen emits the bpf_loop walk
// — which happens only when the program queries an IPv4 option.
// Programs that don't reach into ipv4.options.<X> route through
// the demand-driven bulk-advance fallback (see dsl-internals.md
// §6.5 Mechanism 8 / canFallbackToBulkAdvance) and skip the
// loop entirely.

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

// Self-validating parser: the start state's tuple-select rejects on
// version != 4. Resolver allows ipv4 under any parent (MPLS, GTP-U,
// VXLAN inner Ethernet, ...) via DispatchSelfValidating; the runtime
// version reject happens here.
//
// Options walk shape — Mechanism 8 in dsl-internals.md §6.5:
// ParserCounter pc records remaining-trailer-bytes after the fixed
// 20-byte primary. The `walk` state's 2-key tuple-select dispatches
// on (pc.is_zero(), kind byte): when the counter exhausts or EOL
// (kind=0) is seen, accept; otherwise route to the matching sibling
// extract state, decrement by the consumed byte count, and loop.
// IHL=5 (no options) short-circuits the walk via the `(4, 5):
// accept;` arm in start so the typical case pays no bpf_loop cost.
//
// Demand-driven codegen further skips the bpf_loop subprogram when
// no `ipv4.options.<X>` predicate is in the program — most chains
// (eth/ipv4/tcp, eth/ipv4/udp/gtp/...) fall into this path and emit
// only the Mechanism-1-equivalent bulk advance plus the start
// state's pc.set. Only programs that explicitly read an IPv4
// option pay for the full TLV walk.
//
// Unknown options are rejected (skip-by-length-with-counter-decrement
// would require a variable counter argument that p4lite does not yet
// admit). Phase 1 covers Router Alert; B-4 lands the variable-array
// options (Record Route, LSR/SSR, Timestamp).
parser IPv4Parser(packet_in pkt,
                  out ipv4_h                  hdr,
                  out ipv4_opt_router_alert_h router_alert,
                  out ipv4_opt_rr_h           rr,
                  out ipv4_rr_addr_h[9]       addrs) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set(((bit<8>)(hdr.ihl - 5)) << 5);
        transition select(hdr.version) {
            4:       walk;
            default: reject;
        }
    }
    state walk {
        transition select(pc.is_zero(), pkt.lookahead<bit<8>>()) {
            (true,  _):    accept;
            (false, 0):    accept;
            (false, 1):    parse_nop;
            (false, 7):    parse_rr;
            (false, 148):  parse_router_alert;
            (false, _):    reject;
        }
    }
    state parse_nop {
        pkt.advance(8);
        pc.decrement(1);
        transition walk;
    }
    state parse_router_alert {
        pkt.extract(router_alert);
        pc.decrement(4);
        transition walk;
    }
    state parse_rr {
        // Dispatched-but-not-extracted shape: read the length byte
        // via lookahead (without consuming bytes), decrement the
        // counter by the option's full size, and advance R4 past
        // the entire option in one go. Avoids the JLT+Sub combo a
        // field-driven `pkt.advance((rr.length - 3) << 3)` would
        // emit after a preceding extract — that combo blew the
        // bpf_loop callback past the 1M insn limit when an aux
        // query forced the slot prelude into the loop body. Slot
        // prelude has already recorded R3-at-entry as the rr base
        // before dispatch landed here, so DSL queries reach
        // kind / length / pointer / addrs[N].addr at slot+0 / +1 /
        // +2 / +3 + N*4 without an explicit extract.
        pc.decrement((bit<8>)pkt.lookahead<bit<16>>()[7:0]);
        pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
        transition walk;
    }
}
