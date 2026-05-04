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
// this the simplest IPv4 option to extract — variable-array options
// like Record Route / Source Route / Timestamp need a separate
// follow-up (B-4) before they have first-class accessors.
header ipv4_opt_router_alert_h {
    bit<8>  kind;
    bit<8>  length;
    bit<16> value;
}

// Ethernet/VLAN/QinQ select ipv4 via the ethertype.
const bit<16> IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> IPV4_VLAN_ETHERTYPE = 0x0800;
const bit<16> IPV4_QINQ_ETHERTYPE = 0x0800;

// SRv6 transports IPv4-in-IPv6 (SRv6 → IPv4 inner): the SRH
// next_header byte uses IANA protocol number 4 (IPIP).
const bit<8>  IPV4_SRV6_NEXT_HEADER = 4;

// Under GRE, the protocol_type field carries the EtherType of the
// payload — IPv4 uses the well-known 0x0800.
const bit<16> IPV4_GRE_PROTOCOL_TYPE = 0x0800;

// Cap the option-walk loop. Worst-case trailer is 40 bytes (IHL=15)
// of NOPs (kind=1, single byte), so 40 iterations would drain the
// trailer fully. The verifier-safe bpf_loop cap is 32, which clips
// at IHL=12 with all-NOP options — packets above that drop at the
// loop end. Mixed real-world options (Router Alert at 4 B/iter,
// other options TBD in B-4) hit the cap far sooner; 32 is adequate
// for every well-formed IPv4 packet observed in the wild.
//
// The cap is only consulted when codegen emits the bpf_loop walk
// — which happens only when the program queries an IPv4 option.
// Programs that don't reach into ipv4.options.<X> route through
// the demand-driven bulk-advance fallback (see dsl-internals.md
// §6.5 Mechanism 8 / canFallbackToBulkAdvance) and skip the
// loop entirely.
const bit<8> IPV4_PARSER_MAX_DEPTH = 32;

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
                  out ipv4_opt_router_alert_h router_alert) {
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
}
