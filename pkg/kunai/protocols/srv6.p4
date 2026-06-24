// SRv6: IPv6 Segment Routing Header (RFC 8754).
//
// SRH is an IPv6 Routing extension header (next_header=43 in IPv6,
// routing_type=4 in SRH itself). Total wire size = 8 + hdr_ext_len*8.
// The variable region holds the segment list (16 bytes each) followed
// by any optional TLVs.
//
// This definition uses no kunai annotations: both the any()/all()
// element count and the next-header position derive from the parser's
// element-driven segment walk. `start` extracts the fixed 8-byte SRH and
// seeds a ParserCounter with the segment COUNT
// (`pc.set((bit<8>)(hdr.last_entry + 1))`; RFC 8754: last_entry is the
// index of the last segment, so the list holds last_entry + 1 entries).
// `walk` tests the counter and, while non-zero, `consume_seg` extracts
// one srv6_seg_h (16 bytes) into the `segments` stack via
// `pkt.extract(segments.next)` and decrements by one. The loader reads
// the counter's seed field (last_entry) and addend (+1) off this
// element-granular walk and derives both:
//
//   - the any()/all() element count = last_entry + 1, and
//   - the next-header re-anchor = layer_entry + 8 + (last_entry+1)*16,
//     emitted as an absolute R4 set after the walk converges.
//
// Per RFC 8754 the SRH region equals (last_entry+1)*16 exactly when no
// TLVs follow the segment list, so the count alone gives the next header
// for every TLV-free SRH. TLV support is optional per RFC 8754 Section 2;
// chaining past a TLV-bearing SRH (e.g. `eth/ipv6/srv6/tcp` when the SRH
// carries a Padding or HMAC TLV) is unsupported here: R4 lands at the
// segment-list end, short of the trailing TLVs. Segment queries
// (`srv6.segments[N]`, any()/all()) stay correct regardless of trailing
// TLVs.
//
// The `segments` stack base falls out of the `consume_seg` state's
// layer-entry offset (= sizeof(srv6_h) = 8), so `srv6.segments[N].addr`
// and the any()/all() quantifiers read the same bytes as before.
header srv6_h {
    bit<8>  next_header;
    bit<8>  hdr_ext_len;     // in 8-byte units, excluding the first 8
    bit<8>  routing_type;    // 4 for SRH
    bit<8>  segments_left;
    bit<8>  last_entry;
    bit<8>  flags;
    bit<16> tag;
}

header srv6_seg_h {
    bit<128> addr;
}

// Dispatch from IPv6: SRv6 is carried as Routing extension header
// (next_header == 43). The IPv6 parser block deliberately omits 43
// from its ext-set so users opt into SRv6 by writing it as a
// distinct chain element (e.g. `eth/ipv6/srv6/tcp`).
const bit<8> SRV6_IPV6_NEXT_HEADER = 43;

// routing_type 4 identifies SRH (RFC 8754 Section 2). Named so the
// start-state select arm reads as KUNAI_SRV6_ROUTING_TYPE rather than a
// bare 4. The KUNAI_ prefix marks a value-only const (no inter-layer
// dispatch role): the loader folds it into the select arm and never
// treats it as a dispatch edge.
const bit<8> KUNAI_SRV6_ROUTING_TYPE = 4;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser SRv6Parser(packet_in pkt,
                    out srv6_h        hdr,
                    out srv6_seg_h[8] segments) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        // Seed the counter with the segment COUNT = last_entry + 1
        // (RFC 8754: last_entry is the index of the last segment, so the
        // list holds last_entry + 1 entries). This bare-cast add form
        // (scale=1) makes the walk element-driven: it trips once per
        // pushed segment, so the loader derives the any()/all() element
        // count from this seed field (last_entry) and addend (+1) — no
        // @kunai_stack_count annotation needed. The same count also fixes
        // the next-header position at (last_entry+1)*16 past the segment
        // base (valid for every TLV-free SRH per RFC 8754).
        pc.set((bit<8>)(hdr.last_entry + 1));
        // routing_type 4 (KUNAI_SRV6_ROUTING_TYPE) identifies SRH
        // (RFC 8754 Section 2). Older Type-0 source-routing variants are
        // deprecated and out of scope, so every other routing_type is
        // rejected.
        transition select(hdr.routing_type) {
            KUNAI_SRV6_ROUTING_TYPE: walk;
            default:                 reject;
        }
    }
    // Element-driven walk over the segment list. Each iteration extracts
    // one 16-byte segment into the segments stack and decrements the
    // segment counter by one; when it drains, every segment has been
    // pushed. R4 is left at the segment-list end; codegen re-anchors it
    // to the next header at SRH+8 + (last_entry+1)*16 — the segment-list
    // end, which equals the next header for a TLV-free SRH (RFC 8754).
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume_seg;
        }
    }
    state consume_seg {
        pkt.extract(segments.next);
        pc.decrement(1);
        transition walk;
    }
}
