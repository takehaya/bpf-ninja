// SRv6: IPv6 Segment Routing Header (RFC 8754).
//
// SRH is an IPv6 Routing extension header (next_header=43 in IPv6,
// routing_type=4 in SRH itself). Total wire size = 8 + hdr_ext_len*8.
// The variable region holds the segment list (16 bytes each) followed
// by any optional TLVs.
//
// The parser walks the variable region explicitly with a counter-driven
// extract loop modeled on the ipv4.p4 / geneve.p4 option walks. `start`
// extracts the fixed 8-byte SRH and seeds a ParserCounter with the
// region size in bytes (= hdr_ext_len * 8; the `<< 6` scales the masked
// hdr_ext_len by 8). The `walk` state tests the counter; while it is
// non-zero, `consume_seg` extracts one srv6_seg_h (16 bytes) into the
// `segments` stack via `pkt.extract(segments.next)` and decrements the
// counter by 16, terminating when it drains. Because the loop consumes
// the whole region rather than just the segment list, R4 lands at
// SRH+8 + hdr_ext_len*8 — the next-header position — even when the SRH
// carries trailing TLVs (the extra region bytes are walked as opaque
// 16-byte chunks). This replaces the previous single bulk `pkt.advance`
// with standard P4 parser constructs; correctness for non-16-byte-
// aligned trailing TLVs is bounded by the segment stack capacity (8).
//
// The `segments` stack base falls out of the `consume_seg` state's
// layer-entry offset (= sizeof(srv6_h) = 8), so `srv6.segments[N].addr`
// and the any()/all() quantifiers read the same bytes as before. The
// runtime element count for those quantifiers comes from
// @kunai_stack_count (= last_entry + 1), independent of the walk's loop
// trip count, so queries stay scoped to the real segment list even when
// the walk extracts trailing-TLV bytes as extra chunks.
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
                    @kunai_stack_count[field=last_entry, offset=1]
                    out srv6_seg_h[8] segments) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        // Remaining region in BYTES = hdr_ext_len * 8 (hdr_ext_len is in
        // 8-byte units and already excludes the fixed 8-byte SRH). The
        // mask `& 0x0F` caps the count at 15*8 = 120 bytes so the
        // verifier sees a static upper bound (well-formed SRv6 frames
        // stay well under it); << 6 scales the masked value by 8 (scale
        // = 1 << (6-3)). Encoding the counter in bytes — and capping it
        // — keeps it consistent with the bulk-advance fallback codegen
        // takes when no srv6.segments field is queried: that path
        // advances R4 by exactly this masked byte count, matching the
        // previous single bulk pkt.advance.
        pc.set(((bit<8>)(hdr.hdr_ext_len & 0x0F)) << 6);
        // routing_type 4 (KUNAI_SRV6_ROUTING_TYPE) identifies SRH
        // (RFC 8754 Section 2). Older Type-0 source-routing variants are
        // deprecated and out of scope, so every other routing_type is
        // rejected.
        transition select(hdr.routing_type) {
            KUNAI_SRV6_ROUTING_TYPE: walk;
            default:                 reject;
        }
    }
    // Counter-driven walk over the variable region. Each iteration
    // extracts one 16-byte segment into the segments stack and
    // decrements the byte counter by 16; when the counter drains, R4
    // has reached the next header (past segments + any trailing TLVs).
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume_seg;
        }
    }
    state consume_seg {
        pkt.extract(segments.next);
        pc.decrement(16);
        transition walk;
    }
}
