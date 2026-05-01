// SRv6: IPv6 Segment Routing Header (RFC 8754).
//
// SRH is an IPv6 Routing extension header (next_header=43 in IPv6,
// routing_type=4 in SRH itself). Total wire size = 8 + hdr_ext_len*8
// — codegen handles the variable trail uniformly via the
// knownVariableTails table; segment entries (16 bytes each) and any
// trailing TLVs ride inside the variable region as opaque bytes.
//
// `segments` is declared as an aux header stack so the resolver can
// expose `srv6.segments[N].addr` to predicate / where codegen. The
// parser does NOT push entries to this stack: the variable trail
// handler in parser_machine codegen advances R4 past all segments in
// one statically-bounded skip, and segment-N reads use that base
// offset (= primary header size). Stack capacity 8 caps verifier
// loop iterations identically to gtp.exts / ipv6.exts.
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

parser SRv6Fragment(packet_in pkt,
                    out srv6_h        hdr,
                    out srv6_seg_h[8] segments) {
    state start {
        pkt.extract(hdr);
        // routing_type 4 identifies SRH (RFC 8754 Section 2). Older Type-0
        // source-routing variants are deprecated and out of scope —
        // p4lite's match grammar only accepts integer literals so the
        // value is inlined here.
        transition select(hdr.routing_type) {
            4:       accept;
            default: reject;
        }
    }
}
