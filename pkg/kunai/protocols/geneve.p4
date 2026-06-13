// Geneve (RFC 8926). The fixed 8-byte tunnel header is followed by an
// options section whose length is opt_len 4-byte words (excluding the
// fixed header). The parser skips that section so the inner payload
// resolves at the correct offset regardless of opt_len; individual
// option TLVs are not exposed as fields (no filter inspects them).
header geneve_h {
    bit<2>  version;
    bit<6>  opt_len;
    bit<8>  flags;
    bit<16> protocol_type;
    bit<24> vni;
    bit<8>  reserved;
}

// Dispatch from UDP via the IANA-assigned destination port.
const bit<16> GENEVE_UDP_DPORT = 6081;

parser GeneveParser(packet_in pkt, out geneve_h hdr) {
    state start {
        pkt.extract(hdr);
        transition skip_options;
    }
    // Variable trail: skip the (opt_len * 4)-byte options section
    // (RFC 8926 — opt_len counts 4-byte words and excludes the fixed
    // 8-byte header). Mask 0x3F caps the runtime advance at 252 bytes
    // so the verifier sees a static upper bound; opt_len is 6 bits so
    // the mask preserves its full range. F9-style filters only need the
    // inner payload offset, not the option contents. Same field-driven
    // advance idiom as srv6.p4's segment-list skip.
    state skip_options {
        pkt.advance(((bit<32>)(hdr.opt_len & 0x3F)) << 5);
        transition accept;
    }
}
