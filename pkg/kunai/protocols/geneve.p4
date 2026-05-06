// Geneve (RFC 8926). MVP models the fixed 8-byte header; option TLVs
// signalled by opt_len are not parsed today, so filters whose target
// packets carry options will read the wrong inner payload offset. A
// later commit can extend the parser with a variable-length option
// section.
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
        transition accept;
    }
}
