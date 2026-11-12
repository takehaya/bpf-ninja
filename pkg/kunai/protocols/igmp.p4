// IGMP (RFC 2236 v2, RFC 9776 v3). Every message starts with the same
// 8 bytes: type, max response code, checksum, and a 32-bit word that
// is the group address in queries, v2 reports and leaves:
//
//   0x11 membership query (v1/v2/v3), 0x12 v1 report, 0x16 v2 report,
//   0x17 v2 leave group, 0x22 v3 membership report.
//
// In a v3 report the second 8 bits are Flags (RFC 9776 section 4.2.3),
// read through `igmp.max_resp_code`, and the 32-bit word is Reserved
// (16) + Number of Group Records (16), read through `igmp.group`.
// Group records are not parsed.
//
// The v3 query extension (S, QRV, QQIC, source list) is not modelled:
// a v3 query has the same type (0x11) as a v2 query and is told apart
// only by its length, which the parser cannot test (spec DECISIONS
// D-045). Nothing is carried inside IGMP, so igmp is a terminal layer.
header igmp_h {
    bit<8>  type;
    bit<8>  max_resp_code;
    bit<16> checksum;
    bit<32> group;
}

const bit<8> KUNAI_IGMP_IPV4_PROTOCOL = 2;

parser IgmpParser(packet_in pkt, out igmp_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
