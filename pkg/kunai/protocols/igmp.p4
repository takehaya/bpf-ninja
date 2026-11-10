// IGMP (RFC 2236 v2, RFC 9776 v3). Every message starts with the same
// 8 bytes: type, max response code, checksum, and a 32-bit word that
// is the group address in queries, v2 reports and leaves:
//
//   0x11 membership query (v1/v2/v3), 0x12 v1 report, 0x16 v2 report,
//   0x17 v2 leave group, 0x22 v3 membership report.
//
// In a v3 report the second 8 bits are reserved and the 32-bit word is
// reserved (16) + number of group records (16), so `igmp.group` reads
// those bits there. The first group record header of a v3 report
// (record type, aux data length, number of sources, multicast address)
// is the aux `igmp.record`, extracted only for type 0x22.
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

header igmp_record_h {
    bit<8>  record_type;
    bit<8>  aux_len;
    bit<16> num_sources;
    bit<32> mcast;
}

const bit<8> KUNAI_IGMP_IPV4_PROTOCOL = 2;

// Value-only select-match const (parent token REPORT is not a
// protocol, so no KUNAI_ prefix).
const bit<8> IGMP_V3_REPORT = 0x22;

parser IgmpParser(packet_in pkt,
                  out igmp_h        hdr,
                  out igmp_record_h record) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.type) {
            IGMP_V3_REPORT: parse_record;
            default:        accept;
        }
    }
    state parse_record {
        pkt.extract(record);
        transition accept;
    }
}
