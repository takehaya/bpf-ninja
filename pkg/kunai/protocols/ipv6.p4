// IPv6 base header.
header ipv6_h {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_length;
    bit<8>   next_header;
    bit<8>   hop_limit;
    bit<128> src;
    bit<128> dst;
}

// Extension header (RFC 8200). The first 8 bytes of every chained
// IPv6 ext header share this fixed shape; the variable-length tail
// is `hdr_ext_len * 8` more bytes (codegen handles that advance).
// Fragment (44) is the lone exception with hdr_ext_len always 0,
// keeping the fixed-formula valid.
header ipv6_ext_h {
    bit<8>  next_header;
    bit<8>  hdr_ext_len;
    bit<48> _opts;
}

// Ethernet/VLAN/QinQ select ipv6 via the ethertype.
const bit<16> IPV6_ETH_ETHERTYPE  = 0x86DD;
const bit<16> IPV6_VLAN_ETHERTYPE = 0x86DD;
const bit<16> IPV6_QINQ_ETHERTYPE = 0x86DD;

// Under an MPLS stack or a GTP-U tunnel, check that the first nibble
// of the payload is 6.
const bit<4>  IPV6_MPLS_SANITY_NIBBLE = 6;
const bit<4>  IPV6_GTP_SANITY_NIBBLE  = 6;

// Under GRE, dispatch on the EtherType-shaped protocol_type field.
const bit<16> IPV6_GRE_PROTOCOL_TYPE = 0x86DD;

// Cap the ext-header chain depth. Real frames almost never carry
// more than 2 ext headers (HBH + DestOpt is the typical maximum);
// the verifier needs the loop times the per-iteration max growth
// (8 fixed + ≤24 variable per iter, see knownVariableTails) to stay
// within the 256-byte scratch buffer, so 4 iterations is the
// conservative ceiling.
const bit<8> IPV6_MAX_DEPTH = 4;

parser IPv6Fragment(packet_in pkt,
                    out ipv6_h hdr,
                    out ipv6_ext_h[8] exts) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.next_header) {
            0:  parse_ext;   // Hop-by-Hop options
            44: parse_ext;   // Fragment
            60: parse_ext;   // Destination options
            default: accept;
        }
    }
    state parse_ext {
        pkt.extract(exts.next);
        transition select(exts.last.next_header) {
            0:  parse_ext;
            44: parse_ext;
            60: parse_ext;
            default: accept;
        }
    }
}
