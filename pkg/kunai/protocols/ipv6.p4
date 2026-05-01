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

// Under GRE, dispatch on the EtherType-shaped protocol_type field.
const bit<16> IPV6_GRE_PROTOCOL_TYPE = 0x86DD;

// Cap the ext-header chain depth. Real frames almost never carry
// more than 2 ext headers (HBH + DestOpt is the typical maximum);
// the verifier needs the loop times the per-iteration max growth
// (8 fixed + ≤24 variable per iter, see knownVariableTails) to stay
// within the 256-byte scratch buffer, so 4 iterations is the
// conservative ceiling.
const bit<8> IPV6_MAX_DEPTH = 4;

// Self-validating parser: the start state's tuple-select rejects on
// version != 6, replacing the per-parent SANITY const family. Resolver
// allows ipv6 under any parent (e.g. MPLS, GTP-U) via
// DispatchSelfValidating; the runtime version reject happens here.
// next_header dispatching is unchanged from the pre-migration shape:
// 0 / 44 / 60 walk into ext-chain parsing, anything else accepts the
// primary header and lets the outer chain pick the next protocol.
parser IPv6Fragment(packet_in pkt,
                    out ipv6_h hdr,
                    out ipv6_ext_h[8] exts) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version, hdr.next_header) {
            (6,  0): parse_ext;   // Hop-by-Hop options
            (6, 44): parse_ext;   // Fragment
            (6, 60): parse_ext;   // Destination options
            (6,  _): accept;      // any other inner protocol
            default: reject;      // version != 6
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
