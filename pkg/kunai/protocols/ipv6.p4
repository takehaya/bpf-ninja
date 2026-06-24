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
// is `hdr_ext_len * 8` more bytes consumed by @kunai_variable_tail.
// Fragment (44) is the lone exception with hdr_ext_len always 0,
// keeping the fixed-formula valid. Mask 0x03 caps the runtime advance
// at 24 bytes per iteration so the verifier sees a static upper
// bound; well-formed HBH/Fragment/DestOpt stay under that cap.
// @kunai_writeback keeps ipv6.next_header in sync with the chain
// tail's next_header so the next layer's dispatch (tcp/udp/icmp6/...)
// sees the inner protocol rather than the first ext type.
@kunai_variable_tail[len_field=hdr_ext_len, scale=8, mask=0x03]
@kunai_writeback[source=next_header, parent=ipv6.next_header]
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

// IPv6-in-IPv6 tunneling (RFC 2473): the outer ipv6's next_header is
// 41 (IANA "IPv6"). Lets users write `eth/ipv6/ipv6/tcp` for v6-in-v6
// tunnels without resorting to a chain quantifier — each ipv6 layer
// runs its own parser machine, so ext headers on either layer are
// handled correctly.
const bit<8>  IPV6_IPV6_NEXT_HEADER = 41;

// IPv6 extension-header next_header values (IANA protocol numbers)
// that the parser chains into ext parsing. KUNAI_ marks them as
// value-only consts: the loader folds each into the matching select
// arm and assigns no inter-layer dispatch role (these dispatch to the
// same protocol's own ext walk, not to a child layer).
const bit<8>  KUNAI_IPV6_NH_HOP_BY_HOP = 0;  // Hop-by-Hop Options (RFC 8200)
const bit<8>  KUNAI_IPV6_NH_FRAGMENT   = 44; // Fragment (RFC 8200)
const bit<8>  KUNAI_IPV6_NH_DEST_OPTS  = 60; // Destination Options (RFC 8200)

// Cap the ext-header chain depth. Real frames almost never carry
// more than 2 ext headers (HBH + DestOpt is the typical maximum);
// the verifier needs the loop times the per-iteration max growth
// (8 fixed + ≤24 variable per iter from @kunai_variable_tail on
// ipv6_ext_h above) to stay within the 256-byte scratch buffer, so
// 4 iterations is the conservative ceiling.
const bit<8> IPV6_MAX_DEPTH = 4;

// Self-validating parser: the start state's tuple-select rejects on
// version != 6, replacing the per-parent SANITY const family. Resolver
// allows ipv6 under any parent (e.g. MPLS, GTP-U) via
// DispatchSelfValidating; the runtime version reject happens here.
// next_header dispatching is unchanged from the pre-migration shape:
// 0 / 44 / 60 walk into ext-chain parsing, anything else accepts the
// primary header and lets the outer chain pick the next protocol.
parser IPv6Parser(packet_in pkt,
                    out ipv6_h hdr,
                    out ipv6_ext_h[8] exts) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version, hdr.next_header) {
            (6, KUNAI_IPV6_NH_HOP_BY_HOP): parse_ext;   // Hop-by-Hop options
            (6, KUNAI_IPV6_NH_FRAGMENT):   parse_ext;   // Fragment
            (6, KUNAI_IPV6_NH_DEST_OPTS):  parse_ext;   // Destination options
            (6, _):                        accept;      // any other inner protocol
            default:                       reject;      // version != 6
        }
    }
    state parse_ext {
        pkt.extract(exts.next);
        transition select(exts.last.next_header) {
            KUNAI_IPV6_NH_HOP_BY_HOP: parse_ext;
            KUNAI_IPV6_NH_FRAGMENT:   parse_ext;
            KUNAI_IPV6_NH_DEST_OPTS:  parse_ext;
            default:                  accept;
        }
    }
}
