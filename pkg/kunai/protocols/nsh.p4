// NSH (RFC 8300): Network Service Header for service function
// chaining. The primary header is the 4-byte base header plus the
// 4-byte service path header (SPI + SI). Context headers follow:
//
//   MD type 1: four fixed 4-byte context words, the aux `nsh.md1`
//              (`md1.ctx1` .. `md1.ctx4`).
//   MD type 2: variable-length context TLVs, skipped as a whole by the
//              length field (total NSH size in 4-byte words, 2 for the
//              base + service path headers). The TLVs are not read
//              (spec DECISIONS D-043).
//
// Any other MD type is rejected. The inner protocol follows the
// context headers and is named by next_proto (RFC 8300 §2.2:
// 1 = IPv4, 2 = IPv6, 3 = Ethernet, 5 = MPLS); those edges are
// declared in the child protocols' files.
header nsh_h {
    bit<2>  version;
    bit<1>  o;
    bit<1>  u1;
    bit<6>  ttl;
    bit<6>  length;
    bit<4>  u2;
    bit<4>  md_type;
    bit<8>  next_proto;
    bit<24> spi;
    bit<8>  si;
}

header nsh_md1_h {
    bit<32> ctx1;
    bit<32> ctx2;
    bit<32> ctx3;
    bit<32> ctx4;
}

// NSH is carried directly over Ethernet (EtherType 0x894F), under
// VLAN/QinQ with the same EtherType, and over GRE, whose protocol_type
// carries the payload EtherType.
const bit<16> KUNAI_NSH_ETH_ETHERTYPE     = 0x894F;
const bit<16> KUNAI_NSH_VLAN_ETHERTYPE    = 0x894F;
const bit<16> KUNAI_NSH_QINQ_ETHERTYPE    = 0x894F;
const bit<16> KUNAI_NSH_GRE_PROTOCOL_TYPE = 0x894F;

// Value-only select-match consts (parent token MD is not a protocol,
// so no KUNAI_ prefix).
const bit<4> NSH_MD_TYPE1 = 1;
const bit<4> NSH_MD_TYPE2 = 2;

parser NshParser(packet_in pkt,
                 out nsh_h     hdr,
                 out nsh_md1_h md1) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.md_type) {
            NSH_MD_TYPE1: parse_md1;
            NSH_MD_TYPE2: parse_md2;
            default:      reject;
        }
    }
    state parse_md1 {
        pkt.extract(md1);
        transition accept;
    }
    // length counts the whole NSH in 4-byte words; the base and service
    // path headers are the first 2. A length below 2 rejects.
    state parse_md2 {
        pkt.advance(((bit<32>)(hdr.length - 2)) << 5);
        transition accept;
    }
}
