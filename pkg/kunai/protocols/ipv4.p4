// IPv4 base header (options are not modelled; ihl >5 is left to codegen).
header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_length;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

// Ethernet/VLAN/QinQ select ipv4 via the ethertype.
const bit<16> IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> IPV4_VLAN_ETHERTYPE = 0x0800;
const bit<16> IPV4_QINQ_ETHERTYPE = 0x0800;

// SRv6 transports IPv4-in-IPv6 (SRv6 → IPv4 inner): the SRH
// next_header byte uses IANA protocol number 4 (IPIP).
const bit<8>  IPV4_SRV6_NEXT_HEADER = 4;

// Under GRE, the protocol_type field carries the EtherType of the
// payload — IPv4 uses the well-known 0x0800.
const bit<16> IPV4_GRE_PROTOCOL_TYPE = 0x0800;

// IPv4 options carry a variable trailer past the 20-byte fixed
// header: total header length is IHL × 4 bytes (IHL is the lower
// nibble of byte 0). Codegen reads the byte at offset 0, masks with
// 0x0F, shifts right 0, multiplies by 4, then subtracts the 20-byte
// minimum to obtain the options length and advances R4 past it.
// IHL < 5 falls below MinimumTotal=20 and rejects the packet.
const bit<8> IPV4_HDRLEN_BYTE_OFFSET = 0;
const bit<8> IPV4_HDRLEN_MASK        = 0x0F;
const bit<8> IPV4_HDRLEN_SHIFT       = 0;
const bit<8> IPV4_HDRLEN_SCALE       = 4;
const bit<8> IPV4_HDRLEN_BASE        = 20;

// Self-validating parser: `transition select(hdr.version) { ... }`
// guarantees the first nibble is 4. When a parent layer has no Field
// dispatch (e.g. MPLS, GTP-U, VXLAN inner Ethernet), resolver allows
// the chain via DispatchSelfValidating and the runtime check happens
// here. The IHL trailing is still consumed by the HDRLEN_* family
// after the parser block accepts.
parser IPv4Fragment(packet_in pkt, out ipv4_h hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version) {
            4:       accept;
            default: reject;
        }
    }
}
