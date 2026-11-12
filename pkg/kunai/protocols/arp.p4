// ARP (RFC 826) for IPv4 over Ethernet-style 48-bit hardware addresses:
// 28 bytes with 6-byte hardware and 4-byte protocol addresses.
//
// The field layout holds only when the address lengths are 6 and 4,
// so the start state rejects any other combination; ARP for other
// address sizes is out of scope (spec DECISIONS D-042). The hardware
// and protocol types are not checked: they do not change the layout
// (Ethernet = 1 and IEEE 802 = 6 both carry 6-byte addresses), and a
// 16-bit select key is not supported by codegen. Match IPv4 ARP with
// `arp[ptype == 0x0800]` when it matters.
// Nothing is carried inside ARP, so arp is a terminal layer.
header arp_h {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

// Ethernet/VLAN/QinQ select arp via the ethertype.
const bit<16> KUNAI_ARP_ETH_ETHERTYPE  = 0x0806;
const bit<16> KUNAI_ARP_VLAN_ETHERTYPE = 0x0806;
const bit<16> KUNAI_ARP_QINQ_ETHERTYPE = 0x0806;

parser ArpParser(packet_in pkt, out arp_h hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.hlen, hdr.plen) {
            (6, 4):  accept;
            default: reject;
        }
    }
}
