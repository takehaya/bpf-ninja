// IEEE 802.1Q VLAN tag. 16-bit TCI (PCP + DEI + VID) plus the inner
// ethertype that identifies the next protocol, for 4 bytes total.
header vlan_h {
    bit<16> tci;
    bit<16> ethertype;
}

// VLAN is carried inside Ethernet (or QinQ, below) via ethertype=0x8100.
const bit<16> VLAN_ETH_ETHERTYPE  = 0x8100;
const bit<16> VLAN_QINQ_ETHERTYPE = 0x8100;

// Self-stacked VLAN: an inner tag is marked by the outer VLAN's own
// ethertype being 0x8100. Required by chain codegen for `vlan{n,m}`
// / `vlan+`.
const bit<16> VLAN_VLAN_ETHERTYPE = 0x8100;

parser VlanParser(packet_in pkt, out vlan_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
