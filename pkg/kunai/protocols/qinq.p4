// IEEE 802.1ad Service VLAN (Q-in-Q). Same 4-byte shape as vlan_h; the
// distinguishing ethertype is 0x88A8 rather than 0x8100.
header qinq_h {
    bit<16> tci;
    bit<16> ethertype;
}

// QinQ is carried directly inside Ethernet.
const bit<16> KUNAI_QINQ_ETH_ETHERTYPE = 0x88A8;

parser QinqParser(packet_in pkt, out qinq_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
