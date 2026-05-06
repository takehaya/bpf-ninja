// VXLAN (RFC 7348). 8-byte header carrying a 24-bit VNI; payload is
// always an Ethernet frame.
header vxlan_h {
    bit<8>  flags;
    bit<24> reserved1;
    bit<24> vni;
    bit<8>  reserved2;
}

// Dispatch from UDP via the IANA-assigned destination port.
const bit<16> VXLAN_UDP_DPORT = 4789;

parser VxlanParser(packet_in pkt, out vxlan_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
