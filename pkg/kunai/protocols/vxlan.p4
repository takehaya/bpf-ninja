// VXLAN (RFC 7348). 8-byte header carrying a 24-bit VNI; payload is
// always an Ethernet frame.
header vxlan_h {
    bit<8>  flags;
    bit<24> reserved1;
    bit<24> vni;
    bit<8>  reserved2;
}

// Dispatch from UDP via the IANA-assigned destination port, plus the
// Linux kernel's pre-IANA default 8472 that Cilium and flannel still
// ship as their VXLAN default. The _ALT suffix folds the second value
// into the same dispatch edge (vocab/loader.go mergeAltDispatchConsts).
const bit<16> KUNAI_VXLAN_UDP_DPORT = 4789;
const bit<16> KUNAI_VXLAN_UDP_DPORT_ALT = 8472;

parser VxlanParser(packet_in pkt, out vxlan_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
