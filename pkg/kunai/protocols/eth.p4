// Ethernet II (DIX) header.
header eth_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ethertype;
}

// Dispatch from a parent is identified by <SELF>_<PARENT>_<FIELD>.
// When eth has no identifying field in the parent (L2VPN-over-MPLS or
// Ethernet-over-PWE3 Control Word, VXLAN, Geneve), we declare the
// boundary as NO_CHECK and rely on the user's explicit ordering in
// the one-liner DSL.
const bool ETH_MPLS_NO_CHECK   = true;
const bool ETH_CW_NO_CHECK     = true;
const bool ETH_VXLAN_NO_CHECK  = true;
const bool ETH_GENEVE_NO_CHECK = true;

parser EthFragment(packet_in pkt, out eth_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
