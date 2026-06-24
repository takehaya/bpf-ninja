// Ethernet II (DIX) header.
header eth_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ethertype;
}

// Dispatch from a parent is identified by KUNAI_<SELF>_<PARENT>_<FIELD>.
// When eth has no identifying field in the parent (L2VPN-over-MPLS or
// Ethernet-over-PWE3 Control Word, VXLAN, Geneve), we declare the
// boundary as KUNAI_<SELF>_<PARENT>_NO_CHECK and rely on the user's
// explicit ordering in the one-liner DSL. KUNAI_ marks these as
// inter-layer dispatch edges.
const bool KUNAI_ETH_MPLS_NO_CHECK   = true;
const bool KUNAI_ETH_CW_NO_CHECK     = true;
const bool KUNAI_ETH_VXLAN_NO_CHECK  = true;
const bool KUNAI_ETH_GENEVE_NO_CHECK = true;

parser EthParser(packet_in pkt, out eth_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
