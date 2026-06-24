// UDP header.
header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> length;
    bit<16> checksum;
}

// Dual declaration: udp appears under ipv4.protocol=17 or ipv6.next_header=17.
const bit<8> KUNAI_UDP_IPV4_PROTOCOL    = 17;
const bit<8> KUNAI_UDP_IPV6_NEXT_HEADER = 17;

// SRv6 dispatches to UDP via SRH.next_header.
const bit<8> KUNAI_UDP_SRV6_NEXT_HEADER = 17;

parser UdpParser(packet_in pkt, out udp_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
