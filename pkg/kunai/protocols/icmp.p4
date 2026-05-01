// ICMP (IPv4) header. MVP: fixed 4-byte common header; echo/redirect
// payloads are deferred.
header icmp_h {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

const bit<8> ICMP_IPV4_PROTOCOL = 1;

parser IcmpFragment(packet_in pkt, out icmp_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
