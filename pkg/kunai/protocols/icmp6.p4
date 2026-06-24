// ICMPv6 header. MVP: fixed 4-byte common header; NDP option parsing
// and echo/redirect payloads are deferred.
header icmp6_h {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

const bit<8> KUNAI_ICMP6_IPV6_NEXT_HEADER = 58;

parser Icmp6Parser(packet_in pkt, out icmp6_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
