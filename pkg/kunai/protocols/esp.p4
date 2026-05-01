// ESP (RFC 4303): IPsec Encapsulating Security Payload. The 8-byte
// fixed header (SPI + Sequence Number) is always plaintext, so we
// can match on it; everything past byte 8 is encrypted (or
// integrity-protected) and inaccessible without IKE state, so kunai
// treats ESP as a TERMINAL layer — chains may end on
// `eth/ipv4/esp` or `eth/ipv6/esp` but cannot dispatch into an
// inner protocol.
//
// Use case: ACL / capture for tunnel-mode ESP (`spi == 0x12345678`,
// `seq > N` etc.) — predicate work lands later when aux/primary
// fields wider than the L4 trail get first-class support.
header esp_h {
    bit<32> spi;
    bit<32> seq;
}

// IPv4 protocol number 50 / IPv6 next_header 50 (IANA assigned).
const bit<8> ESP_IPV4_PROTOCOL    = 50;
const bit<8> ESP_IPV6_NEXT_HEADER = 50;

parser EspFragment(packet_in pkt, out esp_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
