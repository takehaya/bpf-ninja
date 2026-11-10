// SCTP (RFC 9260). The 12-byte common header is followed by one or
// more chunks, each starting with a 4-byte chunk header (type, flags,
// length). The header of the first chunk is an aux, `sctp.chunk`;
// RFC 9260 §3 requires at least one chunk, so it is always extracted
// and a packet that ends with the common header is rejected.
//
// Only the first chunk header is modelled. Later chunks would need a
// walk that skips each chunk by its 16-bit length rounded up to a
// multiple of 4, and p4lite advances by a single length byte only
// (spec DECISIONS D-041). The chunk payload (DATA's TSN, INIT's
// initiate tag, ...) is not modelled either, so sctp is a terminal
// layer.
header sctp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> vtag;
    bit<32> checksum;
}

header sctp_chunk_h {
    bit<8>  type;
    bit<8>  flags;
    bit<16> length;
}

// IANA protocol number 132, under IPv4, IPv6 and the SRH (as tcp/udp).
const bit<8> KUNAI_SCTP_IPV4_PROTOCOL    = 132;
const bit<8> KUNAI_SCTP_IPV6_NEXT_HEADER = 132;
const bit<8> KUNAI_SCTP_SRV6_NEXT_HEADER = 132;

parser SctpParser(packet_in pkt,
                  out sctp_h       hdr,
                  out sctp_chunk_h chunk) {
    state start {
        pkt.extract(hdr);
        transition parse_chunk;
    }
    state parse_chunk {
        pkt.extract(chunk);
        transition accept;
    }
}
