// TCP header (no options parsing; variable options consumed via data_offset).
header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

// Dual declaration: tcp appears under ipv4.protocol=6 or ipv6.next_header=6.
const bit<8> TCP_IPV4_PROTOCOL    = 6;
const bit<8> TCP_IPV6_NEXT_HEADER = 6;

// SRv6 dispatches to TCP via the SRH next_header byte (offset 0 of
// srv6_h). The numeric value matches IPv6's protocol assignment.
const bit<8> TCP_SRV6_NEXT_HEADER = 6;

// TCP options carry a variable trailer past the 20-byte fixed
// header: total header length is data_offset × 4 bytes (data_offset
// is the upper nibble of byte 12). Codegen reads the byte at offset
// 12, masks with 0xF0, shifts right 4, multiplies by 4, then
// subtracts the 20-byte minimum to obtain the options length.
// data_offset < 5 falls below MinimumTotal=20 and rejects the
// packet.
const bit<8> TCP_VAREXT_LEN_BYTE_OFFSET = 12;
const bit<8> TCP_VAREXT_LEN_MASK        = 0xF0;
const bit<8> TCP_VAREXT_LEN_SHIFT       = 4;
const bit<8> TCP_VAREXT_LEN_SCALE       = 4;
const bit<8> TCP_VAREXT_LEN_BASE        = 20;

parser TcpFragment(packet_in pkt, out tcp_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
