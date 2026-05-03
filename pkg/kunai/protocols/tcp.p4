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
const bit<8> TCP_HDRLEN_BYTE_OFFSET = 12;
const bit<8> TCP_HDRLEN_MASK        = 0xF0;
const bit<8> TCP_HDRLEN_SHIFT       = 4;
const bit<8> TCP_HDRLEN_SCALE       = 4;
const bit<8> TCP_HDRLEN_BASE        = 20;

// === TCP options (RFC 9293, IANA TCP Parameters) ===
//
// Options live in the variable trailer past the 20-byte fixed
// header. Each non-padding option is TLV-shaped: byte 0 = kind,
// byte 1 = length-in-bytes, then per-kind payload. Kind=0 (EOL)
// and kind=1 (NOP) are special: 1-byte total, no length byte.
//
// The codegen walks the options once at TCP-layer entry, dispatches
// on kind, and records each named option's byte offset within the
// options area in scratch memory. Predicate codegen reads the
// recorded offset to load fields without walking again.
//
// Option-walk behaviour is anchored on three vocab const families:
//   - <PROTO>_OPT_TERMINATOR_KIND : kind value that ends the walk
//   - <PROTO>_OPT_PADDING_KIND    : kind value that advances 1 byte
//                                    (no length byte, no payload)
//   - <PROTO>_OPT_LENGTH_BYTE_OFF : byte position within an option
//                                    that holds total option length
const bit<8> TCP_OPT_TERMINATOR_KIND  = 0; // EOL
const bit<8> TCP_OPT_PADDING_KIND     = 1; // NOP
const bit<8> TCP_OPT_LENGTH_BYTE_OFF  = 1;

// MSS (kind=2, RFC 9293 §3.2.6.2): single 16-bit value.
header tcp_opt_mss_h {
    bit<8>  kind;
    bit<8>  length;
    bit<16> value;
}
const bit<8> TCP_OPT_MSS_KIND = 2;
const bit<8> TCP_OPT_MSS_SIZE = 4;

// Window Scale (kind=3, RFC 7323 §2): single 8-bit shift.
header tcp_opt_ws_h {
    bit<8> kind;
    bit<8> length;
    bit<8> shift;
}
const bit<8> TCP_OPT_WS_KIND = 3;
const bit<8> TCP_OPT_WS_SIZE = 3;

// SACK Permitted (kind=4, RFC 2018): negotiation flag, no payload.
header tcp_opt_sack_perm_h {
    bit<8> kind;
    bit<8> length;
}
const bit<8> TCP_OPT_SACK_PERM_KIND = 4;
const bit<8> TCP_OPT_SACK_PERM_SIZE = 2;

// Timestamps (kind=8, RFC 7323 §3): val + ecr (each 32-bit).
header tcp_opt_ts_h {
    bit<8>  kind;
    bit<8>  length;
    bit<32> val;
    bit<32> ecr;
}
const bit<8> TCP_OPT_TS_KIND = 8;
const bit<8> TCP_OPT_TS_SIZE = 10;

parser TcpFragment(packet_in pkt,
                   out tcp_h               hdr,
                   out tcp_opt_mss_h       mss,
                   out tcp_opt_ws_h        ws,
                   out tcp_opt_sack_perm_h sack_perm,
                   out tcp_opt_ts_h        ts) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
