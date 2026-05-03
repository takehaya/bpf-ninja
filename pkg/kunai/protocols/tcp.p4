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


// === TCP options (RFC 9293, IANA TCP Parameters) ===
//
// Options live in the variable trailer past the 20-byte fixed
// header. Each non-padding option is TLV-shaped: byte 0 = kind,
// byte 1 = length-in-bytes, then per-kind payload. Kind=0 (EOL)
// and kind=1 (NOP) are special: 1-byte total, no length byte.
//
// The parser block walks the options as a state machine that
// dispatches on the next kind byte (peeked via lookahead), extracts
// known options, advances past unknown ones using the length byte,
// and terminates on EOL or by exhausting MAX_DEPTH iterations.
// Predicate codegen reads each option's recorded offset directly
// without re-walking.
//
// EOL kind = 0, NOP kind = 1, length byte at option-offset 1 — the
// loader's RFC-universal defaults match TCP's encoding so no
// TERMINATOR_KIND / PADDING_KIND / LENGTH_BYTE_OFF override is
// declared here.

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

// TCP options trailer is at most 40 bytes (data_offset = 15 → 60 byte
// header → 40 byte trailer). The smallest option is 1 byte (NOP / EOL),
// so the option-walk loop runs at most 32 iterations (= bpf_loop cap).
// Higher values exceed the verifier's per-callback iteration budget;
// 32 covers every well-formed TCP packet observed in the wild.
const bit<8> TCP_PARSER_MAX_DEPTH = 32;

parser TcpFragment(packet_in pkt,
                   out tcp_h               hdr,
                   out tcp_opt_mss_h       mss,
                   out tcp_opt_ws_h        ws,
                   out tcp_opt_sack_perm_h sack_perm,
                   out tcp_opt_ts_h        ts) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.data_offset) {
            5:       accept;
            default: parse_options;
        }
    }
    state parse_options {
        transition select(pkt.lookahead<bit<8>>()) {
            0:       accept;       // EOL
            1:       parse_nop;
            2:       parse_mss;
            3:       parse_ws;
            4:       parse_sack_perm;
            8:       parse_ts;
            default: parse_unknown_opt;
        }
    }
    state parse_nop          { pkt.advance(8);         transition parse_options; }
    state parse_mss          { pkt.extract(mss);       transition parse_options; }
    state parse_ws           { pkt.extract(ws);        transition parse_options; }
    state parse_sack_perm    { pkt.extract(sack_perm); transition parse_options; }
    state parse_ts           { pkt.extract(ts);        transition parse_options; }
    state parse_unknown_opt {
        // Length byte sits at byte +1 of the unknown option (the kind
        // byte at byte 0 already failed dispatch). lookahead<bit<16>>()
        // peeks (kind, length) without advancing; [7:0] picks the
        // length byte (network MSB-first → byte 1 occupies the low 8
        // bits of bit<16>). length is the total option size in bytes,
        // including the kind+length pair.
        pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
        transition parse_options;
    }
}
