// TCP header; data_offset bounds the option region.
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
const bit<8> KUNAI_TCP_IPV4_PROTOCOL    = 6;
const bit<8> KUNAI_TCP_IPV6_NEXT_HEADER = 6;

// SRv6 dispatches to TCP via the SRH next_header byte (offset 0 of
// srv6_h). The numeric value matches IPv6's protocol assignment.
const bit<8> KUNAI_TCP_SRV6_NEXT_HEADER = 6;


// === TCP options (RFC 9293, IANA TCP Parameters) ===
//
// Options live in the variable trailer past the 20-byte fixed
// header. Each non-padding option is TLV-shaped: byte 0 = kind,
// byte 1 = length-in-bytes, then per-kind payload. Kind=0 (EOL)
// and kind=1 (NOP) are special: 1-byte total, no length byte.
//
// ParserCounter tracks the data_offset-bounded trailer. Each iteration
// consumes one option, and EOL or an exhausted counter ends the walk.
// Fixed-size options validate their length before continuing. Unknown
// options consume their complete declared length; short/non-progressing
// lengths and options crossing the region boundary are rejected.
//
// Each option's identity (kind value) and total wire size live in
// the parser block itself: the `transition select(...)` case label
// pins the kind, the `header tcp_opt_<name>_h` decl pins the size.
// Vocabulary need not repeat them as constants.

// MSS (kind=2, RFC 9293 §3.2.6.2): single 16-bit value.
header tcp_opt_mss_h {
    bit<8>  kind;
    bit<8>  length;
    bit<16> value;
}

// Window Scale (kind=3, RFC 7323 §2): single 8-bit shift.
header tcp_opt_ws_h {
    bit<8> kind;
    bit<8> length;
    bit<8> shift;
}

// SACK Permitted (kind=4, RFC 2018): negotiation flag, no payload.
header tcp_opt_sack_perm_h {
    bit<8> kind;
    bit<8> length;
}

// Timestamps (kind=8, RFC 7323 §3): tsval + tsecr (each 32-bit).
// Field names match the RFC's TSval / TSecr nomenclature so DSL
// references like `tcp.options.TS.tsval` cite the spec verbatim.
header tcp_opt_ts_h {
    bit<8>  kind;
    bit<8>  length;
    bit<32> tsval;
    bit<32> tsecr;
}

// SACK option fixed header (kind=5, RFC 2018 §3): only the kind +
// length pair. The {left, right} blocks live in the trailing
// variable region as a separate `tcp_sack_block_h[4]` stack — see
// the parser block + the loader's owner-bound stack resolver. This
// split lets DSL refer to the option's per-packet base via
// `tcp.options.SACK.kind` / `.length` while array predicates
// (`tcp.options.SACK.blocks[N].left`, quantifiers) reach the
// blocks through the owner-relative offset path.
header tcp_opt_sack_h {
    bit<8> kind;
    bit<8> length;
}

// One SACK block: a 32-bit left edge + 32-bit right edge of an
// out-of-order TCP byte range. Up to 4 blocks fit in a 40-byte
// option trailer (40 - 2 / 8 = 4.75 → 4).
header tcp_sack_block_h {
    bit<32> left;
    bit<32> right;
}

// A maximum-size header can contain 40 one-byte NOPs.
const bit<8> TCP_MAX_DEPTH = 40;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser TcpParser(packet_in pkt,
                   out tcp_h                hdr,
                   out tcp_opt_mss_h        mss,
                   out tcp_opt_ws_h         ws,
                   out tcp_opt_sack_perm_h  sack_perm,
                   out tcp_opt_sack_h       sack,
                   out tcp_sack_block_h[4]  blocks,
                   out tcp_opt_ts_h         ts) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set(((bit<8>)(hdr.data_offset - 5)) << 5);
        transition select(hdr.data_offset) {
            5: accept;
            default: parse_options;
        }
    }
    state parse_options {
        transition select(pc.is_zero(), pkt.lookahead<bit<8>>()) {
            (true, _): accept;
            (false, 0):       accept;       // EOL
            (false, 1):       parse_nop;
            (false, 2):       parse_mss;
            (false, 3):       parse_ws;
            (false, 4):       parse_sack_perm;
            (false, 5):       parse_sack;
            (false, 8):       parse_ts;
            (false, _): parse_unknown_opt;
        }
    }
    state parse_nop          { pkt.advance(8); pc.decrement(1);         transition parse_options; }
    state parse_mss          { pkt.extract(mss); pc.decrement(4);       transition select(mss.length) { 4: parse_options; default: reject; } }
    state parse_ws           { pkt.extract(ws); pc.decrement(3);        transition select(ws.length) { 3: parse_options; default: reject; } }
    state parse_sack_perm    { pkt.extract(sack_perm); pc.decrement(2); transition select(sack_perm.length) { 2: parse_options; default: reject; } }
    state parse_ts           { pkt.extract(ts); pc.decrement(10);        transition select(ts.length) { 10: parse_options; default: reject; } }
    state parse_sack {
        // The owner slot records the option start for SACK block queries.
        // Read the length before advancing the cursor.
        pc.decrement((bit<8>)pkt.lookahead<bit<16>>()[7:0]);
        pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
        transition parse_options;
    }
    state parse_unknown_opt {
        // Length byte sits at byte +1 of the unknown option (the kind
        // byte at byte 0 already failed dispatch). lookahead<bit<16>>()
        // peeks (kind, length) without advancing; [7:0] picks the
        // length byte (network MSB-first → byte 1 occupies the low 8
        // bits of bit<16>). length is the total option size in bytes,
        // including the kind+length pair.
        pc.decrement((bit<8>)pkt.lookahead<bit<16>>()[7:0]);
        pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
        transition parse_options;
    }
}
