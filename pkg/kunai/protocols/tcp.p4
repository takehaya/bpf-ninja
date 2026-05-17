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
// and terminates on EOL or by exhausting the bpf_loop iteration cap
// (defaults to 8; see the MAX_DEPTH note near the parser block).
// Predicate codegen reads each option's recorded offset directly
// without re-walking.
//
// Caveat: EOL (kind=0) accepts immediately, so R4 stops at the EOL
// byte rather than draining to the data_offset-bounded trailer end.
// Harmless today because TCP is a terminal layer (no `tcp/<inner>`
// chain reads R4 past the trailer); future inner-protocol support
// would need a ParserCounter-driven walk that drains residue past
// EOL.
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

// TCP options trailer is at most 40 bytes (data_offset = 15 → 60 byte
// header → 40 byte trailer). The smallest option is 1 byte (NOP / EOL),
// so the option-walk loop would need up to 40 iterations to drain a
// worst-case all-NOP trailer. The vocab loader's MAX_DEPTH path
// recognises `<SELF>_MAX_DEPTH = N` (default 8 when omitted, hard cap
// 64 — see vocab/loader.go classifyConsts). We currently leave it
// unset, so codegen uses the default 8-iteration cap — enough to drain
// every well-formed TCP option mix observed in production (MSS / WS /
// SACK_PERM / TS = 4 options at most, terminating well before iter 8).
// A previous declaration named `TCP_PARSER_MAX_DEPTH` was silently
// misclassified by the loader as a `<SELF>_<PARENT>_<FIELD>` dispatch
// const with a phantom parent named "parser"; the intended 32-iter
// cap was never applied. Removed to eliminate the source/impl drift.
// If a higher iteration cap is needed, declare `TCP_MAX_DEPTH = N` and
// verify on every supported kernel (older kernels' 1M-insn callback
// budget can blow up past 8 iterations — see dsl-followups.md "TCP
// malformed unknown-option short length").

parser TcpParser(packet_in pkt,
                   out tcp_h                hdr,
                   out tcp_opt_mss_h        mss,
                   out tcp_opt_ws_h         ws,
                   out tcp_opt_sack_perm_h  sack_perm,
                   out tcp_opt_sack_h       sack,
                   out tcp_sack_block_h[4]  blocks,
                   out tcp_opt_ts_h         ts) {
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
            5:       parse_sack;
            8:       parse_ts;
            default: parse_unknown_opt;
        }
    }
    state parse_nop          { pkt.advance(8);         transition parse_options; }
    state parse_mss          { pkt.extract(mss);       transition parse_options; }
    state parse_ws           { pkt.extract(ws);        transition parse_options; }
    state parse_sack_perm    { pkt.extract(sack_perm); transition parse_options; }
    state parse_ts           { pkt.extract(ts);        transition parse_options; }
    state parse_sack {
        // Drain the entire option by reading the length byte via
        // pre-advance lookahead and bumping R3 by `length` bytes,
        // landing at the next option's kind. The slot prelude has
        // already recorded R3-at-entry as the SACK base before
        // dispatch, so DSL queries reach kind / length / blocks at
        // slot+0 / +1 / +2 without an explicit extract. The
        // dispatched-but-not-extracted shape avoids the JLT+Sub
        // combo an aux-targeted `(sack.length - 2)` advance would
        // emit — that extra branch trips the verifier on kernels
        // 6.1 / 6.6 with het-size alts in the chain.
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
        pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
        transition parse_options;
    }
}
