// GTP-U v1 (3GPP TS 29.281): UDP-encapsulated tunnel protocol used by
// 5G UPF and earlier mobile cores. The MVP models the common form:
// fixed 8-byte header, optional 4-byte block if any of E/S/PN is set,
// and a self-referencing extension header chain terminated by
// next_ext==0.

header gtp_h {
    bit<3>  version;
    bit<1>  pt;
    bit<1>  reserved;
    bit<1>  e;
    bit<1>  s;
    bit<1>  pn;
    bit<8>  msg_type;
    bit<16> length;
    bit<32> teid;
}

// Present when any of E/S/PN is set.
header gtp_opt_h {
    bit<16> seq;
    bit<8>  npdu;
    bit<8>  next_ext;
}

// Extension header; length in 4-byte units. Chain terminates at next_ext==0.
header gtp_ext_h {
    bit<8>  ext_length;
    bit<16> ext_type;
    bit<8>  next_ext;
}

// Dispatch from UDP: GTP-U uses destination port 2152.
const bit<16> GTP_UDP_DPORT = 2152;

// Cap iterations of the parse_ext self-loop so the verifier accepts
// the bpf_loop call. Real frames rarely carry more than 1-2 ext
// headers; 8 leaves headroom without exploding the instruction budget.
const bit<8> GTP_MAX_DEPTH = 8;

parser GtpParser(packet_in pkt,
                   out gtp_h gtp,
                   out gtp_opt_h opt,
                   out gtp_ext_h[8] exts) {
    state start {
        pkt.extract(gtp);
        transition select(gtp.e, gtp.s, gtp.pn) {
            (0, 0, 0): accept;
            default:   parse_opt;
        }
    }
    state parse_opt {
        pkt.extract(opt);
        transition select(opt.next_ext) {
            0: accept;
            _: parse_ext;
        }
    }
    state parse_ext {
        pkt.extract(exts.next);
        transition select(exts.last.next_ext) {
            0: accept;
            _: parse_ext;
        }
    }
}
