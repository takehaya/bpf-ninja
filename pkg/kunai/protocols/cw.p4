// MPLS Pseudowire Control Word (RFC 4385). A 4-byte optional marker
// that precedes the emulated payload inside an MPLS PW. There is no
// identifying field to dispatch on — an EoMPLS deployment either
// inserts a CW or does not — so the child relationship is expressed
// with NO_CHECK and the user opts in by writing the DSL with `cw?`.
header cw_h {
    bit<4>  first_nibble;   // typically 0 on RFC 4385 pseudowires
    bit<4>  flags;
    bit<8>  length;
    bit<16> sequence;
}

const bool CW_MPLS_NO_CHECK = true;

parser CwParser(packet_in pkt, out cw_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
