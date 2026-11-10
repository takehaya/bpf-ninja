// PFCP (3GPP TS 29.244 §7.2.2): the N4/Sxa/Sxb control protocol
// between the 5G SMF and UPF (and the EPC CP/UP functions). Only the
// message header is modelled; the information elements that follow it
// are not parsed, so pfcp is a terminal layer.
//
// The first 4 octets are common to every message. The S flag selects
// one of two header tails:
//
//   S = 0 (node related messages): sequence number (24) + spare (8)
//   S = 1 (session related messages): SEID (64) + sequence number (24)
//         + message priority (4, meaningful when MP = 1) + spare (4)
//
// Both tails are aux headers gated on s: `pfcp.node.seq` and
// `pfcp.sess.seid` / `pfcp.sess.seq` / `pfcp.sess.priority`.
header pfcp_h {
    bit<3>  version;
    bit<2>  spare;
    bit<1>  fo;
    bit<1>  mp;
    bit<1>  s;
    bit<8>  msg_type;
    bit<16> length;
}

header pfcp_node_h {
    bit<24> seq;
    bit<8>  spare;
}

header pfcp_sess_h {
    bit<64> seid;
    bit<24> seq;
    bit<4>  priority;
    bit<4>  spare;
}

// Dispatch from UDP via the IANA-assigned port 8805. A request goes to
// 8805; a response goes back to the requester's source port, which is
// 8805 in practice but is not fixed by TS 29.244, so only the
// destination port is used (as for GTP-U).
const bit<16> KUNAI_PFCP_UDP_DPORT = 8805;

parser PfcpParser(packet_in pkt,
                  out pfcp_h      hdr,
                  out pfcp_node_h node,
                  out pfcp_sess_h sess) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.s) {
            0:       parse_node;
            default: parse_sess;
        }
    }
    state parse_node {
        pkt.extract(node);
        transition accept;
    }
    state parse_sess {
        pkt.extract(sess);
        transition accept;
    }
}
