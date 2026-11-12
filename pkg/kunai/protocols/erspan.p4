// ERSPAN type II and type III over GRE (draft-foschiano-erspan).
// GRE's sequence-number bit distinguishes type II from type I, which
// has no ERSPAN header and is not modelled. Only Ethernet payloads are
// accepted, so `eth/ipv4/gre/erspan/eth/...` reaches the original traffic.
//
// Both types start with the same 4 bytes (version, VLAN, CoS,
// encapsulation / BSO bits, truncation bit, session id), the primary
// header here. The version selects the rest:
//
//   version 1 (type II):  reserved (12) + port index (20), the aux
//                         `erspan.v2`.
//   version 2 (type III): timestamp (32), SGT (16), P, FT, HW ID,
//                         D, Gra, O, the aux `erspan.v3`. When O is
//                         set, an 8-byte platform-specific subheader
//                         follows; it is skipped, not extracted
//                         (spec DECISIONS D-044).
//
// Other versions reject. The field called `en` in type II is the BSO
// (bad/short/oversized) field in type III; the bits sit in the same
// place.
header erspan_h {
    bit<4>  version;
    bit<12> vlan;
    bit<3>  cos;
    bit<2>  en;
    bit<1>  t;
    bit<10> session_id;
}

header erspan_v2_h {
    bit<12> reserved;
    bit<20> index;
}

header erspan_v3_h {
    bit<32> timestamp;
    bit<16> sgt;
    bit<1>  p;
    bit<5>  ft;
    bit<6>  hw_id;
    bit<1>  d;
    bit<2>  gra;
    bit<1>  o;
}

// GRE protocol type 0x88BE carries type II and 0x22EB type III. The
// _ALT_ suffix folds the second value into the same dispatch edge
// (vocab/loader.go mergeAltDispatchConsts).
@kunai_dispatch_require[field=flags, mask=0x1000]
const bit<16> KUNAI_ERSPAN_GRE_PROTOCOL_TYPE = 0x88BE;
const bit<16> KUNAI_ERSPAN_GRE_PROTOCOL_TYPE_ALT_TYPE3 = 0x22EB;

// Value-only select-match consts (parent token VERSION is not a
// protocol, so no KUNAI_ prefix).
const bit<4> ERSPAN_VERSION_TYPE2 = 1;
const bit<4> ERSPAN_VERSION_TYPE3 = 2;

parser ErspanParser(packet_in pkt,
                    out erspan_h    hdr,
                    out erspan_v2_h v2,
                    out erspan_v3_h v3) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version) {
            ERSPAN_VERSION_TYPE2: parse_v2;
            ERSPAN_VERSION_TYPE3: parse_v3;
            default:              reject;
        }
    }
    state parse_v2 {
        pkt.extract(v2);
        transition accept;
    }
    state parse_v3 {
        pkt.extract(v3);
        transition select(v3.ft) {
            0:       check_o;
            default: reject;
        }
    }
    state check_o {
        transition select(v3.o) {
            0:       accept;
            default: skip_platform;
        }
    }
    state skip_platform {
        pkt.advance(64);
        transition accept;
    }
}
