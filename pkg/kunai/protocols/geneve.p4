// Geneve (RFC 8926). The fixed 8-byte tunnel header is followed by an
// options section whose length is opt_len 4-byte words (excluding the
// fixed header). Chains that only need the inner payload (e.g.
// eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp) bulk-advance past the
// options; filters that read geneve.options.<NAME> walk the TLVs.
header geneve_h {
    bit<2>  version;
    bit<6>  opt_len;
    bit<8>  flags;
    bit<16> protocol_type;
    bit<24> vni;
    bit<8>  reserved;
}

// Dispatch from UDP via the IANA-assigned destination port.
const bit<16> GENEVE_UDP_DPORT = 6081;

// Cap the option-walk bpf_loop iterations. Real Geneve frames carry a
// handful of options (AWS GWLB uses 3; OVN uses 1), so a small bound
// keeps the verifier's callback state-exploration in budget.
const bit<8> GENEVE_MAX_DEPTH = 4;

// Each option is a TLV: option_class(16) + type(8) + R(3)+opt_data_len(5),
// then opt_data_len 4-byte words of value. The walk dispatches on the
// 24-bit class+type discriminator. Two widely-deployed option classes
// are exposed below.

// OVN (IANA Geneve option class 0x0102), type 0x80: logical ingress /
// egress port metadata used by OVN (the OpenStack Neutron default
// backend and OVN-Kubernetes). The 32-bit value packs rsv(1) +
// ingress(15) + egress(16); egress is byte-aligned and reachable as
// geneve.options.OVN.egress_port. ingress straddles a byte boundary
// (bit offset 1) so it is not exposed as a filter field.
header geneve_opt_ovn_h {
    bit<16> option_class;
    bit<8>  type;
    bit<8>  flags_len;
    bit<1>  rsv;
    bit<15> ingress_port;
    bit<16> egress_port;
}

// AWS Gateway Load Balancer (IANA Geneve option class 0x0108), type 3:
// the 32-bit flow cookie an appliance echoes back to keep a flow
// pinned, reachable as geneve.options.GWLB.flow_cookie. (Type 1, the
// 64-bit GWLBE/VPCE endpoint id, is also in this class; filtering a
// 64-bit option field needs a 64-bit immediate compare — future work.)
header geneve_opt_gwlb_h {
    bit<16> option_class;
    bit<8>  type;
    bit<8>  flags_len;
    bit<32> flow_cookie;
}

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

// Options walk shape (Mechanism 8 in dsl-internals.md §6.5, mirrors
// ipv4.p4's IHL-driven walk): ParserCounter pc records the remaining
// option bytes after the fixed 8-byte header (opt_len * 4). The walk
// state's 2-key tuple-select dispatches on (pc.is_zero(), 24-bit
// class+type): when the counter exhausts, accept; otherwise route to
// the matching sibling extract state, decrement by the option's byte
// size, and loop. An unknown class+type rejects (skip-by-length with a
// variable counter decrement is future work, as in ipv4.p4).
//
// Both modeled options are fixed-size (opt_data_len = 1, i.e. an 8-byte
// TLV), so the sibling decrements pc by a constant 8. A packet that
// reuses one of these class+type values with a different opt_data_len
// desyncs R4/pc from the real TLV size; the walk then reads trailing
// bytes as a discriminator and falls toward the reject arm. Validating
// opt_data_len for these options, or supporting variable-length Geneve
// TLVs, is future work (same envelope as the variable-length note above).
//
// Demand-driven codegen skips the bpf_loop subprogram when no
// geneve.options.<X> predicate is in the program: most chains
// (eth/.../geneve/eth/ipv4@inner/...) take the bulk-advance fallback
// over the whole options section and never pay for the walk. Only a
// filter that reads a Geneve option pays for the TLV walk.
parser GeneveParser(packet_in pkt,
                    out geneve_h            hdr,
                    out geneve_opt_ovn_h    ovn,
                    out geneve_opt_gwlb_h   gwlb) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        // Remaining option bytes = opt_len * 4. The `.set` grammar
        // requires the `(field - K)` subtract template (cf. ipv4.p4's
        // `ihl - 5`); opt_len already excludes the fixed header, so K=0.
        pc.set(((bit<8>)(hdr.opt_len - 0)) << 5);
        transition select(hdr.version) {
            0:       walk;
            default: reject;
        }
    }
    state walk {
        transition select(pc.is_zero(), pkt.lookahead<bit<24>>()) {
            (true,  _):        accept;
            (false, 0x010280): parse_ovn;    // OVN class 0x0102, type 0x80
            (false, 0x010803): parse_gwlb;   // AWS GWLB class 0x0108, type 3
            (false, _):        reject;
        }
    }
    state parse_ovn  { pkt.extract(ovn);  pc.decrement(8); transition walk; }
    state parse_gwlb { pkt.extract(gwlb); pc.decrement(8); transition walk; }
}
