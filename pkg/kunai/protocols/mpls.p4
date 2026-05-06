// MPLS label entry (RFC 3032). Each entry is 32 bits and a stack is
// represented in the DSL via repetition (e.g. `mpls+`). The s bit
// marks the bottom of the stack, but the resolver/codegen rely on
// quantifier counts rather than peeking at s for now.
header mpls_h {
    bit<20> label;
    bit<3>  tc;
    bit<1>  s;
    bit<8>  ttl;
}

// Dispatch from Ethernet via the MPLS unicast EtherType. The
// multicast variant (0x8848) is intentionally omitted from the MVP.
// MPLS rides under VLAN and QinQ with the same 0x8847 because the
// EtherType identifies the *payload* protocol, independent of the
// outer L2 carrier.
const bit<16> MPLS_ETH_ETHERTYPE  = 0x8847;
const bit<16> MPLS_VLAN_ETHERTYPE = 0x8847;
const bit<16> MPLS_QINQ_ETHERTYPE = 0x8847;

// Stacked MPLS labels: the next label sits immediately after the
// previous one with no boundary marker. The user opts in by writing
// `mpls+` or `mpls{n,m}`.
const bool MPLS_MPLS_NO_CHECK = true;

// Default bpf_loop iteration cap for `mpls+` / `mpls*`. Real-world
// stacks rarely exceed four; eight leaves slack for edge deployments
// without running up against the 5.17 loop limits.
const bit<8> MPLS_MAX_DEPTH = 8;

// Stack-bottom signal: when the s-bit of the just-consumed label is
// 1 the chain ends because no more labels follow. Width matches the
// header field exactly (bit<1>); chain-end codegen handles the
// sub-byte mask + shift.
const bit<1> MPLS_CHAIN_END_S = 1;

parser MplsParser(packet_in pkt, out mpls_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
