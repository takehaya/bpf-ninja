// GRE (RFC 2784/2890). The 4-byte fixed header carries flags +
// protocol_type. Three of the high bits in the flags field gate
// optional 4-byte sub-headers that follow the fixed prefix:
//
//   bit 15 (mask 0x80) — Checksum present (4 bytes: u16 csum + u16 reserved)
//   bit 13 (mask 0x20) — Key present       (4 bytes)
//   bit 12 (mask 0x10) — Sequence present  (4 bytes)
//
// Codegen advances R4 past whichever subset of these is enabled via
// the OPT_TRIGGER/OPT_LEN const pairs below so the inner protocol
// dispatch lines up correctly.
header gre_h {
    bit<16> flags;
    bit<16> protocol_type;
}

// Dispatch from IPv4 / IPv6 via protocol number 47.
const bit<8> GRE_IPV4_PROTOCOL    = 47;
const bit<8> GRE_IPV6_NEXT_HEADER = 47;

// Flag-triggered optional sub-headers. The flag byte sits at offset 0
// of gre_h; declaration order (C → K → S) matches the wire layout so
// codegen advances R4 in the correct sequence.
const bit<8> GRE_OPT_FLAGS_BYTE_OFFSET = 0;
const bit<8> GRE_OPT_TRIGGER_C         = 0x80;
const bit<8> GRE_OPT_LEN_C             = 4;
const bit<8> GRE_OPT_TRIGGER_K         = 0x20;
const bit<8> GRE_OPT_LEN_K             = 4;
const bit<8> GRE_OPT_TRIGGER_S         = 0x10;
const bit<8> GRE_OPT_LEN_S             = 4;
