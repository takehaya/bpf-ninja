package codegen

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// genPredicate emits the comparison asm for one "field op value" entry.
// Supported value types: integer, IPv4 / IPv6 host, IPv4 / IPv6 CIDR,
// MAC. Each accepts == and !=; ordered comparisons land on integers
// only. Other shapes (range, ident, string) surface ErrNotImplemented
// so later phases can plug them in without touching the dispatch path.
//
// The field lookup is delegated to each emit* so the byte/bit-level
// constraints can differ — IPv6 is 128 bits which findFieldByteOffset
// rejects, and MAC is 6 bytes which asmSizeFor rejects.
func genPredicate(pred *ir.Predicate) (asm.Instructions, error) {
	if pred.Unsupported != "" {
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, pred.Unsupported)
	}
	if pred.Kind != ast.PredCmp {
		return nil, fmt.Errorf("%w: predicate kind %s", ErrNotImplemented, pred.Kind)
	}
	if pred.Value == nil {
		return nil, fmt.Errorf("codegen: nil predicate value")
	}

	switch pred.Value.Kind {
	case ast.ValInt:
		return emitIntPredicate(pred)
	case ast.ValIPv4:
		return emitIPv4Predicate(pred)
	case ast.ValIPv6:
		return emitIPv6Predicate(pred)
	case ast.ValMAC:
		return emitMACPredicate(pred)
	case ast.ValCIDR:
		if pred.Value.AF == 4 {
			return emitIPv4CIDRPredicate(pred)
		}
		return emitIPv6CIDRPredicate(pred)
	}
	return nil, fmt.Errorf("%w: predicate value type %s", ErrNotImplemented, pred.Value.Kind)
}

// emitIntPredicate handles `field op INTEGER`. The field is read LE
// from the scratch buffer; for multi-byte fields the register holds
// network-order bytes packed as if they were a host-LE integer, so
// the value differs from the natural numeric reading by a byte
// reversal. Three approaches are possible:
//
//  1. Byte-reverse the register at runtime via BPF_BSWAP (opcode
//     0xd7). Lands in Linux 6.6 — too new for the kernels kunai
//     advertises (5.17+ for header walk, 6.6+ for predicates).
//  2. Byte-reverse via the older BPF_END family (HostTo(BE), opcode
//     0xdc). Available since 5.x. Works for ordered comparisons.
//  3. Byte-reverse the *constant* at codegen time so a single JEq /
//     JNE matches the LE-loaded register directly. No runtime swap,
//     no kernel-version risk — but only works for equality.
//
// Equality (==/!=) takes path 3 (no swap insn). Ordered
// comparisons (<, <=, >, >=) take path 2 (HostTo BE). This keeps
// every emitted predicate on opcodes that work back to Linux 5.x,
// matching the verifier-walk floor we promise.
func emitIntPredicate(pred *ir.Predicate) (asm.Instructions, error) {
	value := pred.Value.Int
	// The resolver guarantees value fits in the field's bit width, so
	// the only remaining constraint is asm.JumpOp.Imm's int32 limit.
	// Larger values require a 64-bit reg-reg compare, deferred to a
	// later phase.
	if value > 0x7FFFFFFF {
		return nil, fmt.Errorf("%w: value %d exceeds int32 immediate range (64-bit compares deferred)", ErrNotImplemented, value)
	}
	jumpOp, ok := rejectingJumpOp(pred.Op)
	if !ok {
		return nil, fmt.Errorf("codegen: unknown comparison op %v", pred.Op)
	}
	var insns asm.Instructions
	var bytes int
	dynamic := pred.Field != nil && pred.Field.Aux != nil && pred.Field.Aux.Stack != nil && !pred.Field.Aux.Stack.IsStatic
	switch {
	case dynamic:
		bytes = pred.Field.Aux.FieldBitWidth / 8
		size, err := asmSizeFor(bytes)
		if err != nil {
			return nil, err
		}
		// Gating doesn't apply to stack auxes (extracted unconditionally
		// inside the parser-machine self-loop), so we skip emitAuxGating.
		dyn, err := emitDynamicStackLoad(pred.Field, size, dslReject)
		if err != nil {
			return nil, err
		}
		insns = append(insns, dyn...)
	default:
		fieldOff, bs, err := fieldRefByteOffset(pred.Field)
		if err != nil {
			return nil, err
		}
		bytes = bs
		size, err := asmSizeFor(bs)
		if err != nil {
			return nil, err
		}
		if pred.Field != nil && pred.Field.Aux != nil {
			insns = append(insns, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
		}
		insns = append(insns, loadFromOffset(int16(fieldOff), size)...)
	}
	size, err := asmSizeFor(bytes)
	if err != nil {
		return nil, err
	}
	switch {
	case bytes <= 1:
		// 1-byte: register holds the raw byte; nothing to swap.
	case pred.Op == ast.CmpEq || pred.Op == ast.CmpNeq:
		// Equality: byte-swap the constant at codegen time and
		// compare with the LE-loaded register directly.
		value = swapValueBytes(value, bytes)
	default:
		// Ordered: bring register to natural numeric order.
		// HostTo(BE) emits the BPF_END opcode (5.x-safe) instead of
		// BSwap (6.6+).
		insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
	}
	insns = append(insns, jumpOp.Imm(asm.R3, int32(value), dslReject))
	return insns, nil
}

// swapValueBytes reverses the low `bytes` bytes of v so an LE-loaded
// register can be compared against the native-order constant with a
// single JEq/JNE. e.g. 443 (0x01BB) over 2 bytes → 0xBB01.
func swapValueBytes(v uint64, bytes int) uint64 {
	out := uint64(0)
	for range bytes {
		out = (out << 8) | (v & 0xff)
		v >>= 8
	}
	return out
}

// emitIPv4Predicate handles `field == 10.0.0.1` and `field != …`.
// IPv4 fields (`bit<32>`, e.g. ipv4.src / ipv4.dst) are read as a
// 32-bit Word in little-endian on x86, so we byte-swap the constant
// at codegen time and compare with a single JEq/JNE — same trick
// genFieldDispatch uses for protocol-id consts.
func emitIPv4Predicate(pred *ir.Predicate) (asm.Instructions, error) {
	if pred.Field != nil && pred.Field.Aux != nil {
		return nil, fmt.Errorf("%w: IPv4 literal predicate on auxiliary header field is not yet supported", ErrNotImplemented)
	}
	fieldOff, bytes, err := findFieldByteOffset(pred.Field.Layer.Spec, pred.Field.Field.Name)
	if err != nil {
		return nil, err
	}
	if bytes != 4 {
		return nil, fmt.Errorf("%w: IPv4 literal needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, bytes, pred.Field.Layer.Spec.Name, pred.Field.Field.Name)
	}
	jumpOp, ok := ipEqualityJumpOp(pred.Op)
	if !ok {
		return nil, fmt.Errorf("%w: IPv4 literal supports only == / != (got %s)", ErrNotImplemented, pred.Op)
	}
	v4 := pred.Value.V4
	expected := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v4[:])), 4))
	insns := loadFromOffset(int16(fieldOff), asm.Word)
	insns = append(insns, cmpRegEqU32(jumpOp, expected, dslReject)...)
	return insns, nil
}

// emitIPv6Predicate handles `field == fe80::1` and `field != fe80::1`.
// IPv6 fields are `bit<128>` (e.g. ipv6.src / ipv6.dst), too wide for a
// single LDX, so the body splits into two 8-byte LDX-DWord loads. Each
// half is byte-swapped at codegen so the LE-reading LDX matches the
// BE constant. The == / != branching shape comes from multiWordRoute.
func emitIPv6Predicate(pred *ir.Predicate) (asm.Instructions, error) {
	if pred.Field != nil && pred.Field.Aux != nil {
		return nil, fmt.Errorf("%w: IPv6 literal predicate on auxiliary header field is not yet supported", ErrNotImplemented)
	}
	fieldOff, err := requireIPv6Field(pred)
	if err != nil {
		return nil, err
	}
	if err := requireEqualityOp(pred, "IPv6 literal"); err != nil {
		return nil, err
	}
	highBE := binary.BigEndian.Uint64(pred.Value.V6[0:8])
	lowBE := binary.BigEndian.Uint64(pred.Value.V6[8:16])
	return multiWordRoute(pred.Op, func(fail string) asm.Instructions {
		var insns asm.Instructions
		insns = append(insns, ipv6HalfCheck(int16(fieldOff), ^uint64(0), highBE, fail)...)
		insns = append(insns, ipv6HalfCheck(int16(fieldOff+8), ^uint64(0), lowBE, fail)...)
		return insns
	}), nil
}

// emitIPv6CIDRPredicate handles `field == 2001:db8::/32` (and !=).
// Same split-load shape as emitIPv6Predicate; for each half we apply
// the prefix mask before the per-word compare, and when a half's
// mask is all zeros the corresponding load + compare collapses.
//
// Edge cases mirror the IPv4 CIDR path:
//   - /128 → host match (collapses to emitIPv6Predicate).
//   - /0 with == → emit nothing (matches every address).
//   - /0 with != → Ja dslReject (matches no address).
func emitIPv6CIDRPredicate(pred *ir.Predicate) (asm.Instructions, error) {
	if pred.Field != nil && pred.Field.Aux != nil {
		return nil, fmt.Errorf("%w: IPv6 CIDR predicate on auxiliary header field is not yet supported", ErrNotImplemented)
	}
	fieldOff, err := requireIPv6Field(pred)
	if err != nil {
		return nil, err
	}
	if err := requireEqualityOp(pred, "IPv6 CIDR"); err != nil {
		return nil, err
	}
	prefix := pred.Value.Prefix
	if prefix < 0 || prefix > 128 {
		return nil, fmt.Errorf("codegen: IPv6 CIDR prefix %d out of [0,128]", prefix)
	}
	if prefix == 128 {
		return emitIPv6Predicate(pred)
	}
	if prefix == 0 {
		if pred.Op == ast.CmpEq {
			return nil, nil
		}
		return asm.Instructions{asm.Ja.Label(dslReject)}, nil
	}
	maskHighBE, maskLowBE := ipv6PrefixMaskBE(prefix)
	hostHighBE := binary.BigEndian.Uint64(pred.Value.V6[0:8]) & maskHighBE
	hostLowBE := binary.BigEndian.Uint64(pred.Value.V6[8:16]) & maskLowBE
	return multiWordRoute(pred.Op, func(fail string) asm.Instructions {
		var insns asm.Instructions
		if maskHighBE != 0 {
			insns = append(insns, ipv6HalfCheck(int16(fieldOff), maskHighBE, hostHighBE, fail)...)
		}
		if maskLowBE != 0 {
			insns = append(insns, ipv6HalfCheck(int16(fieldOff+8), maskLowBE, hostLowBE, fail)...)
		}
		return insns
	}), nil
}

// ipv6HalfCheck emits the load + optional AND + JNE for one 8-byte
// half of an IPv6 host or CIDR check. mask==^uint64(0) skips the AND
// so a host-aligned half is one instruction lighter. failLabel is
// where the per-half mismatch jumps; multiWordRoute picks dslReject
// for == and a per-predicate match landing for !=.
func ipv6HalfCheck(off int16, mask, host uint64, failLabel string) asm.Instructions {
	insns := loadFromOffset(off, asm.DWord)
	if mask != ^uint64(0) {
		insns = append(insns,
			asm.LoadImm(asm.R5, int64(byteSwap(mask, 8)), asm.DWord),
			asm.And.Reg(asm.R3, asm.R5),
		)
	}
	insns = append(insns,
		asm.LoadImm(asm.R5, int64(byteSwap(host, 8)), asm.DWord),
		asm.JNE.Reg(asm.R3, asm.R5, failLabel),
	)
	return insns
}

// requireIPv6Field returns the byte offset of the predicate's field
// after asserting it is byte-aligned and exactly 128 bits wide.
func requireIPv6Field(pred *ir.Predicate) (int, error) {
	bitOff, bits, err := findFieldBitOffset(pred.Field.Layer.Spec, pred.Field.Field.Name)
	if err != nil {
		return 0, err
	}
	if bitOff%8 != 0 || bits != 128 {
		return 0, fmt.Errorf("%w: IPv6 literal needs a 128-bit byte-aligned field, got %s.%s (%d bits at bit %d)", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Field.Name, bits, bitOff)
	}
	return bitOff / 8, nil
}

// emitMACPredicate handles `field == de:ad:be:ef:00:01` (and !=). MAC
// fields are `bit<48>` (eth.dst, eth.src), so the body splits into a
// 4-byte Word load (top 4 octets) plus a 2-byte Half load (bottom 2).
// The address base is cached in R5 so the second LDX skips the Mov+Add
// rebuild — both JNE.Imm comparisons fit in 32 bits and so leave R5
// untouched. The == / != branching shape comes from multiWordRoute.
func emitMACPredicate(pred *ir.Predicate) (asm.Instructions, error) {
	if pred.Field != nil && pred.Field.Aux != nil {
		return nil, fmt.Errorf("%w: MAC literal predicate on auxiliary header field is not yet supported", ErrNotImplemented)
	}
	fieldOff, bytes, err := findFieldByteOffset(pred.Field.Layer.Spec, pred.Field.Field.Name)
	if err != nil {
		return nil, err
	}
	if bytes != 6 {
		return nil, fmt.Errorf("%w: MAC literal needs a 6-byte field, got %d-byte %s.%s", ErrNotImplemented, bytes, pred.Field.Layer.Spec.Name, pred.Field.Field.Name)
	}
	if err := requireEqualityOp(pred, "MAC literal"); err != nil {
		return nil, err
	}
	mac := pred.Value.MAC
	highLE := uint32(byteSwap(uint64(binary.BigEndian.Uint32(mac[0:4])), 4))
	lowLE := uint16(byteSwap(uint64(binary.BigEndian.Uint16(mac[4:6])), 2))
	return multiWordRoute(pred.Op, func(fail string) asm.Instructions {
		// Cache the address base in a non-volatile reg so the second
		// load skips the Mov+Add rebuild. cmpRegEqU16 uses R5 too,
		// so we use R6 for the cached pointer base - actually R5 is
		// fine because LoadImm R5 is followed by JNE.Reg which reads
		// R5 once and we re-Mov to it before the next compare.
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R5, asm.R0),
			asm.Add.Reg(asm.R5, offsetBase),
			asm.LoadMem(asm.R3, asm.R5, int16(fieldOff), asm.Word),
		}
		insns = append(insns, cmpRegEqU32(asm.JNE, highLE, fail)...)
		insns = append(insns,
			asm.Mov.Reg(asm.R5, asm.R0),
			asm.Add.Reg(asm.R5, offsetBase),
			asm.LoadMem(asm.R3, asm.R5, int16(fieldOff+4), asm.Half),
		)
		insns = append(insns, cmpRegEqU16(asm.JNE, lowLE, fail)...)
		return insns
	}), nil
}

// cmpRegEqU32 emits a 64-bit register compare against a 32-bit
// expected value: `LoadImm R5, expected; <op>.Reg R3, R5, failLabel`.
// Used in place of `<op>.Imm(R3, int32(expected), failLabel)` for
// values where the high bit might be set, which BPF would sign-
// extend to int64 before the compare and mismatch a zero-extended
// LdXMemW load. Two instructions instead of one but always correct.
func cmpRegEqU32(jumpOp asm.JumpOp, expected uint32, failLabel string) asm.Instructions {
	return asm.Instructions{
		asm.LoadImm(asm.R5, int64(uint64(expected)), asm.DWord),
		jumpOp.Reg(asm.R3, asm.R5, failLabel),
	}
}

// cmpRegEqU16 is the 16-bit twin of cmpRegEqU32 for the bottom half
// of a MAC literal (or any other 2-byte field whose top bit could
// be set).
func cmpRegEqU16(jumpOp asm.JumpOp, expected uint16, failLabel string) asm.Instructions {
	return asm.Instructions{
		asm.LoadImm(asm.R5, int64(uint64(expected)), asm.DWord),
		jumpOp.Reg(asm.R3, asm.R5, failLabel),
	}
}

// multiWordRoute wraps a per-word body with the control flow for ==
// or !=. The body emits `JNE word, expected → failLabel` for each
// word and falls through when every word matches.
//
//   - == picks failLabel = dslReject. Any mismatch rejects; fall-through
//     is success.
//   - != picks failLabel = a fresh per-predicate match landing. Any
//     mismatch jumps to that landing (success); when control falls
//     through the body all words agreed, so we Ja dslReject.
//
// Callers must filter `op` through requireEqualityOp first — only ==
// and != are valid here.
func multiWordRoute(op ast.CmpOp, body func(failLabel string) asm.Instructions) asm.Instructions {
	if op == ast.CmpEq {
		return body(dslReject)
	}
	match := nextPredicateMatchLabel()
	out := body(match)
	return append(out, asm.Ja.Label(dslReject), landingNoop(match))
}

// requireEqualityOp rejects ordered comparisons on multi-word
// literals (IPv6 host / CIDR, MAC). kind names the literal in the
// error so the user sees what they tripped over.
func requireEqualityOp(pred *ir.Predicate, kind string) error {
	if _, ok := ipEqualityJumpOp(pred.Op); !ok {
		return fmt.Errorf("%w: %s supports only == / != (got %s)", ErrNotImplemented, kind, pred.Op)
	}
	return nil
}

// predMatchLabelPrefix is the label prefix multiWordRoute uses for
// `!=` match landings. Tests scanning emitted instructions for the
// landing symbol depend on this exact string.
const predMatchLabelPrefix = "dsl_pred_match_"

// predLabelCounter feeds nextPredicateMatchLabel. Atomic so concurrent
// Gen() calls produce non-colliding labels; labels are scoped to one
// instruction stream so a process-wide counter suffices for uniqueness.
var predLabelCounter atomic.Uint64

func nextPredicateMatchLabel() string {
	return fmt.Sprintf("%s%d", predMatchLabelPrefix, predLabelCounter.Add(1))
}

// ipv6PrefixMaskBE returns (high, low) uint64 halves of the /N
// network mask, big-endian. /0 → 0,0; /64 → all-ones,0; /128 →
// all-ones,all-ones.
func ipv6PrefixMaskBE(prefix int) (high, low uint64) {
	if prefix <= 0 {
		return 0, 0
	}
	if prefix >= 128 {
		return ^uint64(0), ^uint64(0)
	}
	if prefix <= 64 {
		return ^uint64(0) << (64 - prefix), 0
	}
	return ^uint64(0), ^uint64(0) << (128 - prefix)
}

// emitIPv4CIDRPredicate handles `field == 10.0.0.0/8` (and !=). It
// AND-masks the loaded word with the CIDR's prefix mask before the
// equality check; codegen-time byte-swapping turns both the mask
// and the host into the LE form the LDX produces.
//
// Edge cases short-circuit:
//   - /32 collapses to a host match (the AND-with-all-ones is dead),
//     so we hand off to emitIPv4Predicate.
//   - /0 with == matches every address — emit nothing.
//   - /0 with != matches nothing — jump straight to dslReject.
func emitIPv4CIDRPredicate(pred *ir.Predicate) (asm.Instructions, error) {
	if pred.Field != nil && pred.Field.Aux != nil {
		return nil, fmt.Errorf("%w: IPv4 CIDR predicate on auxiliary header field is not yet supported", ErrNotImplemented)
	}
	fieldOff, bytes, err := findFieldByteOffset(pred.Field.Layer.Spec, pred.Field.Field.Name)
	if err != nil {
		return nil, err
	}
	if bytes != 4 {
		return nil, fmt.Errorf("%w: IPv4 CIDR needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, bytes, pred.Field.Layer.Spec.Name, pred.Field.Field.Name)
	}
	prefix := pred.Value.Prefix
	if prefix < 0 || prefix > 32 {
		return nil, fmt.Errorf("codegen: IPv4 CIDR prefix %d out of [0,32]", prefix)
	}
	if prefix == 32 {
		return emitIPv4Predicate(pred)
	}
	jumpOp, ok := ipEqualityJumpOp(pred.Op)
	if !ok {
		return nil, fmt.Errorf("%w: IPv4 CIDR supports only == / != (got %s)", ErrNotImplemented, pred.Op)
	}
	if prefix == 0 {
		if pred.Op == ast.CmpEq {
			return nil, nil
		}
		return asm.Instructions{asm.Ja.Label(dslReject)}, nil
	}
	maskBE := ipv4PrefixMaskBE(prefix)
	hostBE := binary.BigEndian.Uint32(pred.Value.V4[:]) & maskBE
	expectedLE := uint32(byteSwap(uint64(hostBE), 4))
	maskLE := uint32(byteSwap(uint64(maskBE), 4))
	insns := loadFromOffset(int16(fieldOff), asm.Word)
	insns = append(insns, asm.And.Imm(asm.R3, int32(maskLE)))
	insns = append(insns, cmpRegEqU32(jumpOp, expectedLE, dslReject)...)
	return insns, nil
}

// ipEqualityJumpOp narrows rejectingJumpOp to the equality subset
// IP host / CIDR predicates support. Ordered comparisons (<, >, …)
// have no useful semantics on IP addresses; reuse rejectingJumpOp's
// table so JEq/JNE mapping stays in one place.
func ipEqualityJumpOp(op ast.CmpOp) (asm.JumpOp, bool) {
	if op != ast.CmpEq && op != ast.CmpNeq {
		return 0, false
	}
	return rejectingJumpOp(op)
}

// ipv4PrefixMaskBE returns the network-mask for a /N prefix, with
// the high N bits set in big-endian uint32 form. /0 → 0, /32 →
// 0xffffffff.
func ipv4PrefixMaskBE(prefix int) uint32 {
	if prefix <= 0 {
		return 0
	}
	if prefix >= 32 {
		return 0xffffffff
	}
	return ^uint32(0) << (32 - prefix)
}

// rejectingJumpOp returns the jump that fires when the predicate is
// NOT satisfied. That is the direction that branches to dslReject.
func rejectingJumpOp(op ast.CmpOp) (asm.JumpOp, bool) {
	switch op {
	case ast.CmpEq:
		return asm.JNE, true
	case ast.CmpNeq:
		return asm.JEq, true
	case ast.CmpLt:
		return asm.JGE, true
	case ast.CmpLe:
		return asm.JGT, true
	case ast.CmpGt:
		return asm.JLE, true
	case ast.CmpGe:
		return asm.JLT, true
	}
	return 0, false
}
