package codegen

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// staticHeaderCountedIndex reports whether f is a static index into a
// stack whose element count is a declared field of the primary header
// (vocab.StackCountSpec, e.g. srv6.segments), the shape genPredicate
// guards by reading that byte.
func staticHeaderCountedIndex(f *ir.FieldRef) bool {
	if f == nil || f.Aux == nil || f.Aux.Stack == nil || !f.Aux.Stack.IsStatic || f.Aux.OwnerOption != nil || f.Layer == nil {
		return false
	}
	return f.Layer.Spec.StackCounts[f.Aux.OutParam] != nil
}

// genPredicate emits the comparison asm for one "field op value" entry.
// Supported value types: integer, IPv4 / IPv6 host, IPv4 / IPv6 CIDR,
// MAC. Each accepts == and !=; ordered comparisons land on integers
// only. Other shapes (range, ident, string) surface ErrNotImplemented
// so later phases can plug them in without touching the dispatch path.
//
// The field lookup is delegated to each emit* so the byte/bit-level
// constraints can differ — IPv6 is 128 bits which findFieldByteOffset
// rejects, and MAC is 6 bytes which asmSizeFor rejects.
func genPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if pred.Unsupported != "" {
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, pred.Unsupported)
	}
	// A static index into a stack is absent past the extracted entries
	// (D-031), so the guard precedes every predicate kind. A push-counted
	// stack is guarded against the count slot when the predicate runs after
	// the walk and refused when it runs before (the count is still 0 there
	// and the entry would read the bytes after the stack). A stack with a
	// declared count field (srv6.segments: last_entry + 1) reads that byte
	// of the primary header, which sits at layer entry (R4) both before and
	// after the walk; the where clause's emitCountGuard reads the same byte.
	var guard asm.Instructions
	switch {
	case needsPushCount(pred.Field):
		var slot int16
		ok := false
		if pc != nil && pc.stackCount != nil {
			slot, ok = pc.stackCount(pred.Field)
		}
		if !ok {
			return nil, fmt.Errorf("%w: bracket predicate on %s.%s indexes a stack whose entries are counted by the parser walk, and it runs where that count is not final (a quantified layer replays its predicates per iteration); move the comparison to a where clause", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam)
		}
		guard = asm.Instructions{
			asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
			asm.JLE.Imm(asm.R3, int32(pred.Field.Aux.Stack.Static), dslReject),
		}
	case staticHeaderCountedIndex(pred.Field):
		cnt := pred.Field.Layer.Spec.StackCounts[pred.Field.Aux.OutParam]
		guard = emitHeaderCount(asm.R3, r4Anchor(), cnt, dslReject)
		guard = append(guard, asm.JLE.Imm(asm.R3, int32(pred.Field.Aux.Stack.Static), dslReject))
	}

	var insns asm.Instructions
	var err error
	switch pred.Kind {
	case ast.PredInSet:
		insns, err = emitInSetPredicate(pred, pc)
	case ast.PredIn:
		insns, err = emitInPredicate(pred, pc)
	case ast.PredCmp:
		insns, err = emitCmpPredicate(pred, pc)
	case ast.PredValid:
		var slot int16
		ok := false
		if pc != nil && pc.validSlot != nil {
			slot, ok = pc.validSlot(pred.Field.Layer)
		}
		if !ok {
			// The walk's outcome is only recorded where the predicates run
			// after it; a repeated layer replays them per iteration.
			return nil, fmt.Errorf("%w: %s[options.valid] on a repeated layer; move it to a where clause", ErrNotImplemented, pred.Field.Layer.Spec.Name)
		}
		insns = asm.Instructions{
			asm.LoadMem(asm.R3, asm.R10, slot, asm.DWord),
			asm.JEq.Imm(asm.R3, 0, dslReject),
		}
	default:
		return nil, fmt.Errorf("%w: predicate kind %s", ErrNotImplemented, pred.Kind)
	}
	if err != nil {
		return nil, err
	}
	return append(guard, insns...), nil
}

// emitCmpPredicate lowers `field op value` by the literal's kind.
func emitCmpPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if pred.Value == nil {
		return nil, fmt.Errorf("codegen: nil predicate value")
	}
	switch pred.Value.Kind {
	case ast.ValInt:
		return emitIntPredicate(pred, pc)
	case ast.ValIPv4:
		return emitIPv4Predicate(pred, pc)
	case ast.ValIPv6:
		return emitIPv6Predicate(pred, pc)
	case ast.ValMAC:
		return emitMACPredicate(pred, pc)
	case ast.ValCIDR:
		if pred.Value.AF == 4 {
			return emitIPv4CIDRPredicate(pred, pc)
		}
		return emitIPv6CIDRPredicate(pred, pc)
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
func emitIntPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	value := pred.Value.Int
	// Narrow the literal to the field's effective (possibly sliced) width before the
	// immediate-range check. The resolver's fit-check (typing.go:
	// literalFitsBits) accepts signed-extended negatives (`-1` stored
	// as 0xffff..ff), and at codegen we only ever compare the low
	// `bits` bits of the field anyway, so masking here is the
	// correct narrowing per dsl-types.md §4.1 / §7.3.
	if pred.Field != nil && pred.Field.Field != nil {
		fieldBits := pred.Field.EffectiveBits()
		if fieldBits > 0 && fieldBits < 64 {
			value &= (uint64(1) << fieldBits) - 1
		}
	}
	// After narrowing, the only remaining constraint is the
	// asm.JumpOp.Imm int32 limit. Values that still exceed it come
	// from genuine bit<N> fields with N > 32, which the spec stages
	// (dsl-types.md §9.1, follow-up F3). Type-OK program; rebuild
	// against a kernel that ships the staged emitter.
	if value > 0x7FFFFFFF {
		return nil, fmt.Errorf("%w: value %d exceeds int32 immediate range — staged Int<N>>32 cmp (dsl-types.md §9.1, F3)", ErrNotImplemented, value)
	}
	jumpOp, ok := rejectingJumpOp(pred.Op)
	if !ok {
		return nil, fmt.Errorf("codegen: unknown comparison op %v", pred.Op)
	}
	var insns asm.Instructions
	var bytes int
	dynamic := needsEntryAddress(pred.Field)
	switch {
	case dynamic:
		_, bs, err := auxEntryFieldWindow(pred.Field)
		if err != nil {
			return nil, err
		}
		bytes = bs
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
		insns = append(insns, emitFieldLoad(pc.fieldAnchor(), fieldOff, size)...)
	}
	size, err := asmSizeFor(bytes)
	if err != nil {
		return nil, err
	}
	hasSlice := pred.Field != nil && pred.Field.Slice != nil
	subByte := fieldIsSubByte(pred.Field)
	switch {
	case hasSlice || subByte:
		// Slice-narrowed or sub-byte field: the load went through a
		// covering window, so bring the register to host order then
		// shift+mask down to the field's bits. The constant stays in
		// host order (the user wrote it that way), so we don't apply
		// the constant-side bswap trick the equality fast-path uses.
		if bytes > 1 {
			insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
		}
		insns = append(insns, emitSliceShiftMask(pred.Field, bytes)...)
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

// predCtx threads the host's set-slot resolver and an extraction
// accumulator through the predicate emitters. It is nil-safe: a nil
// predCtx (or a nil Sets) means the host does not support `in @set`.
type predCtx struct {
	sets SetSlotResolver
	out  *[]ExtractSlot
	// stackCount resolves the push count slot of a push-counted stack
	// (option_demand.go needsPushCount). Set only where the predicates
	// run after the parser walk (splitPredicates), since the count is final
	// only then; nil means such an index cannot be guarded.
	stackCount func(*ir.FieldRef) (int16, bool)
	// validSlot resolves a layer's option-validity slot, for
	// `[options.valid]`. Set with stackCount, after the walk.
	validSlot func(*ir.LayerInstance) (int16, bool)
	// guarded is the alternation member whose guard has just run its
	// parent dispatch (genAlternation); its body skips the identical
	// dispatch, which the guard already passed.
	guarded *ir.LayerInstance
	// anchor, when set, is where the predicates read the layer's primary
	// fields from; it carries the write-back overlay of a layer whose
	// predicates run after its walk (D-032). nil: R4 at entry.
	anchor *layerAnchor
}

// fieldAnchor is the anchor a predicate reads primary fields through.
func (pc *predCtx) fieldAnchor() layerAnchor {
	if pc != nil && pc.anchor != nil {
		return *pc.anchor
	}
	return r4Anchor()
}

// dispatchDone reports whether `l`'s parent dispatch already ran as its
// alternation guard.
func (pc *predCtx) dispatchDone(l *ir.LayerInstance) bool {
	return pc != nil && pc.guarded != nil && pc.guarded == l
}

// emitInSetPredicate lowers `field in @set` for architecture B: it does
// NOT emit a map lookup (kunai stays map-agnostic). Instead it extracts
// the packet field into the host-owned R10 slot the SetSlotResolver
// designates, so the host can look the pinned map up against those bytes
// after the filter returns. The atom never affects the verdict — only a
// layer that cannot be reached fails, via the shared dslReject the field
// load already jumps to.
//
// Byte order (correctness-critical): `set add` writes the key value in
// native byte order (setmap.BuildKey/putUint use binary.NativeEndian).
// emitBoundedLoad packs network-order packet bytes into R3 as a host-LE
// integer, so a multi-byte field is byte-reversed relative to its
// numeric value. HostTo(BE) brings R3 to the numeric value in host
// order; StoreMem then writes it native-endian, matching the map key.
// field128RawOffset returns the byte offset of a 16-byte (128-bit) field
// to be extracted as raw wire bytes, and ok=true when the field is one:
// a primary-header field (ipv6.dst) or a static aux-stack element
// (srv6.segments[N].addr). It is the width-relaxed 128-bit sibling of
// fieldRefByteOffset (which caps unsliced aux/primary fields at 8 bytes;
// a slice narrows a 16-byte field to a window it loads). ok=false
// means "not a 16-byte field" (the caller falls back to the <=8 path); a
// non-nil error means a 16-byte field that cannot be extracted (a
// non-byte-aligned or dynamic-index aux stack).
func field128RawOffset(ref *ir.FieldRef) (off int, ok bool, err error) {
	if ref.Slice != nil {
		return 0, false, nil
	}
	if ref.Aux == nil {
		if ref.Field == nil || ref.Field.Bits != 128 {
			return 0, false, nil
		}
		o, _, e := findFieldByteOffset128(ref.Layer.Spec, ref.Field.Name)
		return o, true, e
	}
	if ref.Aux.FieldBitWidth != 128 {
		return 0, false, nil
	}
	o, err := auxStaticByteOffset(ref.Aux)
	if err != nil {
		return 0, false, err
	}
	return o, true, nil
}

// auxStaticByteOffset folds an aux field's constant byte offset within its
// layer: OffsetInLayer + FieldBitOff/8, plus Static*HeaderSize for a static
// aux-stack element (srv6.segments[N]). It errors on a non-byte-aligned
// field or a dynamic stack index, which needs a runtime address compute
// (R5) that a constant-offset caller cannot express. This is the same fold
// fieldRefByteOffset (codegen.go) and auxLoadEmitter apply inline; kept as a
// helper so the 128-bit raw-copy path shares one definition of the formula.
func auxStaticByteOffset(aux *ir.AuxRef) (int, error) {
	if aux.FieldBitOff%8 != 0 {
		return 0, fmt.Errorf("%w: aux field %s (%s) starts at bit %d (not byte-aligned)", ErrNotImplemented, aux.OutParam, aux.HeaderName, aux.FieldBitOff)
	}
	off := aux.OffsetInLayer + aux.FieldBitOff/8
	if aux.Stack != nil {
		if !aux.Stack.IsStatic {
			return 0, fmt.Errorf("%w: dynamic aux stack index needs a runtime offset (use a constant index)", ErrNotImplemented)
		}
		off += int(aux.Stack.Static) * aux.HeaderSize
	}
	return off, nil
}

func emitInSetPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if pc == nil || pc.sets == nil {
		return nil, fmt.Errorf("%w: `in @%s` needs a host that supports set matching", ErrNotImplemented, pred.SetName)
	}
	if !pc.sets.HasSet(pred.SetName) {
		return nil, fmt.Errorf("unknown set @%s (declare it with --set %s=/sys/fs/bpf/...)", pred.SetName, pred.SetName)
	}
	if pred.Field == nil || pred.Field.Field == nil {
		return nil, fmt.Errorf("codegen: in-set predicate missing field reference")
	}
	// The key is extracted from a constant layer offset; an entry whose
	// offset is only known at run time has none.
	if needsEntryAddress(pred.Field) {
		return nil, fmt.Errorf("%w: `in @%s` on %s.%s, an entry whose offset is only known at run time (dynamic index or variable-length entries); use a where clause", ErrNotImplemented, pred.SetName, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam)
	}
	// Implicit name match: the DSL field name is the set's key field name.
	fieldName := pred.Field.Field.Name
	slotOff, slotSize, ok := pc.sets.SlotFor(pred.SetName, fieldName)
	if !ok {
		return nil, fmt.Errorf("set @%s has no key field %q (check `bpf-ninja set schema`)", pred.SetName, fieldName)
	}
	// The extraction is written during the filter and read after it, so
	// the slot must live in the host region, never kunai's stack range.
	if slotOff <= KunaiStackTop {
		return nil, fmt.Errorf("codegen: set slot %d for @%s.%s is inside kunai's stack region (must be > %d)", slotOff, pred.SetName, fieldName, KunaiStackTop)
	}
	// The host looks each set up once, against one key: a second
	// predicate on the same key field (a scalar set's single key under
	// two field names, or the same composite field twice) would silently
	// overwrite the first extraction.
	if pc.out != nil {
		for _, prev := range *pc.out {
			if prev.SetName == pred.SetName && prev.StackOff == slotOff {
				return nil, fmt.Errorf("set @%s: key field %q is written twice (%q and %q); the host holds one key per set and looks it up once", pred.SetName, fieldName, prev.FieldName, fieldName)
			}
		}
	}

	// A 16-byte (128-bit) field is rejected by fieldRefByteOffset (which
	// caps at a single <=8-byte load), so resolve its offset separately and
	// take the two-DWord store path. This covers a primary field
	// (ipv6.dst = the active SRv6 SID) and a static aux-stack element
	// (srv6.segments[N].addr = a specific SID in the SRH list).
	fieldOff, is128, err := field128RawOffset(pred.Field)
	if err != nil {
		return nil, err
	}
	bytes := 16
	if !is128 {
		fieldOff, bytes, err = fieldRefByteOffset(pred.Field)
		if err != nil {
			return nil, err
		}
	}
	// bytes is 1/2/4/8 (the fieldRefByteOffset path rejects wider) or 16
	// (the is128 path), so no explicit 9..15 guard is needed here.
	// Require an exact width match: a narrower packet field would only
	// write a prefix of the key (relying on zero-fill), which silently
	// matches just zero-extended entries — a mis-configuration trap.
	// Size the set key field to the packet field's width.
	if bytes != slotSize {
		return nil, fmt.Errorf("packet field %q is %d bytes but set @%s key field %q is %d bytes; widths must match (create the set with a matching field type)", fieldName, bytes, pred.SetName, fieldName, slotSize)
	}

	var insns asm.Instructions

	// 16-byte (IPv6 address / SID): store the raw network-order bytes.
	// Unlike the <=8 numeric path below, this is an identity byte copy —
	// emitBoundedLoad (LE load) then StoreMem (LE store) preserves wire
	// byte order, so NO HostTo is applied. `set add sid=fc00::1` writes
	// the same net.ParseIP().To16() bytes verbatim (setmap copies, not
	// putUint), so the key matches. Do not add a byte-swap here in any
	// later "unify the store path" refactor — it would reverse the SID on
	// a little-endian host and silently break every IPv6 match.
	if bytes == 16 {
		// A static aux-stack element (srv6.segments[N].addr) gates on
		// presence just like the <=8 aux path; a primary field has no aux
		// and emitAuxGating is skipped. Dynamic/iterator stacks are rejected
		// at resolve time and in field128RawOffset.
		if pred.Field.Aux != nil {
			insns = append(insns, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
		}
		insns = append(insns, emitFieldLoad(pc.fieldAnchor(), fieldOff, asm.DWord)...)
		insns = append(insns, asm.StoreMem(asm.R10, slotOff, asm.R3, asm.DWord))
		insns = append(insns, emitBoundedLoad(asm.R3, int16(fieldOff+8), asm.DWord, dslReject)...)
		insns = append(insns, asm.StoreMem(asm.R10, slotOff+8, asm.R3, asm.DWord))
		if pc.out != nil {
			*pc.out = append(*pc.out, ExtractSlot{
				SetName: pred.SetName, FieldName: fieldName,
				StackOff: slotOff, StoreSize: 16,
			})
		}
		return insns, nil
	}

	size, err := asmSizeFor(bytes)
	if err != nil {
		return nil, err
	}
	// Single-aux fields gate on presence just like emitIntPredicate;
	// iterator-stack (dynamic) aux fields are rejected at resolve time.
	if pred.Field.Aux != nil {
		insns = append(insns, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
	}
	insns = append(insns, emitFieldLoad(pc.fieldAnchor(), fieldOff, size)...)

	// Normalize the register to the field's numeric value in host order.
	hasSlice := pred.Field.Slice != nil
	subByte := fieldIsSubByte(pred.Field)
	switch {
	case hasSlice || subByte:
		if bytes > 1 {
			insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
		}
		insns = append(insns, emitSliceShiftMask(pred.Field, bytes)...)
	case bytes > 1:
		insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
	}
	// Store native-endian into the host key slot (matches `set add`).
	insns = append(insns, asm.StoreMem(asm.R10, slotOff, asm.R3, size))

	if pc.out != nil {
		*pc.out = append(*pc.out, ExtractSlot{
			SetName: pred.SetName, FieldName: fieldName,
			StackOff: slotOff, StoreSize: bytes,
		})
	}
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
func emitIPv4Predicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if pred.Field == nil || pred.Field.Layer == nil || pred.Field.Field == nil {
		return nil, fmt.Errorf("codegen: IPv4 predicate missing field reference")
	}
	jumpOp, ok := ipEqualityJumpOp(pred.Op)
	if !ok {
		return nil, fmt.Errorf("%w: IPv4 literal supports only == / != (got %s)", ErrNotImplemented, pred.Op)
	}
	v4 := pred.Value.V4
	expected := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v4[:])), 4))

	if pred.Field.Aux != nil {
		if pred.Field.EffectiveBits() != 32 {
			return nil, fmt.Errorf("%w: IPv4 literal needs a 32-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam, pred.Field.Field.Name, pred.Field.EffectiveBits())
		}
		prelude, loadAt, err := auxLoadEmitter(pred.Field, r4Anchor(), nil, dslReject)
		if err != nil {
			return nil, err
		}
		insns := append(asm.Instructions{}, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
		insns = append(insns, prelude...)
		insns = append(insns, loadAt(0, asm.Word)...)
		insns = append(insns, cmpRegEqU32(jumpOp, expected, dslReject)...)
		return insns, nil
	}

	fieldOff, bytes, err := whereLiteralFieldOffset(pred.Field)
	if err != nil {
		return nil, err
	}
	if bytes != 4 {
		return nil, fmt.Errorf("%w: IPv4 literal needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, bytes, pred.Field.Layer.Spec.Name, pred.Field.Field.Name)
	}
	insns := emitFieldLoad(pc.fieldAnchor(), fieldOff, asm.Word)
	insns = append(insns, cmpRegEqU32(jumpOp, expected, dslReject)...)
	return insns, nil
}

// emitIPv6Predicate handles `field == fe80::1`, `field != fe80::1`,
// and the ordered comparisons `<` / `≤` / `>` / `≥` (F3). IPv6 fields
// are `bit<128>`, too wide for a single LDX, so the body splits into
// two 8-byte LDX-DWord loads. For ==/!= each half is byte-swapped at
// codegen so the LE-reading LDX matches the BE constant. For ordered
// cmp we host-swap the loaded register so its numeric ordering
// matches the literal, and lexicographic-compare the high half first.
func emitIPv6Predicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if pred.Field != nil && pred.Field.Aux != nil {
		if pred.Op != ast.CmpEq && pred.Op != ast.CmpNeq {
			return nil, fmt.Errorf("%w: IPv6 ordered cmp on aux header field is not yet supported", ErrNotImplemented)
		}
		if pred.Field.EffectiveBits() != 128 {
			return nil, fmt.Errorf("%w: IPv6 literal needs a 128-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam, pred.Field.Field.Name, pred.Field.EffectiveBits())
		}
		prelude, loadAt, err := auxLoadEmitter(pred.Field, r4Anchor(), nil, dslReject)
		if err != nil {
			return nil, err
		}
		highBE := binary.BigEndian.Uint64(pred.Value.V6[0:8])
		lowBE := binary.BigEndian.Uint64(pred.Value.V6[8:16])
		insns := append(asm.Instructions{}, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
		insns = append(insns, prelude...)
		insns = append(insns, multiWordRoute(pred.Op, func(fail string) asm.Instructions {
			body := append(asm.Instructions{}, ipv6AuxHalfCheck(loadAt, 0, ^uint64(0), highBE, fail)...)
			body = append(body, ipv6AuxHalfCheck(loadAt, 8, ^uint64(0), lowBE, fail)...)
			return body
		})...)
		return insns, nil
	}
	fieldOff, err := requireIPv6Field(pred)
	if err != nil {
		return nil, err
	}
	switch pred.Op {
	case ast.CmpEq, ast.CmpNeq:
		highBE := binary.BigEndian.Uint64(pred.Value.V6[0:8])
		lowBE := binary.BigEndian.Uint64(pred.Value.V6[8:16])
		return multiWordRoute(pred.Op, func(fail string) asm.Instructions {
			var insns asm.Instructions
			insns = append(insns, ipv6HalfCheck(int16(fieldOff), ^uint64(0), highBE, fail)...)
			insns = append(insns, ipv6HalfCheck(int16(fieldOff+8), ^uint64(0), lowBE, fail)...)
			return insns
		}), nil
	case ast.CmpLt, ast.CmpLe, ast.CmpGt, ast.CmpGe:
		return emitIPv6OrderedCmp(pred, pc, fieldOff), nil
	}
	return nil, fmt.Errorf("%w: IPv6 literal cmp op %v not supported", ErrNotImplemented, pred.Op)
}

// ipv6AuxHalfCheck mirrors ipv6HalfCheck for the aux path: load via
// the auxLoadAt closure so the address-compute prelude (R5 = element
// start for dynamic / owner-bound modes) is reused across both halves.
// R2 is used as mask/host scratch instead of R5 so the element-start
// address survives between chunks (whereDynamicMultiByte's IPv6 path
// follows the same convention).
func ipv6AuxHalfCheck(loadAt auxLoadAt, chunkOff int, mask, host uint64, failLabel string) asm.Instructions {
	insns := loadAt(chunkOff, asm.DWord)
	if mask != ^uint64(0) {
		insns = append(insns,
			asm.LoadImm(asm.R2, int64(byteSwap(mask, 8)), asm.DWord),
			asm.And.Reg(asm.R3, asm.R2),
		)
	}
	insns = append(insns,
		asm.LoadImm(asm.R2, int64(byteSwap(host, 8)), asm.DWord),
		asm.JNE.Reg(asm.R3, asm.R2, failLabel),
	)
	return insns
}

// emitIPv6OrderedCmp emits the lexicographic compare for `field <op>
// literal` where op ∈ {<, ≤, >, ≥} and field is a 128-bit IPv6
// address (F3). Algorithm:
//
//	load + host-swap high half of field into R3
//	reg-cmp R3 against literal high:
//	  - if `op` is "strictly more permissive" (e.g. < and field<lit) → match
//	  - if `op` is "strictly impossible" (e.g. < and field>lit) → fail
//	  - if equal → fall through to low check
//	load + host-swap low half of field into R3
//	reg-cmp R3 against literal low (same op as the original):
//	  - on miss → fail
//	  - on match → success
//
// Match success falls through to the next predicate; mismatches jump
// to dslReject. We use a per-predicate match landing so the early
// "high half decides" exit can skip the low half emit.
func emitIPv6OrderedCmp(pred *ir.Predicate, pc *predCtx, fieldOff int) asm.Instructions {
	highHostOrder := binary.BigEndian.Uint64(pred.Value.V6[0:8])
	lowHostOrder := binary.BigEndian.Uint64(pred.Value.V6[8:16])
	matchLabel := nextPredicateMatchLabel()

	highSuccess, highFail := highHalfJumps(pred.Op)
	lowMissJump := lowHalfMissJump(pred.Op)

	var insns asm.Instructions
	// High half: load → bswap → cmp.
	insns = append(insns, emitFieldLoad(pc.fieldAnchor(), fieldOff, asm.DWord)...)
	insns = append(insns, asm.HostTo(asm.BE, asm.R3, asm.DWord))
	insns = append(insns, asm.LoadImm(asm.R5, int64(highHostOrder), asm.DWord))
	insns = append(insns, highSuccess.Reg(asm.R3, asm.R5, matchLabel))
	insns = append(insns, highFail.Reg(asm.R3, asm.R5, dslReject))
	// High half equal — proceed to low half.
	insns = append(insns, emitBoundedLoad(asm.R3, int16(fieldOff+8), asm.DWord, dslReject)...)
	insns = append(insns, asm.HostTo(asm.BE, asm.R3, asm.DWord))
	insns = append(insns, asm.LoadImm(asm.R5, int64(lowHostOrder), asm.DWord))
	insns = append(insns, lowMissJump.Reg(asm.R3, asm.R5, dslReject))
	// Match landing — both the early "high decides" exit and the
	// low-half pass land here, then fall through to the next predicate.
	insns = append(insns, landingNoop(matchLabel))
	return insns
}

// highHalfJumps returns the (success, fail) reg-reg jump ops for the
// high-half lexicographic decision under cmp op `op`. "Success" means
// the high half alone proves the inequality; "fail" means the high
// half alone disproves it. The equal case falls through to the
// caller's low-half emit.
func highHalfJumps(op ast.CmpOp) (asm.JumpOp, asm.JumpOp) {
	switch op {
	case ast.CmpLt, ast.CmpLe:
		// field < lit ⟸ high(field) < high(lit)
		// field > lit ⟸ high(field) > high(lit) (so fail high if >)
		return asm.JLT, asm.JGT
	case ast.CmpGt, ast.CmpGe:
		return asm.JGT, asm.JLT
	}
	return 0, 0
}

// lowHalfMissJump returns the reg-reg jump op that *fails* (= jumps
// to dslReject) on the low half. For `<` we miss when low(field) ≥
// low(lit); for `≤` we miss when low(field) > low(lit); etc.
func lowHalfMissJump(op ast.CmpOp) asm.JumpOp {
	switch op {
	case ast.CmpLt:
		return asm.JGE
	case ast.CmpLe:
		return asm.JGT
	case ast.CmpGt:
		return asm.JLE
	case ast.CmpGe:
		return asm.JLT
	}
	return 0
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
func emitIPv6CIDRPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if err := requireEqualityOp(pred, "IPv6 CIDR"); err != nil {
		return nil, err
	}
	prefix := pred.Value.Prefix
	if prefix < 0 || prefix > 128 {
		return nil, fmt.Errorf("codegen: IPv6 CIDR prefix %d out of [0,128]", prefix)
	}
	if prefix == 128 {
		return emitIPv6Predicate(pred, pc)
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

	if pred.Field != nil && pred.Field.Aux != nil {
		if pred.Field.EffectiveBits() != 128 {
			return nil, fmt.Errorf("%w: IPv6 CIDR needs a 128-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam, pred.Field.Field.Name, pred.Field.EffectiveBits())
		}
		prelude, loadAt, err := auxLoadEmitter(pred.Field, r4Anchor(), nil, dslReject)
		if err != nil {
			return nil, err
		}
		insns := append(asm.Instructions{}, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
		insns = append(insns, prelude...)
		insns = append(insns, multiWordRoute(pred.Op, func(fail string) asm.Instructions {
			var body asm.Instructions
			if maskHighBE != 0 {
				body = append(body, ipv6AuxHalfCheck(loadAt, 0, maskHighBE, hostHighBE, fail)...)
			}
			if maskLowBE != 0 {
				body = append(body, ipv6AuxHalfCheck(loadAt, 8, maskLowBE, hostLowBE, fail)...)
			}
			return body
		})...)
		return insns, nil
	}

	fieldOff, err := requireIPv6Field(pred)
	if err != nil {
		return nil, err
	}
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
	insns := emitBoundedLoad(asm.R3, off, asm.DWord, dslReject)
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
// (after its bit-slice, if any) once the window is exactly 16 bytes.
func requireIPv6Field(pred *ir.Predicate) (int, error) {
	off, bytes, err := whereLiteralFieldOffset(pred.Field)
	if err != nil {
		return 0, err
	}
	if bytes != 16 {
		return 0, fmt.Errorf("%w: IPv6 literal needs a 16-byte field, got %d-byte %s.%s", ErrNotImplemented, bytes, pred.Field.Layer.Spec.Name, pred.Field.Field.Name)
	}
	return off, nil
}

// emitMACPredicate handles `field == de:ad:be:ef:00:01` (and !=). MAC
// fields are `bit<48>` (eth.dst, eth.src), so the body splits into a
// 4-byte Word load (top 4 octets) plus a 2-byte Half load (bottom 2).
// The address base is cached in R5 so the second LDX skips the Mov+Add
// rebuild — both JNE.Imm comparisons fit in 32 bits and so leave R5
// untouched. The == / != branching shape comes from multiWordRoute.
func emitMACPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if err := requireEqualityOp(pred, "MAC literal"); err != nil {
		return nil, err
	}
	mac := pred.Value.MAC
	highLE := uint32(byteSwap(uint64(binary.BigEndian.Uint32(mac[0:4])), 4))
	lowLE := uint16(byteSwap(uint64(binary.BigEndian.Uint16(mac[4:6])), 2))

	if pred.Field != nil && pred.Field.Aux != nil {
		if pred.Field.EffectiveBits() != 48 {
			return nil, fmt.Errorf("%w: MAC literal needs a 48-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam, pred.Field.Field.Name, pred.Field.EffectiveBits())
		}
		prelude, loadAt, err := auxLoadEmitter(pred.Field, r4Anchor(), nil, dslReject)
		if err != nil {
			return nil, err
		}
		insns := append(asm.Instructions{}, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
		insns = append(insns, prelude...)
		insns = append(insns, multiWordRoute(pred.Op, func(fail string) asm.Instructions {
			body := loadAt(0, asm.Word)
			body = append(body,
				asm.LoadImm(asm.R2, int64(uint64(highLE)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			)
			body = append(body, loadAt(4, asm.Half)...)
			body = append(body,
				asm.LoadImm(asm.R2, int64(uint64(lowLE)), asm.DWord),
				asm.JNE.Reg(asm.R3, asm.R2, fail),
			)
			return body
		})...)
		return insns, nil
	}

	fieldOff, bytes, err := whereLiteralFieldOffset(pred.Field)
	if err != nil {
		return nil, err
	}
	if bytes != 6 {
		return nil, fmt.Errorf("%w: MAC literal needs a 6-byte field, got %d-byte %s.%s", ErrNotImplemented, bytes, pred.Field.Layer.Spec.Name, pred.Field.Field.Name)
	}
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

// emitInPredicate handles `field in [v1, lo..hi, ...]`. The IR carries
// the field on pred.Field and the alternatives on pred.List; the
// resolver has already fit-checked each value and range bound against
// the field width. We load the field once, emit "if equal jump to
// match" for a value and "if below lo skip, if at most hi match" for a
// range (D-011), and jump to dslReject if none matched. A range needs
// the field in host order, so a list with a range byte-swaps the
// register once instead of swapping each constant.
//
// MVP scope (dsl-followups.md F7): integer and range alternatives, on
// fields ≤ 64 bits. IPv4 / IPv6 / MAC / CIDR alternatives stay as
// ErrNotImplemented since they would each need their own multi-
// word emit path; fold them in when there's user demand.
func emitInPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if len(pred.List) == 0 {
		return nil, fmt.Errorf("codegen: 'in' predicate has empty list")
	}
	hasRange := false
	for _, v := range pred.List {
		if v == nil || (v.Kind != ast.ValInt && v.Kind != ast.ValRange) {
			return nil, fmt.Errorf("%w: 'in' predicate currently supports only integer and range alternatives (got %v)", ErrNotImplemented, vKindOf(v))
		}
		if v.Kind == ast.ValRange {
			hasRange = true
		}
	}
	if pred.Field == nil || pred.Field.Field == nil {
		return nil, fmt.Errorf("codegen: 'in' predicate missing field reference")
	}
	fieldBits := pred.Field.EffectiveBits()
	if fieldBits <= 0 || fieldBits > 64 {
		return nil, fmt.Errorf("%w: 'in' on bit<%d> field — only ≤ bit<64> wired", ErrNotImplemented, fieldBits)
	}

	dynamic := needsEntryAddress(pred.Field)
	var insns asm.Instructions
	var bytes int
	var size asm.Size
	switch {
	case dynamic:
		_, bs, err := auxEntryFieldWindow(pred.Field)
		if err != nil {
			return nil, err
		}
		bytes = bs
		size, err = asmSizeFor(bytes)
		if err != nil {
			return nil, err
		}
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
		size, err = asmSizeFor(bs)
		if err != nil {
			return nil, err
		}
		if pred.Field.Aux != nil {
			insns = append(insns, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
		}
		insns = append(insns, emitFieldLoad(pc.fieldAnchor(), fieldOff, size)...)
	}

	// A sub-byte field (the load read a covering window to narrow) and a
	// range alternative (`lo ≤ v ≤ hi` is an ordered compare, the path
	// emitIntPredicate takes) both need R3 in host order; the
	// alternatives then stay unswapped.
	subByte := fieldIsSubByte(pred.Field) || pred.Field.Slice != nil
	hostOrder := subByte || hasRange
	if hostOrder && bytes > 1 {
		insns = append(insns, asm.HostTo(asm.BE, asm.R3, size))
	}
	if subByte {
		insns = append(insns, emitSliceShiftMask(pred.Field, bytes)...)
	}

	matchLabel := nextPredicateMatchLabel()
	// A range alternative's below-lo branch jumps to the next
	// alternative; the label lands on that alternative's first compare,
	// so `pending` carries it there instead of a filler instruction.
	pending := ""
	emit := func(ins asm.Instructions) {
		if pending != "" {
			ins[0] = ins[0].WithSymbol(pending)
			pending = ""
		}
		insns = append(insns, ins...)
	}
	for i, v := range pred.List {
		last := i+1 == len(pred.List)
		if v.Kind == ast.ValRange {
			// `lo ≤ R3 ≤ hi` in host order (D-011): below lo → next
			// alternative (the final reject for the last one), at most
			// hi → match. The resolver fit-checked both bounds.
			lo, hi := v.RangeLo, v.RangeHi
			next := dslReject
			if lo > 0 {
				if !last {
					next = nextPredicateLabel(predInNextLabelPrefix)
				}
				emit(cmpR3Const(asm.JLT, lo, next))
			}
			emit(cmpR3Const(asm.JLE, hi, matchLabel))
			if next != dslReject {
				pending = next
			}
			continue
		}
		value := v.Int
		if fieldBits < 64 {
			value &= (uint64(1) << fieldBits) - 1
		}
		// Multi-byte fields land in R3 in network-byte order packed
		// as little-endian; mirror emitIntPredicate by byte-swapping
		// the constant so a single JEq still matches. A register already
		// brought to host order (sub-byte field, or a list with a range)
		// compares against the plain constant.
		if bytes > 1 && !hostOrder {
			value = swapValueBytes(value, bytes)
		}
		emit(cmpR3Const(asm.JEq, value, matchLabel))
	}
	insns = append(insns, asm.Ja.Label(dslReject))
	insns = append(insns, landingNoop(matchLabel))
	return insns, nil
}

// cmpR3Const compares R3 against a constant: a single immediate compare
// when the value fits int32, else `LoadImm R5; <op>.Reg` so the compare
// stays an unsigned 64-bit one instead of sign-extending the immediate
// (the same shape as cmpRegEqU32, for any width up to 64 bits).
func cmpR3Const(jumpOp asm.JumpOp, value uint64, label string) asm.Instructions {
	if value <= 0x7FFFFFFF {
		return asm.Instructions{jumpOp.Imm(asm.R3, int32(value), label)}
	}
	return asm.Instructions{
		asm.LoadImm(asm.R5, int64(value), asm.DWord),
		jumpOp.Reg(asm.R3, asm.R5, label),
	}
}

// vKindOf is a nil-safe ValueKind extractor used in error messages
// to keep the formatter from blowing up on a malformed predicate.
func vKindOf(v *ast.Value) ast.ValueKind {
	if v == nil {
		return ast.ValueKind(0)
	}
	return v.Kind
}

// predMatchLabelPrefix is the label prefix multiWordRoute uses for
// `!=` match landings. Tests scanning emitted instructions for the
// landing symbol depend on this exact string.
const predMatchLabelPrefix = "dsl_pred_match_"

// predInNextLabelPrefix labels the fall-through of a range alternative
// inside an `in` list (not a match landing).
const predInNextLabelPrefix = "dsl_pred_in_next_"

// predLabelCounter feeds nextPredicateLabel. Atomic so concurrent
// Gen() calls produce non-colliding labels; labels are scoped to one
// instruction stream so a process-wide counter suffices for uniqueness.
var predLabelCounter atomic.Uint64

// nextPredicateLabel returns a fresh `<prefix><n>` label.
func nextPredicateLabel(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, predLabelCounter.Add(1))
}

func nextPredicateMatchLabel() string {
	return nextPredicateLabel(predMatchLabelPrefix)
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
func emitIPv4CIDRPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	prefix := pred.Value.Prefix
	if prefix < 0 || prefix > 32 {
		return nil, fmt.Errorf("codegen: IPv4 CIDR prefix %d out of [0,32]", prefix)
	}
	if prefix == 32 {
		return emitIPv4Predicate(pred, pc)
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

	if pred.Field != nil && pred.Field.Aux != nil {
		if pred.Field.EffectiveBits() != 32 {
			return nil, fmt.Errorf("%w: IPv4 CIDR needs a 32-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam, pred.Field.Field.Name, pred.Field.EffectiveBits())
		}
		prelude, loadAt, err := auxLoadEmitter(pred.Field, r4Anchor(), nil, dslReject)
		if err != nil {
			return nil, err
		}
		insns := append(asm.Instructions{}, emitAuxGating(pred.Field.Aux.Gating, r4Anchor(), dslReject)...)
		insns = append(insns, prelude...)
		insns = append(insns, loadAt(0, asm.Word)...)
		insns = append(insns, asm.And.Imm(asm.R3, int32(maskLE)))
		insns = append(insns, cmpRegEqU32(jumpOp, expectedLE, dslReject)...)
		return insns, nil
	}

	fieldOff, bytes, err := whereLiteralFieldOffset(pred.Field)
	if err != nil {
		return nil, err
	}
	if bytes != 4 {
		return nil, fmt.Errorf("%w: IPv4 CIDR needs a 4-byte field, got %d-byte %s.%s", ErrNotImplemented, bytes, pred.Field.Layer.Spec.Name, pred.Field.Field.Name)
	}
	insns := emitFieldLoad(pc.fieldAnchor(), fieldOff, asm.Word)
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
