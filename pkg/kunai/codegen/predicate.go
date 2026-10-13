package codegen

import (
	"encoding/binary"
	"fmt"

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
// MAC. Each accepts == and !=; the ordered comparisons apply to
// integers and to the address literals (IPv4, IPv6, MAC), which the
// spec orders as the unsigned number of their wire bytes (cmpValue /
// cmpNat). A CIDR has no order and the resolver refuses one. Other
// shapes (range, ident, string) surface ErrNotImplemented so later
// phases can plug them in without touching the dispatch path.
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
	// An option extracted by a TLV walk (tcp.ts, ipv4.options.RR) has no
	// constant offset: the walk records where it found it in a dynamic-aux
	// slot (the demand walker registers bracket references too), and
	// splitPredicates runs the predicate after the walk, where pc carries
	// the slot. Anywhere else the option cannot be read; an absent option
	// makes the predicate false (D-027).
	if dynamicAuxLayoutOf(pred.Field) != nil {
		if _, ok := pc.optionSlotFor(pred.Field); !ok {
			return nil, fmt.Errorf("%w: bracket predicate on %s.%s, an option located by the parser's walk, here runs where the walk has not recorded it; move it to a where clause", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam)
		}
	}
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
	case pred.Field != nil && pred.Field.Aux != nil && pred.Field.Aux.OwnerOption != nil && pred.Field.Aux.Stack != nil && pred.Field.Aux.Stack.IsStatic:
		// A stack inside an option (tcp.options.SACK.blocks[1]) counts its
		// entries by the option's length byte; the predicate runs after the
		// walk (the option slot check above), as the where clause's guard
		// does.
		src, err := refCountSource(pred.Field)
		if err != nil {
			return nil, err
		}
		if src == nil || src.Owner == nil {
			return nil, fmt.Errorf("codegen: stack %s.%s inside an option has no count source", pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam)
		}
		slot, _ := pc.optionSlotFor(pred.Field)
		guard = emitOwnerCountGuard(slot, src, int(pred.Field.Aux.Stack.Static), dslReject)
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
			return nil, fmt.Errorf("%w: %s[options.valid] on a repeated fixed-length layer; move it to a where clause", ErrNotImplemented, pred.Field.Layer.Spec.Name)
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
	if k := pred.Value.Kind; (k == ast.ValIPv4 || k == ast.ValMAC || k == ast.ValCIDR) && sliceNeedsScalarLoad(pred.Field) {
		return emitLiteralScalarPredicate(pred, pc)
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

// sliceNeedsScalarLoad reports whether ref is a bit-slice with an end off
// a byte boundary. The resolver refuses such a slice above 64 bits, and
// types a network literal against the slice width, so the literals that
// reach one are 32 bits (IPv4) or 48 (MAC) wide: they compare against the
// slice's numeric value, read like an integer field's through a covering
// window, instead of byte by byte.
func sliceNeedsScalarLoad(ref *ir.FieldRef) bool {
	return ref != nil && ref.Slice != nil && (ref.Slice.Lo%8 != 0 || ref.Slice.Hi%8 != 0)
}

// emitLiteralScalarPredicate handles `field[lo:hi] op LITERAL` for a
// slice sliceNeedsScalarLoad accepts.
func emitLiteralScalarPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	insns, bytes, size, err := emitScalarFieldLoad(pred.Field, predicateLoadSite(pc))
	if err != nil {
		return nil, err
	}
	insns = append(insns, emitFieldValue(pred.Field, bytes, size)...)
	cmp, err := literalScalarCompare(pred.Value, pred.Op, dslReject)
	if err != nil {
		return nil, err
	}
	return append(insns, cmp...), nil
}

// literalScalarCompare compares R3, holding a field's numeric value in
// host order, against an IPv4, MAC or IPv4 CIDR literal read as the
// big-endian number of its bytes, and jumps to failLabel when `R3 op
// literal` does not hold. A CIDR masks R3 first; a /0 CIDR always
// matches, so `==` emits nothing and `!=` always fails.
func literalScalarCompare(v *ast.Value, op ast.CmpOp, failLabel string) (asm.Instructions, error) {
	jumpOp, ok := rejectingJumpOp(op)
	if !ok {
		return nil, fmt.Errorf("codegen: unknown comparison op %v", op)
	}
	switch {
	case v.Kind == ast.ValIPv4:
		return cmpR3Const(jumpOp, uint64(binary.BigEndian.Uint32(v.V4[:])), failLabel), nil
	case v.Kind == ast.ValMAC:
		return cmpR3Const(jumpOp, macValue(v), failLabel), nil
	case v.Kind == ast.ValCIDR && v.AF == 4:
		if _, eq := ipEqualityJumpOp(op); !eq {
			return nil, fmt.Errorf("%w: IPv4 CIDR supports only == / != (got %s)", ErrNotImplemented, op)
		}
		if v.Prefix <= 0 {
			if op == ast.CmpEq {
				return nil, nil
			}
			return constantFail(failLabel), nil
		}
		mask := ipv4PrefixMaskBE(v.Prefix)
		network := binary.BigEndian.Uint32(v.V4[:]) & mask
		// R3 holds at most 32 bits, so the sign-extended immediate
		// clears the same bits a zero-extended mask would.
		insns := asm.Instructions{asm.And.Imm(asm.R3, int32(mask))}
		return append(insns, cmpR3Const(jumpOp, uint64(network), failLabel)...), nil
	}
	return nil, fmt.Errorf("codegen: a %v literal cannot compare with a slice off byte boundaries", v.Kind)
}

// constantFail jumps to label on every packet: `!=` against a /0 CIDR
// holds for no address. The jump is conditional on a constant register,
// so the code after it stays reachable in the control-flow graph, which
// the kernel's load-time check demands of every instruction (an
// unconditional jump there fails the load with "unreachable insn"); the
// verifier then prunes the fall-through.
func constantFail(label string) asm.Instructions {
	return asm.Instructions{asm.Mov.Imm(asm.R3, 0), asm.JEq.Imm(asm.R3, 0, label)}
}

// macValue is a MAC literal as the 48-bit big-endian number of its bytes.
func macValue(v *ast.Value) uint64 {
	var n uint64
	for _, b := range v.MAC {
		n = n<<8 | uint64(b)
	}
	return n
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
	insns, bytes, size, err := emitScalarFieldLoad(pred.Field, predicateLoadSite(pc))
	if err != nil {
		return nil, err
	}
	switch {
	case fieldNeedsNarrowing(pred.Field) || (bytes > 1 && pred.Op != ast.CmpEq && pred.Op != ast.CmpNeq):
		// A slice-narrowed or sub-byte field (the load went through a
		// covering window) and an ordered compare both need the field's
		// numeric value in R3; the constant stays as the user wrote it.
		insns = append(insns, emitFieldValue(pred.Field, bytes, size)...)
	case bytes > 1:
		// Equality on a whole multi-byte field: byte-swap the constant
		// at codegen time and compare with the LE-loaded register.
		value = swapValueBytes(value, bytes)
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
	// labels numbers the labels of this compile (Gen's labeler); a
	// rebuilt predCtx carries it over.
	labels *labeler
	// stackCount resolves the push count slot of a push-counted stack
	// (option_demand.go needsPushCount). Set only where the predicates
	// run after the parser walk (splitPredicates), since the count is final
	// only then; nil means such an index cannot be guarded.
	stackCount func(*ir.FieldRef) (int16, bool)
	// optionSlot resolves the slot where the parser walk recorded an
	// option's position (dynamicAuxLayoutOf). Set only where the
	// predicates run after the walk; nil means an option field cannot be
	// read.
	optionSlot func(*ir.FieldRef) (int16, bool)
	// validSlot resolves a layer's option-validity slot, for
	// `[options.valid]`. Set with stackCount, after the walk.
	validSlot func(*ir.LayerInstance) (int16, bool)
	// accWhy says why the multi-option accumulator plan was refused
	// (buildAccPlan); the walk's refusal of two or more options appends it.
	accWhy string
	// guarded is the alternation member whose guard has just run its
	// parent dispatch (genAlternation); its body skips the identical
	// dispatch, which the guard already passed.
	guarded *ir.LayerInstance
	// anchor, when set, is where the predicates read the layer's primary
	// fields from; it carries the write-back overlay of a layer whose
	// predicates run after its walk (D-032). nil: R4 at entry.
	anchor *layerAnchor
}

// labelsOrNil is pc's labeler, nil for a nil pc (minting through it
// panics, see labeler.fresh).
func (pc *predCtx) labelsOrNil() *labeler {
	if pc == nil {
		return nil
	}
	return pc.labels
}

// freshLabel mints a label from pc's labeler.
func (pc *predCtx) freshLabel(prefix string) string {
	return pc.labelsOrNil().fresh(prefix)
}

// fieldAnchor is the anchor a predicate reads primary fields through.
func (pc *predCtx) fieldAnchor() layerAnchor {
	if pc != nil && pc.anchor != nil {
		return *pc.anchor
	}
	return r4Anchor()
}

// optionSlotFor is the slot holding where the walk found ref's option,
// when pc runs after the walk.
func (pc *predCtx) optionSlotFor(ref *ir.FieldRef) (int16, bool) {
	if pc == nil || pc.optionSlot == nil {
		return 0, false
	}
	return pc.optionSlot(ref)
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
	// A static index into variable-length entries (ipv6.exts[1]) has no
	// constant offset either: the entry is walked at run time
	// (emitScalarFieldLoad leaves R5 = entry start), the same read the
	// `==` and `in [...]` predicates use. The push-count guard genPredicate
	// prepends makes the entry present, and splitPredicates has placed
	// the predicate after the walk. An option the walk located is read off
	// its recorded position, after the walk too. No variable-length stack
	// and no option carries a 16-byte field.
	var fieldOff, bytes int
	var is128 bool
	var err error
	if needsEntryAddress(pred.Field) || dynamicAuxLayoutOf(pred.Field) != nil {
		_, bytes, err = scalarFieldWindow(pred.Field)
	} else if fieldOff, is128, err = field128RawOffset(pred.Field); err == nil {
		if is128 {
			bytes = 16
		} else {
			_, bytes, err = scalarFieldWindow(pred.Field)
		}
	}
	if err != nil {
		return nil, err
	}
	// bytes is 1/2/4/8 (scalarFieldWindow rejects wider) or 16 (the
	// is128 path), so no explicit 9..15 guard is needed here.
	// Require an exact width match: a narrower packet field would only
	// write a prefix of the key (relying on zero-fill), which silently
	// matches just zero-extended entries — a mis-configuration trap.
	// Size the set key field to the packet field's width.
	if bytes != slotSize {
		return nil, fmt.Errorf("packet field %q is %d bytes but set @%s key field %q is %d bytes; widths must match (create the set with a matching field type)", fieldName, bytes, pred.SetName, fieldName, slotSize)
	}

	var insns asm.Instructions

	// 16-byte (IPv6 address / SID): store the raw network-order bytes. A
	// walked entry never consults field128RawOffset, so a 16-byte field in
	// a variable-length stack (none exists) would fall to asmSizeFor and
	// its ErrNotImplemented rather than into this constant-offset copy.
	// Unlike the <=8 numeric path below, this is an identity byte copy —
	// emitBoundedLoad (LE load) then StoreMem (LE store) preserves wire
	// byte order, so NO HostTo is applied. `set add sid=fc00::1` writes
	// the same net.ParseIP().To16() bytes verbatim (setmap copies, not
	// putUint), so the key matches. Do not add a byte-swap here in any
	// later "unify the store path" refactor — it would reverse the SID on
	// a little-endian host and silently break every IPv6 match.
	if is128 {
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

	load, loaded, size, err := emitScalarFieldLoad(pred.Field, predicateLoadSite(pc))
	if err != nil {
		return nil, err
	}
	if loaded != bytes {
		return nil, fmt.Errorf("codegen: set key field %q sized %d bytes but read as %d", fieldName, bytes, loaded)
	}
	// Normalize the register to the field's numeric value in host order.
	insns = append(insns, load...)
	insns = append(insns, emitFieldValue(pred.Field, bytes, size)...)
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

// emitIPv4Predicate handles `field == 10.0.0.1`, `field != …` and the
// ordered comparisons. IPv4 fields (`bit<32>`, e.g. ipv4.src /
// ipv4.dst) are read as a 32-bit Word in little-endian on x86, so for
// equality we byte-swap the constant at codegen time and compare with a
// single JEq/JNE — same trick genFieldDispatch uses for protocol-id
// consts. An ordered compare swaps the register instead
// (emitOrderedWireCmp).
func emitIPv4Predicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if pred.Field == nil || pred.Field.Layer == nil || pred.Field.Field == nil {
		return nil, fmt.Errorf("codegen: IPv4 predicate missing field reference")
	}
	v4 := pred.Value.V4
	insns, loadAt, err := bracketLoadAt(pred.Field, pc, 4, "IPv4 literal")
	if err != nil {
		return nil, err
	}
	jumpOp, ok := ipEqualityJumpOp(pred.Op)
	if !ok {
		chunks := []wireChunk{{0, asm.Word, uint64(binary.BigEndian.Uint32(v4[:]))}}
		return append(insns, emitOrderedWireCmp(loadAt, chunks, pred.Op, bracketConstReg(pred.Field), pc.labelsOrNil())...), nil
	}
	expected := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v4[:])), 4))
	insns = append(insns, loadAt(0, asm.Word)...)
	insns = append(insns, cmpRegEqU32(jumpOp, expected, dslReject)...)
	return insns, nil
}

// bracketConstReg is the register a bracket emitter may hold a constant
// in next to R3: R2 when the field is an aux whose prelude may have left
// the entry address in R5, R5 otherwise (the primary emitters' habit, so
// their programs keep their bytes).
func bracketConstReg(ref *ir.FieldRef) asm.Register {
	if ref != nil && ref.Aux != nil {
		return asm.R2
	}
	return asm.R5
}

// wireChunk is one load of an ordered address compare: `size` bytes at
// `off` inside the field window, and the literal's bytes for that chunk
// read as a big-endian number.
type wireChunk struct {
	off   int
	size  asm.Size
	value uint64
}

// emitOrderedWireCmp compares the field against a literal under an
// ordered op (<, <=, >, >=) as unsigned numbers of their wire bytes, the
// order the spec gives address literals (cmpNat over liftValue). The
// field is read chunk by chunk through loadAt, each chunk byte-swapped
// to host order: for every chunk but the last a strict inequality of the
// chunk alone decides (success → match landing, the opposite → reject)
// and equality falls through to the next chunk; the last chunk applies
// the op itself. IPv4 is one Word, MAC a Word and a Half, IPv6 two
// DWords. constReg holds each chunk's constant (bracketConstReg).
func emitOrderedWireCmp(loadAt auxLoadAt, chunks []wireChunk, op ast.CmpOp, constReg asm.Register, labels *labeler) asm.Instructions {
	var insns asm.Instructions
	match := ""
	if len(chunks) > 1 {
		match = labels.fresh(predMatchLabel)
	}
	success, fail := highHalfJumps(op)
	miss := lowHalfMissJump(op)
	for i, c := range chunks {
		insns = append(insns, loadAt(c.off, c.size)...)
		insns = append(insns, asm.HostTo(asm.BE, asm.R3, c.size))
		insns = append(insns, asm.LoadImm(constReg, int64(c.value), asm.DWord))
		if i+1 < len(chunks) {
			insns = append(insns,
				success.Reg(asm.R3, constReg, match),
				fail.Reg(asm.R3, constReg, dslReject),
			)
			continue
		}
		insns = append(insns, miss.Reg(asm.R3, constReg, dslReject))
	}
	if match != "" {
		insns = append(insns, landingNoop(match))
	}
	return insns
}

// bracketAuxLoad is auxLoadEmitter for a bracket predicate: gating (an
// aux the walk extracts in place) or the option slot (an option the walk
// located, readable only after the walk) ahead of the addressing
// prelude, R4 at layer entry, dslReject when absent.
func bracketAuxLoad(ref *ir.FieldRef, pc *predCtx) (asm.Instructions, auxLoadAt, error) {
	prelude, loadAt, err := auxLoadEmitter(ref, r4Anchor(), pc.optionSlotFor, dslReject, pc.labelsOrNil())
	if err != nil {
		return nil, nil, err
	}
	var insns asm.Instructions
	if dynamicAuxLayoutOf(ref) == nil {
		insns = append(insns, emitAuxGating(ref.Aux.Gating, r4Anchor(), dslReject)...)
	}
	return append(insns, prelude...), loadAt, nil
}

// bracketLoadAt prepares the reads of a bracket predicate's field whose
// window must be exactly `bytes` wide (the literal's natural width after
// the slice): the prelude (aux presence gating and, for an entry whose
// offset is only known at run time, the address compute that leaves R5 =
// entry start) and a loadAt closure reading `size` bytes at `chunkOff`
// into R3. A primary field reads through pc.fieldAnchor(); an aux field
// through auxLoadEmitter. kind names the literal in the width error.
//
// Register discipline for the callers: R3 is the load destination; R2 is
// scratch that loadAt may clobber (an option's loadAt builds its pointer
// there), so a constant goes into R2 after the load; R5 is free only when
// the prelude is empty (primary or static aux), so a body that must work
// in every mode keeps its constants in R2 (ipv6AuxHalfCheck, macCheck).
func bracketLoadAt(ref *ir.FieldRef, pc *predCtx, bytes int, kind string) (asm.Instructions, auxLoadAt, error) {
	if ref == nil || ref.Layer == nil || ref.Field == nil {
		return nil, nil, fmt.Errorf("codegen: %s predicate missing field reference", kind)
	}
	if ref.Aux != nil {
		if ref.EffectiveBits() != bytes*8 {
			return nil, nil, fmt.Errorf("%w: %s needs a %d-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, kind, bytes*8, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.EffectiveBits())
		}
		return bracketAuxLoad(ref, pc)
	}
	fieldOff, got, err := literalFieldWindow(ref)
	if err != nil {
		return nil, nil, err
	}
	if got != bytes {
		return nil, nil, fmt.Errorf("%w: %s needs a %d-byte field, got %d-byte %s.%s", ErrNotImplemented, kind, bytes, got, ref.Layer.Spec.Name, ref.Field.Name)
	}
	anchor := pc.fieldAnchor()
	return nil, func(chunkOff int, size asm.Size) asm.Instructions {
		return emitFieldLoad(anchor, fieldOff+chunkOff, size)
	}, nil
}

// emitIPv6Predicate handles `field == fe80::1`, `field != fe80::1`,
// and the ordered comparisons `<` / `≤` / `>` / `≥` (F3) on primary and
// aux fields alike. IPv6 fields are `bit<128>`, too wide for a single
// LDX, so the body splits into two 8-byte LDX-DWord loads. For ==/!=
// each half is byte-swapped at codegen so the LE-reading LDX matches
// the BE constant. For ordered cmp emitOrderedWireCmp host-swaps the
// loaded register so its numeric ordering matches the literal, and
// lexicographic-compares the high half first.
func emitIPv6Predicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if _, eq := ipEqualityJumpOp(pred.Op); !eq {
		insns, loadAt, err := bracketLoadAt(pred.Field, pc, 16, "IPv6 literal")
		if err != nil {
			return nil, err
		}
		return append(insns, emitOrderedWireCmp(loadAt, ipv6Chunks(pred.Value), pred.Op, bracketConstReg(pred.Field), pc.labelsOrNil())...), nil
	}
	if pred.Field != nil && pred.Field.Aux != nil {
		if pred.Field.EffectiveBits() != 128 {
			return nil, fmt.Errorf("%w: IPv6 literal needs a 128-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam, pred.Field.Field.Name, pred.Field.EffectiveBits())
		}
		prelude, loadAt, err := bracketAuxLoad(pred.Field, pc)
		if err != nil {
			return nil, err
		}
		highBE := binary.BigEndian.Uint64(pred.Value.V6[0:8])
		lowBE := binary.BigEndian.Uint64(pred.Value.V6[8:16])
		insns := append(asm.Instructions{}, prelude...)
		insns = append(insns, multiWordRoute(pc.labelsOrNil(), pred.Op, func(fail string) asm.Instructions {
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
	highBE := binary.BigEndian.Uint64(pred.Value.V6[0:8])
	lowBE := binary.BigEndian.Uint64(pred.Value.V6[8:16])
	return multiWordRoute(pc.labelsOrNil(), pred.Op, func(fail string) asm.Instructions {
		var insns asm.Instructions
		insns = append(insns, ipv6HalfCheck(int16(fieldOff), ^uint64(0), highBE, fail)...)
		insns = append(insns, ipv6HalfCheck(int16(fieldOff+8), ^uint64(0), lowBE, fail)...)
		return insns
	}), nil
}

// ipv6Chunks splits an IPv6 literal into the two DWord chunks of an
// ordered compare, high half first.
func ipv6Chunks(v *ast.Value) []wireChunk {
	return []wireChunk{
		{0, asm.DWord, binary.BigEndian.Uint64(v.V6[0:8])},
		{8, asm.DWord, binary.BigEndian.Uint64(v.V6[8:16])},
	}
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

// highHalfJumps returns the (success, fail) reg-reg jump ops for a
// non-final chunk of an ordered multi-chunk compare (emitOrderedWireCmp,
// genArithCompare128). "Success" means the chunk alone proves the
// inequality; "fail" means it alone disproves it. The equal case falls
// through to the next chunk.
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
// to dslReject) on the final chunk. For `<` we miss when low(field) ≥
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
//   - /0 with != matches no address: always reject (constantFail).
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
		return constantFail(dslReject), nil
	}
	maskHighBE, maskLowBE := ipv6PrefixMaskBE(prefix)
	hostHighBE := binary.BigEndian.Uint64(pred.Value.V6[0:8]) & maskHighBE
	hostLowBE := binary.BigEndian.Uint64(pred.Value.V6[8:16]) & maskLowBE

	if pred.Field != nil && pred.Field.Aux != nil {
		if pred.Field.EffectiveBits() != 128 {
			return nil, fmt.Errorf("%w: IPv6 CIDR needs a 128-bit field, got %s.%s.%s (%d bits)", ErrNotImplemented, pred.Field.Layer.Spec.Name, pred.Field.Aux.OutParam, pred.Field.Field.Name, pred.Field.EffectiveBits())
		}
		prelude, loadAt, err := bracketAuxLoad(pred.Field, pc)
		if err != nil {
			return nil, err
		}
		insns := append(asm.Instructions{}, prelude...)
		insns = append(insns, multiWordRoute(pc.labelsOrNil(), pred.Op, func(fail string) asm.Instructions {
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
	return multiWordRoute(pc.labelsOrNil(), pred.Op, func(fail string) asm.Instructions {
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
	off, bytes, err := literalFieldWindow(pred.Field)
	if err != nil {
		return 0, err
	}
	if bytes != 16 {
		return 0, fmt.Errorf("%w: IPv6 literal needs a 16-byte field, got %d-byte %s.%s", ErrNotImplemented, bytes, pred.Field.Layer.Spec.Name, pred.Field.Field.Name)
	}
	return off, nil
}

// emitMACPredicate handles `field == de:ad:be:ef:00:01`, `!=` and the
// ordered comparisons. MAC fields are `bit<48>` (eth.dst, eth.src), so
// the body splits into a 4-byte Word load (top 4 octets) plus a 2-byte
// Half load (bottom 2), both bounded reads through the field's anchor
// (macCheck for equality, emitOrderedWireCmp otherwise). The == / !=
// branching shape comes from multiWordRoute.
func emitMACPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	insns, loadAt, err := bracketLoadAt(pred.Field, pc, 6, "MAC literal")
	if err != nil {
		return nil, err
	}
	if _, eq := ipEqualityJumpOp(pred.Op); !eq {
		mac := pred.Value.MAC
		chunks := []wireChunk{
			{0, asm.Word, uint64(binary.BigEndian.Uint32(mac[0:4]))},
			{4, asm.Half, uint64(binary.BigEndian.Uint16(mac[4:6]))},
		}
		return append(insns, emitOrderedWireCmp(loadAt, chunks, pred.Op, bracketConstReg(pred.Field), pc.labelsOrNil())...), nil
	}
	highLE, lowLE := macLiteralLE(pred.Value)
	insns = append(insns, multiWordRoute(pc.labelsOrNil(), pred.Op, func(fail string) asm.Instructions {
		return macCheck(loadAt, highLE, lowLE, fail)
	})...)
	return insns, nil
}

// macLiteralLE splits a MAC literal into the two constants macCheck
// compares against: the first four octets and the last two, each
// byte-swapped so an LE load of the wire bytes matches directly.
func macLiteralLE(v *ast.Value) (highLE uint32, lowLE uint16) {
	mac := v.MAC
	highLE = uint32(byteSwap(uint64(binary.BigEndian.Uint32(mac[0:4])), 4))
	lowLE = uint16(byteSwap(uint64(binary.BigEndian.Uint16(mac[4:6])), 2))
	return highLE, lowLE
}

// macCheck emits the two-chunk equality test of a 48-bit field against
// a MAC literal: a Word load compared with highLE, then a Half load
// compared with lowLE, each mismatch jumping to failLabel and a full
// match falling through. Constants live in R2 so the loads may be
// R5-relative (an entry whose address the prelude left in R5).
func macCheck(loadAt auxLoadAt, highLE uint32, lowLE uint16, failLabel string) asm.Instructions {
	body := loadAt(0, asm.Word)
	body = append(body,
		asm.LoadImm(asm.R2, int64(uint64(highLE)), asm.DWord),
		asm.JNE.Reg(asm.R3, asm.R2, failLabel),
	)
	body = append(body, loadAt(4, asm.Half)...)
	body = append(body,
		asm.LoadImm(asm.R2, int64(uint64(lowLE)), asm.DWord),
		asm.JNE.Reg(asm.R3, asm.R2, failLabel),
	)
	return body
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
// and != are valid here. labels comes first, unlike the other helpers,
// so the body closure stays the last argument.
func multiWordRoute(labels *labeler, op ast.CmpOp, body func(failLabel string) asm.Instructions) asm.Instructions {
	if op == ast.CmpEq {
		return body(dslReject)
	}
	match := labels.fresh(predMatchLabel)
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
// Address alternatives (the resolver typed each against the field's
// effective width, spec evalPred .inList: an OR of `==` and CIDR
// membership tests) split by the window they need. An IPv4 host or CIDR
// is a 32-bit integer and joins this load-once path, so it mixes freely
// with integers and ranges on the same field. IPv6 / CIDR6 (16 bytes)
// and MAC (6 bytes) do not fit one register and take emitInAddrList,
// which reloads the field per alternative, unless the field is a slice
// off byte boundaries (sliceNeedsScalarLoad): its MAC alternatives are
// numbers on the load-once path. An integer mixed into one of
// those lists stays ErrNotImplemented, as `ipv6[dst == 5]` does.
func emitInPredicate(pred *ir.Predicate, pc *predCtx) (asm.Instructions, error) {
	if len(pred.List) == 0 {
		return nil, fmt.Errorf("codegen: 'in' predicate has empty list")
	}
	if pred.Field == nil || pred.Field.Field == nil {
		return nil, fmt.Errorf("codegen: 'in' predicate missing field reference")
	}
	shape, hasRange, trivial, err := classifyInList(pred.List, sliceNeedsScalarLoad(pred.Field))
	if err != nil {
		return nil, err
	}
	if shape != inListScalar {
		return emitInAddrList(pred, pc, shape, trivial)
	}
	fieldBits := pred.Field.EffectiveBits()
	if fieldBits <= 0 || fieldBits > 64 {
		return nil, fmt.Errorf("%w: 'in' on bit<%d> field — only ≤ bit<64> wired", ErrNotImplemented, fieldBits)
	}

	insns, bytes, size, err := emitScalarFieldLoad(pred.Field, predicateLoadSite(pc))
	if err != nil {
		return nil, err
	}

	// A sub-byte field (the load read a covering window to narrow) and a
	// range alternative (`lo ≤ v ≤ hi` is an ordered compare, the path
	// emitIntPredicate takes) both need R3 in host order; the
	// alternatives then stay unswapped.
	hostOrder := hasRange || fieldNeedsNarrowing(pred.Field)
	if hostOrder {
		insns = append(insns, emitFieldValue(pred.Field, bytes, size)...)
	}
	// A /0 alternative matches every value: the list is true once the
	// field is readable (an absent aux still fails through the gating or
	// the entry walk above), and no compare may follow, or the kernel
	// would see unreachable instructions after the unconditional match.
	if trivial {
		return insns, nil
	}

	matchLabel := pc.freshLabel(predMatchLabel)
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
					next = pc.freshLabel(predInNextLabel)
				}
				emit(cmpR3Const(asm.JLT, lo, next))
			}
			emit(cmpR3Const(asm.JLE, hi, matchLabel))
			if next != dslReject {
				pending = next
			}
			continue
		}
		// An IPv4 CIDR masks a copy of the field (R2) so the register
		// stays whole for the remaining alternatives; the mask and the
		// network take the same byte order as the register. A /32 is a
		// host, a /0 was caught by classifyInList.
		if v.Kind == ast.ValCIDR && v.Prefix < 32 {
			maskBE := uint64(ipv4PrefixMaskBE(v.Prefix))
			netBE := uint64(binary.BigEndian.Uint32(v.V4[:])) & maskBE
			if bytes > 1 && !hostOrder {
				maskBE = swapValueBytes(maskBE, bytes)
				netBE = swapValueBytes(netBE, bytes)
			}
			body := asm.Instructions{
				asm.Mov.Reg(asm.R2, asm.R3),
				asm.And.Imm(asm.R2, int32(uint32(maskBE))),
			}
			emit(append(body, cmpRegConst(asm.R2, asm.JEq, netBE, matchLabel)...))
			continue
		}
		var value uint64
		switch v.Kind {
		case ast.ValIPv4, ast.ValCIDR:
			value = uint64(binary.BigEndian.Uint32(v.V4[:]))
		case ast.ValMAC:
			value = macValue(v)
		default:
			value = v.Int
		}
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

// inListShape is the lowering an `in` list takes, decided by the widest
// window its alternatives need.
type inListShape int

const (
	inListScalar inListShape = iota // integers, ranges, IPv4 hosts and CIDRs: one load, N compares
	inListIPv6                      // IPv6 hosts and CIDRs: 16-byte window, reload per alternative
	inListMAC                       // MAC addresses: 6-byte window, reload per alternative
)

// classifyInList sorts the alternatives of an `in` list into one shape,
// reports whether a range is present (the scalar path then compares in
// host order) and whether a /0 CIDR makes the list trivially true. Mixed
// kinds that no single register layout serves are ErrNotImplemented.
// scalarMAC is set for a slice off byte boundaries: its MAC alternatives
// are 48-bit numbers compared on the load-once path.
func classifyInList(list []*ast.Value, scalarMAC bool) (shape inListShape, hasRange, trivial bool, err error) {
	var scalar, v6, mac bool
	for _, v := range list {
		if v == nil {
			return 0, false, false, fmt.Errorf("codegen: nil alternative in 'in' list")
		}
		switch v.Kind {
		case ast.ValInt:
			scalar = true
		case ast.ValRange:
			scalar, hasRange = true, true
		case ast.ValIPv4:
			scalar = true
		case ast.ValMAC:
			if scalarMAC {
				scalar = true
			} else {
				mac = true
			}
		case ast.ValIPv6:
			v6 = true
		case ast.ValCIDR:
			if v.Prefix == 0 {
				trivial = true
			}
			if v.AF == 4 {
				scalar = true
			} else {
				v6 = true
			}
		default:
			return 0, false, false, fmt.Errorf("%w: 'in' predicate alternative of kind %v", ErrNotImplemented, v.Kind)
		}
	}
	switch {
	case scalar && !v6 && !mac:
		return inListScalar, hasRange, trivial, nil
	case v6 && !scalar && !mac:
		return inListIPv6, false, trivial, nil
	case mac && !scalar && !v6:
		return inListMAC, false, false, nil
	}
	return 0, false, false, fmt.Errorf("%w: 'in' list mixes integer alternatives with IPv6 or MAC addresses; a 128-bit or 48-bit field compares only against addresses of its own width", ErrNotImplemented)
}

// emitInAddrList lowers an `in` list of IPv6 (with CIDR6) or MAC
// alternatives. The field is wider than one register, so each
// alternative reloads it chunk by chunk through the loadAt closure (the
// prelude, gating and any entry-address compute run once) and compares
// with the same body the single-literal predicate uses, failing to the
// next alternative and jumping to the shared match landing on success.
// The last alternative fails straight to dslReject and falls through to
// the landing. Constants live in R2 (ipv6AuxHalfCheck, macCheck), so the
// body is valid in every bracket mode, including the one where R5 holds
// the entry address, and nothing touches the stack, so the callback
// replay of a repeated layer can run it.
func emitInAddrList(pred *ir.Predicate, pc *predCtx, shape inListShape, trivial bool) (asm.Instructions, error) {
	bytes, kind := 16, "IPv6 literal"
	if shape == inListMAC {
		bytes, kind = 6, "MAC literal"
	}
	insns, loadAt, err := bracketLoadAt(pred.Field, pc, bytes, kind)
	if err != nil {
		return nil, err
	}
	if trivial {
		// A /0 alternative matches every address once the field is
		// readable; see emitInPredicate.
		return insns, nil
	}
	match := pc.freshLabel(predMatchLabel)
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
		fail := dslReject
		if !last {
			fail = pc.freshLabel(predInNextLabel)
		}
		emit(emitAddrAlternative(v, loadAt, fail))
		if !last {
			insns = append(insns, asm.Ja.Label(match))
			pending = fail
		}
	}
	if len(pred.List) > 1 {
		insns = append(insns, landingNoop(match))
	}
	return insns, nil
}

// emitAddrAlternative is one alternative of emitInAddrList: the chunked
// equality (or masked CIDR) test of the field against v, every mismatch
// jumping to failLabel and a match falling through. classifyInList has
// excluded a /0 CIDR, so the body is never empty.
func emitAddrAlternative(v *ast.Value, loadAt auxLoadAt, failLabel string) asm.Instructions {
	switch v.Kind {
	case ast.ValMAC:
		highLE, lowLE := macLiteralLE(v)
		return macCheck(loadAt, highLE, lowLE, failLabel)
	case ast.ValIPv6, ast.ValCIDR:
		maskHigh, maskLow := ^uint64(0), ^uint64(0)
		if v.Kind == ast.ValCIDR {
			maskHigh, maskLow = ipv6PrefixMaskBE(v.Prefix)
		}
		highBE := binary.BigEndian.Uint64(v.V6[0:8]) & maskHigh
		lowBE := binary.BigEndian.Uint64(v.V6[8:16]) & maskLow
		var body asm.Instructions
		if maskHigh != 0 {
			body = append(body, ipv6AuxHalfCheck(loadAt, 0, maskHigh, highBE, failLabel)...)
		}
		if maskLow != 0 {
			body = append(body, ipv6AuxHalfCheck(loadAt, 8, maskLow, lowBE, failLabel)...)
		}
		return body
	}
	return nil
}

// cmpR3Const compares R3 against a constant: a single immediate compare
// when the value fits int32, else `LoadImm R5; <op>.Reg` so the compare
// stays an unsigned 64-bit one instead of sign-extending the immediate
// (the same shape as cmpRegEqU32, for any width up to 64 bits).
func cmpR3Const(jumpOp asm.JumpOp, value uint64, label string) asm.Instructions {
	return cmpRegConst(asm.R3, jumpOp, value, label)
}

// cmpRegConst is cmpR3Const for any register; the wide constant still
// goes through R5, so reg must not be R5.
func cmpRegConst(reg asm.Register, jumpOp asm.JumpOp, value uint64, label string) asm.Instructions {
	if value <= 0x7FFFFFFF {
		return asm.Instructions{jumpOp.Imm(reg, int32(value), label)}
	}
	return asm.Instructions{
		asm.LoadImm(asm.R5, int64(value), asm.DWord),
		jumpOp.Reg(reg, asm.R5, label),
	}
}

// predMatchLabel names the match landings of multi-word compares and
// `in` lists; predMatchLabelPrefix is the label it yields. Tests
// scanning emitted instructions for the landing symbol depend on this
// exact string.
const (
	predMatchLabel       = "pred_match"
	predMatchLabelPrefix = "dsl_" + predMatchLabel + "_"
)

// predInNextLabel names the fall-through of a range alternative inside
// an `in` list (not a match landing).
const (
	predInNextLabel       = "pred_in_next"
	predInNextLabelPrefix = "dsl_" + predInNextLabel + "_"
)

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
//   - /0 with != matches nothing — always reject (constantFail).
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
		return constantFail(dslReject), nil
	}
	maskBE := ipv4PrefixMaskBE(prefix)
	hostBE := binary.BigEndian.Uint32(pred.Value.V4[:]) & maskBE
	expectedLE := uint32(byteSwap(uint64(hostBE), 4))
	maskLE := uint32(byteSwap(uint64(maskBE), 4))

	insns, loadAt, err := bracketLoadAt(pred.Field, pc, 4, "IPv4 CIDR")
	if err != nil {
		return nil, err
	}
	insns = append(insns, loadAt(0, asm.Word)...)
	insns = append(insns, asm.And.Imm(asm.R3, int32(maskLE)))
	insns = append(insns, cmpRegEqU32(jumpOp, expectedLE, dslReject)...)
	return insns, nil
}

// ipEqualityJumpOp narrows rejectingJumpOp to the equality subset: the
// CIDR predicates support nothing else (the resolver refuses an ordered
// CIDR compare; this is defence in depth), and the address emitters use
// it to tell the equality path from emitOrderedWireCmp. Reuses
// rejectingJumpOp's table so the JEq/JNE mapping stays in one place.
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
