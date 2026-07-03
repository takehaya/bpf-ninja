package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
)

// emitTransitionWithSelfRewrite lowers a TransitionOp at the inline
// (non-callback) site. Terminal kinds jump to the layer's done/reject
// landings; direct/select jumps go to state labels. selfLabel is the
// optional self-loop redirection target — when non-empty, any branch
// whose target equals fromState is sent to selfLabel instead so the
// caller can stitch in a "fall through to bpf_loop call" landing.
// addr selects the select-key addressing strategy (direct vs stashed
// — see selectAddr).
func (c *pmCtx) emitTransitionWithSelfRewrite(t vocab.TransitionOp, fromState int, selfLabel string, addr selectAddr) (asm.Instructions, error) {
	switch t.Kind {
	case vocab.TransAccept:
		return asm.Instructions{asm.Ja.Label(c.doneLabel)}, nil
	case vocab.TransReject:
		return asm.Instructions{asm.Ja.Label(dslReject)}, nil
	case vocab.TransDirect:
		return asm.Instructions{asm.Ja.Label(c.targetLabel(t.Target, fromState, selfLabel))}, nil
	case vocab.TransSelect:
		if isCounterIsZeroSelect(t.Select) {
			return c.emitCounterIsZeroSelect(t.Select, func(target int) string {
				return c.targetLabel(target, fromState, selfLabel)
			}, inlineCounterEnv())
		}
		return c.emitSelectWithAddr(t.Select, fromState, selfLabel, addr)
	}
	return nil, fmt.Errorf("%w: parser-machine transition kind %d", ErrNotImplemented, t.Kind)
}

// isCounterIsZeroSelect reports whether a SelectOp's keys are a
// single `<counter>.is_zero()` peek — the shape that needs the
// counter-dispatch emit instead of the byte-keyed cascade.
func isCounterIsZeroSelect(sel *vocab.SelectOp) bool {
	if sel == nil || len(sel.Keys) != 1 {
		return false
	}
	return sel.Keys[0].Kind == vocab.SelectKeyCounterIsZero
}

// emitCounterIsZeroSelect emits a 2-arm branch on the counter slot.
// The branch helper is the same one emitSelectGeneric uses, so call-
// site (inline / callback) decides where each target lands.
func (c *pmCtx) emitCounterIsZeroSelect(sel *vocab.SelectOp, branch func(int) string, env counterEnv) (asm.Instructions, error) {
	trueLabel, falseLabel, err := counterIsZeroLabels(sel, branch)
	if err != nil {
		return nil, err
	}
	return c.emitCounterIsZeroBranches(sel.Keys[0].Counter, trueLabel, falseLabel, env)
}

// targetLabel maps a transition target index (state idx, accept/reject
// sentinels) to the label that branch should jump to. selfLabel is
// used for self-loop redirection — empty selfLabel means "no rewrite".
func (c *pmCtx) targetLabel(target, fromState int, selfLabel string) string {
	switch target {
	case vocab.StateAccept:
		return c.doneLabel
	case vocab.StateReject:
		return dslReject
	}
	if target == fromState && selfLabel != "" {
		return selfLabel
	}
	return c.stateLabel(target)
}

// emitSelectWithAddr lowers a `transition select(...)` block at the
// inline (main-program) site, using the supplied addressing
// strategy (direct or stash).
func (c *pmCtx) emitSelectWithAddr(sel *vocab.SelectOp, fromState int, selfLabel string, addr selectAddr) (asm.Instructions, error) {
	return c.emitSelectGeneric(sel, addr, func(target int) string {
		return c.targetLabel(target, fromState, selfLabel)
	})
}

// emitSelectGeneric emits the case-body cascade shared by inline and
// callback select lowerings:
//   - each case JNE-skips on every non-wildcard key, then Ja-jumps to
//     branch(kase.Target);
//   - an all-wildcard case is unconditional: every later case and the
//     default become dead code, so emission stops there;
//   - the trailing default fires when no case fully matched.
//
// addr supplies the addressing (which register receives the byte and
// how to materialise the just-extracted header's start) plus a
// label-tag that keeps inline and callback skip labels disjoint.
func (c *pmCtx) emitSelectGeneric(sel *vocab.SelectOp, addr selectAddr, branch func(int) string) (asm.Instructions, error) {
	if len(sel.Keys) == 0 {
		return nil, fmt.Errorf("codegen: select with no keys (parser=%s)", c.spec.Name)
	}
	keyShapes := make([]selectKeyShape, len(sel.Keys))
	for i, k := range sel.Keys {
		shape, err := c.resolveSelectKey(k)
		if err != nil {
			return nil, err
		}
		keyShapes[i] = shape
	}

	var insns asm.Instructions
	for _, kase := range sel.Cases {
		hasCompare := false
		caseSkip := fmt.Sprintf("%s_%s_%d_skip", c.labelNS, addr.labelTag, c.selectCounter())
		for keyIdx, mv := range kase.Values {
			if mv.IsWildcard {
				continue
			}
			insns = append(insns, emitKeyCompare(addr, keyShapes[keyIdx], keyIdx, mv.Value, caseSkip)...)
			hasCompare = true
		}
		insns = append(insns, asm.Ja.Label(branch(kase.Target)))
		if hasCompare {
			insns = append(insns, landingNoop(caseSkip))
		} else {
			return insns, nil
		}
	}
	insns = append(insns, asm.Ja.Label(branch(sel.Default)))
	return insns, nil
}

// selectKeyShape carries the byte-level encoding for one select key.
// It is the codegen-friendly version of vocab.SelectKey: the bit
// window has been resolved against the parser-bound header (primary,
// stack element, or unconsumed lookahead) and reduced to a load width
// plus byte-swap/shift/mask, so an LDX of loadSize followed by
// normalize() yields the right-aligned key value for the compare.
type selectKeyShape struct {
	// byteOffsetFromR4 is the byte offset relative to the *current*
	// offsetBase. Negative for SelectKeyField (the field lives in a
	// header already extracted, so R4 has advanced past it);
	// non-negative for SelectKeyLookahead (peeking at unconsumed
	// bytes from the cursor forward).
	byteOffsetFromR4 int
	// loadSize is the LDX width used to read the key (Byte for fields
	// and 8-bit lookaheads; Half/Word for wider lookaheads, where the
	// load reads the next power-of-two ≥ ceil(bits/8) bytes).
	loadSize asm.Size
	// bigEndian requests a HostTo(BE) byte-swap after a multi-byte
	// load so the wire value lands right-aligned in the register.
	bigEndian bool
	// mask is applied (And) after shifting; 0 means "no mask needed"
	// (the load size + shift already yield exactly the key bits).
	mask uint64
	// shift is the right shift to align the field to the LSB.
	shift uint
	// bits is the key's bit width.
	bits int
}

func (c *pmCtx) resolveSelectKey(sk vocab.SelectKey) (selectKeyShape, error) {
	switch sk.Kind {
	case vocab.SelectKeyField:
		return c.resolveFieldSelectKey(sk.Field)
	case vocab.SelectKeyLookahead:
		// Read the next power-of-two ≥ ceil(bits/8) bytes at the
		// cursor, byte-swap to host order (multi-byte only), and
		// right-shift so the key's bits land in the LSBs. Allowed
		// widths are gated in vocab/parser_machine.go::buildSelect
		// (8/16/24); the value (≤ 0xFFFFFF) still fits a JNE.Imm.
		loadBytes := loadBytesForBits(sk.Bits)
		loadSize, err := asmSizeFor(loadBytes)
		if err != nil {
			return selectKeyShape{}, fmt.Errorf("%w: lookahead select key %d bits: %v", ErrNotImplemented, sk.Bits, err)
		}
		// After load+swap+shift the value occupies exactly sk.Bits low
		// bits (the register zero-extends), so no mask is needed.
		return selectKeyShape{
			byteOffsetFromR4: 0,
			loadSize:         loadSize,
			bigEndian:        loadBytes > 1,
			mask:             0,
			shift:            uint(loadBytes*8 - sk.Bits),
			bits:             sk.Bits,
		}, nil
	default:
		return selectKeyShape{}, fmt.Errorf("%w: unknown SelectKey kind %d", ErrNotImplemented, sk.Kind)
	}
}

func (c *pmCtx) resolveFieldSelectKey(k vocab.FieldRef) (selectKeyShape, error) {
	if k.BitOffset%8+k.BitWidth > 8 {
		return selectKeyShape{}, fmt.Errorf("%w: select key %s.%s straddles byte boundary (bit_offset=%d width=%d)", ErrNotImplemented, k.HeaderName, k.FieldName, k.BitOffset, k.BitWidth)
	}
	if k.BitWidth > 8 {
		return selectKeyShape{}, fmt.Errorf("%w: select key %s.%s is %d bits; MVP supports up to 8", ErrNotImplemented, k.HeaderName, k.FieldName, k.BitWidth)
	}
	headerBytes := p4HeaderBytes(k.HeaderRef)
	byteInHeader := k.BitOffset / 8
	bitInByte := k.BitOffset % 8
	shift := uint(8-k.BitWidth) - uint(bitInByte)
	// A full-byte field needs no mask after the shift; a sub-byte
	// field masks down to its width.
	var mask uint64
	if k.BitWidth < 8 {
		mask = (uint64(1) << k.BitWidth) - 1
	}

	// The selected header lies at [R4 - headerBytes, R4) when that
	// header is the just-extracted one. For `stack.last`, the just-
	// pushed element is at the same window. So byteOffsetFromR4 is
	// negative.
	off := byteInHeader - headerBytes

	return selectKeyShape{
		byteOffsetFromR4: off,
		loadSize:         asm.Byte,
		bigEndian:        false,
		mask:             mask,
		shift:            shift,
		bits:             k.BitWidth,
	}, nil
}

// lookaheadKindShape resolves the shape of the lookahead (kind) key in
// a select tuple — the key the dispatch and the dynamic-aux slot
// prelude both read. Returns an error if the select has no lookahead
// key (a counter-only select never reaches a kind-keyed prelude).
func (c *pmCtx) lookaheadKindShape(sel *vocab.SelectOp) (selectKeyShape, error) {
	for _, k := range sel.Keys {
		if k.Kind == vocab.SelectKeyLookahead {
			return c.resolveSelectKey(k)
		}
	}
	return selectKeyShape{}, fmt.Errorf("%w: dynamic-aux slot prelude with no lookahead select key", ErrNotImplemented)
}

// selectPeekBytes returns how many bytes the widest lookahead key in a
// select tuple loads, so the pre-dispatch bounds check covers it.
// Non-lookahead keys read no cursor bytes; at least 1 byte is peeked.
func selectPeekBytes(sel *vocab.SelectOp) int {
	n := 1
	for _, k := range sel.Keys {
		if k.Kind == vocab.SelectKeyLookahead {
			if b := loadBytesForBits(k.Bits); b > n {
				n = b
			}
		}
	}
	return n
}

// loadBytesForBits returns the LDX width (1/2/4 bytes) that holds a
// lookahead key of the given bit width: the next power of two ≥
// ceil(bits/8). The power-of-two policy lives in nextLDXSize; widths
// are gated to 8/16/24 upstream, so this never exceeds 4.
func loadBytesForBits(bits int) int {
	return nextLDXSize((bits + 7) / 8)
}

// p4HeaderBytes sums a p4lite.Header's field widths in bytes.
// vocab loader has already validated byte alignment for any header
// reachable from a parser block, so the modulo is exactly zero here.
func p4HeaderBytes(h *p4lite.Header) int {
	bits := 0
	for _, f := range h.Fields {
		bits += f.Bits
	}
	return bits / 8
}

// selectAddr captures how a transition-select key reads its byte.
// Two computed strategies plus an indirect one:
//
//  1. Inline: scratchStart=R0, scratchEnd=R1, offsetReg=R4 (offsetBase),
//     scalarReg=R5, dst=R3.
//  2. Callback: scratchStart=R4, scratchEnd=R5, offsetReg=R3,
//     scalarReg=R1, dst=R0.
//  3. Stash: read pre-loaded byte from R10[stashSlots[i]] (used when
//     a preceding variable-length trail already moved offsetBase past
//     the header the select references).
//
// Computed strategies use foldOffsetIntoScalar + boundedScalarLoad
// rather than direct PTR_TO_PACKET arithmetic so the load survives
// the verifier even when offsetBase is a range (e.g. after a chain
// of pkt.advance templates earlier in the layer stack accumulated
// uncertainty into offsetBase).
//
// pktFailLabel receives the underflow / out-of-bounds jump for the
// computed strategies (typically dslReject for inline, breakLabel
// for callback). labelTag keeps per-case skip labels disjoint across
// the variants.
//
// offsetIsConst flips emitKeyCompare onto the fast path (3-insn
// direct LDX) when offsetReg carries a verifier-constant value. The
// bounded path is unconditionally correct but adds ~5 insns per key
// for the underflow/overflow gate that a constant offset doesn't
// need. Set true for inline paths reachable only through fixed-
// layout layers, and false for callback paths or any path whose
// preceding layer body added a runtime range to offsetReg.
type selectAddr struct {
	dst           asm.Register
	offsetReg     asm.Register
	scalarReg     asm.Register
	scratchStart  asm.Register
	scratchEnd    asm.Register
	pktFailLabel  string
	labelTag      string
	offsetIsConst bool
	fromStash     bool         // true: read from R10[stashSlots[i]] instead of computing the byte
	stashR10      asm.Register // R10 of the right frame (main vs callback)
	stashSlots    [3]int16     // stack slot per key index; only first len(keys) entries used
}

var inlineSelectAddr = selectAddr{
	dst:          asm.R3,
	offsetReg:    offsetBase,
	scalarReg:    asm.R5,
	scratchStart: asm.R0,
	scratchEnd:   asm.R1,
	pktFailLabel: dslReject,
	labelTag:     "case",
}

// callbackSelectAddr returns the addressing strategy for a transition
// select inside a bpf_loop callback. labelTag and pktFailLabel are
// caller-supplied so different subprograms keep their case-skip labels
// disjoint and route bound failures to their own break landings.
func callbackSelectAddr(labelTag, breakLabel string) selectAddr {
	return selectAddr{
		dst:          asm.R0,
		offsetReg:    asm.R3,
		scalarReg:    asm.R1,
		scratchStart: asm.R4,
		scratchEnd:   asm.R5,
		pktFailLabel: breakLabel,
		labelTag:     labelTag,
	}
}

// stashKeySlots picks the kunai-internal stack slots used to spill
// pre-loaded select-key bytes. Reused across inline and callback
// (each frame has its own R10) so they cannot collide.
var stashKeySlots = [3]int16{-56, -64, -72}

// emitKeyCompare emits the per-case load + compare. Three shapes:
//
//   - fromStash: the key byte was pre-loaded into a stack slot before
//     a preceding variable trail moved offsetReg; just LDX the slot
//     and JNE caseSkip.
//   - offsetIsConst: offsetReg is a verifier-known constant scalar
//     (no preceding variable advance), so the verifier admits direct
//     PTR_TO_PACKET arithmetic — emit Mov dst,scratchStart; Add
//     dst,offsetReg; LoadMem dst,dst,byteOff,Byte (3 insns).
//   - default (range offsetReg): emit foldOffsetIntoScalar +
//     boundedScalarLoad so the verifier accepts the load even when
//     offsetReg has accumulated a range from a preceding pkt.advance.
//
// caseSkip is the per-case fall-through (next case or default).
// addr.pktFailLabel receives bounds failures (bounded path only).
func emitKeyCompare(addr selectAddr, shape selectKeyShape, keyIdx int, value uint64, caseSkip string) asm.Instructions {
	if value >= 1<<uint(shape.bits) {
		return asm.Instructions{asm.Ja.Label(caseSkip)}
	}
	if addr.fromStash {
		return asm.Instructions{
			asm.LoadMem(addr.dst, addr.stashR10, addr.stashSlots[keyIdx], asm.DWord),
			asm.JNE.Imm(addr.dst, int32(value), caseSkip),
		}
	}
	var insns asm.Instructions
	if addr.offsetIsConst {
		insns = append(insns,
			asm.Mov.Reg(addr.dst, addr.scratchStart),
			asm.Add.Reg(addr.dst, addr.offsetReg),
			asm.LoadMem(addr.dst, addr.dst, int16(shape.byteOffsetFromR4), shape.loadSize),
		)
	} else {
		insns = append(insns, foldOffsetIntoScalar(addr.scalarReg, addr.offsetReg, int32(shape.byteOffsetFromR4), addr.pktFailLabel)...)
		insns = append(insns, boundedScalarLoad(addr.dst, addr.scratchStart, addr.scalarReg, addr.scratchEnd, shape.loadSize, addr.pktFailLabel)...)
	}
	insns = append(insns, shape.normalize(addr.dst)...)
	insns = append(insns, asm.JNE.Imm(addr.dst, int32(value), caseSkip))
	return insns
}

// normalize turns a freshly-loaded key in dst into the right-aligned
// key value: byte-swap (multi-byte lookahead), right-shift to the LSB,
// and mask to the key width. Shared by emitKeyCompare and
// emitStashSelectKeys so the load → compare and load → stash paths
// agree bit-for-bit.
func (shape selectKeyShape) normalize(dst asm.Register) asm.Instructions {
	var insns asm.Instructions
	if shape.bigEndian {
		insns = append(insns, asm.HostTo(asm.BE, dst, shape.loadSize))
	}
	if shape.shift > 0 {
		insns = append(insns, asm.RSh.Imm(dst, int32(shape.shift)))
	}
	if shape.mask != 0 {
		insns = append(insns, asm.And.Imm(dst, int32(shape.mask)))
	}
	return insns
}

// emitStashSelectKeys emits the pre-load that copies each select
// key's byte (post-mask, post-shift) from scratch into stash slots
// before a variable-length trail moves offsetBase. The transition
// select runs after the trail and reads from the stash via
// selectAddr.fromStash. baseInsns produces the pointer "current
// header start" into `tempReg`; the helper appends the byte load
// and store to slot.
// stashEnv bundles the registers emitStashSelectKeys needs for
// packet-pointer-safe loads of select keys. Field naming mirrors
// trailEnv. addrReg is the load destination (also clobbered as a
// packet-pointer scratch). scalarReg is a scalar scratch — must
// differ from addrReg and from the other env registers. offset is
// the running scalar offset into the packet (= R3 in callback).
type stashEnv struct {
	addrReg      asm.Register
	scalarReg    asm.Register
	offset       asm.Register
	scratchStart asm.Register
	scratchEnd   asm.Register
}

func emitStashSelectKeys(sel *vocab.SelectOp, c *pmCtx, env stashEnv, failLabel string) (asm.Instructions, error) {
	if len(sel.Keys) > len(stashKeySlots) {
		return nil, fmt.Errorf("%w: variable-trail select with %d keys exceeds stash slots", ErrNotImplemented, len(sel.Keys))
	}
	var insns asm.Instructions
	for i, k := range sel.Keys {
		shape, err := c.resolveSelectKey(k)
		if err != nil {
			return nil, err
		}
		// byteOffsetFromR4 can be negative (reading back into the
		// just-passed header). Fold to a non-negative scalar, then
		// bound-load.
		byteOff := int32(shape.byteOffsetFromR4)
		insns = append(insns, foldOffsetIntoScalar(env.scalarReg, env.offset, byteOff, failLabel)...)
		insns = append(insns, boundedScalarLoad(env.addrReg, env.scratchStart, env.scalarReg, env.scratchEnd, shape.loadSize, failLabel)...)
		insns = append(insns, shape.normalize(env.addrReg)...)
		insns = append(insns, asm.StoreMem(asm.R10, stashKeySlots[i], env.addrReg, asm.DWord))
	}
	return insns, nil
}

// emitSelfLoop emits the bpf_loop call wrapping iterations 1..N for
// a self-looping state. The callback re-runs the state body and
