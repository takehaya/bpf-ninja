package codegen

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// staticAuxCap is the largest declared stack capacity for which an
// any()/all() walk stays on the static unroll (genQuantUnroll). Above
// it the walk lowers to a bpf_loop callback whose instruction count is
// flat in the capacity, mirroring staticChainCap for chain quantifiers.
// Kept small: a 1-2 element list is cheaper unrolled than paying the
// bpf_loop ctx setup + a separate bpf2bpf subprogram.
const staticAuxCap = 2

// useBpfLoopAuxWalk reports whether the quantifier should lower to a
// bpf_loop callback instead of the static unroll. The decision is by
// SHAPE, not protocol name: it accepts any aux-list walk whose inner is
// a single `<iterator-field> == <network-literal>` and that has a
// runtime element count (primary-header @kunai_stack_count OR an
// option-internal length). Field width (IPv4/IPv6/MAC) and count source
// (primary/owner) are both handled by the callback, so any future P4
// protocol declaring a large counted list gets the flat lowering for
// free. Richer inner conditions (or/not, !=, ordered, integer arith)
// and count-less stacks (gtp.exts/ipv6.exts) stay on the unroll path,
// which already supports them, so no shape regresses to a hard error.
func useBpfLoopAuxWalk(w *ir.Condition) (bool, error) {
	t := w.QuantTarget
	if t == nil || t.Capacity <= staticAuxCap {
		return false, nil
	}
	in := w.Inner
	if in == nil || in.Kind != ast.WAtomLiteralCmp || in.LiteralOp != ast.CmpEq {
		return false, nil
	}
	ref := in.LiteralField
	if ref == nil || ref.Aux == nil || ref.Aux.Stack == nil || !ref.Aux.Stack.IsIterator {
		return false, nil
	}
	if _, ok := auxWalkLiteralWidth(in.LiteralValue); !ok {
		return false, nil
	}
	cs, err := stackCountSource(w)
	if err != nil {
		return false, err
	}
	return cs != nil, nil
}

// auxWalkLiteralWidth reports the comparison's field byte width for the
// literal kinds the callback compare supports, and false otherwise. It
// is the gate's single source of truth for "supported shape" and must
// stay in sync with the switch in auxWalkCompare (whose default returns
// ErrNotImplemented as a backstop if the two ever diverge).
func auxWalkLiteralWidth(v *ast.Value) (int, bool) {
	switch v.Kind {
	case ast.ValIPv4:
		return 4, true
	case ast.ValIPv6:
		return 16, true
	case ast.ValMAC:
		return 6, true
	case ast.ValCIDR:
		if v.AF == 4 {
			return 4, true
		}
		return 16, true
	}
	return 0, false
}

// genQuantBpfLoop lowers an any()/all() walk over an aux header stack to
// a bpf_loop callback (instead of unrolling Capacity copies). The flat
// instruction count and cap-32 ceiling match how chain quantifiers are
// handled, removing the SRv6-capped-at-8 vs MPLS-scales-to-32 asymmetry.
//
// Flag plumbing reuses the bpf_loop ctx `offset` slot: an aux-walk has
// no running byte offset (it indexes by R1*ElemSize), so the slot is
// free to carry the result flag — any()'s "matched", all()'s "failed".
// The main program zero-inits it, the callback writes 1 on the decisive
// element, and the main program reads it after the loop.
//
// Two addressing modes are supported. A primary-counted stack (SRv6
// segments) is addressed relative to the owning layer's start, stored
// into ctx.layerEntry. An owner-option stack (TCP SACK, IPv4
// record-route) is addressed relative to the option base the parser
// stashed in a dynamic-aux slot, which the callback reads via the ctx
// pointer.
func (c *whereCtx) genQuantBpfLoop(w *ir.Condition, failLabel string, anySemantics bool) (asm.Instructions, error) {
	target := w.QuantTarget
	countSrc, err := stackCountSource(w)
	if err != nil {
		return nil, err
	}
	if countSrc == nil {
		return nil, fmt.Errorf("%w: bpf_loop aux walk needs a runtime count source", ErrNotImplemented)
	}
	if target.Capacity > bpfLoopChainCap {
		return nil, fmt.Errorf("%w: aux walk capacity %d exceeds verifier-safe cap %d", ErrNotImplemented, target.Capacity, bpfLoopChainCap)
	}

	var ownerSlot int16
	if countSrc.Owner != nil {
		slot, ok := c.queried.dynamicAuxSlotForLayout(countSrc.Layer, countSrc.Owner)
		if !ok {
			return nil, fmt.Errorf("codegen: aux walk owner option %q not in demand set for layer %q", countSrc.Owner.OutParam, countSrc.Layer.Spec.Name)
		}
		ownerSlot = slot
	}
	anchor, err := c.layerAnchorFor(target.Layer)
	if err != nil {
		return nil, err
	}

	cbSym := c.freshLabel("auxwalk_cb")
	cb, err := c.genAuxWalkCallback(w, countSrc, cbSym, anySemantics)
	if err != nil {
		return nil, err
	}
	c.callbacks = append(c.callbacks, cb...)

	// Seed ctx: scratchStart (R0) / scratchEnd (R1) / layerEntry, and
	// zero the flag (reused offset slot). Then bpf_loop(max_iter=Capacity,
	// &cb, &ctx, 0). R0..R5 are caller-saved across the helper.
	main := asm.Instructions{
		asm.StoreMem(asm.R10, bpfLoopCtxScratchStartSlot, asm.R0, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchEndSlot, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R3, 0),
		asm.StoreMem(asm.R10, bpfLoopCtxOffsetSlot, asm.R3, asm.DWord), // flag = 0
	}
	// Carry the per-element addressing base through the ctx layerEntry
	// field, a positive-offset ctx slot the callback reads at R2+24.
	// Primary stacks store the owning layer's start; owner-option stacks
	// store the option base the parser stashed in ownerSlot, read here in
	// the main frame. Routing the owner base through the ctx — rather than
	// letting the callback reach back into the parent frame at a negative
	// ctx offset — keeps every callback ctx access non-negative.
	//
	// The owner base may be the absent-option sentinel. Screen it HERE, in
	// the main frame, and skip the loop when absent (the flag stays 0, so
	// any() rejects and all() is vacuously true). The screen must not live
	// in the callback: a compare on the bare base register there mis-JITs
	// the dependent scratch load on kernel 6.6 (see
	// emitRuntimeAuxElementAddrOwner). With the loop skipped, the callback
	// only ever sees a present option, so it never branches on the base.
	skipLoop := c.freshLabel("auxwalk_skip")
	if countSrc.Owner != nil {
		main = append(main,
			asm.LoadMem(asm.R3, asm.R10, ownerSlot, asm.DWord),
			asm.JEq.Imm(asm.R3, dynamicAuxSentinel, skipLoop),
		)
	} else {
		main = append(main, emitLayerEntryToReg(anchor, asm.R3)...)
	}
	main = append(main,
		asm.StoreMem(asm.R10, bpfLoopCtxLayerEntrySlot, asm.R3, asm.DWord),
		asm.Mov.Imm(asm.R1, int32(target.Capacity)),
		loadFunctionRef(asm.R2, cbSym),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, bpfLoopCtxBaseOffset),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnLoop.Call(),
	)
	// Restore the scratch-window pointers the helper dropped, then read
	// the flag and branch. offsetBase is not restored: the where clause
	// addresses fields via scratchStart (R0) + a static/slot offset, not
	// via the running offsetBase, so the aux walk does not need it back.
	// An owner walk that skipped the loop lands here with the flag still 0.
	restore := asm.Instructions{
		asm.LoadMem(asm.R0, asm.R10, bpfLoopCtxScratchStartSlot, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, bpfLoopCtxScratchEndSlot, asm.DWord),
		asm.LoadMem(asm.R3, asm.R10, bpfLoopCtxOffsetSlot, asm.DWord),
	}
	if countSrc.Owner != nil {
		restore[0] = restore[0].WithSymbol(skipLoop)
	}
	main = append(main, restore...)
	if anySemantics {
		main = append(main, asm.JEq.Imm(asm.R3, 0, failLabel)) // no element matched → reject
	} else {
		main = append(main, asm.JNE.Imm(asm.R3, 0, failLabel)) // an element failed → reject
	}
	return main, nil
}

// emitLayerEntryToReg materialises the owning layer's scalar start
// offset (bytes from scratch start) into dst, for storing into the
// bpf_loop ctx so the callback can address elements relative to it.
func emitLayerEntryToReg(anchor layerAnchor, dst asm.Register) asm.Instructions {
	switch {
	case anchor.UseR4:
		return asm.Instructions{asm.Mov.Reg(dst, offsetBase)}
	case anchor.UseSlot:
		return asm.Instructions{asm.LoadMem(dst, asm.R10, anchor.SlotOff, asm.DWord)}
	default:
		return asm.Instructions{asm.Mov.Imm(dst, int32(anchor.AbsOffset))}
	}
}

// genAuxWalkCallback builds the bpf2bpf subprogram bpf_loop calls per
// element. Frame: R1 = element index, R2 = &ctx, R4 = scratchStart,
// R5 = scratchEnd (loaded up front); R0/R3 are scratch. Per iteration:
// stop at the runtime element count, compare the element field to the
// literal, and on the decisive element write the ctx flag and break.
func (c *whereCtx) genAuxWalkCallback(w *ir.Condition, countSrc *quantCountSource, cbSym string, anySemantics bool) (asm.Instructions, error) {
	target := w.QuantTarget
	inner := w.Inner
	ref := inner.LiteralField // pre-checked by useBpfLoopAuxWalk
	if ref.Aux.FieldBitOff%8 != 0 {
		return nil, fmt.Errorf("%w: aux walk field %s not byte-aligned", ErrNotImplemented, ref.Field.Name)
	}
	fieldByteOff := ref.Aux.FieldBitOff / 8

	breakLabel := cbSym + "_break"
	mismatchLabel := cbSym + "_mismatch"

	// load addresses the iterator element field at the runtime index R1.
	// Both modes read their addressing base from the ctx layerEntry field
	// (a positive ctx offset): primary stacks carry the owning layer's
	// start there, owner-option stacks carry the option base the main
	// program copied in from ownerSlot.
	var load elemLoader
	if countSrc.Owner != nil {
		load = func(off int, size asm.Size, fail string) asm.Instructions {
			return emitRuntimeAuxElementAddrOwner(target, ref.Aux.OffsetAfterOwner, fieldByteOff+off, size, fail)
		}
	} else {
		load = func(off int, size asm.Size, fail string) asm.Instructions {
			return emitRuntimeAuxElementAddr(target, fieldByteOff+off, size, fail)
		}
	}

	first := asm.LoadMem(asm.R4, asm.R2, bpfLoopCbCtxScratchStartField, asm.DWord).WithSymbol(cbSym)
	first = btf.WithFuncMetadata(first, chainCallbackFunc(cbSym))
	insns := asm.Instructions{
		first,
		asm.LoadMem(asm.R5, asm.R2, bpfLoopCbCtxScratchEndField, asm.DWord),
	}
	guard, err := auxWalkCountGuard(countSrc, breakLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, guard...)
	cmp, err := auxWalkCompare(load, inner.LiteralValue, mismatchLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, cmp...)

	// Fall-through == this element matched. The flag (ctx.offset slot)
	// and the bpf_loop return value invert between the two semantics:
	//   any(): match → flag=1, return 1 (break); miss → return 0
	//          (continue); exhaust → return 1. Flag stays 0 with no
	//          match, which the main program reads as "reject".
	//   all(): match → return 0 (continue); miss → flag=1, return 1
	//          (break, reject); exhaust → return 1. Flag 0 == "accept".
	if anySemantics {
		insns = append(insns,
			asm.Mov.Imm(asm.R0, 1),
			asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R0, asm.DWord), // flag = matched
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(), // break: a match is enough
			asm.Mov.Imm(asm.R0, 0).WithSymbol(mismatchLabel),
			asm.Return(), // continue to next element
			asm.Mov.Imm(asm.R0, 1).WithSymbol(breakLabel),
			asm.Return(), // exhausted: stop, flag reflects prior matches
		)
	} else {
		insns = append(insns,
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(), // continue: this element satisfies all()
			asm.Mov.Imm(asm.R0, 1).WithSymbol(mismatchLabel),
			asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R0, asm.DWord), // flag = failed
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(), // break: one failure rejects all()
			asm.Mov.Imm(asm.R0, 1).WithSymbol(breakLabel),
			asm.Return(), // exhausted: every real element matched
		)
	}
	if err := assertCallbackComplexity(insns, cbSym); err != nil {
		return nil, err
	}
	return insns, nil
}

// elemLoader loads `size` bytes of the iterator element field at
// `fieldByteOff` past the field start, for the bpf_loop index, into R0.
// It preserves R2 (=&ctx), R4 (scratchStart), R5 (scratchEnd) and uses
// R3 as scratch; an out-of-window read jumps to the supplied label.
type elemLoader func(fieldByteOff int, size asm.Size, fail string) asm.Instructions

// auxWalkCountGuard emits the per-iteration check that the element index
// (R1) is below the stack's runtime element count, breaking the loop
// when it is not. Primary stacks read the count from a layer field;
// owner-option stacks derive it from the option length byte.
func auxWalkCountGuard(countSrc *quantCountSource, breakLabel string) (asm.Instructions, error) {
	if countSrc.Owner != nil {
		// count = (optionLength - SubBefore) >> RShAfter; optionLength is
		// the byte at optionBase + ByteOff. optionBase scalar is carried in
		// the ctx layerEntry field (the main program copied it in from the
		// parser's ownerSlot), read at a positive ctx offset. The absent-
		// option sentinel is screened in the main program before the loop,
		// so this must not branch on the bare base (see
		// emitRuntimeAuxElementAddrOwner: a compare on R0-alone mis-JITs the
		// dependent load on kernel 6.6).
		insns := asm.Instructions{
			asm.LoadMem(asm.R0, asm.R2, bpfLoopCbCtxLayerEntryField, asm.DWord),
			asm.Add.Imm(asm.R0, int32(countSrc.ByteOff)),
			asm.Mov.Reg(asm.R3, asm.R0),
		}
		insns = append(insns, boundedScalarLoad(asm.R0, asm.R4, asm.R3, asm.R5, asm.Byte, breakLabel)...)
		insns = append(insns,
			asm.JLT.Imm(asm.R0, int32(countSrc.SubBefore), breakLabel),
			asm.Sub.Imm(asm.R0, int32(countSrc.SubBefore)),
			asm.RSh.Imm(asm.R0, int32(countSrc.RShAfter)),
			asm.JGE.Reg(asm.R1, asm.R0, breakLabel),
		)
		return insns, nil
	}
	// Primary: count = layer[ByteOff] + addend.
	insns := asm.Instructions{
		asm.LoadMem(asm.R0, asm.R2, bpfLoopCbCtxLayerEntryField, asm.DWord),
		asm.Add.Imm(asm.R0, int32(countSrc.ByteOff)),
		asm.Mov.Reg(asm.R3, asm.R0),
	}
	insns = append(insns, boundedScalarLoad(asm.R0, asm.R4, asm.R3, asm.R5, asm.Byte, breakLabel)...)
	insns = append(insns,
		asm.Add.Imm(asm.R0, int32(countSrc.Offset)),
		asm.JGE.Reg(asm.R1, asm.R0, breakLabel),
	)
	return insns, nil
}

// auxWalkCompare emits the element-vs-literal comparison inside the
// callback, dispatching on the literal kind/width. Fall-through means
// the element matched; any mismatch (or out-of-window load) jumps to
// mismatchLabel. Mirrors the main-frame compares but loads via the
// supplied elemLoader and keeps the comparison in R0/R3 so the callback
// frame's R2/R4/R5 survive.
func auxWalkCompare(load elemLoader, v *ast.Value, mismatchLabel string) (asm.Instructions, error) {
	switch v.Kind {
	case ast.ValIPv4:
		host := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v.V4[:])), 4))
		return auxWalkWord(load, 0, ^uint32(0), host, mismatchLabel), nil
	case ast.ValMAC:
		highLE := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v.MAC[0:4])), 4))
		lowLE := uint16(byteSwap(uint64(binary.BigEndian.Uint16(v.MAC[4:6])), 2))
		insns := auxWalkWord(load, 0, ^uint32(0), highLE, mismatchLabel)
		return append(insns, auxWalkHalfWord(load, 4, lowLE, mismatchLabel)...), nil
	case ast.ValIPv6:
		hi := binary.BigEndian.Uint64(v.V6[0:8])
		lo := binary.BigEndian.Uint64(v.V6[8:16])
		insns := auxWalkHalf(load, 0, ^uint64(0), hi, mismatchLabel)
		return append(insns, auxWalkHalf(load, 8, ^uint64(0), lo, mismatchLabel)...), nil
	case ast.ValCIDR:
		if v.AF == 4 {
			if v.Prefix < 0 || v.Prefix > 32 {
				return nil, fmt.Errorf("codegen: IPv4 CIDR prefix %d out of [0,32]", v.Prefix)
			}
			if v.Prefix == 0 {
				return nil, nil // /0 matches every element
			}
			maskBE := ipv4PrefixMaskBE(v.Prefix)
			host := uint32(byteSwap(uint64(binary.BigEndian.Uint32(v.V4[:])&maskBE), 4))
			mask := uint32(byteSwap(uint64(maskBE), 4))
			return auxWalkWord(load, 0, mask, host, mismatchLabel), nil
		}
		if v.Prefix < 0 || v.Prefix > 128 {
			return nil, fmt.Errorf("codegen: IPv6 CIDR prefix %d out of [0,128]", v.Prefix)
		}
		mh, ml := ipv6PrefixMaskBE(v.Prefix)
		var insns asm.Instructions
		if mh != 0 {
			insns = append(insns, auxWalkHalf(load, 0, mh, binary.BigEndian.Uint64(v.V6[0:8])&mh, mismatchLabel)...)
		}
		if ml != 0 {
			insns = append(insns, auxWalkHalf(load, 8, ml, binary.BigEndian.Uint64(v.V6[8:16])&ml, mismatchLabel)...)
		}
		return insns, nil
	}
	return nil, fmt.Errorf("%w: aux walk literal kind %v not supported", ErrNotImplemented, v.Kind)
}

// auxWalkHalf compares one 8-byte half (DWord) of the element field,
// optionally masked, to the literal half. R0 = value, R3 = scratch.
func auxWalkHalf(load elemLoader, off int, mask, host uint64, mismatchLabel string) asm.Instructions {
	insns := load(off, asm.DWord, mismatchLabel)
	if mask != ^uint64(0) {
		insns = append(insns,
			asm.LoadImm(asm.R3, int64(byteSwap(mask, 8)), asm.DWord),
			asm.And.Reg(asm.R0, asm.R3),
		)
	}
	insns = append(insns,
		asm.LoadImm(asm.R3, int64(byteSwap(host, 8)), asm.DWord),
		asm.JNE.Reg(asm.R0, asm.R3, mismatchLabel),
	)
	return insns
}

// auxWalkWord compares one 4-byte (Word) chunk, optionally masked. The
// host value is already host-order (little-endian of the wire bytes).
func auxWalkWord(load elemLoader, off int, mask, host uint32, mismatchLabel string) asm.Instructions {
	insns := load(off, asm.Word, mismatchLabel)
	if mask != ^uint32(0) {
		insns = append(insns, asm.And.Imm(asm.R0, int32(mask)))
	}
	return append(insns,
		asm.LoadImm(asm.R3, int64(uint64(host)), asm.DWord),
		asm.JNE.Reg(asm.R0, asm.R3, mismatchLabel),
	)
}

// auxWalkHalfWord compares one 2-byte (Half) chunk to a host-order value.
func auxWalkHalfWord(load elemLoader, off int, host uint16, mismatchLabel string) asm.Instructions {
	insns := load(off, asm.Half, mismatchLabel)
	return append(insns,
		asm.LoadImm(asm.R3, int64(uint64(host)), asm.DWord),
		asm.JNE.Reg(asm.R0, asm.R3, mismatchLabel),
	)
}
