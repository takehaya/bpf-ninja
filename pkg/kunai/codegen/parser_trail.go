package codegen

import (
	"fmt"
	"math/bits"

	"github.com/cilium/ebpf/asm"
)


// variableTailSkip describes a header whose total wire size depends
// on a length field embedded in its fixed prefix. The codegen
// emits the fixed-prefix extract first, then a "tail skip" of
//
//	extra_bytes = base + ((loaded_len_byte & LenMask) << log2(scale))
//
// past the fixed prefix. LenMask caps the variable advance per
// iteration so the verifier can propagate a static upper bound on
// the running offset; without it the verifier rejects the next
// iteration's load as potentially out of scratch range.
//
// For IPv6 extension headers (RFC 8200) the canonical formula is
// total = (hdr_ext_len + 1) * 8 — Scale=8, Base=0. The MVP cap of
// LenMask=0x03 truncates the chain to ext headers ≤ 32 bytes,
// which covers every well-formed HBH/Fragment/DestOpt seen in
// practice; widening the cap requires either a larger scratch
// buffer or a reduced max-depth.
//
// WriteBack opts into IPv6's "next_header" carry-forward pattern:
// after each ext-header iteration the codegen copies a byte from
// the just-extracted header back into the parent layer's header
// (e.g. ipv6.next_header) so the next layer's dispatch reads the
// final inner protocol — the parent field still reflects the
// *first* ext type otherwise. This is a standard XDP rewrite
// pattern (verifier-OK against PTR_TO_MAP_VALUE).
type variableTailSkip struct {
	LenFieldByteOff int
	Scale           int
	Base            int
	LenMask         int
	LenShift        int // right-shift after mask (TCP data_offset upper-nibble = 4)
	// MinimumTotal is the minimum byte count the (mask>>shift)*scale
	// product must reach for the packet to be acceptable. Non-zero
	// values trigger an unsigned underflow guard plus a subtract so
	// the resulting variable advance is always >= 0 — used by primary
	// headers whose length field encodes the total wire size (IPv4
	// IHL, TCP data_offset). Zero means "no minimum, no subtract".
	MinimumTotal int
	WriteBack    *writeBackOp
}

// writeBackOp parameterises the parent-header field write-back. A
// nil pointer means the codegen skips the write-back step.
type writeBackOp struct {
	SourceByteOff int // byte offset in the just-extracted header
	ParentByteOff int // byte offset in the parent layer's header
}

// knownVariableTails enumerates the headers whose extracts pull a
// variable trailer past the byte-aligned minimum prefix.
//
//   - ipv6_ext_h: per-iteration HBH/Fragment/DestOpt walking. The
//     write-back keeps ipv6.next_header in sync with the chain tail
//     so the next layer's dispatch (TCP_IPV6_NEXT_HEADER etc.) sees
//     the inner protocol rather than the first ext type.
//
// srv6_h was migrated to a native pkt.advance in srv6.p4's
// skip_segments state; the trail params (Scale=8, Mask=0x0F, etc.)
// now flow through the existing AdvanceOp path that emits the same
// variableTailSkip via state.Advances in parser_state.go.
var knownVariableTails = map[string]variableTailSkip{
	"ipv6_ext_h": {
		LenFieldByteOff: 1,
		Scale:           8,
		Base:            0,
		LenMask:         0x03,
		WriteBack: &writeBackOp{
			SourceByteOff: 0,
			ParentByteOff: 6,
		},
	},
}

// log2PowerOfTwo returns log2(n) when n is a positive power of two,
// else -1. Used to convert byte multipliers (Scale, ElemSize) into
// shift counts; callers fall back / surface a clear error on -1.
func log2PowerOfTwo(n int) int {
	if n <= 0 || n&(n-1) != 0 {
		return -1
	}
	return bits.TrailingZeros(uint(n))
}

// trailEnv parameterises the register conventions used by the two
// sites that emit a variable-length advance: the inline path (after
// extract during state body emit) and the bpf_loop callback path
// (per-iteration suffix). Concrete instances live next to each
// caller, so the shared body in emitVariableTrail does not have to
// branch on inline-vs-callback at every step.
type trailEnv struct {
	scratchStart asm.Register // pointer to start of scratch buffer
	offset       asm.Register // running scratch-relative offset
	scratchEnd   asm.Register // upper bound for the bounds check
	lenReg       asm.Register // holds the variable advance amount
	addrReg      asm.Register // scratch for address arithmetic

	// loadLayerEntry loads the parent layer's entry offset into
	// lenReg (used as a temporary). Differs between inline (stack
	// slot anchored on R10) and callback (struct field on the ctx
	// pointer in R2) so the caller supplies the load.
	loadLayerEntry asm.Instructions

	// storeOffsetBack persists offset back to the bpf_loop ctx in
	// the callback path; empty for inline.
	storeOffsetBack asm.Instructions
}

// emitVariableTrail emits the shared "consume the variable trailer
// of the just-extracted header" sequence. Both the inline and
// callback sites compute identical work modulo register choice and
// where layer_entry / current offset live, so they share this body
// to keep the verifier-friendly invariants (length cap, scalar
// narrowing, optional WriteBack) in one place.
//
// Clobbers env.lenReg and env.addrReg; callers must treat both as
// scratch after the returned instructions run. The offset register
// (env.offset) is updated in place; everything else is preserved.
//
// Verifier safety invariants the emitted sequence relies on:
//
//   - The pre-extract length byte sits at a known byte offset within
//     scratch; LenMask × Scale × bpf_loop iter cap stays under
//     ScratchBufSize so the per-iteration scalar JGT against
//     ScratchBufSize-1 propagates a tight bound.
//   - In the callback path env.scratchStart / scratchEnd come from
//     the bpf_loop ctx pointer (R2). The kernel guarantees R2 is
//     non-NULL on callback entry — verifier accepts the deref
//     without an explicit null check. The inline path uses R0/R1
//     which the host wrapper already proved live.
func emitVariableTrail(fixedHs int, vt variableTailSkip, env trailEnv, failLabel string) (asm.Instructions, error) {
	shift := log2PowerOfTwo(vt.Scale)
	if shift < 0 {
		return nil, fmt.Errorf("%w: variable-trail scale %d is not a power of two", ErrNotImplemented, vt.Scale)
	}

	var insns asm.Instructions
	if wb := vt.WriteBack; wb != nil {
		// Source byte lives at R0 + R4 + (-fixedHs + SourceByteOff).
		// R4 is post-advance so the offset is negative — fold to
		// non-negative scalar (in lenReg, overwritten by the load),
		// then bound-load into addrReg. The subsequent loadLayerEntry
		// reuses lenReg for the writeback target offset.
		wbByteOff := int32(-fixedHs + wb.SourceByteOff)
		insns = append(insns, foldOffsetIntoScalar(env.lenReg, env.offset, wbByteOff, failLabel)...)
		insns = append(insns, boundedScalarLoad(env.addrReg, env.scratchStart, env.lenReg, env.scratchEnd, asm.Byte, failLabel)...)
		insns = append(insns, env.loadLayerEntry...)
		insns = append(insns,
			asm.Add.Reg(env.lenReg, env.scratchStart),
			asm.StoreMem(env.lenReg, int16(wb.ParentByteOff), env.addrReg, asm.Byte),
		)
	}

	// Length byte lives at R0 + R4 + (-fixedHs + LenFieldByteOff).
	// R4 has been pre-advanced past the fixed header (emitAdvance),
	// so the byte offset is negative — fold into a non-negative
	// scalar before the bounded load.
	loadByteOff := int32(-fixedHs + vt.LenFieldByteOff)
	insns = append(insns, foldOffsetIntoScalar(env.addrReg, env.offset, loadByteOff, failLabel)...)
	insns = append(insns, boundedScalarLoad(env.lenReg, env.scratchStart, env.addrReg, env.scratchEnd, asm.Byte, failLabel)...)
	if vt.LenMask != 0 {
		insns = append(insns, asm.And.Imm(env.lenReg, int32(vt.LenMask)))
	}
	if vt.LenShift > 0 {
		insns = append(insns, asm.RSh.Imm(env.lenReg, int32(vt.LenShift)))
	}
	if shift > 0 {
		insns = append(insns, asm.LSh.Imm(env.lenReg, int32(shift)))
	}
	if vt.MinimumTotal > 0 {
		insns = append(insns,
			asm.JLT.Imm(env.lenReg, int32(vt.MinimumTotal), failLabel),
			asm.Sub.Imm(env.lenReg, int32(vt.MinimumTotal)),
		)
	}
	// vt.MinValue would naturally emit a `JLT lenReg, MinValue, fail`
	// guard before the bounds compute. In the bpf_loop callback path
	// (parse_options self-loop) the extra branch inflates verifier
	// state IDs across MAX_DEPTH iterations and trips the 1M insn
	// limit on kernels 6.1 / 6.6 / 6.12 / 6.18. Termination is still
	// bounded by MAX_DEPTH, so a length=0/1 byte just costs MAX_DEPTH
	// wasted iterations rather than spinning indefinitely; the guard
	// is a polish item we defer until the callback can carry a tight
	// early-exit label that won't accumulate scalar IDs.
	if vt.Base != 0 {
		insns = append(insns, asm.Add.Imm(env.lenReg, int32(vt.Base)))
	}
	insns = append(insns,
		asm.Mov.Reg(env.addrReg, env.scratchStart),
		asm.Add.Reg(env.addrReg, env.offset),
		asm.Add.Reg(env.addrReg, env.lenReg),
		asm.JGT.Reg(env.addrReg, env.scratchEnd, failLabel),
		asm.Add.Reg(env.offset, env.lenReg),
		// Narrow offset's static range so subsequent layers' loads
		// stay within the verifier's view of the scratch buffer.
		// The pointer bound check above already enforces this at
		// runtime; the scalar JGT is the verifier-friendly restate.
		asm.JGT.Imm(env.offset, int32(ScratchBufSize)-1, failLabel),
	)
	insns = append(insns, env.storeOffsetBack...)
	return insns, nil
}

// emitVariableTrailInline is the inline-path facade over
// emitVariableTrail: scratch_start=R0, offset=offsetBase(R4),
// scratch_end=R1, scratchA(len)=R5, scratchB(addr)=R3, layer_entry
// from the R10 stack slot.
func emitVariableTrailInline(fixedHs int, vt variableTailSkip, failLabel string) (asm.Instructions, error) {
	return emitVariableTrail(fixedHs, vt, trailEnv{
		scratchStart: asm.R0,
		offset:       offsetBase,
		scratchEnd:   asm.R1,
		lenReg:       asm.R5,
		addrReg:      asm.R3,
		loadLayerEntry: asm.Instructions{
			asm.LoadMem(asm.R5, asm.R10, bpfLoopCtxLayerEntrySlot, asm.DWord),
		},
	}, failLabel)
}

// emitVariableTrailCallback is the bpf_loop-callback facade. The
// callback ABI puts scratch_start in R4, scratch_end in R5, the
// running offset in R3, and the ctx pointer in R2 — so the role
// each register plays is permuted relative to the inline path.
func emitVariableTrailCallback(fixedHs int, vt variableTailSkip, breakLabel string) (asm.Instructions, error) {
	return emitVariableTrail(fixedHs, vt, trailEnv{
		scratchStart: asm.R4,
		offset:       asm.R3,
		scratchEnd:   asm.R5,
		lenReg:       asm.R1,
		addrReg:      asm.R0,
		loadLayerEntry: asm.Instructions{
			asm.LoadMem(asm.R1, asm.R2, bpfLoopCbCtxLayerEntryField, asm.DWord),
		},
		storeOffsetBack: asm.Instructions{
			asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R3, asm.DWord),
		},
	}, breakLabel)
}
