package codegen

import (
	"fmt"
	"math/bits"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// variableTailSkip describes a header whose total wire size depends
// on a length field embedded in its fixed prefix. The codegen
// emits the fixed-prefix extract first, then a "tail skip" of
//
//	extra_bytes = base + ((loaded_len_byte & LenMask) << log2(scale))
//
// past the fixed prefix. LenMask extracts the length's wire-format bits.
// IPv6 uses all eight bits of hdr_ext_len: total = (hdr_ext_len + 1) * 8.
// The scalar and packet bounds reject lengths outside the scratch window.
//
// WriteBack opts into IPv6's "next_header" carry-forward pattern:
// after each ext-header iteration the codegen copies a byte from
// the just-extracted header into the layer's write-back slot
// (stackPlan.writeBack), the value the next layer's dispatch and
// every read of the parent field (e.g. ipv6.next_header) use; the
// parent field in the packet still reflects the *first* ext type.
// The packet itself is never written: the native XDP host runs the
// filter on the live packet, and the spec models the write-back as
// an overlay on the instance, not as a change to the bytes (D-032).
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
	// Slot is the R10-relative stack slot the byte is written to, bound
	// by the layer's emitter (pmCtx.bindWriteBackSlot); 0 means unbound.
	Slot int16
}

// variableTailFor lowers a vocab.HeaderAnnotations entry into the
// codegen-internal variableTailSkip the trail emit consumes. Returns
// ok=false when the header has no @kunai_variable_tail annotation
// (the common case — headers whose trailer is expressed natively via
// pkt.advance flow through state.Advances upstream).
func variableTailFor(spec *vocab.ProtocolSpec, headerName string) (variableTailSkip, bool) {
	if spec == nil || spec.HeaderAnnotations == nil {
		return variableTailSkip{}, false
	}
	ann, ok := spec.HeaderAnnotations[headerName]
	if !ok || ann == nil || ann.VariableTail == nil {
		return variableTailSkip{}, false
	}
	vt := variableTailSkip{
		LenFieldByteOff: ann.VariableTail.LenFieldByteOff,
		Scale:           ann.VariableTail.Scale,
		Base:            ann.VariableTail.Base,
		LenMask:         ann.VariableTail.LenMask,
		LenShift:        ann.VariableTail.LenShift,
		MinimumTotal:    ann.VariableTail.MinTotal,
	}
	if ann.WriteBack != nil {
		if !ann.WriteBack.Resolved {
			panic(fmt.Sprintf("codegen: WriteBackSpec for header %q referenced before resolveHeaderWritebackTargets ran (vocab loader bug — call vocab.Load not loadFile in isolation)", headerName))
		}
		vt.WriteBack = &writeBackOp{
			SourceByteOff: ann.WriteBack.SourceByteOff,
			ParentByteOff: ann.WriteBack.ParentByteOff,
		}
	}
	return vt, true
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

	// storeSlot stores val into the main frame's stack slot `slot`.
	// Differs between inline (R10-relative) and callback (through the
	// ctx pointer in R2, mainStackOffsetFromCb) so the caller supplies it.
	storeSlot func(slot int16, val asm.Register) asm.Instruction

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
//   - The pre-extract length byte is bounds checked before loading.
//     The resulting scalar offset is checked against ScratchBufSize
//     before its pointer is checked against the materialised packet end.
//     LenMask extracts wire-format bits; it must not truncate a length
//     merely to fit a verifier or iteration budget.
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
		// then bound-load into addrReg and keep it in the layer's
		// write-back slot; nothing is written into the packet.
		if wb.Slot >= 0 || env.storeSlot == nil {
			return nil, fmt.Errorf("codegen: write-back into parent byte %d has no stack slot bound (pmCtx.bindWriteBackSlot)", wb.ParentByteOff)
		}
		wbByteOff := int32(-fixedHs + wb.SourceByteOff)
		insns = append(insns, foldOffsetIntoScalar(env.lenReg, env.offset, wbByteOff, failLabel)...)
		insns = append(insns, boundedScalarLoad(env.addrReg, env.scratchStart, env.lenReg, env.scratchEnd, asm.Byte, failLabel)...)
		insns = append(insns, env.storeSlot(wb.Slot, env.addrReg))
	}

	// Length byte lives at R0 + R4 + (-fixedHs + LenFieldByteOff).
	// R4 has been pre-advanced past the fixed header (emitAdvance),
	// so the byte offset is negative — fold into a non-negative
	// scalar before the bounded load.
	loadByteOff := int32(-fixedHs + vt.LenFieldByteOff)
	insns = append(insns, foldOffsetIntoScalar(env.addrReg, env.offset, loadByteOff, failLabel)...)
	insns = append(insns, boundedScalarLoad(env.lenReg, env.scratchStart, env.addrReg, env.scratchEnd, asm.Byte, failLabel)...)
	insns = append(insns, emitTailLengthScalar(vt, shift, env.lenReg, failLabel)...)
	insns = append(insns,
		// Bound the scalar sum before forming a map-value pointer. A pointer
		// comparison alone cannot establish the verifier's map access range.
		asm.Add.Reg(env.offset, env.lenReg),
		asm.JGT.Imm(env.offset, int32(ScratchBufSize), failLabel),
		asm.Mov.Reg(env.addrReg, env.scratchStart),
		asm.Add.Reg(env.addrReg, env.offset),
		asm.JGT.Reg(env.addrReg, env.scratchEnd, failLabel),
	)
	insns = append(insns, env.storeOffsetBack...)
	return insns, nil
}

// emitTailLengthScalar turns the raw length byte in `reg` into the tail's
// byte count: `((byte & LenMask) >> LenShift) << log2(Scale)`, minus
// MinimumTotal (guarded) when the field encodes the total size, plus
// Base. `shift` is log2(vt.Scale), validated by the caller. Shared by the
// parser's advance (emitVariableTrail) and the where-side entry walk
// (emitStaticStackEntryAddress) so both measure an entry the same way.
//
// vt.MinValue would naturally emit a `JLT reg, MinValue, fail` guard
// before the bounds compute. In the bpf_loop callback path
// (parse_options self-loop) the extra branch inflates verifier state IDs
// across MAX_DEPTH iterations and trips the 1M insn limit on kernels 6.1
// / 6.6 / 6.12 / 6.18. Termination is still bounded by MAX_DEPTH, so a
// length=0/1 byte just costs MAX_DEPTH wasted iterations rather than
// spinning indefinitely; the guard is a polish item we defer until the
// callback can carry a tight early-exit label that won't accumulate
// scalar IDs.
func emitTailLengthScalar(vt variableTailSkip, shift int, reg asm.Register, failLabel string) asm.Instructions {
	var insns asm.Instructions
	if vt.LenMask != 0 {
		insns = append(insns, asm.And.Imm(reg, int32(vt.LenMask)))
	}
	if vt.LenShift > 0 {
		insns = append(insns, asm.RSh.Imm(reg, int32(vt.LenShift)))
	}
	if shift > 0 {
		insns = append(insns, asm.LSh.Imm(reg, int32(shift)))
	}
	if vt.MinimumTotal > 0 {
		insns = append(insns,
			asm.JLT.Imm(reg, int32(vt.MinimumTotal), failLabel),
			asm.Sub.Imm(reg, int32(vt.MinimumTotal)),
		)
	}
	if vt.Base != 0 {
		insns = append(insns, asm.Add.Imm(reg, int32(vt.Base)))
	}
	return insns
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
		storeSlot: func(slot int16, val asm.Register) asm.Instruction {
			return asm.StoreMem(asm.R10, slot, val, asm.DWord)
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
		storeSlot: func(slot int16, val asm.Register) asm.Instruction {
			return asm.StoreMem(asm.R2, mainStackOffsetFromCb(slot), val, asm.DWord)
		},
		storeOffsetBack: asm.Instructions{
			asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R3, asm.DWord),
		},
	}, breakLabel)
}
