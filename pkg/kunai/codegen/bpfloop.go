package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// chainCbProto is shared by every chain callback: `long (*)(u32 idx,
// void *ctx)` matches the bpf_loop helper's expected signature. Kept
// as a package var so cilium/ebpf's type deduper interns the
// FuncProto once across every chain layer in the program.
var chainCbProto = &btf.FuncProto{
	Return: btfLong,
	Params: []btf.FuncParam{
		{Name: "index", Type: btfU32},
		{Name: "ctx", Type: btfVoidPtr},
	},
}

// bpf_loop-based chain codegen for quantifiers the static unroll
// (chain.go) cannot cover: `+`, open-ended `{n,}`, and `{n,m}` with
// m > staticChainCap. The main program emits a single iteration with
// parent dispatch, then calls bpf_loop over a bpf2bpf callback that
// keeps advancing a stack-resident ctx while the self-dispatch peek
// keeps matching. On first mismatch (or bounds overrun) the callback
// returns 1 to terminate the loop.
//
// Only uniform chains with Field or NoCheck self-dispatch are covered
// by this commit; MPLS s-bit termination (a break condition baked into
// the callback) lands in a follow-up. `*` (RangeMin == 0) is likewise
// deferred — the whole-chain skip path needs more plumbing than is
// worth here.

// ctx layout on the main program's stack:
//
//	[-208..-200) offset       u64   current byte offset from scratch
//	[-200..-192) scratchStart u64   PTR_TO_MAP_VALUE at layer 0
//	[-192..-184) scratchEnd   u64   PTR_TO_MAP_VALUE + snap length
//	[-184..-176) layerEntry   u64   scalar offset of the current
//	                                parser-machine layer's first byte;
//	                                used by IPv6 ext-chain write-back.
//	                                Unused by chain (mpls+, vlan+)
//	                                bpf_loop calls — they leave the
//	                                slot as-is.
//
// The callback reads each via its second arg (R2 = &ctx at
// stack[-208]). bpfLoopCbCtx*Field are the offsets the callback uses
// against R2 — kept in sync with the stack-slot constants here so a
// future re-layout only edits one place. The arith stack bottom
// (slot 15 at -176 under maxArithDepth=16) sits flush against
// layerEntry's upper bound — the byte ranges [-176, -168) and
// [-184, -176) are disjoint, so packing without a margin is safe.
// The 16-byte gap [-224, -208) below ctx hosts the parser counter
// slots and provides the contract margin against
// whereLayerEntrySlotBase = -224.
const (
	bpfLoopCtxOffsetSlot       int16 = -208
	bpfLoopCtxScratchStartSlot int16 = -200
	bpfLoopCtxScratchEndSlot   int16 = -192
	bpfLoopCtxLayerEntrySlot   int16 = -184
	bpfLoopCtxBaseOffset       int32 = int32(bpfLoopCtxOffsetSlot)

	bpfLoopCbCtxOffsetField       int16 = 0
	bpfLoopCbCtxScratchStartField int16 = 8
	bpfLoopCbCtxScratchEndField   int16 = 16
	bpfLoopCbCtxLayerEntryField   int16 = 24
)

// mainStackOffsetFromCb translates a main-frame R10-relative stack
// slot into the equivalent R2-relative offset usable from inside a
// bpf_loop callback. R2 in the callback is the ctx pointer = main
// R10 + bpfLoopCtxOffsetSlot, so any access at `R2 + (slot -
// bpfLoopCtxOffsetSlot)` lands at `main R10 + slot`. Use this when
// a callback needs to read or write a slot the main frame owns
// (e.g. dynamic aux offset slots written by TLV-walk siblings).
func mainStackOffsetFromCb(slot int16) int16 {
	return slot - bpfLoopCtxOffsetSlot
}

// defaultChainDepth is the bpf_loop max_iter fallback used when the
// protocol's vocab did not declare a <SELF>_MAX_DEPTH.
const defaultChainDepth = 8

// bpfLoopChainCap bounds any user-declared or vocab-declared
// iteration count to something the verifier will accept without
// drama. Tighten if a lower number proves necessary on older kernels.
const bpfLoopChainCap = 32

// genBpfLoopChain handles `+`, `{n,}` and `{n,m>staticChainCap}`. It
// returns the main-program instructions that set up the call plus an
// optional callback stream the Gen-level orchestrator appends after
// the main Return. The returned callback always carries btf.Func
// metadata on its first instruction — required by the kernel for any
// bpf2bpf subprogram.
func genBpfLoopChain(layer *ir.LayerInstance, index int, all []*ir.LayerInstance) (asm.Instructions, asm.Instructions, error) {
	rangeMin, _ := chainBounds(layer)
	if rangeMin == 0 && index == 0 {
		return nil, nil, fmt.Errorf("%w: `*` on the first layer has no parent to peek", ErrNotImplemented)
	}
	hs, err := headerSize(layer.Spec)
	if err != nil {
		return nil, nil, err
	}

	selfConst := layer.Spec.SelectDispatchConst(layer.Spec.Name)
	if selfConst == nil {
		return nil, nil, fmt.Errorf("%w: chained %q has no self-dispatch const", ErrNotImplemented, layer.Spec.Name)
	}

	maxIter, err := chainMaxIter(layer)
	if err != nil {
		return nil, nil, err
	}

	cbSym := fmt.Sprintf("dsl_chain_cb_%d", index)
	callback, err := genBpfLoopCallback(layer.Spec, selfConst, hs, cbSym)
	if err != nil {
		return nil, nil, err
	}

	var mainInsns asm.Instructions
	chainDone := fmt.Sprintf("dsl_chain_done_%d", index)
	optionalChain := rangeMin == 0
	if optionalChain {
		// Whole-chain skip: peek the parent dispatch; on mismatch
		// jump past every iteration (including the bpf_loop call and
		// its reload) so offsetBase stays put for the next layer.
		body, err := emitPeekedIterZero(layer, index, all, chainDone)
		if err != nil {
			return nil, nil, err
		}
		mainInsns = append(mainInsns, body...)
	} else {
		// `+` / `{n,m}` with n ≥ 1: iteration 0 is a mandatory
		// parent-dispatched layer identical to a QuantOne.
		first, err := genStaticLayer(layer, index, all)
		if err != nil {
			return nil, nil, err
		}
		mainInsns = append(mainInsns, first...)
	}

	// Seed ctx with offsetBase + scratch_start/end, then call bpf_loop
	// with (max_iter, &cb, &ctx, flags=0). R0..R5 are caller-saved
	// across the helper so we must restore them from ctx afterwards.
	loopIter := int32(maxIter - 1)
	mainInsns = append(mainInsns,
		asm.StoreMem(asm.R10, bpfLoopCtxOffsetSlot, offsetBase, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchStartSlot, asm.R0, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchEndSlot, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, loopIter),
		loadFunctionRef(asm.R2, cbSym),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, bpfLoopCtxBaseOffset),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnLoop.Call(),
	)

	if rangeMin > 1 {
		// R0 now holds the iteration count the loop ran (0..loopIter).
		// Combined with the pre-loop iteration already at index 0 the
		// total must meet RangeMin.
		threshold := int32(rangeMin - 1)
		mainInsns = append(mainInsns, asm.JLT.Imm(asm.R0, threshold, dslReject))
	}

	// Reload the registers the helper clobbered. ctx.offset holds the
	// advanced offsetBase; scratch_start/end are unchanged but must be
	// re-loaded because the verifier dropped type info during the call.
	mainInsns = append(mainInsns,
		asm.LoadMem(offsetBase, asm.R10, bpfLoopCtxOffsetSlot, asm.DWord),
		asm.LoadMem(asm.R0, asm.R10, bpfLoopCtxScratchStartSlot, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, bpfLoopCtxScratchEndSlot, asm.DWord),
	)

	if optionalChain {
		// Landing for the `*` peek-miss path. The no-op must use a
		// register whose verifier type agrees on both paths: the
		// peek-miss path skipped the helper entirely, so R0 retains
		// the scratch_start PTR_TO_MAP_VALUE; the bpf_loop path
		// just reloaded it from ctx. R3 is caller-saved and would
		// land as !read_ok on the miss path.
		mainInsns = append(mainInsns, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(chainDone))
	}

	return mainInsns, callback, nil
}

// genBpfLoopCallback builds the bpf2bpf subprogram bpf_loop calls
// per iteration. The first instruction carries the callback's Symbol
// (so main's PseudoFunc load resolves) plus btf.Func metadata
// (required for bpf2bpf).
func genBpfLoopCallback(spec *vocab.ProtocolSpec, selfConst *vocab.DispatchConst, hs int, cbSym string) (asm.Instructions, error) {
	breakLabel := cbSym + "_break"

	first := asm.LoadMem(asm.R3, asm.R2, bpfLoopCbCtxOffsetField, asm.DWord).WithSymbol(cbSym)
	first = btf.WithFuncMetadata(first, chainCallbackFunc(cbSym))

	insns := asm.Instructions{
		first,
		asm.LoadMem(asm.R4, asm.R2, bpfLoopCbCtxScratchStartField, asm.DWord),
		asm.LoadMem(asm.R5, asm.R2, bpfLoopCbCtxScratchEndField, asm.DWord),

		// Bounds: scratch_start + offset + hs > scratch_end → break
		asm.Mov.Reg(asm.R0, asm.R4),
		asm.Add.Reg(asm.R0, asm.R3),
		asm.Add.Imm(asm.R0, int32(hs)),
		asm.JGT.Reg(asm.R0, asm.R5, breakLabel),
	}

	if selfConst.Type == vocab.DispatchField {
		peek, err := chainFieldPeek(spec, selfConst, hs, breakLabel)
		if err != nil {
			return nil, err
		}
		insns = append(insns, peek...)
	}
	// DispatchNoCheck contributes zero instructions — bounds alone
	// decides whether to continue.

	insns = append(insns,
		asm.Add.Imm(asm.R3, int32(hs)),
		asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R3, asm.DWord),
	)
	endCheck, err := chainEndCheck(spec, hs, breakLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, endCheck...)
	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0), // continue
		asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol(breakLabel), // break
		asm.Return(),
	)
	return insns, nil
}

// chainEndCheck emits the per-iteration termination check declared
// by the vocab via `<SELF>_CHAIN_END_<FIELD> = <value>`. Runs after
// the iteration advanced ctx.offset; reads the named field of the
// just-consumed header (R4 + R3 - hs + byteOff) and breaks the loop
// when it matches Value. Returns no instructions when the protocol
// declared no chain-end signal, in which case the chain terminates
// only on bounds overrun or self-dispatch mismatch.
//
// MVP supports two field shapes:
//   - byte-aligned, 8-bit: load byte, JNE Value
//   - sub-byte single-bit within a byte (e.g. MPLS s-bit): load byte,
//     mask, JNE shifted Value
//
// Wider byte-aligned fields (16/32-bit) and bit fields wider than 1
// are deliberately rejected so the codegen path stays auditable; add
// support when a real protocol needs it.
func chainEndCheck(spec *vocab.ProtocolSpec, hs int, breakLabel string) (asm.Instructions, error) {
	if spec.ChainEnd == nil {
		return nil, nil
	}
	byteOff, mask, expected, err := chainEndShape(spec)
	if err != nil {
		return nil, err
	}
	// Chain-end byte lives at R4 + R3 + (-hs + byteOff); R3 is
	// post-advance so the const offset is typically negative. R1 is
	// free in this callback frame (bpf_loop idx no longer used) — use
	// it as the scalar scratch.
	loadByteOff := int32(-hs + byteOff)
	insns := append(asm.Instructions{}, foldOffsetIntoScalar(asm.R1, asm.R3, loadByteOff, breakLabel)...)
	insns = append(insns, boundedScalarLoad(asm.R0, asm.R4, asm.R1, asm.R5, asm.Byte, breakLabel)...)
	if mask != 0xff {
		insns = append(insns, asm.And.Imm(asm.R0, int32(mask)))
	}
	// Break when the loaded value equals the chain-end value. MPLS
	// declares CHAIN_END_S = 1: "stop iterating when s == 1 (=
	// bottom of stack)".
	insns = append(insns, asm.JEq.Imm(asm.R0, int32(expected), breakLabel))
	return insns, nil
}

// chainEndShape resolves the vocab's CHAIN_END field into (byteOff,
// mask, expected) for a single-byte load. Returns ErrNotImplemented
// for shapes the MVP cannot encode (multi-byte fields, multi-bit
// sub-byte fields).
func chainEndShape(spec *vocab.ProtocolSpec) (byteOff int, mask uint8, expected uint8, err error) {
	bitOff, bits, err := findFieldBitOffset(spec, spec.ChainEnd.FieldName)
	if err != nil {
		return 0, 0, 0, err
	}
	if bits != spec.ChainEnd.Bits {
		return 0, 0, 0, fmt.Errorf("%w: chain-end const %q width %d != field %q width %d", ErrNotImplemented, spec.ChainEnd.Name, spec.ChainEnd.Bits, spec.ChainEnd.FieldName, bits)
	}
	byteOff, mask, expected, err = encodeChainEndField(bitOff, bits, spec.ChainEnd.Value)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%w: chain-end const %q: %v", ErrNotImplemented, spec.ChainEnd.Name, err)
	}
	return byteOff, mask, expected, nil
}

// encodeChainEndField turns the (header bit offset, width, value)
// triple into the byte offset and 8-bit mask/expected the
// single-byte load uses. Network bytes are big-endian on the wire,
// so within a byte the MSB sits at bit position 7 and a 1-bit field
// at header bit offset B lives at byte (B/8) bit position
// (7 - B%8). Multi-byte fields are not supported here; the caller
// is responsible for surfacing ErrNotImplemented.
func encodeChainEndField(bitOff, width int, value uint64) (byteOff int, mask uint8, expected uint8, err error) {
	if value >= 1<<width {
		return 0, 0, 0, fmt.Errorf("value %d does not fit in bit<%d>", value, width)
	}
	byteOff = bitOff / 8
	bitInByte := bitOff % 8
	switch {
	case bitInByte == 0 && width == 8:
		return byteOff, 0xff, uint8(value), nil
	case bitInByte+width <= 8 && width == 1:
		shift := 7 - bitInByte
		return byteOff, uint8(1) << shift, uint8(value) << shift, nil
	}
	return 0, 0, 0, fmt.Errorf("only byte-aligned 8-bit or single-bit fields supported, got bit_offset=%d width=%d", bitOff, width)
}

// chainFieldPeek reads the self-dispatch field of the previous
// instance and jumps to breakLabel on mismatch. Inside the callback
// R4=scratch_start, R5=scratch_end, R3=ctx.offset; the field lives at
// R4+R3+(fieldOff-hs) (negative const off — the read targets a
// position inside the just-consumed header).
//
// PTR_TO_PACKET-safe emit: pre-fold the negative offset into a
// non-negative scalar (R1, free in this callback frame) so the
// packet-pointer arithmetic uses only positive const offsets, then
// apply the cbpfc-style end+JGT+LoadMem(-size) pattern. See
// emitVariableTrail for the same invariant. Falls back to the simple
// emit (via emitFieldDispatchCheck) when the resolved offset turns
// out to be non-negative.
func chainFieldPeek(spec *vocab.ProtocolSpec, selfConst *vocab.DispatchConst, hs int, breakLabel string) (asm.Instructions, error) {
	fieldOff, fieldBytes, err := findFieldByteOffset(spec, selfConst.FieldName)
	if err != nil {
		return nil, err
	}
	loadByteOff := int32(fieldOff - hs)
	if loadByteOff >= 0 {
		return emitFieldDispatchCheck(
			spec,
			selfConst,
			hs,
			asm.R0,
			asm.Instructions{
				asm.Mov.Reg(asm.R0, asm.R4),
				asm.Add.Reg(asm.R0, asm.R3),
			},
			breakLabel,
		)
	}
	size, err := asmSizeFor(fieldBytes)
	if err != nil {
		return nil, err
	}
	expected := int32(byteSwap(selfConst.Value, fieldBytes))
	insns := append(asm.Instructions{}, foldOffsetIntoScalar(asm.R1, asm.R3, loadByteOff, breakLabel)...)
	insns = append(insns, boundedScalarLoad(asm.R0, asm.R4, asm.R1, asm.R5, size, breakLabel)...)
	insns = append(insns, asm.JNE.Imm(asm.R0, expected, breakLabel))
	return insns, nil
}

// chainBounds normalises QuantPlus / QuantStar / QuantRange into the
// (min, max) pair the bpf_loop path uses. `+` → (1, open), `*` → (0,
// open), `{n,m}` → (n, m as-stored). The second value is negative to
// signal "open-ended" so callers can consult the vocab's MaxDepth.
func chainBounds(layer *ir.LayerInstance) (int, int) {
	switch layer.Quant {
	case ast.QuantPlus:
		return 1, -1
	case ast.QuantStar:
		return 0, -1
	case ast.QuantRange:
		return layer.RangeMin, layer.RangeMax
	}
	return layer.RangeMin, layer.RangeMax
}

// chainMaxIter resolves RangeMax / MaxDepth / default into a concrete
// cap, clamped at bpfLoopChainCap.
func chainMaxIter(layer *ir.LayerInstance) (int, error) {
	_, max := chainBounds(layer)
	if max < 0 {
		max = layer.Spec.MaxDepth
		if max == 0 {
			max = defaultChainDepth
		}
	}
	if max < 1 {
		return 0, fmt.Errorf("%w: chain %q has non-positive iteration cap", ErrNotImplemented, layer.Spec.Name)
	}
	if max > bpfLoopChainCap {
		return 0, fmt.Errorf("%w: chain %q max iterations %d exceeds verifier-safe cap %d", ErrNotImplemented, layer.Spec.Name, max, bpfLoopChainCap)
	}
	return max, nil
}

// chainCallbackFunc wraps chainCbProto with a per-callback name. The
// btf.Func itself must be distinct per subprogram (different Name)
// but every shape below it is shared package-wide.
func chainCallbackFunc(name string) *btf.Func {
	return &btf.Func{
		Name:    name,
		Type:    chainCbProto,
		Linkage: btf.StaticFunc,
	}
}
