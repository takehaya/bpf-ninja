package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
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
// Uniform chains with Field or NoCheck self-dispatch are covered. A
// chain-end protocol (MPLS) ends the loop on its s bit inside the
// callback, and `*` / `{0,m}` enter through the same peek-and-skip as
// `?` (emitPeekedIterZero): for a self edge the peek is the previous
// label's end signal.

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
// The 16 bytes [-224, -208) below ctx hold the parser counter slots;
// the stack plan (entry and dynamic aux slots) starts below them at
// stackPlanTop = -232.
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
const defaultChainDepth = vocab.DefaultMaxDepth

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
//
// s-bit termination here is exact for `+` and `*` (RangeMin ≤ 1,
// unbounded RangeMax): the callback breaks on the chain-end signal and the
// pre-loop check accepts a single-header stack as a valid natural end.
// Under-run is bounded for the bounded `{n,m>staticChainCap}` shape too:
// the pre-loop check rejects a single-header stack when RangeMin > 1, and
// the post-loop RangeMin floor rejects a multi-header under-run. Every
// iteration runs the layer's bounds check and bracket predicates; a
// failure there rejects the packet rather than ending the chain (D-001 /
// D-005 in spec/lean/DECISIONS.md). Over-run is bounded as on the static
// path: the header consumed by the last callback iteration must signal
// chain-end, else the stack is deeper than RangeMax (or MAX_DEPTH for
// `+` / `*`) allows and the packet rejects (D-024). Non-chain-end
// protocols (VLAN) bound both ends via their self-dispatch peek.
func genBpfLoopChain(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, qo queriedOptions, pc *predCtx) (asm.Instructions, asm.Instructions, error) {
	rangeMin, _ := chainBounds(layer)
	if rangeMin == 0 {
		if err := optionalLayerGuard(layer, index, all); err != nil {
			return nil, nil, err
		}
	}
	hs, err := headerSize(layer.Spec)
	if err != nil {
		return nil, nil, err
	}

	selfConst := layer.Spec.SelectDispatchConst(layer.Spec.Name)
	if selfConst == nil {
		return nil, nil, fmt.Errorf("%w: chained %q has no self-dispatch const", ErrNotImplemented, layer.Spec.Name)
	}
	// Same #11-class miscompile guard as genStaticChain — see chain.go.
	if layer.Spec.HasVariableLayout() {
		return nil, nil, fmt.Errorf("%w: `*`, `+` and `{n,}` on the variable-length %q are not implemented; write a bound of at most %d (`{n,m}`) or layered dispatch (`eth/%s/%s/...`)", ErrNotImplemented, layer.Spec.Name, staticChainCap, layer.Spec.Name, layer.Spec.Name)
	}

	maxIter, err := chainMaxIter(layer)
	if err != nil {
		return nil, nil, err
	}

	cbSym := fmt.Sprintf("dsl_chain_cb_%d", index)
	callback, err := genBpfLoopCallback(layer, selfConst, hs, cbSym, qo, pc)
	if err != nil {
		return nil, nil, err
	}

	var mainInsns asm.Instructions
	chainDone := fmt.Sprintf("dsl_chain_done_%d", index)
	optionalChain := rangeMin == 0
	// The absent edge (`*` with no header) gets its own label when it must
	// dispatch the next layer against the grandparent (D-034).
	absentLabel := chainDone
	if optionalChain && ir.AbsentEdgeApplies(all, index) {
		absentLabel = fmt.Sprintf("dsl_absent_%d", index)
	}
	// A marked `*` / `{0,m}` layer's entry slot reads "absent" until a
	// present iteration overwrites it (D-003).
	sentinel, err := emitLayerEntrySentinel(layer, qo)
	if err != nil {
		return nil, nil, err
	}
	mainInsns = append(mainInsns, sentinel...)
	if optionalChain {
		// Whole-chain skip: peek the parent dispatch; on mismatch
		// jump past every iteration (including the bpf_loop call and
		// its reload) so offsetBase stays put for the next layer.
		body, err := emitPeekedIterZero(layer, index, all, absentLabel, qo, pc)
		if err != nil {
			return nil, nil, err
		}
		mainInsns = append(mainInsns, body...)
	} else {
		// `+` / `{n,m}` with n ≥ 1: iteration 0 is a mandatory
		// parent-dispatched layer identical to a QuantOne.
		first, err := genStaticLayer(layer, index, all, qo, pc)
		if err != nil {
			return nil, nil, err
		}
		mainInsns = append(mainInsns, first...)
	}

	// Both branches above consumed iteration 0 and advanced offsetBase. If
	// that header already signals chain-end (e.g. an MPLS single-label
	// stack with s == 1), the stack has exactly one header. For `+` / `*`
	// (RangeMin <= 1) that is a valid natural end → skip the bpf_loop
	// entirely (otherwise its first callback iteration consumes the
	// following layer as a phantom instance). For a bounded quantifier with
	// RangeMin > 1 a single-header stack is an under-run → reject; skipping
	// to chainDone here would bypass the post-loop RangeMin floor check and
	// wrongly accept it. No-op when the protocol declares no ChainEnd (VLAN
	// terminates via its self-dispatch).
	preLoopTarget := chainDone
	if rangeMin > 1 {
		preLoopTarget = dslReject
	}
	preLoopEnd, err := chainEndCheck(layer.Spec, hs, staticChainFrame, preLoopTarget)
	if err != nil {
		return nil, nil, err
	}
	mainInsns = append(mainInsns, preLoopEnd...)

	// Seed ctx with offsetBase + scratch_start/end, then call bpf_loop
	// with (max_iter, &cb, &ctx, flags=0). R0..R5 are caller-saved
	// across the helper so we must restore them from ctx afterwards.
	loopIter := int32(maxIter - 1)
	mainInsns = append(mainInsns,
		asm.StoreMem(asm.R10, bpfLoopCtxOffsetSlot, offsetBase, asm.DWord),
		// Pre-loop offset, for the RangeMin floor below. Chain layers are
		// fixed-size, so nothing downstream reads the layer-entry slot
		// for them; the parser-machine lifecycle in parser_state.go is
		// unaffected.
		asm.StoreMem(asm.R10, bpfLoopCtxLayerEntrySlot, offsetBase, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchStartSlot, asm.R0, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchEndSlot, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, loopIter),
		loadFunctionRef(asm.R2, cbSym),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, bpfLoopCtxBaseOffset),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnLoop.Call(),
	)

	// Reload the registers the helper clobbered. ctx.offset holds the
	// advanced offsetBase; scratch_start/end are unchanged but must be
	// re-loaded because the verifier dropped type info during the call.
	// A callback reject stores -1 into ctx.offset (see genBpfLoopCallback),
	// which the unsigned compare against ScratchBufSize catches; it also
	// gives the verifier an upper bound on offsetBase.
	mainInsns = append(mainInsns,
		asm.LoadMem(offsetBase, asm.R10, bpfLoopCtxOffsetSlot, asm.DWord),
		asm.LoadMem(asm.R0, asm.R10, bpfLoopCtxScratchStartSlot, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, bpfLoopCtxScratchEndSlot, asm.DWord),
		asm.JGT.Imm(offsetBase, ScratchBufSize, dslReject),
	)

	if rangeMin > 1 {
		// RangeMin floor: headers consumed inside the loop are
		// (offset_after - offset_before) / hs. bpf_loop's return value
		// cannot serve here: it counts iterations including the one that
		// broke, and a self-dispatch protocol breaks before consuming
		// while the iteration cap is reached after consuming.
		mainInsns = append(mainInsns,
			asm.LoadMem(asm.R3, asm.R10, bpfLoopCtxLayerEntrySlot, asm.DWord),
			asm.Mov.Reg(asm.R5, offsetBase),
			asm.Sub.Reg(asm.R5, asm.R3),
			asm.JLT.Imm(asm.R5, int32((rangeMin-1)*hs), dslReject),
		)
	}

	// Over-run (D-024): whichever way the loop ended — the chain-end
	// signal, or the iteration cap (RangeMax, or MAX_DEPTH for `+` / `*`)
	// — the last consumed header must signal end, else a header the
	// quantifier disallows follows. The static path's chainEndRequire;
	// no-op for self-dispatch protocols. The pre-loop skip below bypasses
	// it, having already seen the signal.
	overRun, err := chainEndRequire(layer.Spec, hs, staticChainFrame, dslReject)
	if err != nil {
		return nil, nil, err
	}
	mainInsns = append(mainInsns, overRun...)

	if optionalChain || layer.Spec.ChainEnd != nil {
		// Landing for paths that jump past the bpf_loop call: the `*`
		// peek-miss path, and the pre-loop chain-end skip above. The
		// no-op must use a register whose verifier type agrees on both
		// paths: the skip paths never entered the helper, so R0 retains
		// the scratch_start PTR_TO_MAP_VALUE; the bpf_loop path just
		// reloaded it from ctx. R3 is caller-saved and would land as
		// !read_ok on the miss path.
		mainInsns = append(mainInsns, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(chainDone))
	}
	if absentLabel != chainDone {
		mainInsns, err = withAbsentEdge(mainInsns, absentLabel, index, all)
		if err != nil {
			return nil, nil, err
		}
	}

	return mainInsns, callback, nil
}

// genBpfLoopCallback builds the bpf2bpf subprogram bpf_loop calls
// per iteration. The first instruction carries the callback's Symbol
// (so main's PseudoFunc load resolves) plus btf.Func metadata
// (required for bpf2bpf).
//
// Only a self-dispatch miss ends the chain (break). Once the dispatch has
// admitted the next header, a truncated header or a failed bracket
// predicate rejects the packet: the callback stores -1 into ctx.offset and
// breaks, and the main program's post-loop offset check turns that into
// dslReject (same protocol as the parser-machine callback). This matches
// the static unroll path in chain.go, which runs bounds and predicates on
// every iteration.
func genBpfLoopCallback(layer *ir.LayerInstance, selfConst *vocab.DispatchConst, hs int, cbSym string, qo queriedOptions, pc *predCtx) (asm.Instructions, error) {
	spec := layer.Spec
	breakLabel := cbSym + "_break"
	rejectLabel := cbSym + "_reject"

	first := asm.LoadMem(asm.R3, asm.R2, bpfLoopCbCtxOffsetField, asm.DWord).WithSymbol(cbSym)
	first = btf.WithFuncMetadata(first, chainCallbackFunc(cbSym))

	insns := asm.Instructions{
		first,
		asm.LoadMem(asm.R4, asm.R2, bpfLoopCbCtxScratchStartField, asm.DWord),
		asm.LoadMem(asm.R5, asm.R2, bpfLoopCbCtxScratchEndField, asm.DWord),
	}
	// Predicates run in the main frame's register layout and may clobber
	// R2 before jumping to rejectLabel, which stores through ctx: park
	// ctx in the callee-local R6 for the whole callback and restore it
	// on the reject path.
	hasPreds := len(layer.Predicates) > 0
	if hasPreds {
		insns = append(insns, asm.Mov.Reg(asm.R6, asm.R2))
	}
	// Pin ctx.offset so pointer arithmetic below stays bounded.
	insns = append(insns, asm.JGT.Imm(asm.R3, int32(ScratchBufSize), rejectLabel))

	if selfConst.Type == vocab.DispatchField {
		peek, err := chainFieldPeek(spec, selfConst, hs, breakLabel)
		if err != nil {
			return nil, err
		}
		insns = append(insns, peek...)
	}
	// DispatchNoCheck contributes zero instructions: every iteration is
	// admitted until the chain-end signal (or the iteration cap).

	// Bounds: the admitted header must be present in full, else reject.
	insns = append(insns,
		asm.Mov.Reg(asm.R0, asm.R4),
		asm.Add.Reg(asm.R0, asm.R3),
		asm.Add.Imm(asm.R0, int32(hs)),
		asm.JGT.Reg(asm.R0, asm.R5, rejectLabel),
	)

	if hasPreds {
		preds, err := callbackPredicates(layer, rejectLabel, pc)
		if err != nil {
			return nil, err
		}
		insns = append(insns, preds...)
	}

	// Record this instance's start for where / capture (last one wins,
	// D-018) before the cursor moves past it.
	entry, err := emitLayerEntryStoreFromCb(layer, qo)
	if err != nil {
		return nil, err
	}
	insns = append(insns, entry...)
	insns = append(insns,
		asm.Add.Imm(asm.R3, int32(hs)),
		asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R3, asm.DWord),
	)
	endCheck, err := chainEndCheck(spec, hs, loopChainFrame, breakLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, endCheck...)
	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0), // continue
		asm.Return(),
		asm.Mov.Imm(asm.R0, -1).WithSymbol(rejectLabel), // reject: poison ctx.offset, then break
	)
	if hasPreds {
		insns = append(insns, asm.Mov.Reg(asm.R2, asm.R6))
	}
	insns = append(insns,
		asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R0, asm.DWord),
		asm.Mov.Imm(asm.R0, 1).WithSymbol(breakLabel), // break
		asm.Return(),
	)
	if err := assertCallbackComplexity(insns, cbSym); err != nil {
		return nil, err
	}
	return insns, nil
}

// callbackPredicates replays the layer's bracket predicates inside the
// bpf_loop callback. The predicate emitters assume the main frame's
// register layout (R0 = scratch start, R1 = scratch end, R4 = layer
// offset, R2/R3/R5 scratch), so the callback frame (R2 = ctx, R3 =
// offset, R4/R5 = window) is swapped in and out around them; the caller
// parked ctx in the callee-local R6 at callback entry. Their dslReject
// jumps are retargeted at the callback's reject label. Predicates that spill to the main stack
// (`in @set` slots) are not replayable from the callback frame.
func callbackPredicates(layer *ir.LayerInstance, rejectLabel string, pc *predCtx) (asm.Instructions, error) {
	var replayPC *predCtx
	if pc != nil {
		replayPC = &predCtx{sets: pc.sets}
	}
	preds, err := emitPredicates(layer.Predicates, replayPC)
	if err != nil {
		return nil, err
	}
	for i := range preds {
		if preds[i].Dst == asm.R10 || preds[i].Src == asm.R10 {
			return nil, fmt.Errorf("%w: bracket predicate on chained %q uses the main stack (e.g. `in @set`); not replayable inside the bpf_loop callback", ErrNotImplemented, layer.Spec.Name)
		}
		if preds[i].Reference() == dslReject {
			preds[i] = preds[i].WithReference(rejectLabel)
		}
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R0, asm.R4),
		asm.Mov.Reg(asm.R1, asm.R5),
		asm.Mov.Reg(asm.R4, asm.R3),
	}
	insns = append(insns, preds...)
	insns = append(insns,
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.LoadMem(asm.R3, asm.R2, bpfLoopCbCtxOffsetField, asm.DWord),
		asm.LoadMem(asm.R4, asm.R2, bpfLoopCbCtxScratchStartField, asm.DWord),
		asm.LoadMem(asm.R5, asm.R2, bpfLoopCbCtxScratchEndField, asm.DWord),
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
// chainFrame names the registers a chain-end check uses, so the static
// unroll path and the bpf_loop callback can share one chainEndCheck even
// though their frames map the offset / window / scratch to different
// registers. This is what makes quantifier termination uniform across
// protocols: VLAN ends on its self-dispatch ethertype, MPLS on its s-bit
// chain-end signal, and both codegen paths run the same check.
type chainFrame struct {
	offset, start, end, scalar, dst asm.Register
}

var (
	// loopChainFrame: inside the bpf_loop callback the idx is gone, so
	// R0/R1 are free; R3=post-advance offset, R4=window start, R5=end.
	loopChainFrame = chainFrame{offset: asm.R3, start: asm.R4, end: asm.R5, scalar: asm.R1, dst: asm.R0}
	// staticChainFrame: the main frame's host ABI — offsetBase=R4,
	// window is [R0, R1], R3/R5 are scratch.
	staticChainFrame = chainFrame{offset: offsetBase, start: asm.R0, end: asm.R1, scalar: asm.R3, dst: asm.R5}
)

func chainEndCheck(spec *vocab.ProtocolSpec, hs int, fr chainFrame, breakLabel string) (asm.Instructions, error) {
	if spec.ChainEnd == nil {
		return nil, nil
	}
	insns, expected, err := chainEndLoad(spec, hs, fr, breakLabel)
	if err != nil {
		return nil, err
	}
	// Terminate when the loaded value equals the chain-end value. MPLS
	// declares CHAIN_END_S = 1: "stop when s == 1 (= bottom of stack)".
	insns = append(insns, asm.JEq.Imm(fr.dst, expected, breakLabel))
	return insns, nil
}

// chainEndRequire is the over-run guard for the last static iteration:
// after consuming the quantifier's RangeMax headers without an earlier
// natural end, the final header MUST signal chain-end, otherwise the
// stack is longer than the quantifier allows and the chain rejects.
// Inverse of chainEndCheck — jumps to rejectLabel when the signal is
// *absent*. No-op for protocols without a chain-end signal (their
// over-run is caught by the next layer's self-dispatch peek instead).
func chainEndRequire(spec *vocab.ProtocolSpec, hs int, fr chainFrame, rejectLabel string) (asm.Instructions, error) {
	if spec.ChainEnd == nil {
		return nil, nil
	}
	insns, expected, err := chainEndLoad(spec, hs, fr, rejectLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, asm.JNE.Imm(fr.dst, expected, rejectLabel))
	return insns, nil
}

// chainEndLoad emits the load+mask of the just-consumed header's
// chain-end byte into fr.dst and returns the expected value the caller
// compares against. The byte lives in the just-consumed header at
// fr.offset + (-hs + byteOff); the offset is post-advance so the const
// is typically negative. boundsLabel takes an out-of-window load — for a
// terminate check that means "treat as end", for an over-run guard
// "reject", so the caller supplies the right target. Shared by
// chainEndCheck and chainEndRequire.
func chainEndLoad(spec *vocab.ProtocolSpec, hs int, fr chainFrame, boundsLabel string) (asm.Instructions, int32, error) {
	byteOff, mask, expected, err := chainEndShape(spec)
	if err != nil {
		return nil, 0, err
	}
	loadByteOff := int32(-hs + byteOff)
	insns := append(asm.Instructions{}, foldOffsetIntoScalar(fr.scalar, fr.offset, loadByteOff, boundsLabel)...)
	insns = append(insns, boundedScalarLoad(fr.dst, fr.start, fr.scalar, fr.end, asm.Byte, boundsLabel)...)
	if mask != 0xff {
		insns = append(insns, asm.And.Imm(fr.dst, int32(mask)))
	}
	return insns, int32(expected), nil
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
		return 0, 0, 0, fmt.Errorf("%w: chain-end const %q: %w", ErrNotImplemented, spec.ChainEnd.Name, err)
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
	match, err := emitDispatchValueMatch(asm.R0, selfConst, fieldBytes, breakLabel)
	if err != nil {
		return nil, err
	}
	insns := append(asm.Instructions{}, foldOffsetIntoScalar(asm.R1, asm.R3, loadByteOff, breakLabel)...)
	insns = append(insns, boundedScalarLoad(asm.R0, asm.R4, asm.R1, asm.R5, size, breakLabel)...)
	insns = append(insns, match...)
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
