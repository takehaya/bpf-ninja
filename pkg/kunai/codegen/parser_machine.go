package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
)

// genParserMachine compiles a non-trivial vocab.ParseStateMachine into
// BPF instructions. The shape mirrors genStaticLayer for entry-state
// concerns (bounds, parent dispatch, predicates) and then walks the
// state graph, emitting one basic block per state.
//
// Transitions lower as follows:
//   - accept                   → Ja <doneLabel>            (fall through)
//   - reject                   → Ja dslReject
//   - direct  (target = idx)   → Ja <stateLabel(idx)>
//   - select  (cases + default)→ tuple-match cascade
//   - self-loop branch         → bpf_loop callback
//
// Self-loops are detected per state: when any branch of a state's
// transition points at the state itself, the loop body lives in a
// bpf2bpf callback that bpf_loop invokes max_iter times. The first
// iteration runs inline so dispatch and predicates remain in the main
// stream where the verifier can see them.
func genParserMachine(layer *ir.LayerInstance, layerIdx int, all []*ir.LayerInstance, qo queriedOptions) (asm.Instructions, asm.Instructions, error) {
	spec := layer.Spec
	m := spec.ParseStateMachine
	if m == nil {
		return nil, nil, fmt.Errorf("codegen: genParserMachine called with nil ParseStateMachine on %q", spec.Name)
	}

	pmCtx := &pmCtx{
		spec:      spec,
		machine:   m,
		layerIdx:  layerIdx,
		layer:     layer,
		all:       all,
		labelNS:   fmt.Sprintf("dsl_pm_%s_%d", spec.Name, layerIdx),
		doneLabel: fmt.Sprintf("dsl_pm_%s_%d_done", spec.Name, layerIdx),
		absorbed:  map[int]bool{},
		r4IsRange: precedingLayersLeaveR4Range(all, layerIdx),
		queried:   qo,
	}
	// Pre-scan for multi-state self-loops. Each loop entry's siblings
	// inline into the entry's bpf_loop callback, so the per-state
	// emit loop below skips them — no standalone code, no landing
	// label.
	for i := range m.States {
		for sib := range vocab.MultiStateLoopAbsorbedStates(m.States, i) {
			pmCtx.absorbed[sib] = true
		}
	}

	var insns asm.Instructions
	var callbacks asm.Instructions

	for i := range m.States {
		if pmCtx.absorbed[i] {
			continue
		}
		body, cbs, err := pmCtx.emitState(i)
		if err != nil {
			return nil, nil, err
		}
		insns = append(insns, body...)
		callbacks = append(callbacks, cbs...)
	}

	// The done landing is reached from two source kinds: in-machine
	// Ja (R0 = scratch_start) and the bpf_loop reload path (R0 also
	// = scratch_start, just restored from ctx). R3 is killed by the
	// helper call, so a Mov R3,R3 noop here would be !read_ok —
	// pick R0 which is consistent on both paths.
	insns = append(insns, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(pmCtx.doneLabel))
	return insns, callbacks, nil
}

// pmCtx threads compile-time state (specs, layer index, label
// namespace) through the per-state emitters.
type pmCtx struct {
	spec               *vocab.ProtocolSpec
	machine            *vocab.ParseStateMachine
	layerIdx           int
	layer              *ir.LayerInstance
	all                []*ir.LayerInstance
	labelNS            string
	doneLabel          string
	selectCounterValue int
	// absorbed tracks state indices folded into a multi-state self-
	// loop callback — those states have no standalone emit because
	// their bodies live inside the loop entry's callback.
	absorbed map[int]bool
	// r4IsRange records whether R4 may carry a non-constant value at
	// the current emit point. Set when entering this layer if any
	// preceding layer's emit can leave R4 non-constant; raised mid-
	// state by emitStateBody as the per-state extracts/advances run.
	// Drives emitKeyCompare's fast-path / bounded-load choice.
	r4IsRange bool
	// queried is the demand walker's per-program option set; the
	// multi-state callback emits a flat slot-store prelude for every
	// option in this layer's slice (and only those). nil-safe.
	queried queriedOptions
}

// precedingLayersLeaveR4Range scans the layers emitted before idx and
// reports whether any of them can advance R4 by a non-constant amount.
// Variable-layout specs (parser machine with pkt.advance / parser-
// machine sibling extracts / flag triggers), non-One quantifiers
// (`+`, `*`, `{n,m>1}`), and alt groups (per-alt size differences
// after convergence) all qualify.
func precedingLayersLeaveR4Range(all []*ir.LayerInstance, idx int) bool {
	for _, l := range all[:idx] {
		if layerLeavesR4Range(l) {
			return true
		}
	}
	return false
}

func layerLeavesR4Range(l *ir.LayerInstance) bool {
	if l.Quant != ast.QuantOne {
		return true
	}
	if l.Alternation != nil {
		// Each alt body advances R4 by its own size, so even when
		// uniformAltPrefixSize pins the dispatch anchor R4 after
		// convergence reflects whichever alt won.
		return true
	}
	if l.Spec != nil && l.Spec.HasVariableLayout() {
		return true
	}
	return false
}

func (c *pmCtx) stateLabel(idx int) string {
	return fmt.Sprintf("%s_%s", c.labelNS, c.machine.States[idx].Name)
}

func (c *pmCtx) selfLoopCbSym(idx int) string {
	return fmt.Sprintf("%s_%s_cb", c.labelNS, c.machine.States[idx].Name)
}

func (c *pmCtx) selfLoopBreak(idx int) string {
	return c.selfLoopCbSym(idx) + "_break"
}

// emitState lowers one state into a basic block. The entry state
// fronts the layer's parent dispatch and predicates; non-entry states
// receive a Ja landing so other states can reach them.
func (c *pmCtx) emitState(stateIdx int) (asm.Instructions, asm.Instructions, error) {
	state := c.machine.States[stateIdx]
	isEntry := stateIdx == c.machine.EntryIdx

	var insns asm.Instructions
	if isEntry {
		di, err := c.emitEntryDispatch()
		if err != nil {
			return nil, nil, err
		}
		insns = append(insns, di...)
		// Layer-entry slot lifecycle (fp[bpfLoopCtxLayerEntrySlot]):
		//
		//   1. Parent emitted its layer body and stored its own entry
		//      offsetBase to the slot — either here for parser-machine
		//      parents, or in genStaticLayer for OPT parents.
		//   2. emitEntryDispatch (just above) reads that slot to
		//      anchor `parent.field == const` reads on the parent's
		//      primary header, regardless of how far the parent has
		//      advanced R4.
		//   3. We now overwrite the slot with our own entry offsetBase
		//      so OUR children can do step 2 against us.
		//
		// The slot is single-purpose (reused per layer). Step 2 must
		// happen before step 3 — emitEntryDispatch above is the only
		// reader that would observe the parent value, so the order is
		// load-bearing. The slot doubles as bpf_loop ctx field 24, so
		// self-loop callbacks read it via R2+bpfLoopCbCtxLayerEntryField.
		insns = append(insns, asm.StoreMem(asm.R10, bpfLoopCtxLayerEntrySlot, offsetBase, asm.DWord))
		if c.layer.NeedsRuntimeOffset {
			// Independent of the single-shared bpfLoopCtxLayerEntrySlot
			// above (which the next layer's dispatch overwrites): store
			// R4 to this layer's per-layer entry slot so where /
			// capture / option-walk emitted later in the program can
			// recover the layer's start regardless of how far the
			// parser machine advances R4 inside its own body.
			slotEntry, err := whereLayerEntrySlot(c.layer.LayerPos)
			if err != nil {
				return nil, nil, err
			}
			insns = append(insns, asm.StoreMem(asm.R10, slotEntry, offsetBase, asm.DWord))
		}
		// Sentinel-init each queried option's dynamic offset slot so
		// where-time access can detect "option not extracted in this
		// packet" via JEq sentinel. The TLV-walk callback's prelude
		// overwrites the slot only when the matching kind byte runs
		// — un-extracted options keep the sentinel value.
		dynInit, err := c.emitDynamicAuxSentinelInit()
		if err != nil {
			return nil, nil, err
		}
		insns = append(insns, dynInit...)
	} else {
		insns = append(insns, landingNoop(c.stateLabel(stateIdx)))
	}

	body, cbs, err := c.emitStateBody(state, stateIdx, isEntry)
	if err != nil {
		return nil, nil, err
	}
	insns = append(insns, body...)
	return insns, cbs, nil
}

// emitEntryDispatch runs the parent-protocol dispatch once at machine
// entry, identical in shape to genStaticLayer's QuantOne dispatch.
func (c *pmCtx) emitEntryDispatch() (asm.Instructions, error) {
	if c.layerIdx == 0 || c.layer.Dispatch == nil {
		return nil, nil
	}
	return genLayerDispatch(c.layer, c.all[c.layerIdx-1], dslReject)
}

// emitStateBody emits one state's extracts + transition. When the
// state self-loops, the inline body forms the first iteration; the
// bpf_loop call follows for iterations 1..MaxDepth.
//
// The variable-trail interaction with select-key reads is subtle:
// after the trail moves offsetBase past the just-extracted header,
// any select reading "the header we just consumed" via R4-relative
// offsets would land in the wrong byte. The fix is to stash each
// select key's byte (post-mask, post-shift) into a kunai-internal
// stack slot BEFORE the trail runs and have the transition select
// load from those slots.
func (c *pmCtx) emitStateBody(state *vocab.ParseState, stateIdx int, isEntry bool) (asm.Instructions, asm.Instructions, error) {
	selfLoop := transitionRefsState(state.Trans, stateIdx)
	if vocab.IsMultiStateLoopEntry(c.machine.States, stateIdx) {
		return c.emitMultiStateSelfLoop(state, stateIdx)
	}

	var insns asm.Instructions
	stashAddr := inlineSelectAddr
	for i, ex := range state.Extracts {
		exInsns, err := c.emitExtract(ex)
		if err != nil {
			return nil, nil, err
		}
		insns = append(insns, exInsns...)
		if isEntry && i == 0 {
			preds, err := emitPredicates(c.layer.Predicates)
			if err != nil {
				return nil, nil, err
			}
			insns = append(insns, preds...)
		}
		hs := ex.HeaderSize / 8
		insns = append(insns, emitAdvance(hs))
		if vt, ok := knownVariableTails[ex.HeaderName]; ok {
			if state.Trans.Kind == vocab.TransSelect {
				// Inline ABI: R0/R1 are scratch_start/end, R4 is the
				// running offset (offsetBase). Use R3 as the load
				// destination / pointer scratch and R5 as the scalar
				// scratch.
				stashInsns, err := emitStashSelectKeys(state.Trans.Select, c, stashEnv{
					addrReg:      asm.R3,
					scalarReg:    asm.R5,
					offset:       offsetBase,
					scratchStart: asm.R0,
					scratchEnd:   asm.R1,
				}, dslReject)
				if err != nil {
					return nil, nil, err
				}
				insns = append(insns, stashInsns...)
				stashAddr = selectAddr{
					dst:        asm.R3,
					labelTag:   "vcase",
					fromStash:  true,
					stashR10:   asm.R10,
					stashSlots: stashKeySlots,
				}
			}
			tail, err := emitVariableTrailInline(hs, vt, dslReject)
			if err != nil {
				return nil, nil, err
			}
			insns = append(insns, tail...)
			c.r4IsRange = true
		}
	}

	// Per-AdvanceOp emit: pkt.advance(...) has three template
	// variants the loader has already lowered. Field and Lookahead
	// templates share the variableTailSkip path; they differ only in
	// the "bytes already advanced" arg (state.OffsetAtEntry vs 0).
	// Literal templates are a fixed bounds-checked Add.Imm.
	for _, adv := range state.Advances {
		if state.OffsetAtEntry < 0 {
			return nil, nil, fmt.Errorf("%w: state %q has dynamic R4 on entry; pkt.advance requires a static layer-entry offset", ErrNotImplemented, state.Name)
		}
		switch adv.Kind {
		case vocab.AdvanceOpField:
			vt := variableTailSkipFromHeaderLength(adv.Skip)
			tail, err := emitVariableTrailInline(state.OffsetAtEntry, vt, dslReject)
			if err != nil {
				return nil, nil, err
			}
			insns = append(insns, tail...)
			c.r4IsRange = true
		case vocab.AdvanceOpLookahead:
			// LenByteOff is R4-relative; pass hs=0 to skip the
			// layer-entry adjustment emitVariableTrail folds in.
			vt := variableTailSkipFromHeaderLength(adv.Skip)
			tail, err := emitVariableTrailInline(0, vt, dslReject)
			if err != nil {
				return nil, nil, err
			}
			insns = append(insns, tail...)
			c.r4IsRange = true
		case vocab.AdvanceOpLiteral:
			insns = append(insns, emitBounds(adv.LiteralBytes, dslReject)...)
			insns = append(insns, emitAdvance(adv.LiteralBytes))
		default:
			return nil, nil, fmt.Errorf("%w: unknown AdvanceOp kind %d", ErrNotImplemented, adv.Kind)
		}
	}

	// Only the inline non-stash path reads R4 live; stash mode pre-
	// loaded the byte before any range-introducing emit, and callback
	// paths run under bpf_loop where R4 always reloads as a range
	// scalar. So offsetIsConst is meaningful only here.
	if !stashAddr.fromStash {
		stashAddr.offsetIsConst = !c.r4IsRange
	}

	if !selfLoop {
		trans, err := c.emitTransitionWithSelfRewrite(state.Trans, stateIdx, "", stashAddr)
		if err != nil {
			return nil, nil, err
		}
		return append(insns, trans...), nil, nil
	}

	// Self-loop: the inline body just ran iteration 0. Emit the
	// transition with the self-target rewritten to "fall through into
	// the loop call"; non-self targets jump out as usual.
	loopEnter := fmt.Sprintf("%s_%s_loop", c.labelNS, state.Name)
	trans, err := c.emitTransitionWithSelfRewrite(state.Trans, stateIdx, loopEnter, stashAddr)
	if err != nil {
		return nil, nil, err
	}
	insns = append(insns, trans...)
	insns = append(insns, landingNoop(loopEnter))

	loopCall, callback, err := c.emitSelfLoop(state, stateIdx)
	if err != nil {
		return nil, nil, err
	}
	insns = append(insns, loopCall...)
	return insns, callback, nil
}

// emitExtract emits the bounds check for one ExtractOp. The actual
// advance is emitted by the caller (so it can interleave predicates
// in between).
func (c *pmCtx) emitExtract(ex vocab.ExtractOp) (asm.Instructions, error) {
	if ex.HeaderSize%8 != 0 {
		return nil, fmt.Errorf("%w: parser machine extract on %q is %d bits (not byte-aligned)", ErrNotImplemented, ex.HeaderName, ex.HeaderSize)
	}
	hs := ex.HeaderSize / 8
	return emitBounds(hs, dslReject), nil
}

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
//   - srv6_h: an IPv6 Routing extension whose segment list lives in
//     the variable region. SRv6's own next_header byte (offset 0)
//     identifies the inner protocol, so child dispatches can read it
//     directly via the layerEntry slot — no write-back needed.
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
	"srv6_h": {
		LenFieldByteOff: 1,
		Scale:           8,
		Base:            0,
		LenMask:         0x07, // up to 7*8 = 56 bytes (≈ 3 segments)
	},
}

// scaleShift converts a Scale value (must be a power of two ≤ 128)
// to its bit-shift count. Returns -1 when scale is not a clean
// power of two so callers can fall back / surface a clear error.
func scaleShift(scale int) int {
	switch scale {
	case 1:
		return 0
	case 2:
		return 1
	case 4:
		return 2
	case 8:
		return 3
	case 16:
		return 4
	case 32:
		return 5
	case 64:
		return 6
	case 128:
		return 7
	}
	return -1
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
	shift := scaleShift(vt.Scale)
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
		return c.emitSelectWithAddr(t.Select, fromState, selfLabel, addr)
	}
	return nil, fmt.Errorf("%w: parser-machine transition kind %d", ErrNotImplemented, t.Kind)
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
// stack element, or unconsumed lookahead) and reduced to "byte at
// this offset, mask, shift" so a single-byte LDX + AND + cmp
// suffices.
type selectKeyShape struct {
	// byteOffsetFromR4 is the byte offset relative to the *current*
	// offsetBase. Negative for SelectKeyField (the field lives in a
	// header already extracted, so R4 has advanced past it);
	// non-negative for SelectKeyLookahead (peeking at unconsumed
	// bytes from the cursor forward).
	byteOffsetFromR4 int
	// maskAfterShift is the byte mask applied after shifting; it spans
	// only the key's bits.
	maskAfterShift uint8
	// shift is the right shift to align the field to the LSB.
	shift uint
	// bits is the key's bit width (1..8 in MVP).
	bits int
}

func (c *pmCtx) resolveSelectKey(sk vocab.SelectKey) (selectKeyShape, error) {
	switch sk.Kind {
	case vocab.SelectKeyField:
		return c.resolveFieldSelectKey(sk.Field)
	case vocab.SelectKeyLookahead:
		// MVP cap (mirrored in vocab/parser_machine.go::buildSelect):
		// only single-byte lookahead is wired to codegen because the
		// load below is a one-byte LDX. Wider widths require multi-
		// byte loads + assembly of the value.
		if sk.Bits != 8 {
			return selectKeyShape{}, fmt.Errorf("%w: lookahead select key is %d bits; codegen only supports 8", ErrNotImplemented, sk.Bits)
		}
		return selectKeyShape{
			byteOffsetFromR4: 0,
			maskAfterShift:   0xFF,
			shift:            0,
			bits:             8,
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
	mask := uint8((1 << k.BitWidth) - 1)

	// The selected header lies at [R4 - headerBytes, R4) when that
	// header is the just-extracted one. For `stack.last`, the just-
	// pushed element is at the same window. So byteOffsetFromR4 is
	// negative.
	off := byteInHeader - headerBytes

	return selectKeyShape{
		byteOffsetFromR4: off,
		maskAfterShift:   mask,
		shift:            shift,
		bits:             k.BitWidth,
	}, nil
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
			asm.LoadMem(addr.dst, addr.dst, int16(shape.byteOffsetFromR4), asm.Byte),
		)
	} else {
		insns = append(insns, foldOffsetIntoScalar(addr.scalarReg, addr.offsetReg, int32(shape.byteOffsetFromR4), addr.pktFailLabel)...)
		insns = append(insns, boundedScalarLoad(addr.dst, addr.scratchStart, addr.scalarReg, addr.scratchEnd, asm.Byte, addr.pktFailLabel)...)
	}
	if shape.shift > 0 {
		insns = append(insns, asm.RSh.Imm(addr.dst, int32(shape.shift)))
	}
	if shape.maskAfterShift != 0xff {
		insns = append(insns, asm.And.Imm(addr.dst, int32(shape.maskAfterShift)))
	}
	insns = append(insns, asm.JNE.Imm(addr.dst, int32(value), caseSkip))
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
		insns = append(insns, boundedScalarLoad(env.addrReg, env.scratchStart, env.scalarReg, env.scratchEnd, asm.Byte, failLabel)...)
		if shape.shift > 0 {
			insns = append(insns, asm.RSh.Imm(env.addrReg, int32(shape.shift)))
		}
		if shape.maskAfterShift != 0xff {
			insns = append(insns, asm.And.Imm(env.addrReg, int32(shape.maskAfterShift)))
		}
		insns = append(insns, asm.StoreMem(asm.R10, stashKeySlots[i], env.addrReg, asm.DWord))
	}
	return insns, nil
}

// emitSelfLoop emits the bpf_loop call wrapping iterations 1..N for
// a self-looping state. The callback re-runs the state body and
// returns 1 once the transition no longer points back at the state.
func (c *pmCtx) emitSelfLoop(state *vocab.ParseState, stateIdx int) (asm.Instructions, asm.Instructions, error) {
	maxIter := c.spec.MaxDepth
	if maxIter == 0 {
		maxIter = defaultChainDepth
	}
	if maxIter > bpfLoopChainCap {
		return nil, nil, fmt.Errorf("%w: parser machine %s self-loop depth %d exceeds cap %d", ErrNotImplemented, c.spec.Name, maxIter, bpfLoopChainCap)
	}
	cbSym := c.selfLoopCbSym(stateIdx)
	callback, err := c.emitSelfLoopCallback(state, stateIdx, cbSym)
	if err != nil {
		return nil, nil, err
	}

	insns := asm.Instructions{
		asm.StoreMem(asm.R10, bpfLoopCtxOffsetSlot, offsetBase, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchStartSlot, asm.R0, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchEndSlot, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, int32(maxIter)),
		loadFunctionRef(asm.R2, cbSym),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, bpfLoopCtxBaseOffset),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnLoop.Call(),
		asm.LoadMem(offsetBase, asm.R10, bpfLoopCtxOffsetSlot, asm.DWord),
		asm.LoadMem(asm.R0, asm.R10, bpfLoopCtxScratchStartSlot, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, bpfLoopCtxScratchEndSlot, asm.DWord),
		// After the loop, control falls through to doneLabel — bpf_loop
		// terminated either via callback returning 1 (matched
		// accept/reject branch in the transition) or by exhausting
		// max_iter (we treat that as accept; the verifier's bound
		// guarantees we still consume legal bytes only).
		asm.Ja.Label(c.doneLabel),
	}
	return insns, callback, nil
}

// emitMultiStateSelfLoop is the codegen path for indirect self-loops
// (TLV walks). The state body is a single-byte lookahead dispatch
// over sibling states; each sibling does one extract or advance,
// then transitions back to the entry. The callback inlines the
// dispatch + every sibling body, so each bpf_loop iteration is
// "read kind byte, do the matching sibling's work, return 0".
//
// MAX_DEPTH governs the bpf_loop iter cap. The state itself has no
// inline iter-0 — control enters via Ja from a parent state,
// invokes bpf_loop, then jumps to doneLabel.
func (c *pmCtx) emitMultiStateSelfLoop(state *vocab.ParseState, stateIdx int) (asm.Instructions, asm.Instructions, error) {
	maxIter := c.spec.MaxDepth
	if maxIter == 0 {
		maxIter = defaultChainDepth
	}
	if maxIter > bpfLoopChainCap {
		return nil, nil, fmt.Errorf("%w: parser machine %s multi-state self-loop depth %d exceeds cap %d", ErrNotImplemented, c.spec.Name, maxIter, bpfLoopChainCap)
	}
	cbSym := c.selfLoopCbSym(stateIdx)
	callback, err := c.emitMultiStateCallback(state, stateIdx, cbSym)
	if err != nil {
		return nil, nil, err
	}

	insns := asm.Instructions{
		asm.StoreMem(asm.R10, bpfLoopCtxOffsetSlot, offsetBase, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchStartSlot, asm.R0, asm.DWord),
		asm.StoreMem(asm.R10, bpfLoopCtxScratchEndSlot, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, int32(maxIter)),
		loadFunctionRef(asm.R2, cbSym),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, bpfLoopCtxBaseOffset),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnLoop.Call(),
		asm.LoadMem(offsetBase, asm.R10, bpfLoopCtxOffsetSlot, asm.DWord),
		asm.LoadMem(asm.R0, asm.R10, bpfLoopCtxScratchStartSlot, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, bpfLoopCtxScratchEndSlot, asm.DWord),
		asm.Ja.Label(c.doneLabel),
	}
	return insns, callback, nil
}

// emitDynamicAuxSentinelInit zero-inits each queried-option slot to
// dynamicAuxSentinel before the parser machine runs. The TLV-walk
// callback overwrites the slot only when it actually extracts the
// matching kind; where-time access compares the slot value against
// the sentinel to detect "option not present in this packet". Empty
// when no where / capture clause queries this layer's options.
func (c *pmCtx) emitDynamicAuxSentinelInit() (asm.Instructions, error) {
	demand := c.queried[c.layer]
	if len(demand) == 0 {
		return nil, nil
	}
	insns := asm.Instructions{asm.Mov.Imm(asm.R3, dynamicAuxSentinel)}
	for idx := range demand {
		slot, err := dynamicAuxOffsetSlot(c.layer.LayerPos, idx+1)
		if err != nil {
			return nil, err
		}
		insns = append(insns, asm.StoreMem(asm.R10, slot, asm.R3, asm.DWord))
	}
	return insns, nil
}

// emitDynamicAuxSlotPrelude emits the per-iter "load kind byte → for
// each queried option, JNE-skip past a single StoreMem of R3 into the
// option's main-frame slot" sequence. Lives before the dispatch
// cascade, runs once per iter, and writes only the slots the
// program's where / capture clauses actually read (see
// collectQueriedOptions). When no queried options reference this
// layer the prelude is empty.
//
// The store reaches main's stack via R2 (= ctx pointer) plus a
// constant offset — callback R10 points at a separate frame. R1 is
// the kind-byte scratch (R0 was clobbered by the bound check above).
// The byte is loaded from R4+R3 with no additional bound check
// because the immediately preceding `R0 = R4+R3+1; JGT R0, R5,
// break` already proved the byte is in scratch.
func (c *pmCtx) emitDynamicAuxSlotPrelude() (asm.Instructions, error) {
	demand := c.queried[c.layer]
	if len(demand) == 0 {
		return nil, nil
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.R4),
		asm.Add.Reg(asm.R1, asm.R3),
		asm.LoadMem(asm.R1, asm.R1, 0, asm.Byte),
	}
	for idx, layout := range demand {
		slot, err := dynamicAuxOffsetSlot(c.layer.LayerPos, idx+1)
		if err != nil {
			return nil, err
		}
		skip := fmt.Sprintf("%s_pre_skip_%d", c.labelNS, c.selectCounter())
		insns = append(insns,
			asm.JNE.Imm(asm.R1, int32(layout.DynamicKindByte), skip),
			asm.StoreMem(asm.R2, mainStackOffsetFromCb(slot), asm.R3, asm.DWord),
			landingNoop(skip),
		)
	}
	return insns, nil
}

// emitMultiStateCallback emits the bpf_loop callback for an indirect
// self-loop. Each iteration reads the lookahead byte, then runs
// either an inlined sibling body (extract or advance + return 0) or
// breaks (accept / reject / EOL → return 1).
func (c *pmCtx) emitMultiStateCallback(entry *vocab.ParseState, entryIdx int, cbSym string) (asm.Instructions, error) {
	breakLabel := c.selfLoopBreak(entryIdx)
	continueLabel := cbSym + "_continue"

	first := asm.LoadMem(asm.R3, asm.R2, bpfLoopCbCtxOffsetField, asm.DWord).WithSymbol(cbSym)
	first = btf.WithFuncMetadata(first, chainCallbackFunc(cbSym))

	insns := asm.Instructions{
		first,
		asm.LoadMem(asm.R4, asm.R2, bpfLoopCbCtxScratchStartField, asm.DWord),
		asm.LoadMem(asm.R5, asm.R2, bpfLoopCbCtxScratchEndField, asm.DWord),
		// R3 came from a stack spill, so the verifier re-enters this
		// callback with R3 marked as an unbounded scalar. Pin its
		// upper bound against ScratchBufSize before any pkt-pointer
		// arithmetic; on the surviving path R3 ∈ [0, ScratchBufSize),
		// which lets the subsequent `pkt + R3` adds verify.
		asm.JGT.Imm(asm.R3, int32(ScratchBufSize)-1, breakLabel),
	}
	// Per-case dispatch over the lookahead<bit<8>>() byte. Use the
	// existing emitSelectGeneric machinery with a callback-flavoured
	// selectAddr that materialises the byte at R4+R3.
	addr := callbackSelectAddr("tlvcb", breakLabel)
	// Bound-check the 1-byte peek before any case body runs.
	insns = append(insns,
		asm.Mov.Reg(asm.R0, asm.R4),
		asm.Add.Reg(asm.R0, asm.R3),
		asm.Add.Imm(asm.R0, 1),
		asm.JGT.Reg(asm.R0, asm.R5, breakLabel),
	)
	// Slot-store prelude must run BEFORE the dispatch cascade, not
	// inside the case bodies — the per-iter slot value has to be a
	// function of the kind byte alone so the verifier doesn't track
	// "which case ran × which slot was written" across iters. See
	// docs/ja/dsl-internals.md §6.5 Mechanism 7.
	prelude, err := c.emitDynamicAuxSlotPrelude()
	if err != nil {
		return nil, err
	}
	insns = append(insns, prelude...)
	dispatch, err := c.emitMultiStateDispatch(entry, entryIdx, addr, breakLabel, continueLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, dispatch...)

	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(continueLabel),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol(breakLabel),
		asm.Return(),
	)
	return insns, nil
}

// emitMultiStateDispatch builds the per-case cascade for the entry's
// transition select. Each case either inlines its sibling's body
// (followed by Ja continueLabel) or jumps to breakLabel for
// accept / reject targets.
func (c *pmCtx) emitMultiStateDispatch(entry *vocab.ParseState, entryIdx int, addr selectAddr, breakLabel, continueLabel string) (asm.Instructions, error) {
	sel := entry.Trans.Select
	// Single key, single byte (validated by vocab.IsMultiStateLoopEntry).
	shape, err := c.resolveSelectKey(sel.Keys[0])
	if err != nil {
		return nil, err
	}
	var insns asm.Instructions
	for _, kase := range sel.Cases {
		caseSkip := fmt.Sprintf("%s_%s_%d_skip", c.labelNS, addr.labelTag, c.selectCounter())
		mv := kase.Values[0]
		if !mv.IsWildcard {
			insns = append(insns, emitKeyCompare(addr, shape, 0, mv.Value, caseSkip)...)
		}
		body, err := c.emitMultiStateCaseBody(kase.Target, entryIdx, breakLabel, continueLabel)
		if err != nil {
			return nil, err
		}
		insns = append(insns, body...)
		if !mv.IsWildcard {
			insns = append(insns, landingNoop(caseSkip))
		} else {
			return insns, nil
		}
	}
	body, err := c.emitMultiStateCaseBody(sel.Default, entryIdx, breakLabel, continueLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, body...)
	return insns, nil
}

// emitMultiStateCaseBody emits the action a single dispatch arm
// performs: break for accept / reject targets, or inline the
// sibling state's extracts and advances and Ja continueLabel.
func (c *pmCtx) emitMultiStateCaseBody(target, entryIdx int, breakLabel, continueLabel string) (asm.Instructions, error) {
	if target == vocab.StateAccept || target == vocab.StateReject {
		return asm.Instructions{asm.Ja.Label(breakLabel)}, nil
	}
	sib := c.machine.States[target]
	body, err := c.emitSiblingCallbackBody(sib, breakLabel)
	if err != nil {
		return nil, err
	}
	body = append(body, asm.Ja.Label(continueLabel))
	return body, nil
}

// emitSiblingCallbackBody lowers a sibling state's extracts and
// advances using the callback ABI (R3 = offset, R4 = scratchStart,
// R5 = scratchEnd, R0/R1 = scratch). Each iteration of the multi-
// state self-loop runs exactly one sibling.
func (c *pmCtx) emitSiblingCallbackBody(sib *vocab.ParseState, breakLabel string) (asm.Instructions, error) {
	var insns asm.Instructions
	for _, ex := range sib.Extracts {
		if ex.HeaderSize%8 != 0 {
			return nil, fmt.Errorf("%w: multi-state callback extract on %q is %d bits (not byte-aligned)", ErrNotImplemented, ex.HeaderName, ex.HeaderSize)
		}
		hs := ex.HeaderSize / 8
		insns = append(insns,
			asm.Mov.Reg(asm.R0, asm.R4),
			asm.Add.Reg(asm.R0, asm.R3),
			asm.Add.Imm(asm.R0, int32(hs)),
			asm.JGT.Reg(asm.R0, asm.R5, breakLabel),
			asm.Add.Imm(asm.R3, int32(hs)),
			asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R3, asm.DWord),
		)
	}
	for _, adv := range sib.Advances {
		switch adv.Kind {
		case vocab.AdvanceOpLookahead:
			vt := variableTailSkipFromHeaderLength(adv.Skip)
			tail, err := emitVariableTrailCallback(0, vt, breakLabel)
			if err != nil {
				return nil, err
			}
			insns = append(insns, tail...)
		case vocab.AdvanceOpLiteral:
			n := int32(adv.LiteralBytes)
			insns = append(insns,
				asm.Mov.Reg(asm.R0, asm.R4),
				asm.Add.Reg(asm.R0, asm.R3),
				asm.Add.Imm(asm.R0, n),
				asm.JGT.Reg(asm.R0, asm.R5, breakLabel),
				asm.Add.Imm(asm.R3, n),
				asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R3, asm.DWord),
			)
		default:
			return nil, fmt.Errorf("%w: multi-state callback sibling advance kind %d not yet supported", ErrNotImplemented, adv.Kind)
		}
	}
	return insns, nil
}

// emitSelfLoopCallback is the bpf2bpf callback bpf_loop runs per
// iteration. R2 = &ctx (offset/scratch_start/scratch_end), R1 = idx.
// Each transition branch ends with an explicit Ja to either
// continueLabel (= self-target → return 0) or breakLabel (= any
// other target → return 1). The two labels live below the transition
// stream so callers can rely on falling through never being a code
// path that produces a verdict by accident.
func (c *pmCtx) emitSelfLoopCallback(state *vocab.ParseState, stateIdx int, cbSym string) (asm.Instructions, error) {
	breakLabel := c.selfLoopBreak(stateIdx)
	continueLabel := cbSym + "_continue"

	first := asm.LoadMem(asm.R3, asm.R2, bpfLoopCbCtxOffsetField, asm.DWord).WithSymbol(cbSym)
	first = btf.WithFuncMetadata(first, chainCallbackFunc(cbSym))

	insns := asm.Instructions{
		first,
		asm.LoadMem(asm.R4, asm.R2, bpfLoopCbCtxScratchStartField, asm.DWord),
		asm.LoadMem(asm.R5, asm.R2, bpfLoopCbCtxScratchEndField, asm.DWord),
	}

	stashAddr := callbackSelectAddr("cb_case", breakLabel)
	for _, ex := range state.Extracts {
		if ex.HeaderSize%8 != 0 {
			return nil, fmt.Errorf("%w: parser machine self-loop extract on %q is %d bits (not byte-aligned)", ErrNotImplemented, ex.HeaderName, ex.HeaderSize)
		}
		hs := ex.HeaderSize / 8
		insns = append(insns,
			asm.Mov.Reg(asm.R0, asm.R4),
			asm.Add.Reg(asm.R0, asm.R3),
			asm.Add.Imm(asm.R0, int32(hs)),
			asm.JGT.Reg(asm.R0, asm.R5, breakLabel),
			asm.Add.Imm(asm.R3, int32(hs)),
			asm.StoreMem(asm.R2, bpfLoopCbCtxOffsetField, asm.R3, asm.DWord),
		)
		if vt, ok := knownVariableTails[ex.HeaderName]; ok {
			if state.Trans.Kind == vocab.TransSelect {
				// Callback ABI: R0/R1 are free here (R1 = bpf_loop idx
				// is already past use), R3 = current offset, R4/R5 =
				// scratchStart/End. Use R0 as the load destination /
				// pointer scratch and R1 as the scalar scratch.
				stashInsns, err := emitStashSelectKeys(state.Trans.Select, c, stashEnv{
					addrReg:      asm.R0,
					scalarReg:    asm.R1,
					offset:       asm.R3,
					scratchStart: asm.R4,
					scratchEnd:   asm.R5,
				}, breakLabel)
				if err != nil {
					return nil, err
				}
				insns = append(insns, stashInsns...)
				stashAddr = selectAddr{
					dst:        asm.R0,
					labelTag:   "vcb_case",
					fromStash:  true,
					stashR10:   asm.R10,
					stashSlots: stashKeySlots,
				}
			}
			tail, err := emitVariableTrailCallback(hs, vt, breakLabel)
			if err != nil {
				return nil, err
			}
			insns = append(insns, tail...)
		}
	}

	transInsns, err := c.emitCallbackTransition(state.Trans, stateIdx, breakLabel, continueLabel, stashAddr)
	if err != nil {
		return nil, err
	}
	insns = append(insns, transInsns...)

	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(continueLabel),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol(breakLabel),
		asm.Return(),
	)
	return insns, nil
}

// emitCallbackTransition is like emitTransition but inside the
// bpf_loop callback. Self-target branches Ja continueLabel; every
// other branch Ja's breakLabel. addr selects the select-key
// addressing strategy (direct vs stash).
func (c *pmCtx) emitCallbackTransition(t vocab.TransitionOp, fromState int, breakLabel, continueLabel string, addr selectAddr) (asm.Instructions, error) {
	switch t.Kind {
	case vocab.TransAccept, vocab.TransReject:
		return asm.Instructions{asm.Ja.Label(breakLabel)}, nil
	case vocab.TransDirect:
		if t.Target == fromState {
			return asm.Instructions{asm.Ja.Label(continueLabel)}, nil
		}
		return asm.Instructions{asm.Ja.Label(breakLabel)}, nil
	case vocab.TransSelect:
		return c.emitCallbackSelect(t.Select, fromState, breakLabel, continueLabel, addr)
	}
	return nil, fmt.Errorf("%w: parser-machine callback transition kind %d", ErrNotImplemented, t.Kind)
}

// emitCallbackSelect lowers a select inside a bpf_loop callback.
// Self-target branches Ja continueLabel (return 0); every other
// branch Ja's breakLabel (return 1).
func (c *pmCtx) emitCallbackSelect(sel *vocab.SelectOp, fromState int, breakLabel, continueLabel string, addr selectAddr) (asm.Instructions, error) {
	return c.emitSelectGeneric(sel, addr, func(target int) string {
		if target == fromState {
			return continueLabel
		}
		return breakLabel
	})
}

// transitionRefsState reports whether the transition has any branch
// pointing at stateIdx — i.e. the state has a self-loop edge.
func transitionRefsState(t vocab.TransitionOp, stateIdx int) bool {
	switch t.Kind {
	case vocab.TransDirect:
		return t.Target == stateIdx
	case vocab.TransSelect:
		if t.Select.Default == stateIdx {
			return true
		}
		for _, k := range t.Select.Cases {
			if k.Target == stateIdx {
				return true
			}
		}
	}
	return false
}


// selectCounter feeds unique case-skip labels per (layer, state, case).
// Each emit pass starts at zero so labels stay deterministic.
func (c *pmCtx) selectCounter() int {
	c.selectCounterValue++
	return c.selectCounterValue
}
