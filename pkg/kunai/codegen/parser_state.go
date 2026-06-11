package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
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
		spec:         spec,
		machine:      m,
		layerIdx:     layerIdx,
		layer:        layer,
		all:          all,
		labelNS:      fmt.Sprintf("dsl_pm_%s_%d", spec.Name, layerIdx),
		doneLabel:    fmt.Sprintf("dsl_pm_%s_%d_done", spec.Name, layerIdx),
		absorbed:     map[int]bool{},
		r4IsRange:    precedingLayersLeaveR4Range(all, layerIdx),
		queried:      qo,
		queriedAuxes: buildQueriedAuxNames(qo, layer),
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
	// queriedAuxes is the OutParam-name set for c.queried[c.layer]
	// — built once at pmCtx construction and consulted by the
	// TLV-walk dispatch elision predicate (caseRedundantWithDefault)
	// without rebuilding per dispatch site. nil when no options are
	// queried for this layer.
	queriedAuxes map[string]bool
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
		// Zero each declared ParserCounter slot. Counters are
		// machine-local; the slot must hold a known value before any
		// is_zero() reaches it so the verifier accepts the load.
		ctrInit, err := c.emitCounterSlotInit()
		if err != nil {
			return nil, nil, err
		}
		insns = append(insns, ctrInit...)
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
	return genLayerDispatch(c.layer, c.all[c.layerIdx-1], c.r4IsRange, precedingLayersLeaveR4Range(c.all, c.layerIdx-1), dslReject)
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
		if c.canFallbackToBulkAdvance(stateIdx) {
			return c.emitCounterDrivenBulkAdvance(state, stateIdx)
		}
		return c.emitMultiStateSelfLoop(state, stateIdx)
	}

	if (len(state.Advances) > 0 || len(state.Counters) > 0) && state.OffsetAtEntry < 0 {
		return nil, nil, fmt.Errorf("%w: state %q has dynamic R4 on entry; pkt.advance and counter ops require a static layer-entry offset", ErrNotImplemented, state.Name)
	}

	var insns asm.Instructions
	stashAddr := inlineSelectAddr
	// Running byte distance from layer-entry to R4. Updated as each
	// extract emits its post-bounds Add.Imm; the Counters block reads
	// the post-extract value to anchor primary-header byte loads.
	fixedHs := state.OffsetAtEntry
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
		fixedHs += hs
		if vt, ok := variableTailFor(c.spec, ex.HeaderName); ok {
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
	// Literal templates are a fixed bounds-checked Add.Imm. Advances
	// are mutually exclusive with Extracts (loader-enforced), so
	// fixedHs is still equal to state.OffsetAtEntry here.
	for _, adv := range state.Advances {
		switch adv.Kind {
		case vocab.AdvanceOpField:
			// emitVariableTrailInline anchors its byte load at the
			// layer-entry slot via state.OffsetAtEntry, which only
			// matches a primary-header field. The loader admits aux-
			// targeted advance for the SACK / RR option-with-trailing
			// -array shape, but that form must live in a multi-state
			// loop sibling whose state.OffsetAtEntry is undefined and
			// therefore never reaches this inline path; reject loudly
			// rather than emit a silently mis-anchored load.
			if c.machine.AuxLayouts[adv.Target] != nil {
				return nil, nil, fmt.Errorf("%w: pkt.advance via aux-header field (target=%q) outside a multi-state loop sibling is not supported", ErrNotImplemented, adv.Target)
			}
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

	// Counter ops live after Extracts/Advances. fixedHs (running) is
	// the byte distance from layer-entry to R4 — counter set loads
	// the count from a primary-header byte at `R4 - fixedHs +
	// LenByteOff`.
	for _, op := range state.Counters {
		body, err := c.emitCounterOp(op, fixedHs, inlineCounterEnv(), dslReject)
		if err != nil {
			return nil, nil, err
		}
		insns = append(insns, body...)
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
