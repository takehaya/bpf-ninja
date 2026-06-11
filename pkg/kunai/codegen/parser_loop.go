package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

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

// canFallbackToBulkAdvance reports whether the multi-state-loop
// entry at stateIdx can be lowered as a single-shot bulk advance
// instead of a bpf_loop walk. Two conditions must hold:
//
//  1. The entry's select uses a counter key (1-key counter or 2-key
//     counter+lookahead). Lookahead-only walks (Mechanism 7 TCP
//     options) need iter-level kind dispatch and have no static
//     bulk-skip equivalent.
//  2. No options for this layer are queried by the program. When
//     `len(c.queried[c.layer]) == 0`, no per-option position
//     recording is needed, so the bpf_loop's only job is to advance
//     R4 past the trailer — which the bulk-advance path does in
//     ~10 insns instead of dragging in a bpf_loop subprogram and
//     its 32-iter verifier exploration.
//
// This is the demand-driven escape hatch that lets ipv4.p4 stay on
// Mechanism 8 without blowing the 1M-insn verifier limit on chains
// like `eth/ipv4/udp/gtp/...` where ipv4 options aren't queried —
// see dsl-followups.md B-2 for context.
func (c *pmCtx) canFallbackToBulkAdvance(stateIdx int) bool {
	state := c.machine.States[stateIdx]
	sel := state.Trans.Select
	if sel == nil {
		return false
	}
	hasCounter := false
	for _, k := range sel.Keys {
		if k.Kind == vocab.SelectKeyCounterIsZero {
			hasCounter = true
			break
		}
	}
	if !hasCounter {
		return false
	}
	return len(c.queried[c.layer]) == 0
}

// emitCounterDrivenBulkAdvance lowers a counter-driven multi-state
// loop entry as a Mechanism-1-equivalent variable-trail advance —
// no bpf_loop, no per-iter callback. The byte expression comes from
// the matching CounterOpSet's Skip, which encodes the same five-
// tuple (LenByteOff / mask / shift / scale / base) as
// AdvanceField. R4 advances by exactly that count, the (queried-
// option-free) walk's only observable side effect.
//
// Caller must have gated this through canFallbackToBulkAdvance so
// the entry is known counter-driven and the layer has no demand
// slots that would force a real walk.
func (c *pmCtx) emitCounterDrivenBulkAdvance(state *vocab.ParseState, stateIdx int) (asm.Instructions, asm.Instructions, error) {
	sel := state.Trans.Select
	var counterName string
	for _, k := range sel.Keys {
		if k.Kind == vocab.SelectKeyCounterIsZero {
			counterName = k.Counter
			break
		}
	}
	if counterName == "" {
		return nil, nil, fmt.Errorf("%w: bulk-advance fallback called on entry without counter key", ErrNotImplemented)
	}
	skip := vocab.CounterSetSkipForCounter(c.machine.States, counterName)
	if skip == nil {
		return nil, nil, fmt.Errorf("%w: counter %q has no set op; cannot derive bulk-skip expression", ErrNotImplemented, counterName)
	}
	if state.OffsetAtEntry < 0 {
		return nil, nil, fmt.Errorf("%w: bulk-advance fallback at state %q with dynamic R4 offset", ErrNotImplemented, state.Name)
	}
	vt := variableTailSkipFromHeaderLength(skip)
	tail, err := emitVariableTrailInline(state.OffsetAtEntry, vt, dslReject)
	if err != nil {
		return nil, nil, err
	}
	insns := append(asm.Instructions{}, tail...)
	insns = append(insns, asm.Ja.Label(c.doneLabel))
	c.r4IsRange = true
	return insns, nil, nil
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
	return emitFillStackSlots(dynamicAuxSentinel, len(demand), func(i int) (int16, error) {
		return c.queried.slotForLayer(c.layer, i+1)
	})
}

// emitFillStackSlots writes initImm into n stack slots resolved by
// the supplied indexer. Used by sentinel-init paths (dynamic aux
// slots, parser counter slots) where the same Mov+Store cascade
// keeps the per-machine setup tight. Returns nil instructions when
// n == 0 so callers can splat the result unconditionally.
func emitFillStackSlots(initImm int32, n int, resolve func(int) (int16, error)) (asm.Instructions, error) {
	if n == 0 {
		return nil, nil
	}
	insns := asm.Instructions{asm.Mov.Imm(asm.R3, initImm)}
	for i := range n {
		slot, err := resolve(i)
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
//
// The kind byte is loaded through boundedScalarLoad rather than a
// bare `R1 = R4+R3; *(u8*)(R1)`. On PTR_TO_MAP_VALUE the preceding
// `R0 = R4+R3+1; JGT R0, R5, break` would suffice, but on
// PTR_TO_PACKET (native XDP) the verifier does not carry that bound
// across to a freshly built pointer in another register, so it
// rejects the load as out of packet range. boundedScalarLoad re-runs
// the end-pointer check on the load register itself, which both hosts
// accept; the extra check is redundant on the map-value path.
func (c *pmCtx) emitDynamicAuxSlotPrelude(breakLabel string) (asm.Instructions, error) {
	demand := c.queried[c.layer]
	if len(demand) == 0 {
		return nil, nil
	}
	// R1 = kind byte at scratchStart(R4) + cursor(R3); R3/R4/R5 survive.
	insns := boundedScalarLoad(asm.R1, asm.R4, asm.R3, asm.R5, asm.Byte, breakLabel)
	for idx, layout := range demand {
		slot, err := c.queried.slotForLayer(c.layer, idx+1)
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
	prelude, err := c.emitDynamicAuxSlotPrelude(breakLabel)
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
	if err := assertCallbackComplexity(insns, cbSym); err != nil {
		return nil, err
	}
	return insns, nil
}

// emitMultiStateDispatch builds the per-case cascade for the entry's
// transition select. Each case either inlines its sibling's body
// (followed by Ja continueLabel) or jumps to breakLabel for
// accept / reject targets. Three legal entry shapes (validated by
// vocab.IsMultiStateLoopEntry): counter-only, lookahead-only, or
// the 2-key (counter, lookahead) tuple — each routes here through
// the matching helper.
func (c *pmCtx) emitMultiStateDispatch(entry *vocab.ParseState, entryIdx int, addr selectAddr, breakLabel, continueLabel string) (asm.Instructions, error) {
	sel := entry.Trans.Select
	if hasCounterAndKindKeys(sel) {
		return c.emitMultiStateCounterKindDispatch(entry, entryIdx, addr, breakLabel, continueLabel)
	}
	if isCounterIsZeroSelect(sel) {
		return c.emitMultiStateCounterDispatch(entry, entryIdx, breakLabel, continueLabel)
	}
	// Single key, single byte (validated by vocab.IsMultiStateLoopEntry).
	shape, err := c.resolveSelectKey(sel.Keys[0])
	if err != nil {
		return nil, err
	}
	defaultElidable := c.defaultIsLengthByteAdvance(sel.Default)
	var insns asm.Instructions
	for _, kase := range sel.Cases {
		mv := kase.Values[0]
		if !mv.IsWildcard && defaultElidable && c.caseRedundantWithDefault(kase.Target) {
			continue
		}
		caseSkip := fmt.Sprintf("%s_%s_%d_skip", c.labelNS, addr.labelTag, c.selectCounter())
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

// buildQueriedAuxNames materialises the OutParam-name set for the
// layer's queried options once per pmCtx, to avoid rebuilding it
// on every dispatch site. nil when no options are queried.
func buildQueriedAuxNames(qo queriedOptions, layer *ir.LayerInstance) map[string]bool {
	if qo == nil || layer == nil {
		return nil
	}
	layouts := qo[layer]
	if len(layouts) == 0 {
		return nil
	}
	names := make(map[string]bool, len(layouts))
	for _, l := range layouts {
		if l != nil {
			names[l.OutParam] = true
		}
	}
	return names
}

// defaultIsLengthByteAdvance reports whether the dispatch's default
// target is a parse_unknown_opt-equivalent sibling: zero extracts +
// exactly one lookahead-driven advance. When true, cases satisfying
// caseRedundantWithDefault may be elided; when false, every case
// must emit explicitly. Hoisted out of the per-case loop so the
// scan runs once per dispatch instead of once per case.
func (c *pmCtx) defaultIsLengthByteAdvance(defaultIdx int) bool {
	if defaultIdx == vocab.StateAccept || defaultIdx == vocab.StateReject {
		return false
	}
	if c.machine == nil {
		return false
	}
	def := c.machine.States[defaultIdx]
	if def == nil {
		return false
	}
	// Inline the parse_unknown_opt-equivalent shape: zero extracts,
	// exactly one lookahead-driven advance. Same predicate as
	// vocab/parser_machine.go's isAdvanceOnlySibling — duplicated
	// here so the elision contract doesn't require a cross-package
	// vocab export. Vocab-internal callers (ownerCandidate /
	// dispatchedAuxKind) keep using the lowercase predicate.
	return len(def.Extracts) == 0 && len(def.Advances) == 1 && def.Advances[0].Kind == vocab.AdvanceOpLookahead
}

// caseRedundantWithDefault reports whether a TLV-walk dispatch case
// is structurally equivalent to falling through to the cascade's
// default target — i.e. its only effect is extracting an aux that
// no consumer reads, and the default's length-byte advance consumes
// the option equivalently. Caller must have already checked the
// default via defaultIsLengthByteAdvance.
//
// Conditions (all must hold):
//   - Target is a sibling state (not accept/reject).
//   - Target has zero manual Advances (any kind), zero CounterOps.
//   - Target has at least one ExtractOp; no extract is a stack push;
//     no extracted aux is in c.queriedAuxes.
//
// Exclusions: EOL (target == StateAccept), NOP (literal advance),
// queried kinds, and parse_unknown_opt-equivalent siblings (no
// extract — would lose the dispatched-but-not-extracted shape that
// owner-bound stacks rely on; pinned by
// vocab/owner_bound_invariant_test.go) all fail at least one rule
// and stay emitted. Orthogonal to canFallbackToBulkAdvance, which
// elides the entire bpf_loop subprogram when no aux is queried.
//
// Motivation: kernel 6.12 / B-2a-2 fingerprint — see
// docs/ja/dsl-followups.md mitigation (d).
func (c *pmCtx) caseRedundantWithDefault(targetIdx int) bool {
	if targetIdx == vocab.StateAccept || targetIdx == vocab.StateReject {
		return false
	}
	if c.machine == nil {
		return false
	}
	target := c.machine.States[targetIdx]
	if target == nil {
		return false
	}
	if len(target.Advances) > 0 || len(target.Counters) > 0 {
		return false
	}
	if len(target.Extracts) == 0 {
		return false
	}
	for _, ex := range target.Extracts {
		if ex.IsStackPush {
			return false
		}
		if c.queriedAuxes[ex.OutParam] {
			return false
		}
	}
	return true
}

// hasCounterAndKindKeys reports whether sel uses the canonical TNA
// 2-key tuple `(<counter>.is_zero(), pkt.lookahead<bit<8>>())` —
// the byte-bounded TLV walk shape (IPv4 options being the prime
// example). vocab.IsMultiStateLoopEntry has already validated that
// the keys appear in this exact order when both are present.
func hasCounterAndKindKeys(sel *vocab.SelectOp) bool {
	return sel != nil && len(sel.Keys) == 2 &&
		sel.Keys[0].Kind == vocab.SelectKeyCounterIsZero &&
		sel.Keys[1].Kind == vocab.SelectKeyLookahead
}

// emitMultiStateCounterKindDispatch lowers the 2-key (counter,
// lookahead) tuple. Probe the counter first (zero → branch to the
// `(true, _)` body); otherwise cascade over the `(false, K)` cases'
// kind-byte JNE checks, falling back to the `(false, _)` arm or
// the explicit default. The counter-true body lives at the tail
// behind a landing label so the false-arm fall-through doesn't reach
// it accidentally.
func (c *pmCtx) emitMultiStateCounterKindDispatch(entry *vocab.ParseState, entryIdx int, addr selectAddr, breakLabel, continueLabel string) (asm.Instructions, error) {
	sel := entry.Trans.Select
	const (
		counterIdx = 0
		kindIdx    = 1
	)

	counterTrueLabel := fmt.Sprintf("%s_ctr_true_%d", c.labelNS, c.selectCounter())
	probe, err := c.emitCounterIsZeroProbe(sel.Keys[counterIdx].Counter, counterTrueLabel, callbackCounterEnv())
	if err != nil {
		return nil, err
	}
	kindShape, err := c.resolveSelectKey(sel.Keys[kindIdx])
	if err != nil {
		return nil, err
	}

	insns := append(asm.Instructions{}, probe...)

	// The counter-false default (`(false, _)`) needs locating ahead
	// of the case loop so the elision check sees the right fall-
	// through target regardless of vocab declaration order.
	counterFalseDefaultTarget := sel.Default
	for _, kase := range sel.Cases {
		cv := kase.Values[counterIdx]
		isCounterFalse := cv.IsWildcard || (cv.IsBool && !cv.Bool)
		if !isCounterFalse {
			continue
		}
		if kase.Values[kindIdx].IsWildcard {
			counterFalseDefaultTarget = kase.Target
			break
		}
	}
	defaultElidable := c.defaultIsLengthByteAdvance(counterFalseDefaultTarget)

	// Walk counter-false cases. Concrete kinds emit JNE; wildcard
	// kind already captured above. Counter-true cases are deferred
	// to the tail body.
	for _, kase := range sel.Cases {
		cv := kase.Values[counterIdx]
		isCounterFalse := cv.IsWildcard || (cv.IsBool && !cv.Bool)
		if !isCounterFalse {
			continue
		}
		kv := kase.Values[kindIdx]
		if kv.IsWildcard {
			continue
		}
		if defaultElidable && c.caseRedundantWithDefault(kase.Target) {
			continue
		}
		caseSkip := fmt.Sprintf("%s_%s_%d_skip", c.labelNS, addr.labelTag, c.selectCounter())
		insns = append(insns, emitKeyCompare(addr, kindShape, kindIdx, kv.Value, caseSkip)...)
		body, err := c.emitMultiStateCaseBody(kase.Target, entryIdx, breakLabel, continueLabel)
		if err != nil {
			return nil, err
		}
		insns = append(insns, body...)
		insns = append(insns, landingNoop(caseSkip))
	}
	defaultBody, err := c.emitMultiStateCaseBody(counterFalseDefaultTarget, entryIdx, breakLabel, continueLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, defaultBody...)

	insns = append(insns, landingNoop(counterTrueLabel))
	trueTarget := counterTrueTargetFor2Key(sel)
	trueBody, err := c.emitMultiStateCaseBody(trueTarget, entryIdx, breakLabel, continueLabel)
	if err != nil {
		return nil, err
	}
	insns = append(insns, trueBody...)
	return insns, nil
}

// counterTrueTargetFor2Key picks the counter-true target for a 2-key
// dispatch. Looks for the first case whose counter slot is `true` or
// wildcard; falls back to sel.Default. Mirrors the 1-key
// counterIsZeroTrueTarget but indexes the counter slot at 0 of the
// 2-key tuple.
func counterTrueTargetFor2Key(sel *vocab.SelectOp) int {
	for _, kase := range sel.Cases {
		cv := kase.Values[0]
		if cv.IsWildcard || (cv.IsBool && cv.Bool) {
			return kase.Target
		}
	}
	return sel.Default
}

// emitMultiStateCounterDispatch emits the dispatch for a counter-
// driven multi-state loop. The entry's select has exactly two arms
// (true / false on `<counter>.is_zero()`); probe the slot once, JEq
// to a label that runs the true-arm body, then fall through into
// the false-arm body. Each arm uses emitMultiStateCaseBody for
// uniform sibling-vs-terminal handling.
func (c *pmCtx) emitMultiStateCounterDispatch(entry *vocab.ParseState, entryIdx int, breakLabel, continueLabel string) (asm.Instructions, error) {
	sel := entry.Trans.Select
	trueLandingLabel := fmt.Sprintf("%s_ctr_true_%d", c.labelNS, c.selectCounter())
	probe, err := c.emitCounterIsZeroProbe(sel.Keys[0].Counter, trueLandingLabel, callbackCounterEnv())
	if err != nil {
		return nil, err
	}
	falseBody, err := c.emitMultiStateCaseBody(counterIsZeroFalseTarget(sel), entryIdx, breakLabel, continueLabel)
	if err != nil {
		return nil, err
	}
	trueBody, err := c.emitMultiStateCaseBody(counterIsZeroTrueTarget(sel), entryIdx, breakLabel, continueLabel)
	if err != nil {
		return nil, err
	}
	insns := append(probe, falseBody...)
	insns = append(insns, landingNoop(trueLandingLabel))
	return append(insns, trueBody...), nil
}

// counterIsZeroTrueTarget / counterIsZeroFalseTarget pick the
// dispatch target for the matching boolean arm, falling back to the
// default when no explicit case matches. The vocab loader has
// already validated that the select has two-arm shape.
func counterIsZeroTrueTarget(sel *vocab.SelectOp) int {
	for _, kase := range sel.Cases {
		mv := kase.Values[0]
		if (mv.IsBool && mv.Bool) || mv.IsWildcard {
			return kase.Target
		}
	}
	return sel.Default
}

func counterIsZeroFalseTarget(sel *vocab.SelectOp) int {
	for _, kase := range sel.Cases {
		mv := kase.Values[0]
		if (mv.IsBool && !mv.Bool) || mv.IsWildcard {
			return kase.Target
		}
	}
	return sel.Default
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
	totalHs := 0
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
		totalHs += hs
	}
	for _, adv := range sib.Advances {
		switch adv.Kind {
		case vocab.AdvanceOpField:
			// Aux-targeted: the byte sits at offset R3 - totalHs +
			// LenByteOff. emitVariableTrail folds totalHs via fixedHs
			// so the load lands at R3 + (-totalHs + LenByteOff). Used
			// by IPv4 RR's `pkt.advance((rr.length - 3) << 3)` after
			// `pkt.extract(rr)` to drain the trailing addrs[] tail.
			vt := variableTailSkipFromHeaderLength(adv.Skip)
			tail, err := emitVariableTrailCallback(totalHs, vt, breakLabel)
			if err != nil {
				return nil, err
			}
			insns = append(insns, tail...)
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
	for _, op := range sib.Counters {
		// CounterOpSet reads a primary-header byte at fixedHs-relative
		// offset; sibling iterations run with R3 anchored at the
		// per-iter cursor, not at primary-end, so a set here would
		// silently mis-anchor the load. The MVP rejects it loudly so
		// future migrations have to put pc.set in the start (or pre-
		// loop) state where the anchor is well-defined.
		if op.Kind == vocab.CounterOpSet {
			return nil, fmt.Errorf("%w: counter set inside multi-state self-loop sibling %q is not supported (declare it in the loop's pre-entry state)", ErrNotImplemented, sib.Name)
		}
		body, err := c.emitCounterOp(op, 0, callbackCounterEnv(), breakLabel)
		if err != nil {
			return nil, err
		}
		insns = append(insns, body...)
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
		if vt, ok := variableTailFor(c.spec, ex.HeaderName); ok {
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
	if err := assertCallbackComplexity(insns, cbSym); err != nil {
		return nil, err
	}
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
		if isCounterIsZeroSelect(t.Select) {
			return c.emitCounterIsZeroSelect(t.Select, func(target int) string {
				if target == fromState {
					return continueLabel
				}
				return breakLabel
			}, callbackCounterEnv())
		}
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
