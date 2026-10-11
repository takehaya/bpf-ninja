package codegen

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// staticChainCap is the {n,m} m upper bound the unroll path accepts for
// a fixed-length layer (vlan, mpls). Quantifiers beyond it, including
// `+` / `*` / open-ended `{n,}`, take the bpf_loop chain (bpfloop.go). A
// parser-machine layer unrolls further, see staticMachineChainCap.
const staticChainCap = 4

// staticMachineChainCap bounds the instances a repeated parser-machine
// layer unrolls to, one machine per instance (genStaticMachineChain). An
// open quantifier stands for the protocol's MAX_DEPTH, so every bundled
// protocol with a self edge must declare at most this many (ipv4 takes
// the default 8, ipv6 declares 4; TestBundledChainDepthsFitMachineCap
// pins it); a larger depth, or an explicit `{n,m}` past it, is an
// implementation limit (ErrNotImplemented), not a typing error.
const staticMachineChainCap = 8

// isMachineChain reports whether layer is a repeated parser-machine layer
// lowered by genStaticMachineChain: `+`, `*`, `{n,}`, or `{n,m}` with
// m ≥ 2 on a protocol with a parser machine. (`?`, `{0,1}` and `{1,1}`
// are single-instance lowerings; an alternation group has no machine.)
func isMachineChain(layer *ir.LayerInstance) bool {
	if layer == nil || layer.Alternation != nil || layer.Spec == nil || layer.Spec.ParseStateMachine == nil {
		return false
	}
	switch layer.Quant {
	case ast.QuantPlus, ast.QuantStar:
		return true
	case ast.QuantRange:
		return layer.RangeMax < 0 || layer.RangeMax >= 2
	}
	return false
}

// machineChainBounds is the instance range genStaticMachineChain unrolls:
// the quantifier's bounds with the protocol's MAX_DEPTH standing in for an
// open upper bound, as the spec evaluates it (evalProtoLayer: fuel :=
// m.getD maxDepth, so `ipv4+` is `ipv4{1,8}` and `ipv6*` is `ipv6{0,4}`),
// shared with the capture bound (layerMaxInstances) through chainMaxIter.
// A bound past staticMachineChainCap is ErrNotImplemented.
func machineChainBounds(layer *ir.LayerInstance) (lo, hi int, err error) {
	lo, _ = chainBounds(layer)
	hi, err = chainMaxIter(layer)
	if err != nil {
		return 0, 0, err
	}
	if hi > staticMachineChainCap {
		return 0, 0, fmt.Errorf("%w: %s on %q unrolls to %d parser machines, more than the %d supported; write a bound of at most %d (`{n,m}`)", ErrNotImplemented, quantText(layer), layer.Spec.Name, hi, staticMachineChainCap, staticMachineChainCap)
	}
	return lo, hi, nil
}

// quantText prints a layer's quantifier as the DSL spells it.
func quantText(layer *ir.LayerInstance) string {
	switch layer.Quant {
	case ast.QuantOne:
		return ""
	case ast.QuantOpt:
		return "?"
	case ast.QuantPlus:
		return "+"
	case ast.QuantStar:
		return "*"
	}
	if layer.RangeMax < 0 {
		return fmt.Sprintf("{%d,}", layer.RangeMin)
	}
	return fmt.Sprintf("{%d,%d}", layer.RangeMin, layer.RangeMax)
}

// staticChainFitsRange reports whether a QuantRange's upper bound can
// ride the static-unroll path. Open-ended ({n,} has RangeMax=-1) and
// anything past the cap spill to the bpf_loop path.
func staticChainFitsRange(max int) bool {
	return max > 0 && max <= staticChainCap
}

// genStaticChain emits `{n,m}` by repeating the layer block m times.
// Chain iteration is required because `{n,m>1}` identifies the *next*
// instance by the previous one, not by the outer parent — so the
// second and later iterations peek a self-dispatch const that must be
// declared in the vocab (e.g. KUNAI_VLAN_VLAN_ETHERTYPE,
// KUNAI_MPLS_MPLS_NO_CHECK).
// Iterations below RangeMin fail hard; iterations at or above RangeMin
// skip to a single chain-done landing so a short stack falls through.
func genStaticChain(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, qo queriedOptions, pc *predCtx) (asm.Instructions, error) {
	if !staticChainFitsRange(layer.RangeMax) {
		// genLayerInner routes an open or larger bound to the bpf_loop chain.
		return nil, fmt.Errorf("codegen: genStaticChain on %q with %s", layer.Spec.Name, quantText(layer))
	}
	optional := layer.RangeMin == 0
	if optional {
		if err := optionalLayerGuard(layer, index, all); err != nil {
			return nil, err
		}
	}

	hs, err := headerSize(layer.Spec)
	if err != nil {
		return nil, err
	}

	chainDone := fmt.Sprintf("dsl_chain_done_%d", index)
	// Iteration 0: mandatory when RangeMin ≥ 1; for `{0,m}` it is the
	// same peek-and-skip block as `?` (`{0,1}` ≡ `?`), landing on chainDone.
	// The absent edge (`{0,m}` with no header) gets its own label when it
	// must dispatch the next layer against the grandparent (D-034).
	absentLabel := chainDone
	if ir.AbsentEdgeApplies(all, index) {
		absentLabel = fmt.Sprintf("dsl_absent_%d", index)
	}
	// A marked optional layer's entry slot reads "absent" until a present
	// iteration overwrites it (D-003); the absent path never writes again.
	sentinel, err := emitLayerEntrySentinel(layer, qo)
	if err != nil {
		return nil, err
	}
	var first asm.Instructions
	if optional {
		first, err = emitPeekedIterZero(layer, index, all, absentLabel, qo, pc)
	} else {
		first, err = genStaticLayer(layer, index, all, qo, pc)
	}
	if err != nil {
		return nil, err
	}
	insns := append(asm.Instructions{}, sentinel...)
	insns = append(insns, first...)
	if layer.RangeMax == 1 {
		// One header at most. For a chain-end protocol it must signal
		// end, else an (RangeMax+1)-th header follows that the quantifier
		// disallows — reject. No-op for self-dispatch protocols.
		overRun, err := chainEndRequire(layer.Spec, hs, staticChainFrame, dslReject)
		if err != nil {
			return nil, err
		}
		insns = append(insns, overRun...)
		return chainLanding(insns, layer, optional, chainDone, absentLabel, index, all, qo)
	}

	selfConst := layer.Spec.SelectDispatchConst(layer.Spec.Name)
	if selfConst == nil {
		self := strings.ToUpper(layer.Spec.Name)
		return nil, fmt.Errorf("%w: chained %q has no self-dispatch const (declare KUNAI_%s_%s_<FIELD> or KUNAI_%s_%s_NO_CHECK in %s.p4)", ErrNotImplemented, layer.Spec.Name, self, self, self, self, layer.Spec.Name)
	}
	// chain iter ≥ 1 skips genStaticLayer / parser machine and only does
	// extract+advance(hs). For variable-layout protocols (ipv4 IHL,
	// ipv6 ext, srv6 segments, etc.) that means the iter would advance
	// by primary-header size only, missing the variable trailer — silent
	// miscompile (= the #11 class). Use layered dispatch
	// (`eth/X/X/...`) instead so each layer runs its own parser machine.
	if layer.Spec.HasVariableLayout() {
		return nil, fmt.Errorf("%w: chained %q has a variable-length primary header (parser machine present); chain iter ≥ 1 would skip the trailer walk and silently miscompile. Use layered dispatch (e.g. `eth/%s/%s/...`) so each layer runs its own parser machine", ErrNotImplemented, layer.Spec.Name, layer.Spec.Name, layer.Spec.Name)
	}
	selfLayer := &ir.LayerInstance{
		Spec:     layer.Spec,
		Dispatch: &ir.DispatchChoice{Type: selfConst.Type, Const: selfConst},
	}
	// Predicates are identical across iterations; emit once and append
	// the same slice from each iteration. Use a no-accumulate predCtx so
	// an `in @set` extraction records its host slot only once (genStaticLayer
	// above already did); the store asm still replays each iteration.
	// nil-safe: a nil pc (host without set support) stays nil.
	var replayPC *predCtx
	if pc != nil {
		replayPC = &predCtx{sets: pc.sets}
	}
	preds, err := emitPredicates(layer.Predicates, replayPC)
	if err != nil {
		return nil, err
	}

	// Self-repeating layer: the dispatch parent is this same layer, so
	// R4-range and parent-entry-range both reduce to "did anything
	// before this layer leave R4 a range scalar". Computed once outside
	// the unroll loop since it is invariant across iterations.
	selfRange := precedingLayersLeaveR4Range(all, index)
	for i := 1; i < layer.RangeMax; i++ {
		// Where this iteration goes when the chain ends here (i headers in
		// so far). Below RangeMin a chain-end means the stack is shorter
		// than the quantifier requires (under-run) → reject; at or above
		// RangeMin it is a valid natural end → terminate the chain and fall
		// through to the next layer. genDispatch's fail path covers both
		// termination mechanisms: the chain-end signal of the previous
		// header (the MPLS s-bit, the same check the bpf_loop path runs)
		// and the self-dispatch peek (VLAN's ethertype).
		target := dslReject
		if i >= layer.RangeMin {
			target = chainDone
		}
		dispatch, err := genDispatch(selfLayer, layer, hs, qo, selfRange, selfRange, target)
		if err != nil {
			return nil, err
		}
		insns = append(insns, dispatch...)
		insns = append(insns, emitBounds(hs, dslReject)...)
		insns = append(insns, preds...)
		entry, err := emitLayerEntryStore(layer, qo)
		if err != nil {
			return nil, err
		}
		insns = append(insns, entry...)
		insns = append(insns, emitAdvance(hs))
	}

	// All RangeMax headers consumed without an earlier natural end: the
	// last one must signal chain-end, else the stack is longer than the
	// quantifier allows (over-run) → reject. No-op for self-dispatch
	// protocols, whose over-run the next layer's dispatch peek catches.
	overRun, err := chainEndRequire(layer.Spec, hs, staticChainFrame, dslReject)
	if err != nil {
		return nil, err
	}
	insns = append(insns, overRun...)
	return chainLanding(insns, layer, optional, chainDone, absentLabel, index, all, qo)
}

// genOptionalMachineLayer lowers `?` / `{0,1}` on a parser-machine layer:
// the machine runs as for a mandatory layer, except that a failed dispatch
// jumps to the absent label instead of rejecting. The dispatch is the
// parent's constant (`ipv6/srv6?`, `eth/ipv4?`) or, under a parent with
// none, the probe of the layer's self-validation fields (`mpls/ipv4?`).
// `layer` is the instance the demand walker and the stack plan know, not
// a `{0,1}` copy.
func genOptionalMachineLayer(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, qo queriedOptions, plan *accPlan, pc *predCtx) (asm.Instructions, asm.Instructions, error) {
	if err := optionalLayerGuard(layer, index, all); err != nil {
		return nil, nil, err
	}
	chainDone := fmt.Sprintf("dsl_chain_done_%d", index)
	absentLabel := chainDone
	if ir.AbsentEdgeApplies(all, index) {
		absentLabel = fmt.Sprintf("dsl_absent_%d", index)
	}
	sentinel, err := emitLayerEntrySentinel(layer, qo)
	if err != nil {
		return nil, nil, err
	}
	body, callbacks, err := genParserMachineOn(layer, index, all, qo, plan, pc, absentLabel)
	if err != nil {
		return nil, nil, err
	}
	insns := append(asm.Instructions{}, sentinel...)
	insns = append(insns, body...)
	if absentLabel != chainDone {
		insns, err = withAbsentEdge(insns, absentLabel, index, all, qo)
		return insns, callbacks, err
	}
	// R0 (the scratch window) is live on both paths; R3 is not after the
	// machine's bpf_loop, so the landing must not touch it.
	return append(insns, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(chainDone)), callbacks, nil
}

// genStaticMachineChain lowers a repeated parser-machine layer with a
// declared self edge (`ipv4{1,2}`, `ipv6{0,2}`, `ipv4+`, `ipv6*`,
// `ipv4{2,}`): one parser machine per instance, so each header's variable
// length, option walk and bracket predicates are those of that header
// (spec `iterate`: every instance runs `extract`, a predicate failure
// rejects, only a dispatch miss ends the chain). The instance range is
// machineChainBounds: an open bound stands for MAX_DEPTH instances.
// Iteration 0 is the layer as usual, optional when n = 0. Iteration i ≥ 1
// dispatches through the self edge against iteration i-1
// (genParserMachineIter); its miss ends the chain at the done landing when
// i ≥ n, and rejects below n (under-run). The slots are the layer's own,
// written after each successful dispatch: a where reference reads the
// last instance.
func genStaticMachineChain(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, qo queriedOptions, plan *accPlan, pc *predCtx) (asm.Instructions, asm.Instructions, error) {
	if !isMachineChain(layer) {
		return nil, nil, fmt.Errorf("codegen: genStaticMachineChain on %q with %s", layer.Spec.Name, quantText(layer))
	}
	lo, hi, err := machineChainBounds(layer)
	if err != nil {
		return nil, nil, err
	}
	if layer.Spec.ChainEnd != nil {
		// The over-run check at the bound (D-024) assumes a fixed header.
		return nil, nil, fmt.Errorf("%w: %s on %q: a parser-machine layer with a chain-end rule", ErrNotImplemented, quantText(layer), layer.Spec.Name)
	}
	if layer.Spec.SelectDispatchConst(layer.Spec.Name) == nil {
		return nil, nil, fmt.Errorf("%w: repeated %q has no self-dispatch const (resolver bug)", ErrNotImplemented, layer.Spec.Name)
	}
	optional := lo == 0
	if optional {
		if err := optionalLayerGuard(layer, index, all); err != nil {
			return nil, nil, err
		}
	}
	chainDone := fmt.Sprintf("dsl_chain_done_%d", index)
	absentLabel := chainDone
	if optional && ir.AbsentEdgeApplies(all, index) {
		absentLabel = fmt.Sprintf("dsl_absent_%d", index)
	}
	// A marked optional layer's entry slot reads "absent" until a present
	// iteration overwrites it (D-003).
	insns, err := emitLayerEntrySentinel(layer, qo)
	if err != nil {
		return nil, nil, err
	}
	var callbacks asm.Instructions
	for i := 0; i < hi; i++ {
		target := dslReject
		switch {
		case i == 0 && optional:
			target = absentLabel
		case i >= lo && i > 0:
			target = chainDone
		}
		body, cbs, err := genParserMachineIter(layer, index, all, qo, plan, pc, target, i)
		if err != nil {
			return nil, nil, err
		}
		insns = append(insns, body...)
		callbacks = append(callbacks, cbs...)
	}
	// The done landing is where an iteration ≥ n ends the chain (and the
	// absent iteration 0 of `{0,m}` without its own edge); `{m,m}` never
	// jumps there. R0 (the scratch window) is live on both paths; R3 is
	// not after the machine's bpf_loop, so the landing must not touch it.
	if lo < hi {
		insns = append(insns, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(chainDone))
	}
	if absentLabel != chainDone {
		insns, err = withAbsentEdge(insns, absentLabel, index, all, qo)
		if err != nil {
			return nil, nil, err
		}
	}
	return insns, callbacks, nil
}

// chainLanding closes a static chain. chainDone is where an in-range
// iteration ≥ 1 that hit its natural chain-end (or, for self-dispatch
// protocols, missed its self-dispatch peek) falls through to the next
// layer with offsetBase still past the last successful iteration; for an
// optional chain the iteration-0 peek miss lands there too, unless the
// absent edge has its own block that dispatches the next layer against
// the grandparent (D-034).
func chainLanding(insns asm.Instructions, layer *ir.LayerInstance, optional bool, chainDone, absentLabel string, index int, all []*ir.LayerInstance, qo queriedOptions) (asm.Instructions, error) {
	if (layer.RangeMax > 1 && layer.RangeMin < layer.RangeMax) || (optional && absentLabel == chainDone) {
		insns = append(insns, landingNoop(chainDone))
	}
	if optional && absentLabel != chainDone {
		return withAbsentEdge(insns, absentLabel, index, all, qo)
	}
	return insns, nil
}
