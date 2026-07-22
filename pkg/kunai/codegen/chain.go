package codegen

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// staticChainCap is the {n,m} m upper bound the unroll path accepts.
// Quantifiers beyond this (including `+` / `*` / open-ended `{n,}`)
// require bpf_loop-based chain codegen and land in a later commit.
const staticChainCap = 4

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
func genStaticChain(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, pc *predCtx) (asm.Instructions, error) {
	if layer.RangeMax < 0 {
		return nil, fmt.Errorf("%w: open-ended quantifier {%d,} on %q needs bpf_loop chain codegen", ErrNotImplemented, layer.RangeMin, layer.Spec.Name)
	}
	if layer.RangeMax > staticChainCap {
		return nil, fmt.Errorf("%w: {%d,%d} on %q exceeds static-unroll cap %d; bpf_loop chain codegen will cover this", ErrNotImplemented, layer.RangeMin, layer.RangeMax, layer.Spec.Name, staticChainCap)
	}
	if layer.RangeMin < 1 {
		return nil, fmt.Errorf("%w: quantifier {%d,%d} with min < 1 on %q needs bpf_loop chain codegen", ErrNotImplemented, layer.RangeMin, layer.RangeMax, layer.Spec.Name)
	}

	hs, err := headerSize(layer.Spec)
	if err != nil {
		return nil, err
	}

	first, err := genStaticLayer(layer, index, all, pc)
	if err != nil {
		return nil, err
	}
	insns := append(asm.Instructions{}, first...)
	if layer.RangeMax == 1 {
		// One mandatory header. For a chain-end protocol it must signal
		// end, else an (RangeMax+1)-th header follows that the quantifier
		// disallows — reject. No-op for self-dispatch protocols.
		overRun, err := chainEndRequire(layer.Spec, hs, staticChainFrame, dslReject)
		if err != nil {
			return nil, err
		}
		insns = append(insns, overRun...)
		return insns, nil
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

	chainDone := fmt.Sprintf("dsl_chain_done_%d", index)
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
		// through to the next layer. Both termination mechanisms share the
		// target: chainEndCheck (the MPLS s-bit, the same check the bpf_loop
		// path runs) and genDispatch's fail path (VLAN's self-dispatch peek,
		// for which chainEndCheck is a no-op).
		target := dslReject
		if i >= layer.RangeMin {
			target = chainDone
		}
		endCheck, err := chainEndCheck(layer.Spec, hs, staticChainFrame, target)
		if err != nil {
			return nil, err
		}
		insns = append(insns, endCheck...)

		dispatch, err := genDispatch(selfLayer, layer, hs, selfRange, selfRange, target)
		if err != nil {
			return nil, err
		}
		insns = append(insns, dispatch...)
		insns = append(insns, emitBounds(hs, dslReject)...)
		insns = append(insns, preds...)
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

	if layer.RangeMin < layer.RangeMax {
		// Landing for any in-range iteration that hit its natural chain-end
		// (or, for self-dispatch protocols, missed its self-dispatch peek):
		// falls through to the next layer with offsetBase still pointing
		// past the last successful iteration.
		insns = append(insns, landingNoop(chainDone))
	}
	return insns, nil
}
