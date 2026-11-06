package injectcheck

import (
	"cmp"
	"maps"
	"slices"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/ctxflow"
)

// passCall is a direct call, at original index at, inside the function that
// starts at caller.
type passCall struct{ at, caller int }

type passPremise struct {
	frame PassFrame
	calls []passCall // every call to the function, unless the frame is Saved
}

// passFrames collects the passed-context premises of the site targets and
// re-derives each from the original stream: the function is called directly
// and never used as a callback; unless Saved, it reads its register before
// writing it on no path, and every call to it lies in the entry or in another
// function with a premise, whose slot the call loads from. It returns the
// premises by function start and the function start of each site that names
// one. No frame floor may start inside such a function, or inside the entry
// when a call there passes the context, after its start: the slot would move
// or be overwritten by the original code.
func passFrames(in asm.Instructions, pcs []int, index map[int]int, targets targetBindings, frames []FrameFloor) (map[int]passPremise, map[int]int, error) {
	refs, calls, starts := map[int]bool{}, map[int][]int{}, []int{0}
	for i, ins := range in {
		if !ins.IsFunctionReference() {
			continue
		}
		t, err := target(in, pcs, index, i)
		if err != nil {
			return nil, nil, inputError(InputOriginalCFG, "original edge: %v", err)
		}
		if ins.IsLoadOfFunctionPointer() {
			refs[t] = true
		} else {
			calls[t] = append(calls[t], i)
		}
		starts = append(starts, t)
	}
	bodies := map[int]map[int]bool{}
	bodyOf := func(start int) map[int]bool {
		if bodies[start] == nil {
			bodies[start] = body(in, pcs, index, start)
		}
		return bodies[start]
	}
	premises, owner := map[int]PassFrame{}, map[int]int{}
	keys := slices.SortedFunc(maps.Keys(targets), func(a, b targetKey) int { return cmp.Or(cmp.Compare(a.site, b.site), cmp.Compare(a.when, b.when)) })
	for _, key := range keys {
		ctx := targets[key].ctx
		if ctx == nil || len(ctx.Pass) == 0 {
			continue
		}
		for _, frame := range ctx.Pass {
			if prior, ok := premises[frame.Start]; ok && prior != frame {
				return nil, nil, inputError(InputTarget, "inconsistent passed-context premises for the function at %d", frame.Start)
			}
			premises[frame.Start] = frame
		}
		if start := ctx.Pass[0].Start; !bodyOf(start)[key.site] {
			return nil, nil, reject(CtxProvenance, "site %d is not reachable from the function at %d its context premise names", key.site, start)
		} else {
			owner[key.site] = start
		}
	}
	// ownerOf returns the function containing i: the closest start at or
	// before it, from which i must be reachable.
	ownerOf := func(i int) int {
		best := -1
		for _, s := range starts {
			if s <= i && s > best {
				best = s
			}
		}
		if best < 0 || !bodyOf(best)[i] {
			return -1
		}
		return best
	}
	out, fromEntry := map[int]passPremise{}, false
	for _, start := range slices.Sorted(maps.Keys(premises)) {
		frame := premises[start]
		switch {
		case refs[start]:
			return nil, nil, reject(CtxProvenance, "the function at %d the context is passed to is used as a callback", start)
		case len(calls[start]) == 0:
			return nil, nil, reject(CtxProvenance, "the function at %d the context is passed to is never called directly", start)
		}
		premise := passPremise{frame: frame}
		if !frame.Saved {
			reads, err := ctxflow.ArgReads(in, start)
			if err != nil {
				return nil, nil, reject(CtxProvenance, "the function at %d: %v", start, err)
			}
			if reads&(1<<frame.Reg) != 0 {
				return nil, nil, reject(CtxProvenance, "the function at %d reads r%d before writing it, so it cannot take the context there", start, frame.Reg)
			}
			for _, at := range calls[start] {
				caller := ownerOf(at)
				if _, ok := premises[caller]; caller != 0 && !ok {
					return nil, nil, reject(CtxProvenance, "the call at %d to the function at %d is in a function with no passed context", at, start)
				}
				fromEntry = fromEntry || caller == 0
				premise.calls = append(premise.calls, passCall{at: at, caller: caller})
			}
		}
		out[start] = premise
	}
	for _, frame := range frames {
		inside := fromEntry && frame.Start != 0 && bodyOf(0)[frame.Start]
		for start := range out {
			inside = inside || frame.Start != start && bodyOf(start)[frame.Start]
		}
		if inside {
			return nil, nil, reject(CtxProvenance, "a frame floor starts at %d, inside a function the context is passed through", frame.Start)
		}
	}
	return out, owner, nil
}
