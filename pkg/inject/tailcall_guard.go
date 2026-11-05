package inject

import "github.com/cilium/ebpf/asm"

// losesTailCallReachability models the buggy check_max_stack_depth_subprog
// walk which replaces the local flag on callee entry but doesn't restore it.
func losesTailCallReachability(insns asm.Instructions) (bool, error) {
	funcs, err := stackCallGraph(insns, 0)
	if err != nil {
		return false, err
	}
	if _, err := stackTopoOrder(funcs); err != nil {
		return false, err
	}
	want := make([]bool, len(funcs))
	var reachesTail func(int) bool
	reachesTail = func(i int) bool {
		if want[i] || funcs[i].tailCall {
			want[i] = true
			return true
		}
		for _, callee := range funcs[i].callees {
			if reachesTail(callee) {
				want[i] = true
			}
		}
		return want[i]
	}
	if len(funcs) == 0 || !reachesTail(0) {
		return false, nil
	}

	marked := make([]bool, len(funcs))
	for i := range funcs {
		marked[i] = funcs[i].tailCall
	}
	local := false
	var walk func(int, []int)
	walk = func(i int, callers []int) {
		callers = append(callers, i)
		for _, callee := range funcs[i].walk {
			local = funcs[callee].tailCall
			walk(callee, callers)
		}
		if local {
			for _, caller := range callers {
				marked[caller] = true
			}
		}
	}
	walk(0, nil)
	return !marked[0], nil
}

func introducesTailCallReachabilityLoss(original, transformed asm.Instructions) (bool, error) {
	before, err := losesTailCallReachability(original)
	if err != nil || before {
		return false, err
	}
	return losesTailCallReachability(transformed)
}
