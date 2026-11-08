package core

import "fmt"

// Window kinds (README.md, Windows). The kind selects the obligations; the
// extraction outside the core assigns it (layout.go windowKind).
const (
	KindSite     = "site"         // P1c, P2 HF/HO/MO/MF, P3, P5, generic
	KindTail     = "site-P4"      // tail-call site
	KindWrap     = "site-P8"      // WP(i)·call W_i, W_i inlined
	KindEntry    = "prologue-P1"  // Pro_0
	KindCallback = "prologue-P1b" // FP(G) of a callback
	KindPass     = "prologue-P9"  // FP(G) of a pass callee
	KindPassLoad = "passload-P9"  // PL(i) before a call to an original function
	KindHook     = "hook-P7"      // hook body
)

// Window is everything the core sees : the window's instructions,
// the frame floor, which pseudo calls target hooks, and the inlined wrapper
// body for P8. The entry state is implicit (fresh symbols).
type Window struct {
	Kind       string
	Insns      []Insn       // contiguous, in stream order
	Center     int          // index in Insns of the original helper call or `call W_i`; -1 if none
	Callee     []Insn       // P8: body of W_i, nil otherwise
	Hook       map[int]bool // indices of Insns that are pseudo calls to a hook
	CalleeHook map[int]bool // the same for Callee
	Floor      int16        // f of the function holding the window (from the capture, trusted)
	HasFloor   bool
	// P8: the original helper call O[i] (full identity) and its pc in
	// Callee. Every path must execute exactly this instruction and no other
	// helper call may appear in Callee.
	HelperPC int
	Helper   Insn
	// P9 pass load: the pass prologue FP(G) of the called G, from which the
	// core derives r_G (for a pass prologue, Insns itself), and
	// LiveIn(O)[G], the registers live at G's entry in the original (S10).
	PassPrologue []Insn
	PassLive     uint16
}

// Verdict is binary. Its zero value is "not validated", so a
// missing or defaulted verdict never reads as validated. Rule
// is the category of the first failed obligation (C1-C6, site, R15, R0,
// P1, P1b, P9, P7, P8, kind, model, limit).
type Verdict struct {
	Validated bool   `json:"validated"`
	Rule      string `json:"rule,omitempty"`
	Reason    string `json:"reason"`
	Paths     int    `json:"paths"`
}

func notValidated(rule, format string, a ...any) Verdict {
	return Verdict{Rule: rule, Reason: rule + ": " + fmt.Sprintf(format, a...)}
}

// Check judges one window: the allowlist over every instruction (C6), then
// exhaustive symbolic execution (Explore), then the obligations (validated).
func Check(w Window) Verdict {
	for i, x := range w.Insns {
		if _, why := Allowed(x); why != "" { // rule:C6
			return notValidated("C6", "insn %d: %s", i, why)
		}
	}
	for i, x := range w.Callee {
		if _, why := Allowed(x); why != "" { // rule:C6-callee
			return notValidated("C6", "callee insn %d: %s", i, why)
		}
	}
	paths, f := Explore(w)
	if f != nil {
		return notValidated(f.Rule, "%s", f.Msg)
	}
	return validated(w, paths)
}
