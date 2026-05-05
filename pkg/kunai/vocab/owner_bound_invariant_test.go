package vocab

// Regression invariant for B-4 / B-4a R1 contingency.
//
// Both TCP SACK (B-4) and IPv4 RR (B-4a) hit a verifier blowup when
// the parser block extracted the option header (`extract(sack); ...`)
// — the bpf_loop callback's JLT+Sub combo for the trailing
// `pkt.advance((field - base) << shift)` inflated scalar IDs past
// the 1M insn cap. Fix in both PR series: pivot to
// "dispatched-but-not-extracted" shape — the parse state body has
// only `pc.decrement(...lookahead...)` + `pkt.advance(...lookahead...)`
// with no `extract`, and the slot prelude (auxLoadEmitter) records
// the per-packet base before dispatch lands.
//
// This test pins the invariant: every HeaderStack with
// `OwnerOption != ""` (= owner-bound stack riding past an option)
// must have its owner option's parse state contain ZERO `ExtractOp`s.
// A future revert to `extract(option_header)` would re-introduce the
// verifier blowup; this test fails fast in CI before the matrix
// hits 1M insn.

import (
	"strings"
	"testing"
)

func TestOwnerBoundStacksUseDispatchedButNotExtracted(t *testing.T) {
	specs := loadBundled(t)

	for protoName, spec := range specs {
		if spec.ParseStateMachine == nil {
			continue
		}
		for stackParam, stack := range spec.ParseStateMachine.StackRefs {
			if stack.OwnerOption == "" {
				continue
			}
			// Find the parse state that handles the owner option.
			// Convention: state name is `parse_<owner>` (e.g.
			// parse_sack, parse_rr).
			stateName := "parse_" + stack.OwnerOption
			var state *ParseState
			for _, st := range spec.ParseStateMachine.States {
				if strings.EqualFold(st.Name, stateName) {
					state = st
					break
				}
			}
			if state == nil {
				t.Errorf("%s: owner-bound stack %q references option %q but no state %q found",
					protoName, stackParam, stack.OwnerOption, stateName)
				continue
			}
			if len(state.Extracts) > 0 {
				t.Errorf(
					"%s: owner-bound stack %q's owner state %q has %d Extract op(s); expected 0 (dispatched-but-not-extracted shape — see B-4 / B-4a R1 contingency in dsl-followups.md)",
					protoName, stackParam, stateName, len(state.Extracts),
				)
			}
		}
	}
}
