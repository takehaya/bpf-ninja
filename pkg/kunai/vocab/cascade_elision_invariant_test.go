package vocab

import "testing"

// The TCP vocabulary must reject malformed fixed option lengths whether or
// not the DSL reads that particular option. These checks cannot be elided.
func TestTCPOptionLengthValidation(t *testing.T) {
	spec := loadBundled(t)["tcp"]
	want := map[string]int{"parse_mss": 4, "parse_ws": 3, "parse_sack_perm": 2, "parse_ts": 10}
	for _, state := range spec.ParseStateMachine.States {
		n, ok := want[state.Name]
		if !ok {
			continue
		}
		delete(want, state.Name)
		if state.Trans.Kind != TransSelect || state.Trans.Select == nil {
			t.Fatalf("%s has no validation", state.Name)
		}
		sel := state.Trans.Select
		if sel.Default != StateReject || len(sel.Keys) != 1 || len(sel.Cases) != 1 || len(sel.Cases[0].Values) != 1 || sel.Cases[0].Values[0].Value != uint64(n) {
			t.Errorf("%s must reject lengths other than %d", state.Name, n)
		}
		if LoopSiblingTarget(state) < 0 {
			t.Errorf("%s has no loop continuation", state.Name)
		}
	}
	if len(want) > 0 {
		t.Fatalf("missing option validators: %v", want)
	}
}
