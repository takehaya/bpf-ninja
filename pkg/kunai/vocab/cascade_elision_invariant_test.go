package vocab

// Regression invariant for B-2a-2 mitigation (d) (TLV-walk cascade
// elision). See docs/ja/dsl-followups.md.
//
// The codegen elision (`pkg/kunai/codegen/parser_loop.go::
// caseRedundantWithDefault`) collapses TLV-walk dispatch arms whose
// extract aux no consumer reads, AS LONG AS the cascade's default
// is parse_unknown_opt-equivalent (zero extracts + one lookahead-
// driven advance) and the case sibling is extract-only with no
// manual advance / counter / IsStackPush. With four extract-only
// arms in tcp.p4's parse_options today (MSS, WS, SACK_PERM, TS),
// this lets a single-option query (e.g. `where tcp.options.MSS.
// value == 1460`) compile to a 4-case cascade instead of 8 — the
// kernel-6.12 verifier coalescing fix.
//
// A vocab edit that adds even a `pkt.advance(<lit>)` after the
// extract in any of those four siblings silently turns elision
// off for that kind. The unit tests in
// `pkg/kunai/codegen/parser_loop_elision_test.go` use the bundled
// vocab, so a regression there fails locally — but only after CI
// has burned through the 4-kernel BPF verifier matrix. This test
// fails *at vocab-load time* (in `make test`) before a slow CI run
// has a chance to surface the symptom downstream.
//
// Invariant: for every bundled vocab with a multi-state self-loop
// entry whose default sibling is parse_unknown_opt-equivalent, the
// expected elide-eligible kind set matches a hardcoded snapshot.
// New protocols with a TLV walk shape add an entry here as part of
// their landing PR — implicit endorsement that the elision is
// understood.

import (
	"sort"
	"strings"
	"testing"
)

func TestCascadeElisionEligibilityIsPinned(t *testing.T) {
	specs := loadBundled(t)

	// Hardcoded expected snapshot. Format: protocol name → sorted
	// list of state names whose dispatch arm is currently
	// elide-eligible (extract-only, no manual advance, no counter,
	// no stack push). New protocols extending this set must also
	// add an entry; existing protocols losing entries indicates a
	// silent elision regression.
	want := map[string][]string{
		"tcp": {"parse_mss", "parse_sack_perm", "parse_ts", "parse_ws"},
	}

	got := map[string][]string{}
	for protoName, spec := range specs {
		machine := spec.ParseStateMachine
		if machine == nil {
			continue
		}
		for entryIdx, entry := range machine.States {
			if !IsMultiStateLoopEntry(machine.States, entryIdx) {
				continue
			}
			sel := entry.Trans.Select
			if sel == nil {
				continue
			}
			defaultIdx := sel.Default
			if defaultIdx < 0 || defaultIdx >= len(machine.States) {
				continue
			}
			defState := machine.States[defaultIdx]
			if defState == nil || !isAdvanceOnlySibling(defState) {
				continue
			}
			// Cascade default is parse_unknown_opt-equivalent.
			// Walk concrete-kind cases, identify elide-eligible
			// siblings.
			for _, kase := range sel.Cases {
				if kase.Target < 0 || kase.Target >= len(machine.States) {
					continue
				}
				target := machine.States[kase.Target]
				if target == nil {
					continue
				}
				if isElideEligibleSibling(target) {
					got[protoName] = append(got[protoName], target.Name)
				}
			}
		}
	}

	for proto, names := range got {
		sort.Strings(names)
		got[proto] = names
	}

	if !equalStringSliceMap(want, got) {
		t.Errorf(
			"cascade elision-eligibility set drifted from snapshot.\n"+
				"want: %s\n"+
				"got:  %s\n"+
				"\nNew protocols with a TLV walk shape add an entry to `want`.\n"+
				"Existing protocols losing entries indicates a silent elision regression\n"+
				"(e.g. a `pkt.advance(<lit>)` accidentally added after the extract in a\n"+
				"parse_<aux> sibling state). See B-2a-2 mitigation (d) in dsl-followups.md.",
			formatMap(want), formatMap(got),
		)
	}
}

// isElideEligibleSibling mirrors the `caseRedundantWithDefault`
// predicate's case-side check (excluding the queriedAuxes runtime
// gate, which is per-program not per-vocab). Pinned here as a
// vocab-side test helper so codegen and vocab agree on the
// structural shape.
func isElideEligibleSibling(s *ParseState) bool {
	if s == nil || len(s.Extracts) == 0 {
		return false
	}
	if len(s.Advances) > 0 || len(s.Counters) > 0 {
		return false
	}
	for _, ex := range s.Extracts {
		if ex.IsStackPush {
			return false
		}
	}
	return true
}

func equalStringSliceMap(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
	}
	return true
}

func formatMap(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(k)
		b.WriteString(": [")
		b.WriteString(strings.Join(m[k], " "))
		b.WriteString("]")
	}
	b.WriteString("}")
	return b.String()
}
