package codegen

import (
	"strings"
	"testing"
)

func TestLabelerNumbersPerPrefix(t *testing.T) {
	l := newLabeler()
	got := []string{l.fresh("a"), l.fresh("b"), l.fresh("a"), l.fresh("b"), l.fresh("a")}
	want := []string{"dsl_a_1", "dsl_b_1", "dsl_a_2", "dsl_b_2", "dsl_a_3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("label %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLabelerNilPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a nil labeler minted a label; want a panic")
		}
	}()
	var l *labeler
	l.fresh("a")
}

// TestGenLabelsStartAtOnePerCompile pins that label numbers come from the
// compile, not the process: the same filter compiled twice gives the same
// text, and each prefix starts at 1.
func TestGenLabelsStartAtOnePerCompile(t *testing.T) {
	const expr = "eth/(ipv4|ipv6)/tcp[dport in [1..5, 80], sport != 22]"
	first := compileBundled(t, expr).Instructions().String()
	second := compileBundled(t, expr).Instructions().String()
	if first != second {
		t.Fatalf("two compiles of %q differ", expr)
	}
	for _, label := range []string{"dsl_altdisp_done_1", predMatchLabelPrefix + "1", predInNextLabelPrefix + "1"} {
		if !strings.Contains(first, label) {
			t.Errorf("%q has no %s:\n%s", expr, label, first)
		}
	}
}

// TestStaticChainPredicateLabelsUnique pins that an unrolled chain emits
// its predicates per header with their own labels: reusing one emission
// placed each label once per header, which the loader refuses as a
// duplicate symbol.
func TestStaticChainPredicateLabelsUnique(t *testing.T) {
	out := compileBundled(t, "eth/mpls[label in [1..5, 100]]{1,3}/ipv4")
	if _, err := out.Instructions().SymbolOffsets(); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{predInNextLabelPrefix + "3", predMatchLabelPrefix + "3"} {
		if !strings.Contains(out.Instructions().String(), label) {
			t.Errorf("no %s: each of the three headers should mint its own", label)
		}
	}
}
