package resolve

import (
	"strings"
	"testing"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/parser"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// The tests below pin the wording of every type-system error helper
// against docs/ja/dsl-types.md §8. The catalog there is informally
// formatted but each "code" line should be reproducible by calling
// the matching helper here. If the spec's wording moves the test
// breaks, prompting whoever updated the wording to update both.
//
// We compare on the message body (= without the "<file>:L:C: "
// position prefix that errorf prepends) so the assertions stay
// position-agnostic.

func errorMessage(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("nil error")
	}
	msg := err.Error()
	if i := strings.Index(msg, ": "); i > 0 {
		// Strip the "1:1: " position prefix.
		return msg[i+2:]
	}
	return msg
}

func TestErrFitInFieldMatchesSpec(t *testing.T) {
	got := errorMessage(t, errFitInField(ast.Position{Line: 1, Col: 1}, 99999, 16, "tcp", "dport"))
	want := "value 99999 does not fit in 16-bit field tcp.dport"
	if got != want {
		t.Errorf("\n  got:  %q\n  want: %q", got, want)
	}
}

func TestErrFitInArithMatchesSpec(t *testing.T) {
	got := errorMessage(t, errFitInArith(ast.Position{Line: 1, Col: 1}, 99999, 16))
	want := "value 99999 does not fit in bit<16> (in arithmetic context)"
	if got != want {
		t.Errorf("\n  got:  %q\n  want: %q", got, want)
	}
}

func TestErrStaticDivZeroMatchesSpec(t *testing.T) {
	for op, want := range map[ast.ArithOp]string{
		ast.ArithDiv: "division by zero",
		ast.ArithMod: "modulo by zero",
	} {
		got := errorMessage(t, errStaticDivZero(ast.Position{Line: 1, Col: 1}, op))
		if got != want {
			t.Errorf("op %v:\n  got:  %q\n  want: %q", op, got, want)
		}
	}
}

func TestErrLiteralFieldShapeMatchesSpec(t *testing.T) {
	ref := &ir.FieldRef{
		Layer: &ir.LayerInstance{Spec: &vocab.ProtocolSpec{Name: "tcp"}},
		Field: &vocab.Field{Name: "dport", Bits: 16},
	}
	got := errorMessage(t, errLiteralFieldShape(ast.Position{Line: 1, Col: 1}, "IPv4 address", 32, ref))
	want := "IPv4 address literal needs a bit<32> field; tcp.dport is bit<16>"
	if got != want {
		t.Errorf("\n  got:  %q\n  want: %q", got, want)
	}
}

func TestErrUnknownActionLiteralMatchesSpec(t *testing.T) {
	got := errorMessage(t, errUnknownActionLiteral(ast.Position{Line: 1, Col: 1}, "XDP_FOO", 5))
	want := `unknown action "XDP_FOO" (host accepts 5 symbols)`
	if got != want {
		t.Errorf("\n  got:  %q\n  want: %q", got, want)
	}
}

func TestErrOrderedNotAllowedMatchesSpec(t *testing.T) {
	got := errorMessage(t, errOrderedNotAllowed(ast.Position{Line: 1, Col: 1}, ast.CmpLt, "CIDR"))
	want := "ordered comparison < not allowed for CIDR (CIDR supports only == and !=)"
	if got != want {
		t.Errorf("\n  got:  %q\n  want: %q", got, want)
	}
}

// TestResolveRejectsBareIdentValue locks the resolver's typing reject
// for bracket predicates whose RHS is a bare identifier. Previously
// the codegen surfaced ErrNotImplemented "predicate value type ident"
// for these — a misleading "missing emit" diagnostic for what is
// actually a type-system violation. The resolver now stops them with
// a clear error before codegen.
func TestResolveRejectsBareIdentValue(t *testing.T) {
	cases := []string{
		"eth/ipv4/tcp[dport==true]",
		"eth/ipv4/tcp[dport==port]",
		"eth/ipv4/tcp[dport==X]",
		// 'in' list element bare-ident is also rejected — typing rule
		// is per-element, not per-predicate.
		"eth/ipv4/tcp[dport in [443, foo]]",
	}
	for _, expr := range cases {
		f, perr := parser.Parse(expr, "t.dsl", nil)
		if perr != nil {
			t.Fatalf("%s: parse: %v", expr, perr)
		}
		_, err := Resolve(f, loadVocab(t), nil)
		if err == nil {
			t.Errorf("%s: expected reject", expr)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "bare identifier") && !strings.Contains(msg, "predicate value") {
			t.Errorf("%s: error message lacks typing hint: %v", expr, msg)
		}
	}
}
