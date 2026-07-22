package codegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

func TestPositionedErrorAttachesLineCol(t *testing.T) {
	// Build a program where checkUnsupported has a layer flagged
	// Unsupported; the resulting error must carry the layer's Pos.
	p := ethIPv4TCPProgram()
	p.Layers[1].Unsupported = "synthetic for test"
	p.Layers[1].Pos = ast.Position{Line: 7, Col: 13}

	_, err := Gen(p, Capabilities{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("err = %v; want errors.Is(err, ErrNotImplemented)", err)
	}
	var pe *PositionedError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v; want PositionedError in chain", err)
	}
	if pe.Pos.Line != 7 || pe.Pos.Col != 13 {
		t.Errorf("Pos = %v; want 7:13", pe.Pos)
	}
	if !strings.HasPrefix(err.Error(), "7:13:") {
		t.Errorf("error %q should start with 7:13:", err.Error())
	}
}

func TestPositionedErrorPredicateLevelWins(t *testing.T) {
	// Predicates carry their own Pos. When a predicate-level error
	// surfaces (here: PredIn marked Unsupported by the resolver)
	// it should keep the predicate's Pos rather than be re-wrapped
	// to the layer's Pos by genLayer.
	p := ethIPv4TCPProgram()
	p.Layers[1].Pos = ast.Position{Line: 1, Col: 1}
	p.Layers[2].Predicates = []*ir.Predicate{
		{
			Kind:        ast.PredIn,
			Unsupported: "in predicate (test)",
			Pos:         ast.Position{Line: 9, Col: 22},
		},
	}

	_, err := Gen(p, Capabilities{})
	if err == nil {
		t.Fatal("expected error")
	}
	var pe *PositionedError
	if !errors.As(err, &pe) {
		t.Fatalf("expected PositionedError, got %v", err)
	}
	// Inner predicate Pos should win.
	if pe.Pos.Line != 9 || pe.Pos.Col != 22 {
		t.Errorf("Pos = %v; want predicate-level 9:22", pe.Pos)
	}
}

func TestPositionedErrorZeroPosOmitted(t *testing.T) {
	// A PositionedError with a zero Position should still print
	// without a line:col prefix so the message stays readable when
	// the resolver did not attach a source location.
	pe := &PositionedError{Pos: ast.Position{}, Wrapped: ErrNotImplemented}
	if got := pe.Error(); got != ErrNotImplemented.Error() {
		t.Errorf("got %q; want bare ErrNotImplemented message", got)
	}
}
