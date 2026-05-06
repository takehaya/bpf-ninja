package codegen

import (
	"fmt"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// computeCapture walks p.Captures, derives the perf-output length the
// wrapper should use, and folds any per-capture `where` into the
// top-level where via AND. The merged condition replaces p.Where as
// the filter gate, so the MVP treats "capture only when X" as
// "filter to X". Multiple clauses take the max length (so no clause
// is truncated) and AND their wheres together; per-clause length
// semantics live on captureLength.
func computeCapture(p *ir.Program, topWhere *ir.Condition) (CaptureInfo, *ir.Condition, error) {
	merged := topWhere
	if len(p.Captures) == 0 {
		return CaptureInfo{}, merged, nil
	}

	info := CaptureInfo{}
	for _, c := range p.Captures {
		if c.Unsupported != "" {
			return CaptureInfo{}, nil, withPos(fmt.Errorf("%w: %s", ErrNotImplemented, c.Unsupported), c.Pos)
		}
		length, err := captureLength(c, p)
		if err != nil {
			return CaptureInfo{}, nil, withPos(err, c.Pos)
		}
		if length > info.MaxCapLen {
			info.MaxCapLen = length
		}
		if c.Where != nil {
			merged = andCondition(merged, c.Where, c.Pos)
		}
	}
	return info, merged, nil
}

// captureLength returns the static capture length for a single clause:
//   - CapAll: 0 (wrapper uses its configured default)
//   - CapHeaders / CapHeadersPlus: prefix sum of header sizes + Extra
//   - CapToLayer: prefix sum up to and including the target layer + Extra
//   - CapAbsolute: c.Extra (= N), independent of chain shape
//
// Chains containing a quantified layer in the prefix fail because the
// length would otherwise be runtime-variable. CapAbsolute escapes
// this constraint because it does not consult the chain at all.
func captureLength(c *ir.CaptureClause, p *ir.Program) (int, error) {
	switch c.Kind {
	case ast.CapAll:
		return 0, nil
	case ast.CapHeaders, ast.CapHeadersPlus:
		// Capture length is an upper bound: when a het-alt makes the
		// prefix runtime-variable, we round up to the largest alt
		// rather than error. The wrapper still emits the same bytes
		// regardless of which alt matched, so a slightly larger
		// MaxCapLen just means a few wasted bytes at the tail when
		// the smaller alt fired — acceptable for "headers" semantics.
		total, err := prefixHeaderSizeMaxAlt(p, nil, "capture headers")
		if err != nil {
			return 0, err
		}
		return total + c.Extra, nil
	case ast.CapToLayer:
		if c.TargetLayer == nil {
			return 0, fmt.Errorf("codegen: capture to-layer missing resolved target")
		}
		// prefixHeaderSize sums up to (but excluding) the target;
		// add the target's own header size to capture through it.
		// Same het-alt upper-bound treatment as CapHeaders.
		prefix, err := prefixHeaderSizeMaxAlt(p, c.TargetLayer, "capture <label>")
		if err != nil {
			return 0, err
		}
		hs, err := headerSize(c.TargetLayer.Spec)
		if err != nil {
			return 0, err
		}
		return prefix + hs + c.Extra, nil
	case ast.CapAbsolute:
		// Resolver already enforces Extra > 0; no defence-in-depth
		// check here keeps the error path single-sourced.
		return c.Extra, nil
	}
	return 0, fmt.Errorf("%w: unknown capture kind %v", ErrNotImplemented, c.Kind)
}

func andCondition(left, right *ir.Condition, pos ast.Position) *ir.Condition {
	if left == nil {
		return right
	}
	return &ir.Condition{
		Kind:  ast.WAnd,
		Left:  left,
		Right: right,
		Pos:   pos,
	}
}
