package codegen

import (
	"fmt"
	"os"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// computeCapture walks p.Captures, derives the perf-output length the
// wrapper should use, and folds any per-capture `where` into the
// top-level where via AND. The merged condition replaces p.Where as
// the filter gate, so the MVP treats "capture only when X" as
// "filter to X". Multiple clauses take the max length (so no clause
// is truncated) and AND their wheres together; per-clause length
// semantics live on captureLength.
//
// When no `capture` clause is present, the chain is treated as if the
// user wrote `capture all` — MaxCapLen stays 0, which the host adapter
// interprets as "use the configured DefaultCapLen (= 1500 B,
// libpcap-equivalent)". This is the principle-of-least-surprise
// behaviour: `tcp where dport == 443` captures full packets, the same
// way tcpdump does. The where-clause-derived prefix is still exposed
// separately via FilterMinPrefix (below) and used to size the
// in-kernel scratch read; that throughput optimisation is preserved
// without surprising users into silently truncated payloads.
//
// Users who want the ringbuf-reservation throughput win (small
// reservation → more records fit simultaneously → less back-pressure)
// must opt in via an explicit `capture headers` or `capture headers+N`
// clause. R32 reproduces this behaviour with explicit `capture
// headers` cells.
func computeCapture(p *ir.Program, topWhere *ir.Condition) (CaptureInfo, *ir.Condition, error) {
	merged := topWhere
	info := CaptureInfo{}

	if len(p.Captures) == 0 {
		// No clause = `capture all` sugar. Leave MaxCapLen = 0 so the
		// host falls back to DefaultCapLen. FilterMinPrefix below still
		// runs the analyser to size the scratch read.
	} else {
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
	}

	// FilterMinPrefix bounds the bytes the *filter* itself must read,
	// independent of the payload's MaxCapLen above. It's the max of
	// (a) the chain's natural header prefix sum (covers dispatch reads
	// through every layer), and (b) the merged where condition's
	// rightmost field-byte offset. The tracing host uses this to size
	// its scratch probe_read_kernel. Optimisation-only: on any analysis
	// bail (quantified chain, het-alt, unresolved alt spec) leave it
	// at zero so the host keeps the conservative ScratchBufSize.
	info.FilterMinPrefix = inferFilterMinPrefix(p, merged)
	return info, merged, nil
}

// inferFilterMinPrefix returns the maximum byte offset the compiled
// filter must read from the packet, or 0 if the analysis is not
// statically decidable for this chain shape.
//
// The recover() is load-bearing: prefixHeaderSizeMaxAlt → altPrefixSizeRange
// → headerSize derefs alt.Spec, which can be nil for programs that the
// resolver hasn't fully tightened (e.g. nested-alternation-on-quantified
// chains, which the test suite checks are rejected downstream — see
// TestCompileNestedAlternationQuantifiedRejected). The host treats prefix=0
// as "analyser bailed, use ScratchBufSize fallback"; logging the panic so
// the underlying defect stays visible.
func inferFilterMinPrefix(p *ir.Program, where *ir.Condition) (prefix int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "kunai: filter-min-prefix analyser panicked (falling back to ScratchBufSize): %v\n", r)
			prefix = 0
		}
	}()
	if n, err := prefixHeaderSizeMaxAlt(p, nil, "filter min prefix"); err == nil {
		prefix = n
	}
	if n, err := inferMinCapLenFromWhere(p, where); err == nil && n > prefix {
		prefix = n
	}
	return prefix
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

// inferMinCapLenFromWhere derives the smallest packet prefix length
// the where condition's field references demand. Returns 0 (= "use
// the host default") when:
//   - the condition has no field references (e.g. action-only fexit
//     filters like `where action == XDP_DROP`),
//   - any reference's owning layer or any preceding layer in the chain
//     has runtime-variable offsets (the analyser cannot statically
//     bound the prefix in that case), or
//   - a het-alt or quantified layer prefix forces us into the same
//     "max-of-alts" upper bound captureLength uses.
//
// Aux-header field refs add the aux's offset within its layer plus the
// field's bit window inside the aux. Bit-slice references narrow via
// EffectiveBits.
func inferMinCapLenFromWhere(p *ir.Program, where *ir.Condition) (int, error) {
	if where == nil {
		return 0, nil
	}

	maxOff := 0
	bailed := false
	var walkErr error

	ir.WalkConditionFieldRefs(where, func(fr *ir.FieldRef) {
		if walkErr != nil || bailed {
			return
		}
		if fr.Layer == nil {
			return // action atom or scalar literal — no field offset
		}
		// Bail if the layer or any preceding layer in the chain has a
		// runtime-variable offset (then we cannot statically bound the
		// prefix). The "preceding layer" check is necessary because the
		// per-layer NeedsRuntimeOffset only flags the layer itself; a
		// preceding TLV-walked layer makes everything after it
		// runtime-variable too.
		for _, l := range p.Layers {
			if l.NeedsRuntimeOffset {
				bailed = true
				return
			}
			if l == fr.Layer {
				break
			}
		}

		prefix, err := prefixHeaderSizeMaxAlt(p, fr.Layer, "snaplen analysis")
		if err != nil {
			// The reference points at an alt-member layer or some
			// other arrangement we cannot statically bound; bail so
			// the host falls back to DefaultCapLen. We deliberately
			// do not propagate the error — the analyser is a
			// best-effort optimisation, and any genuinely-unsupported
			// reference will surface a clearer error from the main
			// codegen passes.
			bailed = true
			return
		}

		// Field-end byte offset within the layer.
		var endBit int
		switch {
		case fr.Aux != nil:
			endBit = fr.Aux.OffsetInLayer*8 + fr.Aux.FieldBitOff + fr.EffectiveBits()
		case fr.Field != nil:
			fieldBitOff, _, ok := vocab.BitOffsetIn(fr.Layer.Spec.Fields, fr.Field.Name)
			if !ok {
				return // field not found in spec — should not happen, conservative skip
			}
			sliceLo := 0
			if fr.Slice != nil {
				sliceLo = fr.Slice.Lo
			}
			endBit = fieldBitOff + sliceLo + fr.EffectiveBits()
		default:
			return
		}
		fieldEnd := (endBit + 7) / 8 // round up to byte

		candidate := prefix + fieldEnd
		if candidate > maxOff {
			maxOff = candidate
		}
	})

	if walkErr != nil {
		return 0, walkErr
	}
	if bailed {
		return 0, nil
	}
	return maxOff, nil
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
