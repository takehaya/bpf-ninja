// Package resolve binds an AST filter to a loaded vocabulary,
// producing a resolved IR that codegen can walk without re-consulting
// the vocabulary. The resolver:
//
//   - Looks up each protocol leaf in the vocabulary
//   - Selects a dispatch constant for each adjacent (parent, child)
//     pair, preferring Field > Sanity > NoCheck
//   - Tracks @label assignments, auto-indexes repeated protocols
//     without labels, and enforces the MVP 2-label-per-protocol cap
//   - Rejects unknown protocols and unknown field references
//   - Marks MVP-unsupported constructs (alternation groups, in/has
//     predicates) so the next phase can emit a unified error
//
// Where-clause and capture-clause resolution live in sibling files and
// arrive in the next commit.
package resolve

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// MaxLabelInstancesPerProto is the MVP limit on how many user-labeled
// instances of the same protocol a single filter may contain. The SRv6
// three-segment labelling case (@transit/@service/@user) is deferred.
const MaxLabelInstancesPerProto = 2

// Options control optional resolver passes that are off by default.
// Add fields here when introducing strict / lint-style checks that
// callers may opt into without changing the default behaviour.
type Options struct {
	// StrictArithLint promotes the F1 overflow-suspect lint from
	// silent to a resolver-level error. Triggered by where-clause
	// arith binops that almost certainly wrap at the field's natural
	// width — currently `field + field` / `field * field` and
	// `field - field` with RHS at least as wide as LHS. Off by
	// default so the existing typed-OK / silent-wrap behaviour stays
	// the contract for unaware callers.
	StrictArithLint bool
}

// Resolve walks an AST filter, binds every symbolic reference to the
// vocabulary, and returns a resolved IR program. allowedActions names
// the symbolic identifiers the host accepts in `where action == NAME`
// atoms; pass nil when the host disables action atoms (the resolver
// will then reject any such atom with a clear error). Typically this
// is the keys of Capabilities.Action.
func Resolve(f *ast.Filter, vocabulary map[string]*vocab.ProtocolSpec, allowedActions map[string]int32) (*ir.Program, error) {
	return ResolveWithOptions(f, vocabulary, allowedActions, Options{})
}

// ResolveWithOptions is Resolve with caller-supplied Options.
// Existing callers should keep using Resolve; this entry point is
// for hosts that want to enable a lint pass.
func ResolveWithOptions(f *ast.Filter, vocabulary map[string]*vocab.ProtocolSpec, allowedActions map[string]int32, opts Options) (*ir.Program, error) {
	if f == nil {
		return nil, errorf(ast.Position{}, "nil filter")
	}
	r := &resolver{
		vocab:           vocabulary,
		allowedActions:  allowedActions,
		opts:            opts,
		labels:          make(map[string]*ir.LayerInstance),
		protoLabelCount: make(map[string]int),
		protoAutoIndex:  make(map[string]int),
	}
	return r.resolveFilter(f)
}

type resolver struct {
	vocab           map[string]*vocab.ProtocolSpec
	allowedActions  map[string]int32             // host-declared action symbols
	opts            Options                      // caller-supplied resolver options
	labels          map[string]*ir.LayerInstance // explicit @labels + auto "proto#index"
	protoLabelCount map[string]int               // count of user-labeled instances per proto
	protoAutoIndex  map[string]int               // next auto-index per proto

	// flatLayers is populated as layers are resolved, giving
	// where-clause resolution a complete map of reachable instances.
	flatLayers []*ir.LayerInstance
}

func (r *resolver) resolveFilter(f *ast.Filter) (*ir.Program, error) {
	layers := make([]*ir.LayerInstance, 0, len(f.Layers))
	for i, al := range f.Layers {
		var parent *ir.LayerInstance
		if i > 0 {
			parent = layers[i-1]
		}
		li, err := r.resolveLayer(al, parent)
		if err != nil {
			return nil, err
		}
		layers = append(layers, li)
	}

	for proto, count := range r.protoLabelCount {
		if count > MaxLabelInstancesPerProto {
			return nil, errorf(f.Pos, "protocol %q has %d labeled instances; MVP supports up to %d (@outer/@inner). SRv6 3-stage labelling is deferred", proto, count, MaxLabelInstancesPerProto)
		}
	}

	var where *ir.Condition
	if f.Where != nil {
		w, err := r.resolveWhere(f.Where)
		if err != nil {
			return nil, err
		}
		where = w
	}

	captures := make([]*ir.CaptureClause, 0, len(f.Captures))
	for _, ac := range f.Captures {
		c, err := r.resolveCapture(ac)
		if err != nil {
			return nil, err
		}
		captures = append(captures, c)
	}

	p := &ir.Program{
		Layers:     layers,
		Where:      where,
		Captures:   captures,
		LabelTable: r.labels,
		Pos:        f.Pos,
	}
	markRuntimeOffsetLayers(p)
	return p, nil
}

// markRuntimeOffsetLayers populates LayerPos on every layer (including
// alt members) and sets NeedsRuntimeOffset on layers whose runtime
// position cannot be computed via the static-prefix path because a
// heterogeneous-size alternation group sits earlier in the chain.
// Codegen consumes NeedsRuntimeOffset to decide whether a layer must
// store offsetBase (R4) into its per-layer entry slot, and whether
// downstream where / capture / option-walk loads must address through
// that slot rather than R0+static_prefix.
//
// Alt members share the alt group's LayerPos so all members write
// into the same slot — codegen's per-alt advance logic guarantees
// whichever alt matched is the one whose R4 entry was just stored.
func markRuntimeOffsetLayers(p *ir.Program) {
	hetAltPos := -1
	for i, l := range p.Layers {
		if l == nil {
			continue
		}
		l.LayerPos = i
		for _, alt := range l.Alternation {
			if alt != nil {
				alt.LayerPos = i
			}
		}
		if hetAltPos == -1 && ir.IsHeterogeneousAlt(l) {
			hetAltPos = i
		}
	}
	if hetAltPos == -1 {
		return
	}

	mark := func(target *ir.LayerInstance) {
		if target == nil || target.LayerPos <= hetAltPos {
			return
		}
		target.NeedsRuntimeOffset = true
		for _, alt := range target.Alternation {
			if alt != nil {
				alt.NeedsRuntimeOffset = true
			}
		}
	}

	visitField := func(f *ir.FieldRef) {
		if f != nil {
			mark(f.Layer)
		}
	}

	if p.Where != nil {
		ir.WalkConditionFieldRefs(p.Where, visitField)
	}
	for _, c := range p.Captures {
		if c == nil {
			continue
		}
		mark(c.TargetLayer)
		if c.Where != nil {
			ir.WalkConditionFieldRefs(c.Where, visitField)
		}
		for _, f := range c.Fields {
			visitField(f)
		}
	}
}
