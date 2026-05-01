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

// Resolve walks an AST filter, binds every symbolic reference to the
// vocabulary, and returns a resolved IR program. allowedActions names
// the symbolic identifiers the host accepts in `where action == NAME`
// atoms; pass nil when the host disables action atoms (the resolver
// will then reject any such atom with a clear error). Typically this
// is the keys of Capabilities.Action.
func Resolve(f *ast.Filter, vocabulary map[string]*vocab.ProtocolSpec, allowedActions map[string]int32) (*ir.Program, error) {
	if f == nil {
		return nil, errorf(ast.Position{}, "nil filter")
	}
	r := &resolver{
		vocab:           vocabulary,
		allowedActions:  allowedActions,
		labels:          make(map[string]*ir.LayerInstance),
		protoLabelCount: make(map[string]int),
		protoAutoIndex:  make(map[string]int),
	}
	return r.resolveFilter(f)
}

type resolver struct {
	vocab           map[string]*vocab.ProtocolSpec
	allowedActions  map[string]int32             // host-declared action symbols
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

	return &ir.Program{
		Layers:     layers,
		Where:      where,
		Captures:   captures,
		LabelTable: r.labels,
		Pos:        f.Pos,
	}, nil
}
