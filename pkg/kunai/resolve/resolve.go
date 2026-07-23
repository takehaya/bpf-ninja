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
	"fmt"
	"slices"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
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

	// PacketStartsAtL3 mirrors codegen.HostLayout.PacketStartsAtL3:
	// the host's packet window begins at the network header, so the
	// chain-root advice flips — an `eth/...` root would misparse and
	// draws the warning, while ipv4/ipv6 roots are the expected entry.
	PacketStartsAtL3 bool
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
	addChainRootWarning(p, f, r.opts)
	markRuntimeOffsetLayers(p)
	return p, nil
}

// addChainRootWarning appends a notice to p.Warnings when the chain's
// root protocol does not match the host's packet entry point. For the
// default L2 layout a non-eth root is almost always a typo (e.g. `tcp`
// instead of `eth/ipv4/tcp`); for an L3-start host (PacketStartsAtL3)
// the polarity flips — an `eth/...` root would misparse because the
// window has no Ethernet header, and ipv4/ipv6 are the expected roots.
// Either way it can be legitimate for unusual datapaths, so it stays a
// warning rather than an error. Skips alternation-group roots and
// empty chains; both are handled by other passes.
func addChainRootWarning(p *ir.Program, f *ast.Filter, opts Options) {
	if p == nil || len(f.Layers) == 0 {
		return
	}
	root := f.Layers[0]
	if root.Kind == ast.LayerAltGroup {
		return
	}
	if root.ProtoName == "" {
		return
	}
	if opts.PacketStartsAtL3 {
		switch root.ProtoName {
		case "ipv4", "ipv6":
			return
		case "eth":
			p.Warnings = append(p.Warnings,
				"chain root is 'eth' but this attach point has no Ethernet header in the packet bytes; start the chain at 'ipv4/...' or 'ipv6/...'. Use --dump-asm filter (with --dump-hook matching the attach point) to inspect the generated BPF.")
		default:
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"chain root %q is not 'ipv4' or 'ipv6'; this attach point's packet bytes start at the network header. Use --dump-asm filter (with --dump-hook matching the attach point) to inspect the generated BPF.",
				root.ProtoName,
			))
		}
		return
	}
	if root.ProtoName == "eth" {
		return
	}
	p.Warnings = append(p.Warnings, fmt.Sprintf(
		"chain root %q is not 'eth'; standard L2 packet entry expects 'eth/...'. Use --dump-asm filter to inspect the generated BPF.",
		root.ProtoName,
	))
}

// markRuntimeOffsetLayers populates LayerPos on every layer (including
// alt members) and sets NeedsRuntimeOffset on layers whose runtime
// position cannot be computed via the static-prefix path because an
// earlier layer has a runtime-variable size. Two things make a layer's
// size runtime-variable: a heterogeneous-size alternation group, or a
// variable-length layer body (parser-machine trailer / pkt.advance
// skip — ipv4 options, gtp opt/exts, ipv6 exts, srv6 segments, geneve
// options). Either one shifts every later layer's start offset by a
// runtime amount.
//
// Codegen consumes NeedsRuntimeOffset to decide whether a layer must
// store offsetBase (R4) into its per-layer entry slot, and whether
// downstream where / capture / option-walk loads must address through
// that slot rather than R0+static_prefix.
//
// Alt members share the alt group's LayerPos so all members write
// into the same slot — codegen's per-alt advance logic guarantees
// whichever alt matched is the one whose R4 entry was just stored.
func markRuntimeOffsetLayers(p *ir.Program) {
	// A layer makes every later layer's start offset runtime-variable
	// when it is a heterogeneous-size alternation or has a variable-
	// length body (parser-machine trailer / pkt.advance skip). A
	// uniform-size alt group is not heterogeneous, but a member with a
	// variable-length body still shifts post-alt offsets on the branch
	// that matches it (e.g. `(vxlan|geneve)` — both 8-byte fixed, but
	// geneve carries an opt_len-driven options trailer), so the alt
	// members are checked too.
	hasVarBody := func(l *ir.LayerInstance) bool {
		return l != nil && l.Spec != nil && l.Spec.HasVariableLayout()
	}
	isRuntimeBoundary := func(l *ir.LayerInstance) bool {
		return ir.IsHeterogeneousAlt(l) || hasVarBody(l) || slices.ContainsFunc(l.Alternation, hasVarBody)
	}
	boundary := -1
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
		// The earliest runtime boundary fixes the point past which every
		// later layer's start offset is runtime, so downstream where /
		// capture reads must address through the per-layer entry slot
		// instead of a compile-time prefix.
		if boundary == -1 && isRuntimeBoundary(l) {
			boundary = i
		}
	}
	if boundary == -1 {
		return
	}

	mark := func(target *ir.LayerInstance) {
		if target == nil || target.LayerPos <= boundary {
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
