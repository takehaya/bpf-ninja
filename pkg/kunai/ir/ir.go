// Package ir is the resolved intermediate representation produced by
// the DSL resolver. It mirrors the shape of the AST but with symbolic
// references (protocol names, field names) bound to concrete
// vocabulary objects (*vocab.ProtocolSpec, *vocab.Field) so codegen
// does not need to consult the vocabulary again.
//
// Atoms that the MVP cannot implement (e.g. flow state, in/has
// predicates, field-list capture) carry a non-empty Unsupported
// message that a later PR will surface to the user.
package ir

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// Program is the top-level resolved filter.
type Program struct {
	Layers   []*LayerInstance
	Where    *Condition        // nil when no top-level where
	Captures []*CaptureClause  // 0 or more

	// LabelTable maps label text to layer. It includes both
	// user-provided "@label" names and auto-generated names of the
	// form "<proto>#<index>" for each layer.
	LabelTable map[string]*LayerInstance

	Pos ast.Position
}

// LayerInstance is one resolved protocol layer.
type LayerInstance struct {
	Spec  *vocab.ProtocolSpec
	Label string // "outer", "inner", "" when unlabeled
	// Index is the zero-based occurrence order among layers with the
	// same protocol name. For the first ipv4 it is 0, the second 1,
	// and so on — regardless of whether the user labelled them.
	Index int

	// LayerPos is this layer's position within Program.Layers (0-based).
	// Distinct from Index, which counts per-protocol occurrences. Used
	// by codegen to allocate per-layer entry-offset stack slots
	// (whereLayerEntrySlot) when NeedsRuntimeOffset is set. Alt
	// members carry the alt group's LayerPos rather than their own
	// position so all alts share the same slot — see resolver mark
	// pass for the allocation invariant.
	LayerPos int

	Predicates []*Predicate

	// Quantifier; QuantOne when none was specified.
	Quant    ast.QuantKind
	RangeMin int
	RangeMax int // -1 means open upper bound

	// Dispatch is how this layer is identified from its parent. It is
	// nil for the first layer (which needs no dispatch) and non-nil
	// for every subsequent layer.
	Dispatch *DispatchChoice

	// Alternation is populated when the source layer was a
	// LayerAltGroup (a|b|c). Each alternative is itself resolved and
	// its Dispatch is determined independently. When Alternation is
	// non-empty, ProtoName on this instance is unused and the
	// Alternatives are the ones to evaluate.
	Alternation []*LayerInstance

	// Unsupported, when non-empty, indicates the layer has a shape
	// the MVP codegen cannot emit (e.g. alternation combined with
	// a quantifier). Resolution still succeeds so that other errors
	// are surfaced alongside.
	Unsupported string

	// NeedsRuntimeOffset tells codegen that where / capture clauses
	// reference fields in this layer (or pass through it) and that
	// the layer's position in the packet cannot be known at compile
	// time — typically because a heterogeneous-size alternation group
	// sits at or before this layer in the chain. When set, the layer's
	// emit MUST store offsetBase (R4) into whereLayerEntrySlot at
	// layer entry, and field loads in where / capture / option-walk
	// MUST address through that slot rather than R0+static_prefix.
	// Resolver decides; codegen executes.
	NeedsRuntimeOffset bool

	Pos ast.Position
}

// DispatchChoice records how this layer is selected from its parent.
//
// AltConsts / IsAltDiverged are populated when the parent is an
// alternation group. Codegen consumes them to route the dispatch
// check through a matched-alt-index check (set by the alt block,
// read here) so that `(ipv4|ipv6)/tcp` and friends — where the alts
// disagree on which field carries the next protocol — can compile.
// When the alts agree, IsAltDiverged stays false and Const carries
// the single representative dispatch (existing fast path).
type DispatchChoice struct {
	Type          vocab.DispatchType
	Const         *vocab.DispatchConst
	AltConsts     []*vocab.DispatchConst
	IsAltDiverged bool
}

// Predicate is a resolved [field op value] entry.
type Predicate struct {
	Kind     ast.PredKind
	Field    *FieldRef
	Op       ast.CmpOp    // PredCmp
	Value    *ast.Value   // PredCmp
	List     []*ast.Value // PredIn
	FlagName string       // PredHas

	Unsupported string

	Pos ast.Position
}

// FieldRef is a resolved pointer into a layer's protocol header.
//
// When Aux is nil (the common case), Field references one entry of
// the layer's primary header — codegen reads the bytes anchored on
// R4 (the running offset register) at the field's bit window.
//
// When Aux is non-nil, Field references one entry of an auxiliary
// header (e.g. gtp_opt_h.next_ext). Codegen must:
//   1. Optionally evaluate Aux.Gating to decide whether the aux is
//      present on this packet's path. A failed gate means the field
//      does not exist for this packet — predicate codegen treats
//      that as "match fails", consistent with `proto.aux.exists`
//      being false.
//   2. Read the field at offset (Aux.OffsetInLayer + Field's bit
//      window) anchored on the layer-entry slot, not R4 (which has
//      advanced past the layer by the time predicates run).
type FieldRef struct {
	Layer *LayerInstance
	Field *vocab.Field
	Aux   *AuxRef // nil when Field is in the primary header

	// Slice is non-nil for `field[lo:hi]` bit-slice references. When
	// set, downstream codegen narrows the field load to the slice's
	// byte range and the effective width becomes Hi - Lo bits.
	Slice *FieldSlice
}

// FieldSlice represents a half-open bit range [Lo, Hi) on the
// referenced field. Bit 0 is the network-order MSB so users reading
// e.g. `ipv6.src[0:32]` as "the first 32 bits" get the natural IETF
// convention. The MVP requires both endpoints byte-aligned (Lo % 8
// == 0 and Hi % 8 == 0); non-aligned slices follow up under F11.
type FieldSlice struct {
	Lo int // bit position, inclusive
	Hi int // bit position, exclusive
}

// Bits returns the slice's effective width.
func (s *FieldSlice) Bits() int {
	if s == nil {
		return 0
	}
	return s.Hi - s.Lo
}

// EffectiveBits returns the number of bits a field reference yields
// after applying any bit-slice. Used by the typing pass and codegen
// instead of reading FieldRef.Field.Bits directly so slice-narrowed
// references behave consistently.
func (r *FieldRef) EffectiveBits() int {
	if r == nil {
		return 0
	}
	if r.Slice != nil {
		return r.Slice.Bits()
	}
	if r.Aux != nil {
		return r.Aux.FieldBitWidth
	}
	if r.Field != nil {
		return r.Field.Bits
	}
	return 0
}

// AuxRef captures the metadata predicate codegen needs to read an
// aux header field: where the aux sits within the layer, the field's
// bit window inside the aux header, and either an optional gating
// predicate (single aux) or a stack-index descriptor (aux header
// stack).
//
// Single auxes (Stack == nil) read at offset OffsetInLayer with an
// optional gate; stack auxes (Stack != nil) read at offset
// OffsetInLayer + index*ElemSize where index comes from
// Stack.Static or Stack.Dynamic depending on Stack.IsStatic.
type AuxRef struct {
	OutParam      string         // parser out parameter name (e.g. "opt", "segments")
	HeaderName    string         // aux header type name (e.g. "gtp_opt_h", "srv6_seg_h")
	OffsetInLayer int            // bytes from layer-entry slot to aux start (for stacks: base of stack)
	HeaderSize    int            // bytes; element size when Stack != nil
	Gating        *vocab.AuxGating
	// FieldBitOff / FieldBitWidth give the field's window inside the
	// aux header (or per-entry stack header), in bits (matches
	// vocab.findFieldBitWindow output).
	FieldBitOff   int
	FieldBitWidth int
	// Stack is non-nil when this AuxRef indexes into an aux header
	// stack (`out <type>[N] segments`) instead of a single aux.
	Stack *StackIndex
	// OwnerOption is non-nil when the stack lives past an option
	// aux's per-packet base rather than the layer's variable trail.
	// Address compute becomes
	// slot[OwnerOption] + OffsetAfterOwner + index*HeaderSize +
	// FieldBitOff/8, routed through the dynamic-aux slot allocator
	// instead of the layer-entry anchor.
	OwnerOption      *vocab.AuxLayout
	OffsetAfterOwner int
}

// StackIndex describes which element of an aux header stack a
// FieldRef addresses. Static indices (`segments[0]`) inline as a
// constant byte offset; dynamic indices (`segments[srv6.last_entry]`)
// load the parent field at runtime, multiply by ElemSize, and add to
// the stack base. IsIterator marks the field as the iteration
// variable of an enclosing any/all quantifier — codegen substitutes
// the loop iteration index for the offset compute.
type StackIndex struct {
	Capacity   int       // declared array size from `out <type>[N]` (= verifier-safe upper bound)
	IsStatic   bool
	Static     uint64    // when IsStatic
	Dynamic    *FieldRef // when !IsStatic && !IsIterator; primary-header field of the same layer
	IsIterator bool      // when this StackIndex is the any/all iteration variable
}

// IsExistsCheck reports whether this FieldRef represents an
// `<proto>.<aux>.exists` access — i.e. an aux reference whose Field
// is the synthetic "exists" sentinel (FieldBitWidth == 0). Codegen
// short-circuits to "evaluate gating only" for these.
func (r *FieldRef) IsExistsCheck() bool {
	return r != nil && r.Aux != nil && r.Field == nil
}

// QuantTarget identifies the aux header stack a `any(...)` / `all(...)`
// expression iterates over. Codegen wraps the inner condition in a
// bpf_loop callback whose per-iter state addresses
// `OffsetInLayer + iter*ElemSize` within the owning layer.
type QuantTarget struct {
	OutParam      string // parser out parameter name (e.g. "segments")
	HeaderName    string // aux header type name (e.g. "srv6_seg_h")
	OffsetInLayer int    // bytes from layer-entry slot to stack start
	ElemSize      int    // bytes per stack entry
	Capacity      int    // declared array size = verifier loop cap
}

// Condition mirrors ast.WhereExpr but with any field references
// resolved to FieldRef. Binary operators are 2-ary.
type Condition struct {
	Kind ast.WhereKind

	Left  *Condition
	Right *Condition
	Inner *Condition // WNot / WAny / WAll inner expression

	// QuantTarget is populated for WAny / WAll: it identifies the
	// aux header stack the inner expression iterates over.
	QuantTarget *QuantTarget

	// WAtomArith
	ArithL *ArithExpr
	ArithR *ArithExpr
	Op     ast.CmpOp

	// WAtomLiteralCmp (field op IPv4/IPv6/MAC/CIDR literal)
	LiteralField *FieldRef
	LiteralValue *ast.Value
	LiteralOp    ast.CmpOp

	// WAtomAction
	ActionValue string

	// WAtomBoolLit (bare `true` / `false`).
	BoolLitValue bool

	// WAtomBoolExists (bare `<aux>.exists` in where atom position).
	// BoolField is a FieldRef whose Aux is set; Field == nil (i.e.
	// IsExistsCheck() returns true).
	BoolField *FieldRef

	// WAtomBoolEq operands (Bool == Bool / Bool != Bool).
	BoolL    *Condition
	BoolR    *Condition
	BoolEqOp ast.CmpOp

	Unsupported string

	Pos ast.Position
}

// ArithExpr is a resolved arithmetic expression (used inside where).
type ArithExpr struct {
	Kind  ast.ArithKind
	Const uint64     // ArithConst
	Field *FieldRef  // ArithField

	Op    ast.ArithOp
	Left  *ArithExpr
	Right *ArithExpr

	Pos ast.Position
}

// IsHeterogeneousAlt reports whether l is an alternation group whose
// members differ in fixed primary-header byte size. Co-resolver and
// codegen both consult this — the resolver to decide whether layers
// past l need NeedsRuntimeOffset, codegen to handle the per-alt
// inline advance / matched-flag plumbing. Returns false for non-alt
// layers, single-alt groups, or alt groups whose members all agree
// on header size (the latter still ride the static prefix path).
//
// Members with non-byte-aligned headers are treated as agreeing
// (returns false) — the actual size mismatch will surface as a
// distinct error from headerSize when codegen tries to advance R4.
func IsHeterogeneousAlt(l *LayerInstance) bool {
	if l == nil || len(l.Alternation) == 0 {
		return false
	}
	var hs int
	first := true
	for _, alt := range l.Alternation {
		if alt == nil || alt.Spec == nil {
			return false
		}
		bits := vocab.SumBits(alt.Spec.Fields)
		if bits%8 != 0 {
			return false
		}
		ahs := bits / 8
		if first {
			hs = ahs
			first = false
			continue
		}
		if ahs != hs {
			return true
		}
	}
	return false
}

// CaptureClause is a resolved "capture ..." directive.
type CaptureClause struct {
	Kind   ast.CaptureKind
	Extra  int         // CapHeadersPlus / CapToLayer / CapAbsolute
	Fields []*FieldRef // CapFields
	// TargetLayer is the resolved layer for CapToLayer. The chain
	// prefix (eth..TargetLayer inclusive) determines the static
	// capture length.
	TargetLayer *LayerInstance
	Where       *Condition // per-capture condition; nil when absent

	Unsupported string

	Pos ast.Position
}
