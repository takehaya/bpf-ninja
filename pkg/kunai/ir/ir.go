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

	Pos ast.Position
}

// DispatchChoice records how this layer is selected from its parent.
type DispatchChoice struct {
	Type  vocab.DispatchType
	Const *vocab.DispatchConst
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
type FieldRef struct {
	Layer *LayerInstance
	Field *vocab.Field
}

// Condition mirrors ast.WhereExpr but with any field references
// resolved to FieldRef. Binary operators are 2-ary.
type Condition struct {
	Kind ast.WhereKind

	Left  *Condition
	Right *Condition
	Inner *Condition

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

	// WAtomFlow
	FlowKind string

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
