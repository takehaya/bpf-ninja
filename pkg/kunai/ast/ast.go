// Package ast defines the AST produced by xdp-ninja's one-liner DSL
// parser. It carries no semantics beyond shape: a Layer knows its
// protocol name but not whether that protocol exists in the loaded
// vocabulary; a Predicate knows its operator and value kind but not
// whether the referenced field is actually declared. Validation of
// those concerns is the resolver's job (later PR).
//
// Unsupported AST nodes (e.g. flow.*, CapFields) carry Unsupported=true
// so that MVP codegen can emit a user-friendly "not yet implemented"
// error while keeping syntax stable for future phases.
package ast

import (
	"fmt"
	"strings"
)

// Position is a 1-indexed location within the DSL source expression.
// Column counts bytes, not runes, because the DSL uses ASCII exclusively.
type Position struct {
	Line int
	Col  int
}

func (p Position) String() string {
	return fmt.Sprintf("%d:%d", p.Line, p.Col)
}

// Filter is the top-level AST node for a parsed one-liner.
type Filter struct {
	Layers   []*Layer
	Where    *WhereExpr       // top-level filter condition; nil when absent
	Captures []*CaptureClause // 0 or more, order preserved
	Pos      Position
}

// Layer is one entry in the protocol stack.
type Layer struct {
	Kind         LayerKind
	ProtoName    string       // LayerProto only
	Alternatives []*Layer     // LayerAltGroup only; each entry is a sub-stack (Layers []*Layer actually)
	Label        string       // "@outer" → "outer"; empty when absent
	Predicates   []*Predicate // optional
	Quant        QuantKind
	RangeMin     int // QuantRange only
	RangeMax     int // QuantRange only; -1 for open upper bound
	Pos          Position
}

// FieldPath is a dotted identifier chain such as "outer.total_length".
type FieldPath struct {
	Parts []string
	Pos   Position
}

func (f *FieldPath) String() string {
	if f == nil {
		return "<nil>"
	}
	return strings.Join(f.Parts, ".")
}

// Predicate is one entry within a layer's [...] list.
type Predicate struct {
	Kind     PredKind
	Field    *FieldPath
	Op       CmpOp    // PredCmp
	Value    *Value   // PredCmp
	List     []*Value // PredIn
	FlagName string   // PredHas
	Pos      Position
}

// WhereExpr is a node in a where-clause expression tree. Binary operators
// (or/and) produce 2-ary nodes to simplify short-circuit codegen.
type WhereExpr struct {
	Kind WhereKind

	// WOr, WAnd
	Left  *WhereExpr
	Right *WhereExpr

	// WNot
	Inner *WhereExpr

	// WAtomArith
	ArithL *ArithExpr
	ArithR *ArithExpr
	Op     CmpOp

	// WAtomLiteralCmp (e.g. tcp.dst == 192.168.1.1, eth.dst == aa:bb:..)
	// LiteralField is the LHS field path; LiteralValue carries the
	// classified RHS literal (IPv4 / IPv6 / MAC / CIDR).
	LiteralField *FieldPath
	LiteralValue *Value
	LiteralOp    CmpOp

	// WAtomAction (e.g. action == XDP_DROP)
	ActionValue string

	// WAtomFlow (e.g. flow.is_new)
	FlowKind string

	// Unsupported marks MVP-not-yet-implemented atoms so downstream
	// stages can emit a consistent error without re-parsing.
	Unsupported bool

	Pos Position
}

// ArithExpr is an arithmetic expression (only used inside where clauses).
type ArithExpr struct {
	Kind ArithKind

	Const uint64     // ArithConst
	Field *FieldPath // ArithField

	// ArithBinOp
	Op    ArithOp
	Left  *ArithExpr
	Right *ArithExpr

	Pos Position
}

// CaptureClause is a single "capture ..." directive. Multiple clauses may
// appear per filter; each can carry its own where condition.
type CaptureClause struct {
	Kind   CaptureKind
	Extra  int          // CapHeadersPlus / CapToLayer: trailing payload bytes; CapAbsolute: total bytes (N)
	Fields []*FieldPath // CapFields: field list (MVP-unsupported)
	// LayerName carries the parsed label or protocol name for
	// CapToLayer (`capture inner` / `capture ipv4`). Resolved into
	// an *ir.LayerInstance during the resolve pass.
	LayerName string
	Where     *WhereExpr // per-capture condition; nil when absent

	// Unsupported is set when the clause shape is not yet implemented
	// by codegen. Currently: CapFields.
	Unsupported bool

	Pos Position
}
