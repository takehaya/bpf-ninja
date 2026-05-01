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
//
// Indices, when non-nil, is parallel to Parts: Indices[i] holds the
// optional `[expr]` that followed Parts[i] in the source. nil entries
// mean "no index for that segment". Used by aux header stack access
// such as `srv6.segments[0].addr` (Parts = [srv6, segments, addr],
// Indices[1] = int literal 0).
type FieldPath struct {
	Parts   []string
	Indices []*IndexExpr // nil when no segment carries an index
	Pos     Position
}

func (f *FieldPath) String() string {
	if f == nil {
		return "<nil>"
	}
	if len(f.Indices) == 0 {
		return strings.Join(f.Parts, ".")
	}
	var b strings.Builder
	for i, p := range f.Parts {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(p)
		if i < len(f.Indices) && f.Indices[i] != nil {
			b.WriteByte('[')
			b.WriteString(f.Indices[i].String())
			b.WriteByte(']')
		}
	}
	return b.String()
}

// IndexExpr is the resolved form of a `[…]` index that follows a
// path segment. Three mutually exclusive shapes:
//   - IsInt: a single integer index (`stack[3]`)
//   - Field set (and IsInt/IsSlice false): a dynamic index sourced
//     from a field path (`stack[srv6.last_entry]`)
//   - IsSlice: a bit-range slice on the field's value
//     (`ipv6.src[0:32]`), with SliceLo / SliceHi giving the
//     half-open bit range (lo inclusive, hi exclusive). Bit 0 is
//     the network-order MSB.
type IndexExpr struct {
	Int   uint64 // when IsInt is true
	IsInt bool
	Field *FieldPath // when IsInt and IsSlice are both false

	IsSlice bool
	SliceLo uint64 // bit position (inclusive)
	SliceHi uint64 // bit position (exclusive)

	Pos Position
}

func (e *IndexExpr) String() string {
	if e == nil {
		return ""
	}
	if e.IsSlice {
		return fmtInt(e.SliceLo) + ":" + fmtInt(e.SliceHi)
	}
	if e.IsInt {
		return fmtInt(e.Int)
	}
	if e.Field != nil {
		return e.Field.String()
	}
	return "?"
}

func fmtInt(v uint64) string {
	// Avoid pulling in strconv just for this; the values that show up
	// here are small (chain index caps, parent.field bit widths).
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
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

	// WAtomBoolLit (e.g. `where true` / `where false`).
	BoolLitValue bool

	// WAtomBoolExists (e.g. `where gtp.opt.exists`). The trailing
	// `.exists` segment is consumed at parse time; BoolField holds the
	// path up to (but not including) `exists`.
	BoolField *FieldPath

	// WAtomBoolEq operands. BoolL/BoolR are themselves Bool-valued
	// where expressions (cmp result / exists / Int decay / literal).
	BoolL *WhereExpr
	BoolR *WhereExpr
	// BoolEqOp distinguishes `==` (iff) from `!=` (xor).
	BoolEqOp CmpOp

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
