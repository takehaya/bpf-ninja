package ast

import "fmt"

// LayerKind enumerates the kinds of Layer node.
type LayerKind int

const (
	LayerProto    LayerKind = iota // a single protocol leaf (e.g. "tcp")
	LayerAltGroup                  // a parenthesised alternation like "(a|b|c)"
)

func (k LayerKind) String() string {
	switch k {
	case LayerProto:
		return "proto"
	case LayerAltGroup:
		return "alt"
	}
	return fmt.Sprintf("LayerKind(%d)", int(k))
}

// QuantKind is the multiplicity of a Layer.
type QuantKind int

const (
	QuantOne   QuantKind = iota // default: exactly one occurrence
	QuantOpt                    // "?"
	QuantPlus                   // "+"
	QuantStar                   // "*"
	QuantRange                  // "{n,m}"
)

func (q QuantKind) String() string {
	switch q {
	case QuantOne:
		return "one"
	case QuantOpt:
		return "?"
	case QuantPlus:
		return "+"
	case QuantStar:
		return "*"
	case QuantRange:
		return "{n,m}"
	}
	return fmt.Sprintf("QuantKind(%d)", int(q))
}

// CmpOp is a comparison operator shared by predicates and arith comparisons.
type CmpOp int

const (
	CmpEq  CmpOp = iota // ==
	CmpNeq              // !=
	CmpLt               // <
	CmpLe               // <=
	CmpGt               // >
	CmpGe               // >=
)

func (o CmpOp) String() string {
	switch o {
	case CmpEq:
		return "=="
	case CmpNeq:
		return "!="
	case CmpLt:
		return "<"
	case CmpLe:
		return "<="
	case CmpGt:
		return ">"
	case CmpGe:
		return ">="
	}
	return fmt.Sprintf("CmpOp(%d)", int(o))
}

// ArithOp is a binary arithmetic operator inside a where-clause.
type ArithOp int

const (
	ArithAdd ArithOp = iota // +
	ArithSub                // -
	ArithMul                // *
	ArithDiv                // /
	ArithMod                // %
)

func (o ArithOp) String() string {
	switch o {
	case ArithAdd:
		return "+"
	case ArithSub:
		return "-"
	case ArithMul:
		return "*"
	case ArithDiv:
		return "/"
	case ArithMod:
		return "%"
	}
	return fmt.Sprintf("ArithOp(%d)", int(o))
}

// ArithKind classifies arithmetic expression nodes.
type ArithKind int

const (
	ArithConst ArithKind = iota
	ArithField
	ArithBinOp
)

func (k ArithKind) String() string {
	switch k {
	case ArithConst:
		return "const"
	case ArithField:
		return "field"
	case ArithBinOp:
		return "binop"
	}
	return fmt.Sprintf("ArithKind(%d)", int(k))
}

// WhereKind classifies where-clause expression nodes. Arithmetic
// comparison (WAtomArith) covers predicate-shaped atoms such as
// "tcp.dport == 443"; the parser does not produce a separate Pred kind.
type WhereKind int

const (
	WOr         WhereKind = iota // a or b
	WAnd                         // a and b
	WNot                         // not a
	WAtomArith                   // arith cmp arith, e.g. tcp.dport == 443
	WAtomLiteralCmp              // field cmp network literal, e.g. ipv4.dst == 10.0.0.1
	WAtomAction                  // action == XDP_DROP
	WAtomFlow                    // flow.is_new | flow.age | flow.state
)

func (k WhereKind) String() string {
	switch k {
	case WOr:
		return "or"
	case WAnd:
		return "and"
	case WNot:
		return "not"
	case WAtomArith:
		return "arith"
	case WAtomLiteralCmp:
		return "literalcmp"
	case WAtomAction:
		return "action"
	case WAtomFlow:
		return "flow"
	}
	return fmt.Sprintf("WhereKind(%d)", int(k))
}

// PredKind classifies predicate shapes.
type PredKind int

const (
	PredCmp PredKind = iota // field op value
	PredIn                  // field in [v1, v2, ...]
	PredHas                 // field has FLAG
)

func (k PredKind) String() string {
	switch k {
	case PredCmp:
		return "cmp"
	case PredIn:
		return "in"
	case PredHas:
		return "has"
	}
	return fmt.Sprintf("PredKind(%d)", int(k))
}

// CaptureKind classifies capture specs.
type CaptureKind int

const (
	CapAll         CaptureKind = iota // "all"
	CapHeaders                        // "headers"
	CapHeadersPlus                    // "headers + N"
	CapFields                         // "f.a, f.b, ..."
	CapToLayer                        // "<label_or_proto>" or "<label> + N"
	CapAbsolute                       // "absolute N"
)

func (k CaptureKind) String() string {
	switch k {
	case CapAll:
		return "all"
	case CapHeaders:
		return "headers"
	case CapHeadersPlus:
		return "headers+N"
	case CapFields:
		return "fields"
	case CapToLayer:
		return "tolayer"
	case CapAbsolute:
		return "absolute"
	}
	return fmt.Sprintf("CaptureKind(%d)", int(k))
}
