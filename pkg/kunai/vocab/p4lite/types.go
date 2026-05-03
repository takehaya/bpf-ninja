// Package p4lite is a minimal Go-native subset parser for P4-16 used
// internally by xdp-ninja's DSL vocabulary loader.
//
// Only the MVP subset is accepted: `header`, `const`, `parser` with
// `state` / `transition` / `transition select` (supports tuple match and
// self-referencing states for chains). Constructs outside that subset
// (`action`, `table`, `control`, `apply`, `extern`) are rejected with a
// clear error so unsupported vocabulary authoring fails fast.
//
// Entry point: Parse.
//
// Spec: P4-16 Language Specification v1.2.5
//
//	https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html
//
// Section references for the individual constructs implemented here
// live at the head of lexer.go (tokens, numeric literals) and
// parser.go (declarations, parser blocks). conformance_test.go
// pins the constructs p4lite deliberately rejects from full P4-16.
package p4lite

import "fmt"

type Position struct {
	Line int
	Col  int
}

func (p Position) String() string {
	return fmt.Sprintf("%d:%d", p.Line, p.Col)
}

type SyntaxError struct {
	File    string
	Pos     Position
	Message string
}

func (e *SyntaxError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("%s:%s: %s", e.File, e.Pos, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Pos, e.Message)
}

// AST nodes below are tagged with the BNF production they correspond
// to in the P4-16 grammar. Production names match the YACC source at
//
//	https://github.com/p4lang/p4c/blob/main/frontends/parsers/p4/p4parser.ypp
//
// (which is the implementation form of the spec's Appendix G). The
// section number cited next to each rule is the prose chapter that
// describes the construct's semantics.

// File is the top-level AST node representing a parsed .p4 source file.
//
// BNF: input (start rule, Appendix G)
type File struct {
	Headers []*Header
	Consts  []*Const
	Parsers []*Parser
}

// Header is a `header H { bit<N> f; ... }` declaration.
//
// BNF: headerTypeDeclaration (P4-16 Section 7.2.2 "Header types")
type Header struct {
	Name   string
	Fields []Field
	Pos    Position
}

// Field is a single member of a Header (`bit<N> name;`).
//
// BNF: structField (P4-16 Section 7.2.5 "Struct types")
type Field struct {
	Name string
	Bits int
	Pos  Position
}

// Const is a `const bit<N> X = ...;` or `const bool X = true;` decl.
//
// BNF: constantDeclaration (P4-16 Section 11.1 "Constants")
type Const struct {
	Name   string
	IsBool bool
	Bits   int    // zero when IsBool
	Bool   bool   // valid when IsBool
	Int    uint64 // valid when !IsBool
	Pos    Position
}

// Parser is `parser P(packet_in pkt, out H hdr) { state ... }`.
//
// BNF: parserDeclaration (P4-16 Section 13.2 "Parser declarations")
type Parser struct {
	Name   string
	Params []Param
	States []*State
	Pos    Position
}

// Param is one entry in a parser's parameter list, e.g. `packet_in
// pkt`, `out H hdr`, or `out H[8] stack`.
//
// BNF: parameter (P4-16 Section 6.8 "Calling convention: call by copy in/out")
type Param struct {
	IsPacketIn bool
	IsOut      bool
	TypeName   string
	IsArray    bool
	ArraySize  int
	VarName    string
	Pos        Position
}

// State is one `state name { stmts; transition ...; }` block.
//
// BNF: parserState (P4-16 Section 13.4 "Parser states")
type State struct {
	Name       string
	Stmts      []Stmt
	Transition *Transition
	Pos        Position
}

// Stmt is the sum type for parser-state body statements. The MVP
// only emits ExtractStmt; assignments / verify() are deferred.
//
// BNF: parserStatement (P4-16 Section 13.5 "Parser statements")
type Stmt interface {
	stmtNode()
}

// ExtractStmt represents `obj.extract(target)` or `obj.extract(target.next)`.
//
// BNF: parserStatement (the methodCall variant of expressionStatement,
// P4-16 Section 13.5)
type ExtractStmt struct {
	Object string
	Target string
	IsNext bool
	Pos    Position
}

func (*ExtractStmt) stmtNode() {}

// AdvanceKind tags AdvanceStmt with the template shape the parser
// recognised. Each variant gates a distinct subset of fields; the
// other groups are zero-valued.
type AdvanceKind int

const (
	// AdvanceField is the `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)`
	// template — primary-header variable trailer (IPv4 IHL, TCP
	// data_offset). Active fields: BitWidth, Target, FieldName,
	// BaseWords, ScaleLog2.
	AdvanceField AdvanceKind = iota
	// AdvanceLookahead is the
	// `pkt.advance(((bit<N>)pkt.lookahead<bit<M>>()[lo:hi]) << S)`
	// template — a peek-and-skip whose advance length is a slice of
	// the next M bits the parser hasn't consumed. Active fields:
	// BitWidth, LookaheadBits, SliceLo, SliceHi, ScaleLog2.
	AdvanceLookahead
	// AdvanceLiteral is `pkt.advance(<INT>)` — a fixed bit advance.
	// Active field: LiteralBits.
	AdvanceLiteral
)

// AdvanceStmt represents one of three variable-trailer skip templates
// p4lite recognises inside parser-state bodies. Each template's arg,
// in P4-16 standard form, evaluates to a bit count fed to
// `packet_in.advance(in bit<32> sizeInBits)` (P4-16 Section 13.5).
type AdvanceStmt struct {
	Object string // method receiver, e.g. "pkt"
	Kind   AdvanceKind
	Pos    Position

	// Common to AdvanceField and AdvanceLookahead.
	BitWidth  int // the N in `(bit<N>) ...`
	ScaleLog2 int // the S in `<< S` (unit: bits)

	// AdvanceField only.
	Target    string // the `hdr` in `hdr.<F>` — the parser's `out` parameter holding the field
	FieldName string // the `<F>` in `hdr.<F>`
	BaseWords int    // the K subtracted from the field value

	// AdvanceLookahead only.
	LookaheadBits int // the M in `pkt.lookahead<bit<M>>()`
	SliceLo       int // the lo in `[lo:hi]` (LSB-numbered)
	SliceHi       int // the hi in `[lo:hi]` (LSB-numbered, inclusive)

	// AdvanceLiteral only.
	LiteralBits int // raw integer bit count
}

func (*AdvanceStmt) stmtNode() {}

// TransKind tags Transition with which transition shape was parsed.
type TransKind int

const (
	TransAccept TransKind = iota
	TransReject
	TransDirect
	TransSelect
)

// Transition is the tail of a parser state — `transition <target>;`
// or `transition select(...) { ... }`.
//
// BNF: transitionStatement (P4-16 Section 13.6 "Select expressions")
type Transition struct {
	Kind   TransKind
	Target string  // valid when Kind == TransDirect
	Select *Select // valid when Kind == TransSelect
	Pos    Position
}

// SelectKeyKind tags SelectKey with the syntactic form of one
// select-tuple slot.
type SelectKeyKind int

const (
	// SelectKeyField is a dotted field path, e.g. `gtp.e` or
	// `exts.last.next_ext`. The Path field carries the source
	// text; Bits is unused.
	SelectKeyField SelectKeyKind = iota
	// SelectKeyLookahead is `pkt.lookahead<bit<N>>()` — peek N
	// bits ahead without advancing R4. Bits = N; Path is unused.
	SelectKeyLookahead
)

// SelectKey is one slot of a `transition select(...)` tuple —
// either a dotted field path on an extracted header (the legacy
// shape) or a `pkt.lookahead<bit<N>>()` peek of the next N
// unconsumed bits.
type SelectKey struct {
	Kind SelectKeyKind
	Path string // valid when Kind == SelectKeyField
	Bits int    // valid when Kind == SelectKeyLookahead
	Pos  Position
}

// Select is the `select(key1, key2) { case...; default: ...; }`
// payload of a transition.
//
// BNF: selectExpression (P4-16 Section 13.6)
type Select struct {
	Keys  []SelectKey
	Cases []Case
	Pos   Position
}

// Case is one line of a select body: `(v1, v2): targetState;` or
// `default: targetState;`.
//
// BNF: selectCase (P4-16 Section 13.6)
type Case struct {
	IsDefault bool
	Values    []Match // tuple-matched; len must equal len(Select.Keys)
	Target    string  // state name or "accept" / "reject"
	Pos       Position
}

// Match is one slot of a select case keyset — a literal integer or
// the `_` wildcard.
//
// BNF: keysetExpression (P4-16 Section 13.6, simpleKeysetExpression
// alternatives: number, '_', default)
type Match struct {
	IsWildcard bool // true for "_"
	Value      uint64
	Pos        Position
}
