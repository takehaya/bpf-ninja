// p4lite/parser.go — recursive-descent parser for the strict subset
// of P4-16 the xdp-ninja vocab loader consumes.
//
// Spec reference: P4-16 Language Specification v1.2.5
//
//	https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html
//
// Sections this implementation aligns with (verified against the v1.2.5 ToC):
//   - Appendix G "Appendix: P4 grammar" — formal lexer / parser BNF.
//   - Section 7.2.2 "Header types" — header type declarations
//     (`header H { bit<N> f; ... }`).
//   - Section 11.1  "Constants" — `const bit<N> X = ...;` declarations.
//   - Section 13.2  "Parser declarations" — parser blocks
//     (`parser P(packet_in pkt, out H hdr) { ... }`).
//   - Section 13.4  "Parser states" — state body shape and `extract` calls.
//   - Section 13.6  "Select expressions" — `transition select(...) { ... }`
//     tuple matches.
package p4lite

import (
	"fmt"
	"sort"
	"strings"
)

// Parse reads a P4 source file and returns its AST. Only the p4lite subset
// is accepted (see the package doc).
func Parse(src []byte, file string) (*File, error) {
	p := &parser{lex: NewLexer(src, file), file: file}
	if err := p.advance(); err != nil {
		return nil, err
	}
	return p.parseFile()
}

type parser struct {
	lex  *Lexer
	cur  Token
	file string
}

func (p *parser) advance() error {
	var err error
	p.cur, err = p.lex.Next()
	return err
}

func (p *parser) errorf(pos Position, format string, args ...any) error {
	return &SyntaxError{File: p.file, Pos: pos, Message: fmt.Sprintf(format, args...)}
}

func (p *parser) expect(k TokenKind) (Token, error) {
	if p.cur.Kind != k {
		return Token{}, p.errorf(p.cur.Pos, "expected %s, got %s (%q)", k, p.cur.Kind, p.cur.Value)
	}
	t := p.cur
	if err := p.advance(); err != nil {
		return Token{}, err
	}
	return t, nil
}

func (p *parser) accept(k TokenKind) (Token, bool, error) {
	if p.cur.Kind != k {
		return Token{}, false, nil
	}
	t := p.cur
	if err := p.advance(); err != nil {
		return Token{}, false, err
	}
	return t, true, nil
}

func (p *parser) parseFile() (*File, error) {
	f := &File{}
	// pending accumulates @-prefixed annotations encountered before the
	// next declaration so a dangling @anno (EOF or before an extern
	// p4lite can't decorate) errors instead of silently dropping.
	var pending []Annotation
	for p.cur.Kind != TokEOF {
		switch p.cur.Kind {
		case TokAt:
			ann, err := p.parseAnnotation()
			if err != nil {
				return nil, err
			}
			pending = append(pending, *ann)
		case TokHeader:
			h, err := p.parseHeader()
			if err != nil {
				return nil, err
			}
			h.Annotations = pending
			pending = nil
			f.Headers = append(f.Headers, h)
		case TokConst:
			c, err := p.parseConst()
			if err != nil {
				return nil, err
			}
			c.Annotations = pending
			pending = nil
			f.Consts = append(f.Consts, c)
		case TokExtern:
			if len(pending) > 0 {
				return nil, p.errorf(pending[0].Pos, "annotations are not supported on extern declarations (p4lite treats extern bodies as opaque)")
			}
			ex, err := p.parseExtern()
			if err != nil {
				return nil, err
			}
			f.Externs = append(f.Externs, ex)
		case TokParser:
			par, err := p.parseParser()
			if err != nil {
				return nil, err
			}
			par.Annotations = pending
			pending = nil
			f.Parsers = append(f.Parsers, par)
		default:
			return nil, p.errorf(p.cur.Pos, "expected 'header', 'const', 'extern', 'parser', or '@annotation' at top level, got %s (%q)", p.cur.Kind, p.cur.Value)
		}
	}
	if len(pending) > 0 {
		return nil, p.errorf(pending[0].Pos, "annotation @%s has no following declaration to attach to", pending[0].Name)
	}
	if err := p.resolveConstMatches(f); err != nil {
		return nil, err
	}
	return f, nil
}

// resolveConstMatches folds named-const select-match arms into their
// integer value once the whole file is parsed. A select arm written
// as `SRV6_ROUTING_TYPE: state;` parses to a Match with ConstName set
// but Value unknown (the const decl may appear after the parser
// block). This pass, run from parseFile after all declarations are
// in hand, looks each name up in File.Consts and stamps the const's
// Int into Match.Value — making the named arm byte-for-byte identical
// to the literal it stands for. ConstName is left in place purely for
// diagnostics; no downstream consumer reads it.
//
// Errors, all positioned at the offending arm:
//   - unknown const name;
//   - a bool const used in an integer match slot;
//   - an int const used in a bool slot (a `<counter>.is_zero()` key,
//     whose arms must be the literals true/false).
//
// The bool-slot direction needs the key alignment, so the walk
// pairs each Case value with its Select key by index.
func (p *parser) resolveConstMatches(f *File) error {
	byName := make(map[string]*Const, len(f.Consts))
	for _, c := range f.Consts {
		byName[c.Name] = c
	}
	for _, par := range f.Parsers {
		for _, st := range par.States {
			tr := st.Transition
			if tr == nil || tr.Kind != TransSelect || tr.Select == nil {
				continue
			}
			sel := tr.Select
			for ci := range sel.Cases {
				c := &sel.Cases[ci]
				for vi := range c.Values {
					m := &c.Values[vi]
					boolSlot := vi < len(sel.Keys) &&
						sel.Keys[vi].Kind == SelectKeyCounterIsZero
					if err := p.resolveOneMatch(m, boolSlot, byName); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// resolveOneMatch handles a single Match slot. Literals, wildcards and
// bool literals pass through untouched; only a ConstName arm is
// resolved. boolSlot is true when the aligned select key is a
// `<counter>.is_zero()` peek, whose arms must be boolean.
func (p *parser) resolveOneMatch(m *Match, boolSlot bool, byName map[string]*Const) error {
	if m.ConstName == "" {
		// A bool literal landing in an integer slot, or an integer
		// literal in a bool slot, is a separate concern checked by
		// downstream codegen; this pass only owns const folding.
		return nil
	}
	c, ok := byName[m.ConstName]
	if !ok {
		return p.errorf(m.Pos, "select match references unknown const %q (no such const declared in this file)", m.ConstName)
	}
	if c.IsBool {
		if boolSlot {
			return p.errorf(m.Pos, "select match references bool const %q for a `<counter>.is_zero()` key; named bool consts are not supported here, use the literals true/false", m.ConstName)
		}
		return p.errorf(m.Pos, "select match references bool const %q where an integer match value is required (use a bit<N> const)", m.ConstName)
	}
	if boolSlot {
		return p.errorf(m.Pos, "select match references integer const %q for a `<counter>.is_zero()` key, which only matches the literals true/false", m.ConstName)
	}
	m.Value = c.Int
	return nil
}

// parseAnnotation parses one structured `@name[k=v, ...]` decorator.
// Cursor sits on the `@` token on entry. Only the structured form is
// accepted; positional `@name(...)` is rejected so heterogeneous
// parameter sets can't be silently reordered. Empty `@name[]` is
// accepted (lets callers omit args while still declaring the
// annotation name for future extension).
func (p *parser) parseAnnotation() (*Annotation, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokAt); err != nil {
		return nil, err
	}
	nameTok, err := p.expect(TokIdent)
	if err != nil {
		return nil, err
	}
	switch p.cur.Kind {
	case TokLBracket:
		// structured form, fall through
	case TokLParen:
		return nil, p.errorf(p.cur.Pos, "positional annotation form @%s(...) is not supported in p4lite; use the structured form @%s[k=v, ...]", nameTok.Value, nameTok.Value)
	default:
		return nil, p.errorf(p.cur.Pos, "expected '[' to start structured annotation arg list for @%s, got %s", nameTok.Value, p.cur.Kind)
	}
	if _, err := p.expect(TokLBracket); err != nil {
		return nil, err
	}
	var kvs map[string]AnnotationValue
	for p.cur.Kind != TokRBracket {
		keyTok, err := p.expect(TokIdent)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TokEquals); err != nil {
			return nil, err
		}
		val, err := p.parseAnnotationValue()
		if err != nil {
			return nil, err
		}
		if _, exists := kvs[keyTok.Value]; exists {
			return nil, p.errorf(keyTok.Pos, "duplicate annotation key %q in @%s", keyTok.Value, nameTok.Value)
		}
		if kvs == nil {
			kvs = make(map[string]AnnotationValue)
		}
		kvs[keyTok.Value] = val
		if _, ok, err := p.accept(TokComma); err != nil {
			return nil, err
		} else if !ok {
			break
		}
	}
	if _, err := p.expect(TokRBracket); err != nil {
		return nil, err
	}
	return &Annotation{Name: nameTok.Value, KVs: kvs, Pos: startPos}, nil
}

// parseAnnotationValue parses one RHS of a `k=v` pair: an integer
// literal, a bare identifier, or a dotted `proto.field` reference.
// P4-16 §7.4 also permits string literals and expression forms;
// p4lite defers those until a kunai annotation needs them.
func (p *parser) parseAnnotationValue() (AnnotationValue, error) {
	pos := p.cur.Pos
	switch p.cur.Kind {
	case TokInt:
		tok := p.cur
		if err := p.advance(); err != nil {
			return AnnotationValue{}, err
		}
		return AnnotationValue{Kind: AnnotationInt, Int: tok.Int, Pos: pos}, nil
	case TokIdent:
		name := p.cur.Value
		if err := p.advance(); err != nil {
			return AnnotationValue{}, err
		}
		if p.cur.Kind == TokDot {
			if err := p.advance(); err != nil {
				return AnnotationValue{}, err
			}
			fldTok, err := p.expect(TokIdent)
			if err != nil {
				return AnnotationValue{}, err
			}
			return AnnotationValue{Kind: AnnotationFieldRef, Proto: name, Field: fldTok.Value, Pos: pos}, nil
		}
		return AnnotationValue{Kind: AnnotationIdent, Ident: name, Pos: pos}, nil
	default:
		return AnnotationValue{}, p.errorf(pos, "expected int literal, identifier, or 'proto.field' as annotation value, got %s", p.cur.Kind)
	}
}

// parseExtern records `extern <Name> { ... }` and skips the body
// through balanced braces. The body is opaque to p4lite — vocab files
// declare it so p4c-check can resolve names like `ParserCounter`, but
// the loader only consumes the type name.
func (p *parser) parseExtern() (*Extern, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokExtern); err != nil {
		return nil, err
	}
	// Accept either an ident or the reserved ParserCounter keyword.
	var name string
	switch p.cur.Kind {
	case TokIdent, TokParserCounter:
		name = p.cur.Value
		if err := p.advance(); err != nil {
			return nil, err
		}
	default:
		return nil, p.errorf(p.cur.Pos, "expected extern type name, got %s", p.cur.Kind)
	}
	if _, err := p.expect(TokLBrace); err != nil {
		return nil, err
	}
	depth := 1
	for depth > 0 {
		switch p.cur.Kind {
		case TokEOF:
			return nil, p.errorf(startPos, "unterminated extern body")
		case TokLBrace:
			depth++
		case TokRBrace:
			depth--
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
	}
	return &Extern{Name: name, Pos: startPos}, nil
}

func (p *parser) parseHeader() (*Header, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokHeader); err != nil {
		return nil, err
	}
	name, err := p.expect(TokIdent)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TokLBrace); err != nil {
		return nil, err
	}
	h := &Header{Name: name.Value, Pos: startPos}
	for p.cur.Kind != TokRBrace && p.cur.Kind != TokEOF {
		f, err := p.parseField()
		if err != nil {
			return nil, err
		}
		h.Fields = append(h.Fields, f)
	}
	if _, err := p.expect(TokRBrace); err != nil {
		return nil, err
	}
	return h, nil
}

func (p *parser) parseField() (Field, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokBit); err != nil {
		return Field{}, err
	}
	if _, err := p.expect(TokLAngle); err != nil {
		return Field{}, err
	}
	width, err := p.expect(TokInt)
	if err != nil {
		return Field{}, err
	}
	// Header fields may legitimately exceed 64 bits (IPv6 addresses are
	// 128, SRv6 segment entries 128, etc). Cap at a generous 2048 so
	// typos still fail fast.
	if width.Int < 1 || width.Int > 2048 {
		return Field{}, p.errorf(width.Pos, "bit width %d out of range [1,2048]", width.Int)
	}
	if _, err := p.expect(TokRAngle); err != nil {
		return Field{}, err
	}
	name, err := p.expect(TokIdent)
	if err != nil {
		return Field{}, err
	}
	if _, err := p.expect(TokSemi); err != nil {
		return Field{}, err
	}
	return Field{Name: name.Value, Bits: int(width.Int), Pos: startPos}, nil
}

func (p *parser) parseConst() (*Const, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokConst); err != nil {
		return nil, err
	}
	c := &Const{Pos: startPos}
	switch p.cur.Kind {
	case TokBool:
		c.IsBool = true
		if err := p.advance(); err != nil {
			return nil, err
		}
	case TokBit:
		if err := p.advance(); err != nil {
			return nil, err
		}
		if _, err := p.expect(TokLAngle); err != nil {
			return nil, err
		}
		width, err := p.expect(TokInt)
		if err != nil {
			return nil, err
		}
		// Consts carry a uint64 value, so the width cap here is 64.
		if width.Int < 1 || width.Int > 64 {
			return nil, p.errorf(width.Pos, "const bit width %d out of range [1,64]", width.Int)
		}
		c.Bits = int(width.Int)
		if _, err := p.expect(TokRAngle); err != nil {
			return nil, err
		}
	default:
		return nil, p.errorf(p.cur.Pos, "expected 'bool' or 'bit<N>' in const, got %s", p.cur.Kind)
	}
	name, err := p.expect(TokIdent)
	if err != nil {
		return nil, err
	}
	c.Name = name.Value
	if _, err := p.expect(TokEquals); err != nil {
		return nil, err
	}
	if c.IsBool {
		switch p.cur.Kind {
		case TokTrue:
			c.Bool = true
		case TokFalse:
			c.Bool = false
		default:
			return nil, p.errorf(p.cur.Pos, "expected 'true' or 'false', got %s", p.cur.Kind)
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
	} else {
		vt, err := p.expect(TokInt)
		if err != nil {
			return nil, err
		}
		if c.Bits < 64 {
			max := uint64(1) << c.Bits
			if vt.Int >= max {
				return nil, p.errorf(vt.Pos, "value %d does not fit in bit<%d>", vt.Int, c.Bits)
			}
		}
		c.Int = vt.Int
	}
	if _, err := p.expect(TokSemi); err != nil {
		return nil, err
	}
	return c, nil
}

func (p *parser) parseParser() (*Parser, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokParser); err != nil {
		return nil, err
	}
	name, err := p.expect(TokIdent)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TokLParen); err != nil {
		return nil, err
	}
	par := &Parser{Name: name.Value, Pos: startPos}
	for p.cur.Kind != TokRParen && p.cur.Kind != TokEOF {
		var paramAnnotations []Annotation
		for p.cur.Kind == TokAt {
			ann, err := p.parseAnnotation()
			if err != nil {
				return nil, err
			}
			paramAnnotations = append(paramAnnotations, *ann)
		}
		param, err := p.parseParam()
		if err != nil {
			return nil, err
		}
		param.Annotations = paramAnnotations
		par.Params = append(par.Params, param)
		if _, ok, err := p.accept(TokComma); err != nil {
			return nil, err
		} else if !ok {
			break
		}
	}
	if _, err := p.expect(TokRParen); err != nil {
		return nil, err
	}
	if _, err := p.expect(TokLBrace); err != nil {
		return nil, err
	}
	for p.cur.Kind != TokRBrace && p.cur.Kind != TokEOF {
		switch p.cur.Kind {
		case TokState:
			st, err := p.parseState()
			if err != nil {
				return nil, err
			}
			par.States = append(par.States, st)
		case TokParserCounter:
			ci, err := p.parseCounterInst()
			if err != nil {
				return nil, err
			}
			for _, prev := range par.Counters {
				if prev.Name == ci.Name {
					return nil, p.errorf(ci.Pos, "ParserCounter %q already declared at %s", ci.Name, prev.Pos)
				}
			}
			par.Counters = append(par.Counters, ci)
		default:
			return nil, p.errorf(p.cur.Pos, "expected 'state' or 'ParserCounter' in parser body, got %s (%q)", p.cur.Kind, p.cur.Value)
		}
	}
	if _, err := p.expect(TokRBrace); err != nil {
		return nil, err
	}
	return par, nil
}

// parseCounterInst handles `ParserCounter() <name>;` — a no-arg
// constructor call followed by the in-parser handle name. p4lite
// admits exactly the no-arg shape Tofino's TNA documents; richer
// constructors (used by the threshold-counter mode) are out of subset.
func (p *parser) parseCounterInst() (CounterInst, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokParserCounter); err != nil {
		return CounterInst{}, err
	}
	if _, err := p.expect(TokLParen); err != nil {
		return CounterInst{}, err
	}
	if _, err := p.expect(TokRParen); err != nil {
		return CounterInst{}, err
	}
	name, err := p.expect(TokIdent)
	if err != nil {
		return CounterInst{}, err
	}
	if _, err := p.expect(TokSemi); err != nil {
		return CounterInst{}, err
	}
	return CounterInst{Name: name.Value, Pos: startPos}, nil
}

func (p *parser) parseParam() (Param, error) {
	startPos := p.cur.Pos
	switch p.cur.Kind {
	case TokPacketIn:
		if err := p.advance(); err != nil {
			return Param{}, err
		}
		name, err := p.expect(TokIdent)
		if err != nil {
			return Param{}, err
		}
		return Param{IsPacketIn: true, TypeName: "packet_in", VarName: name.Value, Pos: startPos}, nil
	case TokOut:
		if err := p.advance(); err != nil {
			return Param{}, err
		}
		typeTok, err := p.expect(TokIdent)
		if err != nil {
			return Param{}, err
		}
		param := Param{IsOut: true, TypeName: typeTok.Value, Pos: startPos}
		if _, ok, err := p.accept(TokLBracket); err != nil {
			return Param{}, err
		} else if ok {
			size, err := p.expect(TokInt)
			if err != nil {
				return Param{}, err
			}
			if size.Int < 1 {
				return Param{}, p.errorf(size.Pos, "array size %d must be >= 1", size.Int)
			}
			param.IsArray = true
			param.ArraySize = int(size.Int)
			if _, err := p.expect(TokRBracket); err != nil {
				return Param{}, err
			}
		}
		name, err := p.expect(TokIdent)
		if err != nil {
			return Param{}, err
		}
		param.VarName = name.Value
		return param, nil
	default:
		return Param{}, p.errorf(p.cur.Pos, "expected 'packet_in' or 'out' in parser parameter, got %s", p.cur.Kind)
	}
}

func (p *parser) parseState() (*State, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokState); err != nil {
		return nil, err
	}
	name, err := p.expect(TokIdent)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TokLBrace); err != nil {
		return nil, err
	}
	st := &State{Name: name.Value, Pos: startPos}
	for p.cur.Kind != TokRBrace && p.cur.Kind != TokTransition && p.cur.Kind != TokEOF {
		stmt, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		st.Stmts = append(st.Stmts, stmt)
	}
	if p.cur.Kind != TokTransition {
		return nil, p.errorf(p.cur.Pos, "state %q missing 'transition'", name.Value)
	}
	tr, err := p.parseTransition()
	if err != nil {
		return nil, err
	}
	st.Transition = tr
	if _, err := p.expect(TokRBrace); err != nil {
		return nil, err
	}
	return st, nil
}

// supportedMethods maps the method-keyword token to the per-method
// parser. Adding a new method means adding one entry here; the
// dispatch error in parseStmt picks up the new name automatically.
var supportedMethods = map[TokenKind]func(p *parser, obj string, startPos Position) (Stmt, error){
	TokExtract: (*parser).parseExtractCall,
	TokAdvance: (*parser).parseAdvanceCall,
}

// counterMethods maps a ParserCounter method's source name (TNA
// nomenclature: `set`, `decrement`) to its statement parser. These
// names are plain identifiers in P4-16 (the TNA spec doesn't reserve
// them), so dispatch happens after the keyword-based table misses.
var counterMethods = map[string]func(p *parser, counter string, startPos Position) (Stmt, error){
	"set":       (*parser).parseCounterSetCall,
	"decrement": (*parser).parseCounterDecrementCall,
}

// parseStmt dispatches on the method name in `obj.method(...)` to
// the per-method parser via supportedMethods.
func (p *parser) parseStmt() (Stmt, error) {
	startPos := p.cur.Pos
	obj, err := p.expect(TokIdent)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TokDot); err != nil {
		return nil, err
	}
	if handler, ok := supportedMethods[p.cur.Kind]; ok {
		if err := p.advance(); err != nil {
			return nil, err
		}
		return handler(p, obj.Value, startPos)
	}
	if p.cur.Kind == TokIdent {
		if handler, ok := counterMethods[p.cur.Value]; ok {
			if err := p.advance(); err != nil {
				return nil, err
			}
			return handler(p, obj.Value, startPos)
		}
	}
	names := make([]string, 0, len(supportedMethods)+len(counterMethods))
	for k := range supportedMethods {
		names = append(names, k.String())
	}
	for n := range counterMethods {
		names = append(names, "'"+n+"'")
	}
	sort.Strings(names)
	return nil, p.errorf(p.cur.Pos, "unsupported method %s (%q) on %q (recognised: %s)", p.cur.Kind, p.cur.Value, obj.Value, strings.Join(names, ", "))
}

// parseExtractCall handles `obj.extract(target)` or
// `obj.extract(target.next)`. Cursor sits past the `extract` token.
func (p *parser) parseExtractCall(obj string, startPos Position) (Stmt, error) {
	if _, err := p.expect(TokLParen); err != nil {
		return nil, err
	}
	targ, err := p.expect(TokIdent)
	if err != nil {
		return nil, err
	}
	es := &ExtractStmt{Object: obj, Target: targ.Value, Pos: startPos}
	if _, ok, err := p.accept(TokDot); err != nil {
		return nil, err
	} else if ok {
		nt, err := p.expect(TokIdent)
		if err != nil {
			return nil, err
		}
		if nt.Value != "next" {
			return nil, p.errorf(nt.Pos, "only '.next' accessor supported, got %q", nt.Value)
		}
		es.IsNext = true
	}
	if _, err := p.expect(TokRParen); err != nil {
		return nil, err
	}
	if _, err := p.expect(TokSemi); err != nil {
		return nil, err
	}
	return es, nil
}

// parseCounterSetCall handles `<counter>.set(((bit<N>)(hdr.<F> - K)) << S);`
// (subtract form) or `<counter>.set(((bit<N>)(hdr.<F> & MASK)) << S);`
// (mask form). Cursor sits past the `set` token. The arg shares
// AdvanceField's cast-and-shift template so the byte expression flowing
// into the counter slot is the same one trailer-skip already lowers.
// The mask form lets the counter carry a statically-bounded byte count
// (e.g. SRH's `(hdr_ext_len & 0x0F) * 8`) so the bulk-advance fallback
// the counter-driven walk degrades to stays verifier-bounded. The
// shared core consumes both the closing `)` and the trailing `;`.
func (p *parser) parseCounterSetCall(counter string, startPos Position) (Stmt, error) {
	if _, err := p.expect(TokLParen); err != nil {
		return nil, err
	}
	// Two structurally distinct arg shapes share the `set(` opener:
	//   shifted form: `((bit<N>) ...) << S)`  — second token after the
	//                 leading `(` is another `(`.
	//   bare-cast   : `(bit<N>)(hdr.<F> + K))` — second token is `bit`.
	// The shifted form wraps the cast in an extra paren so the `<< S`
	// scopes the whole expression; the bare-cast add form drops both the
	// outer paren and the shift (scale=1). Consume the first `(` and
	// dispatch on what follows (single-token lookahead only).
	if _, err := p.expect(TokLParen); err != nil {
		return nil, err
	}
	if p.cur.Kind == TokBit {
		return p.parseCounterSetBareCast(counter, startPos)
	}
	adv, err := p.parseAdvanceCastedShiftInner(counter, counter+".set", startPos)
	if err != nil {
		return nil, err
	}
	if adv.Kind != AdvanceField {
		return nil, p.errorf(startPos, "%s.set requires the `((bit<N>)(hdr.<F> - K)) << S` or `((bit<N>)(hdr.<F> & MASK)) << S` template (lookahead form not supported here)", counter)
	}
	return &CounterCallStmt{
		Counter:   counter,
		Op:        CounterSet,
		BitWidth:  adv.BitWidth,
		Target:    adv.Target,
		FieldName: adv.FieldName,
		BaseWords: adv.BaseWords,
		Mask:      adv.Mask,
		ScaleLog2: adv.ScaleLog2,
		Pos:       startPos,
	}, nil
}

// parseCounterSetBareCast parses the bare-cast add form
// `bit<N>)(hdr.<F> + K))` (the two leading `(` and the `bit` token's
// position were already established by parseCounterSetCall, with the
// cursor sitting on `bit`). This is the scale=1, shift-free counter
// seed used by element-driven aux-stack walks: the count trips once
// per pushed entry, so the seed is a small element count
// (`last_entry + 1`) rather than a byte length. The `+ K` addend is
// optional; `(bit<N>)(hdr.<F>)` parses with Addend=0.
//
// Grammar after the consumed `((`:
//
//	bit < N > ) ( hdr . F [ + K ] ) )
//
// The trailing two `)` close the cast group and the `set(` opener.
func (p *parser) parseCounterSetBareCast(counter string, startPos Position) (Stmt, error) {
	expectShape := func(k TokenKind) (Token, error) {
		if p.cur.Kind != k {
			return Token{}, p.errorf(p.cur.Pos, "%s.set bare-cast form must be `(bit<N>)(hdr.<F> + K)` (got %s)", counter, p.cur.Kind)
		}
		t := p.cur
		if err := p.advance(); err != nil {
			return Token{}, err
		}
		return t, nil
	}
	// `bit<N>)` — the cast prefix (outer `(` already consumed).
	if _, err := expectShape(TokBit); err != nil {
		return nil, err
	}
	if _, err := expectShape(TokLAngle); err != nil {
		return nil, err
	}
	nTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	for _, k := range []TokenKind{TokRAngle, TokRParen} {
		if _, err := expectShape(k); err != nil {
			return nil, err
		}
	}
	// `(hdr.<F>` — the field operand group opener.
	if _, err := expectShape(TokLParen); err != nil {
		return nil, err
	}
	hdrTok, err := expectShape(TokIdent)
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokDot); err != nil {
		return nil, err
	}
	fldTok, err := expectShape(TokIdent)
	if err != nil {
		return nil, err
	}
	// Optional `+ K`.
	addend := 0
	if p.cur.Kind == TokPlus {
		if _, err := expectShape(TokPlus); err != nil {
			return nil, err
		}
		kTok, err := expectShape(TokInt)
		if err != nil {
			return nil, err
		}
		if kTok.Int > uint64(maxInt32) {
			return nil, p.errorf(kTok.Pos, "%s.set addend K=%d exceeds the int32 range", counter, kTok.Int)
		}
		addend = int(kTok.Int)
	}
	// Closing `)` of the operand group, then `)` of `set(`.
	for _, k := range []TokenKind{TokRParen, TokRParen} {
		if _, err := expectShape(k); err != nil {
			return nil, err
		}
	}
	if _, err := p.expect(TokSemi); err != nil {
		return nil, err
	}
	return &CounterCallStmt{
		Counter:   counter,
		Op:        CounterSet,
		BitWidth:  int(nTok.Int),
		Target:    hdrTok.Value,
		FieldName: fldTok.Value,
		ScaleLog2: 0, // scale=1: element count, no byte shift
		Addend:    addend,
		Pos:       startPos,
	}, nil
}

// parseCounterDecrementCall handles three pc.decrement templates:
//   - literal: pc.decrement(<INT>)
//   - field-expr: pc.decrement(<aux>.<field>)
//   - lookahead: pc.decrement(((bit<N>)pkt.lookahead<bit<M>>()[lo:hi]))
//
// The lookahead form is the dispatched-but-not-extracted shape used
// by variable-size IPv4 options whose length byte sits in the
// pre-dispatch lookahead window — RR's
// pc.decrement(((bit<8>)pkt.lookahead<bit<16>>()[7:0])) drains the
// counter by the option's total size while pkt.advance with the same
// lookahead operand consumes the bytes. Cursor sits past the
// `decrement` token.
func (p *parser) parseCounterDecrementCall(counter string, startPos Position) (Stmt, error) {
	if _, err := p.expect(TokLParen); err != nil {
		return nil, err
	}
	switch p.cur.Kind {
	case TokLParen:
		return p.parseCounterDecrementLookahead(counter, startPos)
	case TokInt:
		iTok, err := p.expect(TokInt)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TokRParen); err != nil {
			return nil, err
		}
		if _, err := p.expect(TokSemi); err != nil {
			return nil, err
		}
		if iTok.Int == 0 {
			return nil, p.errorf(iTok.Pos, "%s.decrement(0) is a no-op (use a positive byte count)", counter)
		}
		if iTok.Int > uint64(maxInt32) {
			return nil, p.errorf(iTok.Pos, "%s.decrement(%d) exceeds the int32 range", counter, iTok.Int)
		}
		return &CounterCallStmt{
			Counter:      counter,
			Op:           CounterDecrement,
			LiteralBytes: int(iTok.Int),
			Pos:          startPos,
		}, nil
	case TokIdent:
		targetTok, err := p.expect(TokIdent)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TokDot); err != nil {
			return nil, err
		}
		fieldTok, err := p.expect(TokIdent)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TokRParen); err != nil {
			return nil, err
		}
		if _, err := p.expect(TokSemi); err != nil {
			return nil, err
		}
		return &CounterCallStmt{
			Counter:            counter,
			Op:                 CounterDecrement,
			DecrementTarget:    targetTok.Value,
			DecrementFieldName: fieldTok.Value,
			Pos:                startPos,
		}, nil
	}
	return nil, p.errorf(p.cur.Pos, "%s.decrement(...) expects an integer literal, `<aux>.<field>`, or `((bit<N>)pkt.lookahead<bit<M>>()[hi:lo])`", counter)
}

// parseCounterDecrementLookahead parses
// `((bit<N>)pkt.lookahead<bit<M>>()[hi:lo]));` after the opening `(`
// of `<counter>.decrement(`. Cursor sits on the inner opening `(`
// (the cast prefix). Mirrors parseAdvanceLookaheadOperand but does
// not require a trailing `<< S` shift — counter values are bytes,
// not bit counts. The slice [hi:lo] selects exactly one byte inside
// the lookahead window.
func (p *parser) parseCounterDecrementLookahead(counter string, startPos Position) (Stmt, error) {
	mismatch := func(pos Position) error {
		return p.errorf(pos, "%s.decrement(((bit<N>)pkt.lookahead<bit<M>>()[hi:lo])) is the only nested form supported; got an unexpected token", counter)
	}
	expectShape := func(k TokenKind) (Token, error) {
		if p.cur.Kind != k {
			return Token{}, mismatch(p.cur.Pos)
		}
		t := p.cur
		if err := p.advance(); err != nil {
			return Token{}, err
		}
		return t, nil
	}
	// Cast prefix `((bit<N>)`. The outer `(` of `decrement((bit<N>)...)`
	// was consumed by the caller; we open the second `(` here.
	for _, k := range []TokenKind{TokLParen, TokBit, TokLAngle} {
		if _, err := expectShape(k); err != nil {
			return nil, err
		}
	}
	nTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	for _, k := range []TokenKind{TokRAngle, TokRParen} {
		if _, err := expectShape(k); err != nil {
			return nil, err
		}
	}
	pktTok, err := expectShape(TokIdent)
	if err != nil {
		return nil, err
	}
	if pktTok.Value != "pkt" {
		return nil, p.errorf(pktTok.Pos, "expected `pkt.lookahead<...>()` inside the cast, got `%s.<...>`", pktTok.Value)
	}
	if _, err := expectShape(TokDot); err != nil {
		return nil, err
	}
	if _, err := expectShape(TokLookahead); err != nil {
		return nil, err
	}
	mBits, err := p.parseLookaheadType()
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokLBracket); err != nil {
		return nil, err
	}
	hiTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokColon); err != nil {
		return nil, err
	}
	loTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokRBracket); err != nil {
		return nil, err
	}
	// Closing `)` of `decrement(...)`.
	if _, err := p.expect(TokRParen); err != nil {
		return nil, err
	}
	if _, err := p.expect(TokSemi); err != nil {
		return nil, err
	}
	if loTok.Int > hiTok.Int {
		return nil, p.errorf(loTok.Pos, "slice lo=%d must be ≤ hi=%d (use [hi:lo] convention)", loTok.Int, hiTok.Int)
	}
	if hiTok.Int >= uint64(mBits) {
		return nil, p.errorf(hiTok.Pos, "slice hi=%d must be smaller than the lookahead width M=%d", hiTok.Int, mBits)
	}
	return &CounterCallStmt{
		Counter:                counter,
		Op:                     CounterDecrement,
		Pos:                    startPos,
		DecrementBitWidth:      int(nTok.Int),
		DecrementLookaheadBits: mBits,
		DecrementSliceLo:       int(loTok.Int),
		DecrementSliceHi:       int(hiTok.Int),
	}, nil
}

// parseAdvanceCall handles all three pkt.advance templates:
//   - field shift:  pkt.advance(((bit<N>)(hdr.<F> - K)) << S)
//   - lookahead:    pkt.advance(((bit<N>)pkt.lookahead<bit<M>>()[lo:hi]) << S)
//   - literal:      pkt.advance(<INT>)
//
// Cursor sits past the `advance` token. Anything that doesn't match
// one of these shapes gets a loud, source-located error pointing at
// the supported forms.
func (p *parser) parseAdvanceCall(obj string, startPos Position) (Stmt, error) {
	if _, err := p.expect(TokLParen); err != nil {
		return nil, err
	}
	// Template C dispatch: literal advance is the only form whose
	// arg starts with an integer rather than a paren.
	if p.cur.Kind == TokInt {
		return p.parseAdvanceLiteral(obj, startPos)
	}
	return p.parseAdvanceCastedShift(obj, startPos)
}

// parseAdvanceLiteral parses `<INT>);` — the tail of `pkt.advance(<INT>)`.
// Cursor sits at the int token.
func (p *parser) parseAdvanceLiteral(obj string, startPos Position) (Stmt, error) {
	iTok := p.cur
	if err := p.advance(); err != nil {
		return nil, err
	}
	if _, err := p.expect(TokRParen); err != nil {
		return nil, err
	}
	if _, err := p.expect(TokSemi); err != nil {
		return nil, err
	}
	if iTok.Int > uint64(maxInt32) {
		return nil, p.errorf(iTok.Pos, "literal advance %d exceeds the int32 range", iTok.Int)
	}
	return &AdvanceStmt{
		Object:      obj,
		Kind:        AdvanceLiteral,
		LiteralBits: int(iTok.Int),
		Pos:         startPos,
	}, nil
}

// parseAdvanceCastedShift parses the templates that share the
// `((bit<N>) ...) << S` shape — AdvanceField and AdvanceLookahead.
// Cursor sits one token past the `pkt.advance(` opener (so on the
// first inner `(`). It eats the first `(` and delegates to the
// inner parser, which is shared with `<counter>.set`'s shifted form
// (whose caller has already consumed that first `(`).
func (p *parser) parseAdvanceCastedShift(obj string, startPos Position) (*AdvanceStmt, error) {
	if _, err := p.expect(TokLParen); err != nil {
		return nil, err
	}
	return p.parseAdvanceCastedShiftInner(obj, "pkt.advance", startPos)
}

// parseAdvanceCastedShiftInner parses `(bit<N>) ...) << S` — the
// shifted cast template with the leading `(` already consumed by the
// caller (parseAdvanceCastedShift for pkt.advance, parseCounterSetCall
// for the counter.set shifted form). construct names the surface form
// for diagnostics ("pkt.advance" or "<counter>.set") so a malformed arg
// is reported against the construct the author actually wrote.
func (p *parser) parseAdvanceCastedShiftInner(obj, construct string, startPos Position) (*AdvanceStmt, error) {
	mismatch := func(pos Position) error {
		if construct == "pkt.advance" {
			return p.errorf(pos, "pkt.advance must use one of `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` / `pkt.advance(((bit<N>)pkt.lookahead<bit<M>>()[lo:hi]) << S)` / `pkt.advance(<INT>)`")
		}
		return p.errorf(pos, "%s must use the casted-shift form `%s(((bit<N>)(hdr.<F> - K)) << S)` or `%s(((bit<N>)(hdr.<F> & MASK)) << S)`", construct, construct, construct)
	}
	expectShape := func(k TokenKind) (Token, error) {
		if p.cur.Kind != k {
			return Token{}, mismatch(p.cur.Pos)
		}
		t := p.cur
		if err := p.advance(); err != nil {
			return Token{}, err
		}
		return t, nil
	}
	// Remaining prefix `(bit<N>)` (the outer `(` is already consumed).
	for _, k := range []TokenKind{TokLParen, TokBit, TokLAngle} {
		if _, err := expectShape(k); err != nil {
			return nil, err
		}
	}
	nTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	for _, k := range []TokenKind{TokRAngle, TokRParen} {
		if _, err := expectShape(k); err != nil {
			return nil, err
		}
	}
	// Branch on the cast operand: `(` opens an arith group (template A);
	// `pkt` starts a lookahead expression (template B).
	var adv *AdvanceStmt
	switch {
	case p.cur.Kind == TokLParen:
		adv, err = p.parseAdvanceFieldOperand(obj, startPos, nTok, expectShape)
	case p.cur.Kind == TokIdent && p.cur.Value == "pkt":
		adv, err = p.parseAdvanceLookaheadOperand(obj, startPos, nTok, expectShape)
	default:
		return nil, mismatch(p.cur.Pos)
	}
	if err != nil {
		return nil, err
	}
	// Common tail: `) << S );`.
	for _, k := range []TokenKind{TokRParen, TokLShift} {
		if _, err := expectShape(k); err != nil {
			return nil, err
		}
	}
	sTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokRParen); err != nil {
		return nil, err
	}
	if _, err := p.expect(TokSemi); err != nil {
		return nil, err
	}
	// ScaleLog2 ≥ N would shift past the cast width (P4-16 §8.7 makes
	// this implementation-defined).
	if sTok.Int >= uint64(nTok.Int) {
		return nil, p.errorf(sTok.Pos, "shift S=%d must be smaller than the cast width N=%d", sTok.Int, nTok.Int)
	}
	adv.ScaleLog2 = int(sTok.Int)
	return adv, nil
}

// parseAdvanceFieldOperand parses `(hdr.<F> - K)` (subtract form) or
// `(hdr.<F> & MASK)` (mask form) after the `((bit<N>)` prefix. Cursor
// sits on the opening `(`. Subtract form is used by primary-header
// variable trailers (IPv4 IHL, TCP data_offset); mask form is used by
// extension-header variable trailers (IPv6 hdr_ext_len, SRH hdr_ext_len).
func (p *parser) parseAdvanceFieldOperand(obj string, startPos Position, nTok Token, expectShape func(TokenKind) (Token, error)) (*AdvanceStmt, error) {
	if _, err := expectShape(TokLParen); err != nil {
		return nil, err
	}
	hdrTok, err := expectShape(TokIdent)
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokDot); err != nil {
		return nil, err
	}
	fldTok, err := expectShape(TokIdent)
	if err != nil {
		return nil, err
	}
	// Branch on `-` (subtract form) vs `&` (mask form). Any other
	// token here is a parse error pointing at this position so the
	// diagnostic names exactly which operator was expected.
	opTok := p.cur
	var baseWords, mask int
	switch opTok.Kind {
	case TokMinus:
		if _, err := expectShape(TokMinus); err != nil {
			return nil, err
		}
		kTok, err := expectShape(TokInt)
		if err != nil {
			return nil, err
		}
		if kTok.Int > uint64(maxInt32) {
			return nil, p.errorf(kTok.Pos, "K=%d exceeds the int32 range", kTok.Int)
		}
		baseWords = int(kTok.Int)
	case TokAmp:
		if _, err := expectShape(TokAmp); err != nil {
			return nil, err
		}
		mTok, err := expectShape(TokInt)
		if err != nil {
			return nil, err
		}
		if mTok.Int == 0 {
			return nil, p.errorf(mTok.Pos, "mask MASK=0 makes the advance always zero — unintended")
		}
		if mTok.Int > uint64(maxInt32) {
			return nil, p.errorf(mTok.Pos, "MASK=0x%x exceeds the int32 range", mTok.Int)
		}
		mask = int(mTok.Int)
	default:
		return nil, p.errorf(opTok.Pos, "expected `-` (subtract form) or `&` (mask form) after `hdr.<field>` inside pkt.advance, got %s", opTok.Kind)
	}
	if _, err := expectShape(TokRParen); err != nil {
		return nil, err
	}
	return &AdvanceStmt{
		Object:    obj,
		Kind:      AdvanceField,
		BitWidth:  int(nTok.Int),
		Target:    hdrTok.Value,
		FieldName: fldTok.Value,
		BaseWords: baseWords,
		Mask:      mask,
		Pos:       startPos,
	}, nil
}

// parseAdvanceLookaheadOperand parses `pkt.lookahead<bit<M>>()[lo:hi]`
// after the `((bit<N>)` prefix. Cursor sits on the `pkt` ident.
func (p *parser) parseAdvanceLookaheadOperand(obj string, startPos Position, nTok Token, expectShape func(TokenKind) (Token, error)) (*AdvanceStmt, error) {
	pktTok, err := expectShape(TokIdent)
	if err != nil {
		return nil, err
	}
	if pktTok.Value != "pkt" {
		return nil, p.errorf(pktTok.Pos, "expected `pkt.lookahead<...>()` inside the cast, got `%s.<...>`", pktTok.Value)
	}
	if _, err := expectShape(TokDot); err != nil {
		return nil, err
	}
	if _, err := expectShape(TokLookahead); err != nil {
		return nil, err
	}
	mBits, err := p.parseLookaheadType()
	if err != nil {
		return nil, err
	}
	// `[lo:hi]` slice.
	if _, err := expectShape(TokLBracket); err != nil {
		return nil, err
	}
	hiTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokColon); err != nil {
		return nil, err
	}
	loTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokRBracket); err != nil {
		return nil, err
	}
	// Slice operands: P4-16 spec writes [hi:lo] (MSB:LSB, inclusive,
	// LSB-numbered). hi >= lo required; both must fit inside the
	// lookahead width.
	if loTok.Int > hiTok.Int {
		return nil, p.errorf(loTok.Pos, "slice lo=%d must be ≤ hi=%d (use [hi:lo] convention)", loTok.Int, hiTok.Int)
	}
	if hiTok.Int >= uint64(mBits) {
		return nil, p.errorf(hiTok.Pos, "slice hi=%d must be smaller than the lookahead width M=%d", hiTok.Int, mBits)
	}
	return &AdvanceStmt{
		Object:        obj,
		Kind:          AdvanceLookahead,
		BitWidth:      int(nTok.Int),
		LookaheadBits: mBits,
		SliceLo:       int(loTok.Int),
		SliceHi:       int(hiTok.Int),
		Pos:           startPos,
	}, nil
}

const maxInt32 = 1<<31 - 1

func (p *parser) parseTransition() (*Transition, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokTransition); err != nil {
		return nil, err
	}
	t := &Transition{Pos: startPos}
	switch p.cur.Kind {
	case TokAccept:
		t.Kind = TransAccept
		if err := p.advance(); err != nil {
			return nil, err
		}
		if _, err := p.expect(TokSemi); err != nil {
			return nil, err
		}
	case TokReject:
		t.Kind = TransReject
		if err := p.advance(); err != nil {
			return nil, err
		}
		if _, err := p.expect(TokSemi); err != nil {
			return nil, err
		}
	case TokIdent:
		t.Kind = TransDirect
		t.Target = p.cur.Value
		if err := p.advance(); err != nil {
			return nil, err
		}
		if _, err := p.expect(TokSemi); err != nil {
			return nil, err
		}
	case TokSelect:
		sel, err := p.parseSelect()
		if err != nil {
			return nil, err
		}
		t.Kind = TransSelect
		t.Select = sel
	default:
		return nil, p.errorf(p.cur.Pos, "expected 'accept', 'reject', state name, or 'select' after 'transition', got %s", p.cur.Kind)
	}
	return t, nil
}

func (p *parser) parseSelect() (*Select, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(TokSelect); err != nil {
		return nil, err
	}
	if _, err := p.expect(TokLParen); err != nil {
		return nil, err
	}
	sel := &Select{Pos: startPos}
	for p.cur.Kind != TokRParen && p.cur.Kind != TokEOF {
		key, err := p.parseSelectKey()
		if err != nil {
			return nil, err
		}
		sel.Keys = append(sel.Keys, key)
		if _, ok, err := p.accept(TokComma); err != nil {
			return nil, err
		} else if !ok {
			break
		}
	}
	if _, err := p.expect(TokRParen); err != nil {
		return nil, err
	}
	if _, err := p.expect(TokLBrace); err != nil {
		return nil, err
	}
	for p.cur.Kind != TokRBrace && p.cur.Kind != TokEOF {
		c, err := p.parseCase(len(sel.Keys))
		if err != nil {
			return nil, err
		}
		sel.Cases = append(sel.Cases, c)
	}
	if _, err := p.expect(TokRBrace); err != nil {
		return nil, err
	}
	return sel, nil
}

// parseSelectKey accepts a dotted field path, a
// `pkt.lookahead<bit<N>>()` peek, or a `<counter>.is_zero()` test.
// The two method forms share an `<ident>.<method>` shape that
// collides with the dotted-path syntax until we see what's after
// the `.`, so each speculatively descends through tryDottedMethod
// and rewinds on miss.
func (p *parser) parseSelectKey() (SelectKey, error) {
	startPos := p.cur.Pos
	if p.cur.Kind == TokIdent && p.cur.Value == "pkt" {
		if _, ok, err := p.tryDottedMethod(TokLookahead, ""); err != nil {
			return SelectKey{}, err
		} else if ok {
			bits, err := p.parseLookaheadType()
			if err != nil {
				return SelectKey{}, err
			}
			return SelectKey{Kind: SelectKeyLookahead, Bits: bits, Pos: startPos}, nil
		}
	}
	if obj, ok, err := p.tryDottedMethod(TokIdent, "is_zero"); err != nil {
		return SelectKey{}, err
	} else if ok {
		if _, err := p.expect(TokLParen); err != nil {
			return SelectKey{}, err
		}
		if _, err := p.expect(TokRParen); err != nil {
			return SelectKey{}, err
		}
		return SelectKey{Kind: SelectKeyCounterIsZero, Counter: obj, Pos: startPos}, nil
	}
	path, err := p.parseDottedPath()
	if err != nil {
		return SelectKey{}, err
	}
	return SelectKey{Kind: SelectKeyField, Path: path, Pos: startPos}, nil
}

// tryDottedMethod speculatively consumes `<obj>.<method>` from the
// current cursor and reports whether it matched. methodKind picks
// the method's token kind; methodValue (when non-empty) additionally
// requires the method ident's text to match — used to disambiguate
// plain idents like "is_zero" without lexer-level reservation. On
// match the cursor sits past the method token and obj returns the
// receiver name. On miss the lexer rewinds so the cursor is exactly
// where it started, and the caller can try the next form.
func (p *parser) tryDottedMethod(methodKind TokenKind, methodValue string) (obj string, matched bool, err error) {
	if p.cur.Kind != TokIdent {
		return "", false, nil
	}
	snap := p.lex.Save()
	objTok := p.cur
	if err := p.advance(); err != nil {
		return "", false, err
	}
	if p.cur.Kind != TokDot {
		p.lex.Restore(snap)
		p.cur = objTok
		return "", false, nil
	}
	if err := p.advance(); err != nil {
		return "", false, err
	}
	methodMatches := p.cur.Kind == methodKind &&
		(methodValue == "" || p.cur.Value == methodValue)
	if !methodMatches {
		p.lex.Restore(snap)
		p.cur = objTok
		return "", false, nil
	}
	if err := p.advance(); err != nil {
		return "", false, err
	}
	return objTok.Value, true, nil
}

// parseLookaheadType consumes the `<bit<N>>()` tail of a
// `pkt.lookahead` expression and returns the N. Cursor sits past
// the `lookahead` keyword on entry.
func (p *parser) parseLookaheadType() (int, error) {
	if _, err := p.expect(TokLAngle); err != nil {
		return 0, err
	}
	if _, err := p.expect(TokBit); err != nil {
		return 0, err
	}
	if _, err := p.expect(TokLAngle); err != nil {
		return 0, err
	}
	nTok, err := p.expect(TokInt)
	if err != nil {
		return 0, err
	}
	if _, err := p.expect(TokRAngle); err != nil {
		return 0, err
	}
	if _, err := p.expect(TokRAngle); err != nil {
		return 0, err
	}
	if _, err := p.expect(TokLParen); err != nil {
		return 0, err
	}
	if _, err := p.expect(TokRParen); err != nil {
		return 0, err
	}
	return int(nTok.Int), nil
}

func (p *parser) parseDottedPath() (string, error) {
	first, err := p.expect(TokIdent)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(first.Value)
	for p.cur.Kind == TokDot {
		if err := p.advance(); err != nil {
			return "", err
		}
		seg, err := p.expect(TokIdent)
		if err != nil {
			return "", err
		}
		b.WriteByte('.')
		b.WriteString(seg.Value)
	}
	return b.String(), nil
}

func (p *parser) parseCase(keyCount int) (Case, error) {
	startPos := p.cur.Pos
	c := Case{Pos: startPos}
	switch p.cur.Kind {
	case TokDefault:
		c.IsDefault = true
		if err := p.advance(); err != nil {
			return Case{}, err
		}
	case TokLParen:
		if err := p.advance(); err != nil {
			return Case{}, err
		}
		for p.cur.Kind != TokRParen && p.cur.Kind != TokEOF {
			m, err := p.parseMatch()
			if err != nil {
				return Case{}, err
			}
			c.Values = append(c.Values, m)
			if _, ok, err := p.accept(TokComma); err != nil {
				return Case{}, err
			} else if !ok {
				break
			}
		}
		if _, err := p.expect(TokRParen); err != nil {
			return Case{}, err
		}
		if len(c.Values) != keyCount {
			return Case{}, p.errorf(startPos, "select case has %d values, expected %d", len(c.Values), keyCount)
		}
	case TokInt, TokIdent, TokTrue, TokFalse:
		m, err := p.parseMatch()
		if err != nil {
			return Case{}, err
		}
		c.Values = []Match{m}
		if keyCount != 1 {
			return Case{}, p.errorf(startPos, "select case has 1 value, expected %d", keyCount)
		}
	default:
		return Case{}, p.errorf(p.cur.Pos, "expected 'default', value (int or true/false), or '(' for select case, got %s", p.cur.Kind)
	}
	if _, err := p.expect(TokColon); err != nil {
		return Case{}, err
	}
	target, err := p.parseTransitionTarget()
	if err != nil {
		return Case{}, err
	}
	c.Target = target
	if _, err := p.expect(TokSemi); err != nil {
		return Case{}, err
	}
	return c, nil
}

func (p *parser) parseTransitionTarget() (string, error) {
	switch p.cur.Kind {
	case TokAccept:
		if err := p.advance(); err != nil {
			return "", err
		}
		return "accept", nil
	case TokReject:
		if err := p.advance(); err != nil {
			return "", err
		}
		return "reject", nil
	case TokIdent:
		v := p.cur.Value
		if err := p.advance(); err != nil {
			return "", err
		}
		return v, nil
	default:
		return "", p.errorf(p.cur.Pos, "expected state name or 'accept'/'reject', got %s", p.cur.Kind)
	}
}

func (p *parser) parseMatch() (Match, error) {
	startPos := p.cur.Pos
	switch p.cur.Kind {
	case TokInt:
		m := Match{Value: p.cur.Int, Pos: startPos}
		if err := p.advance(); err != nil {
			return Match{}, err
		}
		return m, nil
	case TokTrue:
		if err := p.advance(); err != nil {
			return Match{}, err
		}
		return Match{IsBool: true, Bool: true, Pos: startPos}, nil
	case TokFalse:
		if err := p.advance(); err != nil {
			return Match{}, err
		}
		return Match{IsBool: true, Bool: false, Pos: startPos}, nil
	case TokIdent:
		if p.cur.Value == "_" {
			m := Match{IsWildcard: true, Pos: startPos}
			if err := p.advance(); err != nil {
				return Match{}, err
			}
			return m, nil
		}
		// A bare identifier names an integer const declared elsewhere
		// in the file. The value isn't known until every const is
		// parsed, so record the name and defer the lookup to
		// resolveConstMatches (run from parseFile once the whole file
		// is in hand). Value stays the single source of truth: the
		// resolution pass folds the const's integer into Value.
		m := Match{ConstName: p.cur.Value, Pos: startPos}
		if err := p.advance(); err != nil {
			return Match{}, err
		}
		return m, nil
	default:
		return Match{}, p.errorf(p.cur.Pos, "expected integer, named const, '_' or true/false in select match, got %s", p.cur.Kind)
	}
}
