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
	for p.cur.Kind != TokEOF {
		switch p.cur.Kind {
		case TokHeader:
			h, err := p.parseHeader()
			if err != nil {
				return nil, err
			}
			f.Headers = append(f.Headers, h)
		case TokConst:
			c, err := p.parseConst()
			if err != nil {
				return nil, err
			}
			f.Consts = append(f.Consts, c)
		case TokParser:
			par, err := p.parseParser()
			if err != nil {
				return nil, err
			}
			f.Parsers = append(f.Parsers, par)
		default:
			return nil, p.errorf(p.cur.Pos, "expected 'header', 'const', or 'parser' at top level, got %s (%q)", p.cur.Kind, p.cur.Value)
		}
	}
	return f, nil
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
		param, err := p.parseParam()
		if err != nil {
			return nil, err
		}
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
		if p.cur.Kind != TokState {
			return nil, p.errorf(p.cur.Pos, "expected 'state' in parser body, got %s (%q)", p.cur.Kind, p.cur.Value)
		}
		st, err := p.parseState()
		if err != nil {
			return nil, err
		}
		par.States = append(par.States, st)
	}
	if _, err := p.expect(TokRBrace); err != nil {
		return nil, err
	}
	return par, nil
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
	names := make([]string, 0, len(supportedMethods))
	for k := range supportedMethods {
		names = append(names, k.String())
	}
	sort.Strings(names)
	return nil, p.errorf(p.cur.Pos, "unsupported method %s on %q (recognised: %s)", p.cur.Kind, obj.Value, strings.Join(names, ", "))
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
// first inner `(`).
func (p *parser) parseAdvanceCastedShift(obj string, startPos Position) (Stmt, error) {
	mismatch := func(pos Position) error {
		return p.errorf(pos, "pkt.advance must use one of `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` / `pkt.advance(((bit<N>)pkt.lookahead<bit<M>>()[lo:hi]) << S)` / `pkt.advance(<INT>)`")
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
	// Common prefix `((bit<N>)`.
	for _, k := range []TokenKind{TokLParen, TokLParen, TokBit, TokLAngle} {
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

// parseAdvanceFieldOperand parses `(hdr.<F> - K)` after the
// `((bit<N>)` prefix. Cursor sits on the opening `(`.
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
	if _, err := expectShape(TokMinus); err != nil {
		return nil, err
	}
	kTok, err := expectShape(TokInt)
	if err != nil {
		return nil, err
	}
	if _, err := expectShape(TokRParen); err != nil {
		return nil, err
	}
	if kTok.Int > uint64(maxInt32) {
		return nil, p.errorf(kTok.Pos, "K=%d exceeds the supported range for the BaseWords slot", kTok.Int)
	}
	return &AdvanceStmt{
		Object:    obj,
		Kind:      AdvanceField,
		BitWidth:  int(nTok.Int),
		Target:    hdrTok.Value,
		FieldName: fldTok.Value,
		BaseWords: int(kTok.Int),
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

// parseSelectKey accepts either a dotted field path (keyed on an
// extracted-header field) or a `pkt.lookahead<bit<N>>()` peek that
// dispatches on bytes the parser hasn't consumed yet.
func (p *parser) parseSelectKey() (SelectKey, error) {
	startPos := p.cur.Pos
	// `pkt` is a TokIdent; lookahead requires recognising the method
	// name after `.`. The parser look-ahead is one token, so we save
	// the lexer position and try the lookahead form first.
	if p.cur.Kind == TokIdent && p.cur.Value == "pkt" {
		snap := p.lex.Save()
		objTok := p.cur
		if err := p.advance(); err != nil {
			return SelectKey{}, err
		}
		if p.cur.Kind == TokDot {
			if err := p.advance(); err != nil {
				return SelectKey{}, err
			}
			if p.cur.Kind == TokLookahead {
				if err := p.advance(); err != nil {
					return SelectKey{}, err
				}
				bits, err := p.parseLookaheadType()
				if err != nil {
					return SelectKey{}, err
				}
				return SelectKey{Kind: SelectKeyLookahead, Bits: bits, Pos: startPos}, nil
			}
		}
		// Not a lookahead — rewind and fall through to dotted path,
		// where `pkt.foo` is a (rare but legal) field path.
		p.lex.Restore(snap)
		p.cur = objTok
	}
	path, err := p.parseDottedPath()
	if err != nil {
		return SelectKey{}, err
	}
	return SelectKey{Kind: SelectKeyField, Path: path, Pos: startPos}, nil
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
	case TokInt, TokIdent:
		m, err := p.parseMatch()
		if err != nil {
			return Case{}, err
		}
		c.Values = []Match{m}
		if keyCount != 1 {
			return Case{}, p.errorf(startPos, "select case has 1 value, expected %d", keyCount)
		}
	default:
		return Case{}, p.errorf(p.cur.Pos, "expected 'default', value, or '(' for select case, got %s", p.cur.Kind)
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
	case TokIdent:
		if p.cur.Value == "_" {
			m := Match{IsWildcard: true, Pos: startPos}
			if err := p.advance(); err != nil {
				return Match{}, err
			}
			return m, nil
		}
		return Match{}, p.errorf(p.cur.Pos, "unexpected identifier %q in match (only integers or '_' supported)", p.cur.Value)
	default:
		return Match{}, p.errorf(p.cur.Pos, "expected integer or '_' in select match, got %s", p.cur.Kind)
	}
}
