package parser

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/lexer"
)

// parsePredicateList is called after the leading "[" has been consumed;
// the closing "]" is the caller's responsibility.
//
//	pred_list := predicate ("," predicate)*
func (p *parser) parsePredicateList() ([]*ast.Predicate, error) {
	first, err := p.parsePredicate()
	if err != nil {
		return nil, err
	}
	preds := []*ast.Predicate{first}
	for p.cur.Kind == lexer.TokComma {
		if err := p.advance(); err != nil {
			return nil, err
		}
		next, err := p.parsePredicate()
		if err != nil {
			return nil, err
		}
		preds = append(preds, next)
	}
	return preds, nil
}

// predicate := field_path ("in" value_list | "has" IDENT | cmp_op value)
func (p *parser) parsePredicate() (*ast.Predicate, error) {
	startPos := p.cur.Pos
	field, err := p.parseFieldPath()
	if err != nil {
		return nil, err
	}
	pred := &ast.Predicate{Field: field, Pos: startPos}

	switch p.cur.Kind {
	case lexer.TokIn:
		if err := p.advance(); err != nil {
			return nil, err
		}
		list, err := p.parseValueList()
		if err != nil {
			return nil, err
		}
		pred.Kind = ast.PredIn
		pred.List = list
		return pred, nil

	case lexer.TokHas:
		if err := p.advance(); err != nil {
			return nil, err
		}
		flag, err := p.expect(lexer.TokIdent)
		if err != nil {
			return nil, err
		}
		pred.Kind = ast.PredHas
		pred.FlagName = flag.Text
		return pred, nil
	}

	op, ok := cmpOpFor(p.cur.Kind)
	if !ok {
		return nil, p.errorf(p.cur.Pos, "expected 'in', 'has', or comparison operator after field, got %s", p.cur.Kind)
	}
	// Read the value in value mode.
	if err := p.advanceValue(); err != nil {
		return nil, err
	}
	if p.cur.Kind != lexer.TokValue {
		return nil, p.errorf(p.cur.Pos, "expected value after comparison operator, got %s", p.cur.Kind)
	}
	pred.Kind = ast.PredCmp
	pred.Op = op
	pred.Value = p.cur.Value
	// Resume structural mode for whatever follows (',' or ']').
	if err := p.advance(); err != nil {
		return nil, err
	}
	return pred, nil
}

// cmpOpFor maps lexer comparison tokens to AST operators.
func cmpOpFor(k lexer.TokenKind) (ast.CmpOp, bool) {
	switch k {
	case lexer.TokEqEq:
		return ast.CmpEq, true
	case lexer.TokNeq:
		return ast.CmpNeq, true
	case lexer.TokLt:
		return ast.CmpLt, true
	case lexer.TokLe:
		return ast.CmpLe, true
	case lexer.TokGt:
		return ast.CmpGt, true
	case lexer.TokGe:
		return ast.CmpGe, true
	}
	return 0, false
}

// field_path := IDENT ("." IDENT)*
func (p *parser) parseFieldPath() (*ast.FieldPath, error) {
	first, err := p.expect(lexer.TokIdent)
	if err != nil {
		return nil, err
	}
	return p.parseFieldPathFromHead(first)
}

// parseFieldPathFromHead finishes a field path parse when the caller
// has already consumed the leading IDENT (e.g. capture's IDENT
// branch peeks at the next token to disambiguate before committing
// to a field path). The dotted tail is parsed identically to
// parseFieldPath's loop body.
func (p *parser) parseFieldPathFromHead(head lexer.Token) (*ast.FieldPath, error) {
	parts := []string{head.Text}
	for p.cur.Kind == lexer.TokDot {
		if err := p.advance(); err != nil {
			return nil, err
		}
		next, err := p.expect(lexer.TokIdent)
		if err != nil {
			return nil, err
		}
		parts = append(parts, next.Text)
	}
	return &ast.FieldPath{Parts: parts, Pos: head.Pos}, nil
}

// value_list := "[" value ("," value)* "]"
// Called with p.cur positioned at the leading "[".
func (p *parser) parseValueList() ([]*ast.Value, error) {
	if p.cur.Kind != lexer.TokLBracket {
		return nil, p.errorf(p.cur.Pos, "expected '[' for value list, got %s", p.cur.Kind)
	}
	// Consume "[" (it is the current token) and read the following
	// characters in value mode. A plain expect() would trigger a
	// structural prefetch that would misparse "10.0.0.1" as TokInt(10)
	// followed by a stray ".0.0.1".
	if err := p.advanceValue(); err != nil {
		return nil, err
	}
	if p.cur.Kind != lexer.TokValue {
		return nil, p.errorf(p.cur.Pos, "expected value inside [ ], got %s", p.cur.Kind)
	}
	values := []*ast.Value{p.cur.Value}
	if err := p.advance(); err != nil {
		return nil, err
	}
	for p.cur.Kind == lexer.TokComma {
		if err := p.advanceValue(); err != nil {
			return nil, err
		}
		if p.cur.Kind != lexer.TokValue {
			return nil, p.errorf(p.cur.Pos, "expected value after ',', got %s", p.cur.Kind)
		}
		values = append(values, p.cur.Value)
		if err := p.advance(); err != nil {
			return nil, err
		}
	}
	if _, err := p.expect(lexer.TokRBracket); err != nil {
		return nil, err
	}
	return values, nil
}
