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
// parseFieldPath's loop body. Bracketed indices `[N]` or
// `[<proto>.<field>]` after any segment are captured into Indices
// (parallel to Parts); empty/missing indices stay nil so the common
// non-indexed case is unchanged.
func (p *parser) parseFieldPathFromHead(head lexer.Token) (*ast.FieldPath, error) {
	parts := []string{head.Text}
	var indices []*ast.IndexExpr
	if idx, err := p.tryParseIndexExpr(); err != nil {
		return nil, err
	} else if idx != nil {
		indices = ensureIndexLen(indices, 1)
		indices[0] = idx
	}
	for p.cur.Kind == lexer.TokDot {
		if err := p.advance(); err != nil {
			return nil, err
		}
		next, err := p.expect(lexer.TokIdent)
		if err != nil {
			return nil, err
		}
		parts = append(parts, next.Text)
		idx, err := p.tryParseIndexExpr()
		if err != nil {
			return nil, err
		}
		if idx != nil {
			indices = ensureIndexLen(indices, len(parts))
			indices[len(parts)-1] = idx
		}
	}
	return &ast.FieldPath{Parts: parts, Indices: indices, Pos: head.Pos}, nil
}

// tryParseIndexExpr peeks for a `[...]` index following the most
// recently parsed identifier. Returns (nil, nil) when the next token
// is anything other than `[`. The index body is either an int
// literal or a (possibly nested) field path.
func (p *parser) tryParseIndexExpr() (*ast.IndexExpr, error) {
	if p.cur.Kind != lexer.TokLBracket {
		return nil, nil
	}
	openPos := p.cur.Pos
	if err := p.advance(); err != nil {
		return nil, err
	}
	switch p.cur.Kind {
	case lexer.TokInt:
		v := p.cur.Int
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.cur.Kind == lexer.TokColon {
			// Bit-slice `[lo:hi]`: half-open range, lo inclusive /
			// hi exclusive. Bit 0 is the network-order MSB, matching
			// the IETF convention users expect when reading e.g.
			// `ipv6.src[0:32]` as "the first 32 bits".
			if err := p.advance(); err != nil {
				return nil, err
			}
			if p.cur.Kind != lexer.TokInt {
				return nil, p.errorf(p.cur.Pos, "expected slice end after ':' in `[lo:hi]`, got %s", p.cur.Kind)
			}
			hi := p.cur.Int
			if err := p.advance(); err != nil {
				return nil, err
			}
			if _, err := p.expect(lexer.TokRBracket); err != nil {
				return nil, err
			}
			if hi <= v {
				return nil, p.errorf(openPos, "bit-slice [%d:%d] requires lo < hi", v, hi)
			}
			return &ast.IndexExpr{IsSlice: true, SliceLo: v, SliceHi: hi, Pos: openPos}, nil
		}
		if _, err := p.expect(lexer.TokRBracket); err != nil {
			return nil, err
		}
		return &ast.IndexExpr{Int: v, IsInt: true, Pos: openPos}, nil
	case lexer.TokIdent:
		head, err := p.expect(lexer.TokIdent)
		if err != nil {
			return nil, err
		}
		// Inside the index brackets the field path may not carry
		// further nested indices: that would invite ambiguity with
		// the surrounding bracket. Reuse the dotted-path parse and
		// then guard against nested indices.
		fp, err := p.parseFieldPathFromHead(head)
		if err != nil {
			return nil, err
		}
		if hasAnyIndex(fp) {
			return nil, p.errorf(openPos, "nested index inside index expression %q is not supported", fp.String())
		}
		if _, err := p.expect(lexer.TokRBracket); err != nil {
			return nil, err
		}
		return &ast.IndexExpr{Field: fp, Pos: openPos}, nil
	default:
		return nil, p.errorf(p.cur.Pos, "expected integer or field reference inside `[...]`, got %s", p.cur.Kind)
	}
}

func ensureIndexLen(indices []*ast.IndexExpr, n int) []*ast.IndexExpr {
	for len(indices) < n {
		indices = append(indices, nil)
	}
	return indices
}

func hasAnyIndex(fp *ast.FieldPath) bool {
	if fp == nil {
		return false
	}
	for _, idx := range fp.Indices {
		if idx != nil {
			return true
		}
	}
	return false
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
