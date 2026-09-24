package parser

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/lexer"
)

// whereValue retains the operand type while parsing. In particular, grouping
// an integer is not a Boolean context. Only logical operators, Boolean equality
// and the completed where clause request an Int-to-Bool conversion.
// The public AST remains unchanged: these temporary values are lowered to its
// existing arithmetic, literal-comparison and Boolean nodes.
type whereValue struct {
	arith   *ast.ArithExpr
	boolean *ast.WhereExpr
	literal *ast.Value
	pos     ast.Position
}

const (
	precOr  = 1
	precAnd = 2
	precNot = 3
	precCmp = 4
	precAdd = 5
	precMul = 6
)

func (p *parser) parseWhereClause() (*ast.WhereExpr, error) {
	if _, err := p.expect(lexer.TokWhere); err != nil {
		return nil, err
	}
	return p.parseOrExpr()
}

func (p *parser) parseOrExpr() (*ast.WhereExpr, error) {
	value, err := p.parseWhereExpr(precOr)
	if err != nil {
		return nil, err
	}
	return p.whereBool(value)
}

func (p *parser) whereBool(v whereValue) (*ast.WhereExpr, error) {
	if v.boolean != nil {
		return v.boolean, nil
	}
	if v.arith == nil {
		return nil, p.errorf(v.pos, "network literal requires a field comparison")
	}
	return &ast.WhereExpr{Kind: ast.WAtomArith, ArithL: v.arith, Op: ast.CmpNeq,
		ArithR: &ast.ArithExpr{Kind: ast.ArithConst, Pos: v.pos}, Pos: v.pos}, nil
}

func wherePrecedence(k lexer.TokenKind) int {
	switch k {
	case lexer.TokOr:
		return precOr
	case lexer.TokAnd:
		return precAnd
	case lexer.TokEqEq, lexer.TokNeq, lexer.TokLt, lexer.TokLe, lexer.TokGt, lexer.TokGe:
		return precCmp
	case lexer.TokPlus, lexer.TokMinus, lexer.TokPipe, lexer.TokCaret:
		return precAdd
	case lexer.TokStar, lexer.TokSlash, lexer.TokPercent, lexer.TokAmp, lexer.TokShl, lexer.TokShr:
		return precMul
	}
	return 0
}

// parseWhereExpr uses the DSL's existing precedence: bitwise |/^ are additive,
// and &/shifts are multiplicative. Integer comparisons cannot be chained;
// Boolean equality retains its right-associative Boolean-atom RHS.
func (p *parser) parseWhereExpr(minPrec int) (whereValue, error) {
	if p.exprDepth >= maxParenDepth*4 {
		return whereValue{}, p.errorf(p.cur.Pos, "expression nesting too deep")
	}
	p.exprDepth++
	defer func() { p.exprDepth-- }()
	left, err := p.parseWherePrimary()
	if err != nil {
		return whereValue{}, err
	}
	for {
		if p.cur.Kind == lexer.TokIn {
			return whereValue{}, p.errorf(p.cur.Pos, "'in' is only valid in bracket predicates (`proto[field in [...]]`); inside `where` use a chain of `or` (`field == v1 or field == v2`) instead")
		}
		token := p.cur
		prec := wherePrecedence(token.Kind)
		if prec < minPrec {
			return left, nil
		}
		nextPrec := prec + 1
		boolComparison := prec == precCmp && left.boolean != nil
		if boolComparison {
			nextPrec = prec
		}
		if err := p.advance(); err != nil {
			return whereValue{}, err
		}
		right, err := p.parseWhereExpr(nextPrec)
		if err != nil {
			return whereValue{}, err
		}
		left, err = p.combineWhere(left, token, right)
		if err != nil {
			return whereValue{}, err
		}
		if prec == precCmp && !boolComparison {
			if _, chained := cmpOpFor(p.cur.Kind); chained {
				return whereValue{}, p.errorf(p.cur.Pos, "chained comparison not supported; use 'and' to combine")
			}
		}
	}
}

func (p *parser) combineWhere(left whereValue, token lexer.Token, right whereValue) (whereValue, error) {
	result := whereValue{pos: left.pos}
	if token.Kind == lexer.TokAnd || token.Kind == lexer.TokOr {
		l, err := p.whereBool(left)
		if err != nil {
			return result, err
		}
		r, err := p.whereBool(right)
		if err != nil {
			return result, err
		}
		kind := ast.WAnd
		if token.Kind == lexer.TokOr {
			kind = ast.WOr
		}
		result.boolean = &ast.WhereExpr{Kind: kind, Left: l, Right: r, Pos: token.Pos}
		return result, nil
	}
	if op, ok := cmpOpFor(token.Kind); ok {
		if left.literal != nil || right.literal != nil {
			if op != ast.CmpEq && op != ast.CmpNeq {
				return result, p.errorf(token.Pos, "ordered comparison %s not allowed for network literals", op)
			}
			field, lit := left.arith, right.literal
			side := "left"
			if left.literal != nil {
				field, lit, side = right.arith, left.literal, "right"
			}
			if field == nil || field.Kind != ast.ArithField {
				return result, p.errorf(token.Pos, "%s-hand side of network-literal comparison must be a single field path; got an arithmetic expression", side)
			}
			result.boolean = &ast.WhereExpr{Kind: ast.WAtomLiteralCmp, LiteralField: field.Field, LiteralOp: op, LiteralValue: lit, Pos: left.pos}
			return result, nil
		}
		if left.boolean != nil || right.boolean != nil {
			if op != ast.CmpEq && op != ast.CmpNeq {
				return result, p.errorf(token.Pos, "ordered comparison %s not allowed for Bool (Bool supports only == and !=)", op)
			}
			l, err := p.whereBool(left)
			if err != nil {
				return result, err
			}
			r, err := p.whereBool(right)
			if err != nil {
				return result, err
			}
			result.boolean = &ast.WhereExpr{Kind: ast.WAtomBoolEq, BoolL: l, BoolR: r, BoolEqOp: op, Pos: left.pos}
		} else {
			result.boolean = &ast.WhereExpr{Kind: ast.WAtomArith, ArithL: left.arith, Op: op, ArithR: right.arith, Pos: left.pos}
		}
		return result, nil
	}
	if left.arith == nil || right.arith == nil {
		return result, p.errorf(token.Pos, "arithmetic operator %s requires integer operands", token.Kind)
	}
	var op ast.ArithOp
	switch token.Kind {
	case lexer.TokPlus:
		op = ast.ArithAdd
	case lexer.TokMinus:
		op = ast.ArithSub
	case lexer.TokPipe:
		op = ast.ArithOr
	case lexer.TokCaret:
		op = ast.ArithXor
	case lexer.TokStar:
		op = ast.ArithMul
	case lexer.TokSlash:
		op = ast.ArithDiv
	case lexer.TokPercent:
		op = ast.ArithMod
	case lexer.TokAmp:
		op = ast.ArithAnd
	case lexer.TokShl:
		op = ast.ArithShl
	case lexer.TokShr:
		op = ast.ArithShr
	}
	result.arith = &ast.ArithExpr{Kind: ast.ArithBinOp, Op: op, Left: left.arith, Right: right.arith, Pos: token.Pos}
	return result, nil
}

func (p *parser) parseWherePrimary() (whereValue, error) {
	pos := p.cur.Pos
	v := whereValue{pos: pos}
	switch p.cur.Kind {
	case lexer.TokLParen:
		return p.parseWhereGroup()
	case lexer.TokNot:
		if err := p.advance(); err != nil {
			return v, err
		}
		inner, err := p.parseWhereExpr(precNot)
		if err != nil {
			return v, err
		}
		b, err := p.whereBool(inner)
		if err != nil {
			return v, err
		}
		v.boolean = &ast.WhereExpr{Kind: ast.WNot, Inner: b, Pos: pos}
		return v, nil
	case lexer.TokTrue, lexer.TokFalse:
		v.boolean = &ast.WhereExpr{Kind: ast.WAtomBoolLit, BoolLitValue: p.cur.Kind == lexer.TokTrue, Pos: pos}
		return v, p.advance()
	case lexer.TokAction:
		var err error
		v.boolean, err = p.parseActionAtom(pos)
		return v, err
	case lexer.TokAny, lexer.TokAll:
		kind := ast.WAny
		if p.cur.Kind == lexer.TokAll {
			kind = ast.WAll
		}
		if err := p.advance(); err != nil {
			return v, err
		}
		if p.cur.Kind != lexer.TokLParen {
			return v, p.errorf(p.cur.Pos, "expected '(', got %s (%q)", p.cur.Kind, p.cur.Text)
		}
		inner, err := p.parseWhereGroup()
		if err != nil {
			return v, err
		}
		b, err := p.whereBool(inner)
		if err != nil {
			return v, err
		}
		v.boolean = &ast.WhereExpr{Kind: kind, Inner: b, Pos: pos}
		return v, nil
	case lexer.TokMinus:
		if err := p.advance(); err != nil {
			return v, err
		}
		if p.cur.Kind != lexer.TokInt {
			return v, p.errorf(p.cur.Pos, "expected integer literal after unary '-', got %s", p.cur.Kind)
		}
		n := p.cur.Int
		if n > uint64(1)<<63 {
			return v, p.errorf(pos, "negative literal -%d exceeds the supported range [-2^63, 0)", n)
		}
		v.arith = &ast.ArithExpr{Kind: ast.ArithConst, Const: ^n + 1, Pos: pos}
		return v, p.advance()
	}
	// Network literals share initial structural tokens with fields and integers.
	// Re-read just this primary in value mode, restoring it on a miss.
	if lit, ok, err := p.tryNetworkLiteral(p.preCurSnap); err != nil {
		return v, err
	} else if ok {
		v.literal = lit
		return v, nil
	}
	switch p.cur.Kind {
	case lexer.TokInt:
		v.arith = &ast.ArithExpr{Kind: ast.ArithConst, Const: p.cur.Int, Pos: pos}
		return v, p.advance()
	case lexer.TokIdent:
		field, err := p.parseFieldPath()
		if err != nil {
			return v, err
		}
		if fieldPathEndsWithExists(field) {
			v.boolean = &ast.WhereExpr{Kind: ast.WAtomBoolExists, BoolField: stripExistsTail(field), Pos: pos}
		} else {
			v.arith = &ast.ArithExpr{Kind: ast.ArithField, Field: field, Pos: pos}
		}
		return v, nil
	}
	return v, p.errorf(pos, "expected integer, field path, Boolean or '(' in expression, got %s", p.cur.Kind)
}

func (p *parser) parseWhereGroup() (whereValue, error) {
	if p.parenDepth >= maxParenDepth {
		return whereValue{}, p.errorf(p.cur.Pos, "expression nesting too deep (limit: %d)", maxParenDepth)
	}
	p.parenDepth++
	defer func() { p.parenDepth-- }()
	if _, err := p.expect(lexer.TokLParen); err != nil {
		return whereValue{}, err
	}
	inner, err := p.parseWhereExpr(precOr)
	if err != nil {
		return whereValue{}, err
	}
	if _, err := p.expect(lexer.TokRParen); err != nil {
		return whereValue{}, err
	}
	return inner, nil
}

// action_atom := "action" "==" IDENT
func (p *parser) parseActionAtom(startPos ast.Position) (*ast.WhereExpr, error) {
	if _, err := p.expect(lexer.TokAction); err != nil {
		return nil, err
	}
	if p.cur.Kind != lexer.TokEqEq {
		return nil, p.errorf(p.cur.Pos, "expected '==' after 'action', got %s", p.cur.Kind)
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	ident, err := p.expect(lexer.TokIdent)
	if err != nil {
		return nil, err
	}
	return &ast.WhereExpr{Kind: ast.WAtomAction, ActionValue: ident.Text, Pos: startPos}, nil
}

func fieldPathEndsWithExists(fp *ast.FieldPath) bool {
	if fp == nil || len(fp.Parts) == 0 {
		return false
	}
	return fp.Parts[len(fp.Parts)-1] == "exists"
}

// stripExistsTail returns a new FieldPath with the trailing `.exists`
// segment (and any associated index) removed.
func stripExistsTail(fp *ast.FieldPath) *ast.FieldPath {
	n := len(fp.Parts) - 1
	out := &ast.FieldPath{Parts: append([]string(nil), fp.Parts[:n]...), Pos: fp.Pos}
	if len(fp.Indices) > 0 {
		// Preserve any indices that still apply. The trailing `exists`
		// would not carry an index, but its slot might exist when the
		// indices slice was previously expanded; trim accordingly.
		idxLen := min(len(fp.Indices), n)
		out.Indices = append([]*ast.IndexExpr(nil), fp.Indices[:idxLen]...)
	}
	return out
}

// tryNetworkLiteral re-reads a primary in value mode and restores structural
// lexer state on a miss. On success it advances past the complete literal.
func (p *parser) tryNetworkLiteral(snap lexer.Snapshot) (*ast.Value, bool, error) {
	p.lex.Restore(snap)
	tok, err := p.lex.NextValue()
	if err != nil || tok.Kind != lexer.TokValue || !isNetworkLiteralKind(tok.Value.Kind) {
		// Roll back and re-sync p.cur to the structural advance the
		// caller already took.
		p.lex.Restore(snap)
		next, err2 := p.lex.Next()
		if err2 != nil {
			return nil, false, err2
		}
		p.cur = next
		return nil, false, nil
	}
	// Literal accepted — advance into the next structural token so
	// the caller sees it as p.cur.
	if err := p.advance(); err != nil {
		return nil, false, err
	}
	return tok.Value, true, nil
}

func isNetworkLiteralKind(k ast.ValueKind) bool {
	return k == ast.ValIPv4 || k == ast.ValIPv6 || k == ast.ValMAC || k == ast.ValCIDR
}
