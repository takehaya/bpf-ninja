package parser

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/lexer"
)

// parseWhereClause handles the "where <or_expr>" portion of a filter.
// The caller must ensure p.cur.Kind == TokWhere before invoking.
//   where_clause := "where" or_expr
func (p *parser) parseWhereClause() (*ast.WhereExpr, error) {
	if _, err := p.expect(lexer.TokWhere); err != nil {
		return nil, err
	}
	return p.parseOrExpr()
}

// or_expr := and_expr ("or" and_expr)*
func (p *parser) parseOrExpr() (*ast.WhereExpr, error) {
	left, err := p.parseAndExpr()
	if err != nil {
		return nil, err
	}
	for p.cur.Kind == lexer.TokOr {
		pos := p.cur.Pos
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseAndExpr()
		if err != nil {
			return nil, err
		}
		left = &ast.WhereExpr{Kind: ast.WOr, Left: left, Right: right, Pos: pos}
	}
	return left, nil
}

// and_expr := not_expr ("and" not_expr)*
func (p *parser) parseAndExpr() (*ast.WhereExpr, error) {
	left, err := p.parseNotExpr()
	if err != nil {
		return nil, err
	}
	for p.cur.Kind == lexer.TokAnd {
		pos := p.cur.Pos
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseNotExpr()
		if err != nil {
			return nil, err
		}
		left = &ast.WhereExpr{Kind: ast.WAnd, Left: left, Right: right, Pos: pos}
	}
	return left, nil
}

// not_expr := "not" not_expr | atom
func (p *parser) parseNotExpr() (*ast.WhereExpr, error) {
	if p.cur.Kind == lexer.TokNot {
		pos := p.cur.Pos
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseNotExpr()
		if err != nil {
			return nil, err
		}
		return &ast.WhereExpr{Kind: ast.WNot, Inner: inner, Pos: pos}, nil
	}
	return p.parseWhereAtom()
}

// atom := "(" or_expr ")" | action_atom | flow_atom | quant_atom | arith_cmp
//
// quant_atom is `any( inner )` or `all( inner )` where inner is a
// where expression that references an aux header stack (e.g.
// `srv6.segments.addr == fc00::1`). The resolver locates the
// iteration target inside the inner expression and codegen emits a
// bpf_loop wrapper.
func (p *parser) parseWhereAtom() (*ast.WhereExpr, error) {
	startPos := p.cur.Pos
	switch p.cur.Kind {
	case lexer.TokLParen:
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseOrExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(lexer.TokRParen); err != nil {
			return nil, err
		}
		return inner, nil
	case lexer.TokAction:
		return p.parseActionAtom(startPos)
	case lexer.TokFlow:
		return p.parseFlowAtom(startPos)
	case lexer.TokAny:
		return p.parseQuantAtom(startPos, ast.WAny)
	case lexer.TokAll:
		return p.parseQuantAtom(startPos, ast.WAll)
	}
	return p.parseArithCmp(startPos)
}

// quant_atom := ("any"|"all") "(" or_expr ")"
func (p *parser) parseQuantAtom(startPos ast.Position, kind ast.WhereKind) (*ast.WhereExpr, error) {
	if err := p.advance(); err != nil { // consume 'any' / 'all'
		return nil, err
	}
	if _, err := p.expect(lexer.TokLParen); err != nil {
		return nil, err
	}
	inner, err := p.parseOrExpr()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(lexer.TokRParen); err != nil {
		return nil, err
	}
	return &ast.WhereExpr{Kind: kind, Inner: inner, Pos: startPos}, nil
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

// flow_atom := "flow" "." IDENT  (IDENT must be is_new | age | state)
// MVP codegen does not implement flow state; parsed atoms are marked
// Unsupported so later stages can produce a uniform error.
func (p *parser) parseFlowAtom(startPos ast.Position) (*ast.WhereExpr, error) {
	if _, err := p.expect(lexer.TokFlow); err != nil {
		return nil, err
	}
	if p.cur.Kind != lexer.TokDot {
		return nil, p.errorf(p.cur.Pos, "expected '.' after 'flow', got %s", p.cur.Kind)
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	ident, err := p.expect(lexer.TokIdent)
	if err != nil {
		return nil, err
	}
	switch ident.Text {
	case "is_new", "age", "state":
		// ok
	default:
		return nil, p.errorf(ident.Pos, "unknown flow property %q (expected is_new, age, or state)", ident.Text)
	}
	return &ast.WhereExpr{
		Kind:        ast.WAtomFlow,
		FlowKind:    ident.Text,
		Unsupported: true,
		Pos:         startPos,
	}, nil
}

// arith_cmp := arith_expr cmp_op (arith_expr | network_literal)
//
// network_literal short-circuits the arith RHS for `field == ipv4`,
// `field != mac`, etc. — RHS is consumed in lexer value mode and
// classified into IPv4 / IPv6 / MAC / CIDR. Triggered only when the
// LHS is a single field path (no arith) and the op is == / !=, so
// `tcp.dport == 443` and `total_length > 100` continue to parse as
// integer arith.
func (p *parser) parseArithCmp(startPos ast.Position) (*ast.WhereExpr, error) {
	left, err := p.parseArithExpr()
	if err != nil {
		return nil, err
	}
	op, ok := cmpOpFor(p.cur.Kind)
	if !ok {
		return nil, p.errorf(p.cur.Pos, "expected comparison operator in where expression, got %s", p.cur.Kind)
	}
	// Snapshot the lexer position right after the op — at this point
	// p.cur is still the op token but the lexer's internal cursor is
	// already past it. Saving here lets us roll back to "just past
	// the op" and re-scan in value mode if the structural advance
	// turns out to be a network literal.
	postOpSnap := p.lex.Save()
	if err := p.advance(); err != nil {
		return nil, err
	}

	if (op == ast.CmpEq || op == ast.CmpNeq) && isFieldPath(left) {
		lit, ok, err := p.tryNetworkLiteral(postOpSnap)
		if err != nil {
			return nil, err
		}
		if ok {
			if _, chained := cmpOpFor(p.cur.Kind); chained {
				return nil, p.errorf(p.cur.Pos, "chained comparison not supported; use 'and' to combine")
			}
			return &ast.WhereExpr{
				Kind:         ast.WAtomLiteralCmp,
				LiteralField: left.Field,
				LiteralOp:    op,
				LiteralValue: lit,
				Pos:          startPos,
			}, nil
		}
	}

	right, err := p.parseArithExpr()
	if err != nil {
		return nil, err
	}
	// Chained comparison rejection.
	if _, chained := cmpOpFor(p.cur.Kind); chained {
		return nil, p.errorf(p.cur.Pos, "chained comparison not supported; use 'and' to combine")
	}
	return &ast.WhereExpr{
		Kind:   ast.WAtomArith,
		ArithL: left,
		Op:     op,
		ArithR: right,
		Pos:    startPos,
	}, nil
}

// isFieldPath reports whether the arith expression is a single field
// reference (no arithmetic operators). Used to gate the network-
// literal short-circuit: `tcp.dport == 443` allows fallback to arith,
// but `tcp.dport + 1 == 444` does not (the LHS is an arith tree).
func isFieldPath(a *ast.ArithExpr) bool {
	return a != nil && a.Kind == ast.ArithField
}

// tryNetworkLiteral re-reads the RHS in value mode from the post-op
// snapshot. On match, the lexer / p.cur are both advanced past the
// literal so the caller can continue parsing whatever comes after.
// On miss (RHS is integer arith / not a network literal), both the
// lexer and p.cur are restored to their post-`advance()` state so
// the caller can fall through to `parseArithExpr` cleanly.
func (p *parser) tryNetworkLiteral(snap lexer.Snapshot) (*ast.Value, bool, error) {
	savedCur := p.cur
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
		_ = savedCur // savedCur and `next` should match modulo identity
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

// arith_expr := arith_term (("+"|"-") arith_term)*
func (p *parser) parseArithExpr() (*ast.ArithExpr, error) {
	left, err := p.parseArithTerm()
	if err != nil {
		return nil, err
	}
	for p.cur.Kind == lexer.TokPlus || p.cur.Kind == lexer.TokMinus {
		op := ast.ArithAdd
		if p.cur.Kind == lexer.TokMinus {
			op = ast.ArithSub
		}
		pos := p.cur.Pos
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseArithTerm()
		if err != nil {
			return nil, err
		}
		left = &ast.ArithExpr{Kind: ast.ArithBinOp, Op: op, Left: left, Right: right, Pos: pos}
	}
	return left, nil
}

// arith_term := arith_fac (("*"|"/"|"%") arith_fac)*
func (p *parser) parseArithTerm() (*ast.ArithExpr, error) {
	left, err := p.parseArithFac()
	if err != nil {
		return nil, err
	}
	for {
		var op ast.ArithOp
		switch p.cur.Kind {
		case lexer.TokStar:
			op = ast.ArithMul
		case lexer.TokSlash:
			op = ast.ArithDiv
		case lexer.TokPercent:
			op = ast.ArithMod
		default:
			return left, nil
		}
		pos := p.cur.Pos
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseArithFac()
		if err != nil {
			return nil, err
		}
		left = &ast.ArithExpr{Kind: ast.ArithBinOp, Op: op, Left: left, Right: right, Pos: pos}
	}
}

// arith_fac := INT | field_path | "(" arith_expr ")"
func (p *parser) parseArithFac() (*ast.ArithExpr, error) {
	startPos := p.cur.Pos
	switch p.cur.Kind {
	case lexer.TokInt:
		v := p.cur.Int
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &ast.ArithExpr{Kind: ast.ArithConst, Const: v, Pos: startPos}, nil
	case lexer.TokIdent:
		field, err := p.parseFieldPath()
		if err != nil {
			return nil, err
		}
		return &ast.ArithExpr{Kind: ast.ArithField, Field: field, Pos: startPos}, nil
	case lexer.TokLParen:
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseArithExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(lexer.TokRParen); err != nil {
			return nil, err
		}
		return inner, nil
	}
	return nil, p.errorf(startPos, "expected integer, field path, or '(' in arithmetic expression, got %s", p.cur.Kind)
}
