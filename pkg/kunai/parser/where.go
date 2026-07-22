package parser

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/lexer"
)

// parseWhereClause handles the "where <or_expr>" portion of a filter.
// The caller must ensure p.cur.Kind == TokWhere before invoking.
//
//	where_clause := "where" or_expr
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

// atom := "(" or_expr ")" | bool_atom | action_atom | quant_atom | arith_cmp
//
// bool_atom covers bare 'true'/'false' literals and aux-exists; an
// Int<N> field path that ends without a comparison op is also a Bool
// atom (Int -> Bool coerce per dsl-types.md §5.4) and is recognised
// inside parseCmpOrBoolAtom by the absence of a trailing op.
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
		if p.parenDepth >= maxParenDepth {
			return nil, p.errorf(p.cur.Pos, "expression nesting too deep (limit: %d)", maxParenDepth)
		}
		p.parenDepth++
		if err := p.advance(); err != nil {
			p.parenDepth--
			return nil, err
		}
		inner, err := p.parseOrExpr()
		if err != nil {
			p.parenDepth--
			return nil, err
		}
		if _, err := p.expect(lexer.TokRParen); err != nil {
			p.parenDepth--
			return nil, err
		}
		p.parenDepth--
		return p.maybeBoolEqTail(startPos, inner)
	case lexer.TokAction:
		return p.parseActionAtom(startPos)
	case lexer.TokAny:
		left, err := p.parseQuantAtom(startPos, ast.WAny)
		if err != nil {
			return nil, err
		}
		return p.maybeBoolEqTail(startPos, left)
	case lexer.TokAll:
		left, err := p.parseQuantAtom(startPos, ast.WAll)
		if err != nil {
			return nil, err
		}
		return p.maybeBoolEqTail(startPos, left)
	case lexer.TokTrue, lexer.TokFalse:
		return p.parseBoolLitAtom(startPos)
	}
	return p.parseCmpOrBoolAtom(startPos)
}

// parseBoolLitAtom consumes a bare 'true' or 'false' bool literal and
// optionally the right-hand side of a `Bool == Bool` / `Bool != Bool`
// comparison.
func (p *parser) parseBoolLitAtom(startPos ast.Position) (*ast.WhereExpr, error) {
	val := p.cur.Kind == lexer.TokTrue
	if err := p.advance(); err != nil {
		return nil, err
	}
	lit := &ast.WhereExpr{Kind: ast.WAtomBoolLit, BoolLitValue: val, Pos: startPos}
	return p.maybeBoolEqTail(startPos, lit)
}

// maybeBoolEqTail wraps a freshly-built Bool atom in a WAtomBoolEq when
// the next token is `==` / `!=`. Other comparison operators on Bool
// values (ordered cmp) are rejected with a clear error so the user
// sees the spec violation early.
func (p *parser) maybeBoolEqTail(startPos ast.Position, left *ast.WhereExpr) (*ast.WhereExpr, error) {
	op, ok := cmpOpFor(p.cur.Kind)
	if !ok {
		return left, nil
	}
	if op != ast.CmpEq && op != ast.CmpNeq {
		return nil, p.errorf(p.cur.Pos, "ordered comparison %s not allowed for Bool (Bool supports only == and !=)", op)
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	right, err := p.parseWhereAtom()
	if err != nil {
		return nil, err
	}
	return &ast.WhereExpr{Kind: ast.WAtomBoolEq, BoolL: left, BoolR: right, BoolEqOp: op, Pos: startPos}, nil
}

// quant_atom := ("any"|"all") "(" or_expr ")"
func (p *parser) parseQuantAtom(startPos ast.Position, kind ast.WhereKind) (*ast.WhereExpr, error) {
	if err := p.advance(); err != nil { // consume 'any' / 'all'
		return nil, err
	}
	if p.cur.Kind != lexer.TokLParen {
		return nil, p.errorf(p.cur.Pos, "expected '(', got %s (%q)", p.cur.Kind, p.cur.Text)
	}
	if p.parenDepth >= maxParenDepth {
		return nil, p.errorf(p.cur.Pos, "expression nesting too deep (limit: %d)", maxParenDepth)
	}
	p.parenDepth++
	if _, err := p.expect(lexer.TokLParen); err != nil {
		p.parenDepth--
		return nil, err
	}
	inner, err := p.parseOrExpr()
	if err != nil {
		p.parenDepth--
		return nil, err
	}
	if _, err := p.expect(lexer.TokRParen); err != nil {
		p.parenDepth--
		return nil, err
	}
	p.parenDepth--
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

// cmp_or_bool_atom := (network_literal cmp_op arith_expr)
//
//	| arith_expr (cmp_op (arith_expr | network_literal))?
//
// dsl-types.md §6.2 makes comparisons fully symmetric in their
// operands, so we first try to read the LHS in lexer value mode: if
// it classifies as a network literal AND is followed by `==` / `!=`,
// we commit to the literal-LHS form. Otherwise the lexer is rolled
// back and we fall through to the legacy arith path, which already
// handles the field-LHS / literal-RHS shape.
//
// When NOT followed by a comparison operator, the LHS is treated as a
// bare Bool atom: a field path ending in `.exists` becomes
// WAtomBoolExists, any other Int<N>-typed field becomes a Bool decay
// (WAtomArith with `field != 0`) so the resolver can apply the §5.4
// coercion.
func (p *parser) parseCmpOrBoolAtom(startPos ast.Position) (*ast.WhereExpr, error) {
	if lit, op, ok, err := p.tryLeadingNetworkLiteralCmp(); err != nil {
		return nil, err
	} else if ok {
		right, err := p.parseArithExpr()
		if err != nil {
			return nil, err
		}
		if !isFieldPath(right) {
			return nil, p.errorf(startPos, "right-hand side of literal-on-left comparison must be a single field path; got an arithmetic expression")
		}
		if _, chained := cmpOpFor(p.cur.Kind); chained {
			return nil, p.errorf(p.cur.Pos, "chained comparison not supported; use 'and' to combine")
		}
		return &ast.WhereExpr{
			Kind:         ast.WAtomLiteralCmp,
			LiteralField: right.Field,
			LiteralOp:    op,
			LiteralValue: lit,
			Pos:          startPos,
		}, nil
	}
	left, err := p.parseArithExpr()
	if err != nil {
		return nil, err
	}
	if p.cur.Kind == lexer.TokIn {
		// `in` is a bracket-predicate operator only. Surfacing the
		// usual "expected ')'" from the enclosing scope hides what
		// the user got wrong; nudge them at the source position.
		return nil, p.errorf(p.cur.Pos, "'in' is only valid in bracket predicates (`proto[field in [...]]`); inside `where` use a chain of `or` (`field == v1 or field == v2`) instead")
	}
	op, ok := cmpOpFor(p.cur.Kind)
	if !ok {
		// No comparison operator: treat as bare Bool atom.
		atom, err := p.bareBoolAtomFromArith(startPos, left)
		if err != nil {
			return nil, err
		}
		return p.maybeBoolEqTail(startPos, atom)
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

// bareBoolAtomFromArith converts an arith expression that appears in
// where-atom position without a trailing comparison operator into the
// matching Bool atom kind. Field paths ending in `.exists` become
// WAtomBoolExists; any other Int<N> field decays to a Bool by being
// wrapped in `arith != 0` (the resolver materialises the coercion).
// Numeric literals appearing bare are rejected as ambiguous.
func (p *parser) bareBoolAtomFromArith(startPos ast.Position, e *ast.ArithExpr) (*ast.WhereExpr, error) {
	if e == nil {
		return nil, p.errorf(startPos, "internal: nil arith expression in where atom")
	}
	if e.Kind == ast.ArithField && e.Field != nil && fieldPathEndsWithExists(e.Field) {
		stripped := stripExistsTail(e.Field)
		return &ast.WhereExpr{Kind: ast.WAtomBoolExists, BoolField: stripped, Pos: startPos}, nil
	}
	// Bool decay path: rewrite as `<expr> != 0` so existing arith codegen
	// handles the non-zero check.
	zero := &ast.ArithExpr{Kind: ast.ArithConst, Const: 0, Pos: startPos}
	return &ast.WhereExpr{
		Kind:   ast.WAtomArith,
		ArithL: e,
		Op:     ast.CmpNeq,
		ArithR: zero,
		Pos:    startPos,
	}, nil
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

// isFieldPath reports whether the arith expression is a single field
// reference (no arithmetic operators). Used to gate the network-
// literal short-circuit: `tcp.dport == 443` allows fallback to arith,
// but `tcp.dport + 1 == 444` does not (the LHS is an arith tree).
func isFieldPath(a *ast.ArithExpr) bool {
	return a != nil && a.Kind == ast.ArithField
}

// tryLeadingNetworkLiteralCmp probes the start of a where atom for a
// `<network-literal> ⨀ ...` shape. It rewinds the lexer to just before
// p.cur, re-reads the same byte run in value mode, and accepts only
// when the value classifies as a network literal AND is followed by
// `==` / `!=` (D5: ordered cmp on network literals is reject). On
// commit, p.cur lands on the first token of the RHS expression.
//
// On miss the lexer is restored to its entry state (lex position
// past p.cur, p.cur unchanged) so the caller can run the legacy arith
// path without observing any side effects.
func (p *parser) tryLeadingNetworkLiteralCmp() (*ast.Value, ast.CmpOp, bool, error) {
	preSnap := p.preCurSnap
	savedCur := p.cur

	bail := func() (*ast.Value, ast.CmpOp, bool, error) {
		// Replay the structural Next() so the lexer ends up exactly
		// where it was on entry; restore p.cur so the caller can run
		// the legacy arith path without observing any side effects.
		p.lex.Restore(preSnap)
		if _, rerr := p.lex.Next(); rerr != nil {
			return nil, 0, false, rerr
		}
		p.cur = savedCur
		return nil, 0, false, nil
	}

	p.lex.Restore(preSnap)
	tok, err := p.lex.NextValue()
	if err != nil || tok.Kind != lexer.TokValue || !isNetworkLiteralKind(tok.Value.Kind) {
		return bail()
	}

	opTok, err := p.lex.Next()
	if err != nil {
		return nil, 0, false, err
	}
	op, ok := cmpOpFor(opTok.Kind)
	if !ok || (op != ast.CmpEq && op != ast.CmpNeq) {
		// Network literals support only ==/!= per dsl-types.md §6.2.
		return bail()
	}

	if err := p.advance(); err != nil {
		return nil, 0, false, err
	}
	return tok.Value, op, true, nil
}

// tryNetworkLiteral re-reads the RHS in value mode from the post-op
// snapshot. On match, the lexer / p.cur are both advanced past the
// literal so the caller can continue parsing whatever comes after.
// On miss (RHS is integer arith / not a network literal), both the
// lexer and p.cur are restored to their post-`advance()` state so
// the caller can fall through to `parseArithExpr` cleanly.
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

// arith_expr := arith_term (("+"|"-"|"|"|"^") arith_term)*
//
// `|` and `^` (bitwise OR / XOR) join `+` / `-` at the same
// precedence — they're additive in the lattice sense and treating
// them at this level mirrors the way users write masked equality
// (`(flags >> 4) & 0x0f | extra_bit == val`).
func (p *parser) parseArithExpr() (*ast.ArithExpr, error) {
	left, err := p.parseArithTerm()
	if err != nil {
		return nil, err
	}
	for {
		var op ast.ArithOp
		switch p.cur.Kind {
		case lexer.TokPlus:
			op = ast.ArithAdd
		case lexer.TokMinus:
			op = ast.ArithSub
		case lexer.TokPipe:
			op = ast.ArithOr
		case lexer.TokCaret:
			op = ast.ArithXor
		default:
			return left, nil
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
}

// arith_term := arith_fac (("*"|"/"|"%"|"&"|"<<"|">>") arith_fac)*
//
// Bitwise `&` and the shifts `<<` / `>>` sit at the same
// precedence as `*` / `/` / `%`. This is a deliberate
// simplification of C: it keeps the natural flag idiom
// `tcp.flags & 0x12 == 0x12` parens-free, and shift-with-mask
// patterns like `flags >> 4 & 1` reading left-to-right at one
// precedence. `|` / `^` live one level up (arith_expr) since they
// behave more like additive on the truth-value side.
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
		case lexer.TokAmp:
			op = ast.ArithAnd
		case lexer.TokShl:
			op = ast.ArithShl
		case lexer.TokShr:
			op = ast.ArithShr
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

// arith_fac := "-"? INT | field_path | "(" arith_expr ")"
//
// Unary minus is permitted only directly in front of an integer
// literal. The negated value is stored as its 2's-complement uint64
// (Const = ^v + 1) so the resolver's typing pass can narrow it to
// any target Int<N> per dsl-types.md §4.1.
func (p *parser) parseArithFac() (*ast.ArithExpr, error) {
	startPos := p.cur.Pos
	if p.cur.Kind == lexer.TokMinus {
		// Look ahead: only an integer literal may follow a unary minus.
		// The structural lexer doesn't peek across positions, so we
		// just advance and require TokInt next.
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.cur.Kind != lexer.TokInt {
			return nil, p.errorf(p.cur.Pos, "expected integer literal after unary '-', got %s", p.cur.Kind)
		}
		v := p.cur.Int
		if err := p.advance(); err != nil {
			return nil, err
		}
		// 2's-complement negation: -v = ^v + 1 (mod 2^64). Reject
		// values that overflow signed int64 since they cannot have
		// originated from a literal in [-2^63, 0).
		if v > uint64(1)<<63 {
			return nil, p.errorf(startPos, "negative literal -%d exceeds the supported range [-2^63, 0)", v)
		}
		neg := ^v + 1
		return &ast.ArithExpr{Kind: ast.ArithConst, Const: neg, Pos: startPos}, nil
	}
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
		if p.parenDepth >= maxParenDepth {
			return nil, p.errorf(p.cur.Pos, "expression nesting too deep (limit: %d)", maxParenDepth)
		}
		p.parenDepth++
		if err := p.advance(); err != nil {
			p.parenDepth--
			return nil, err
		}
		inner, err := p.parseArithExpr()
		if err != nil {
			p.parenDepth--
			return nil, err
		}
		if _, err := p.expect(lexer.TokRParen); err != nil {
			p.parenDepth--
			return nil, err
		}
		p.parenDepth--
		return inner, nil
	}
	return nil, p.errorf(startPos, "expected integer, field path, or '(' in arithmetic expression, got %s", p.cur.Kind)
}
