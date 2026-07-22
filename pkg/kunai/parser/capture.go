package parser

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/lexer"
)

// parseCaptureClause handles "capture <spec> (where <expr>)?". The
// where-clause portion is implemented in an upcoming commit; until
// then we reject it with a clear message so users know it is coming.
//
//	capture_clause := "capture" capture_spec where_clause?
func (p *parser) parseCaptureClause() (*ast.CaptureClause, error) {
	startPos := p.cur.Pos
	if _, err := p.expect(lexer.TokCapture); err != nil {
		return nil, err
	}
	c, err := p.parseCaptureSpec()
	if err != nil {
		return nil, err
	}
	c.Pos = startPos
	if p.cur.Kind == lexer.TokWhere {
		w, err := p.parseWhereClause()
		if err != nil {
			return nil, err
		}
		c.Where = w
	}
	return c, nil
}

// capture_spec := "all"
//
//	| "headers" ("+" INT)?
//	| "absolute" INT
//	| IDENT ("+" INT)?              # layer label or protocol name
//	| field_path ("," field_path)*  # CapFields (MVP-unsupported)
//
// "absolute" is a contextual keyword (only special inside capture).
// A label literally named "absolute" can still be referenced via
// `capture absolute+0` to force the label branch.
func (p *parser) parseCaptureSpec() (*ast.CaptureClause, error) {
	switch p.cur.Kind {
	case lexer.TokAll:
		startPos := p.cur.Pos
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &ast.CaptureClause{Kind: ast.CapAll, Pos: startPos}, nil

	case lexer.TokHeaders:
		startPos := p.cur.Pos
		if err := p.advance(); err != nil {
			return nil, err
		}
		extra, hadPlus, err := p.parseOptionalPlusInt()
		if err != nil {
			return nil, err
		}
		kind := ast.CapHeaders
		if hadPlus {
			kind = ast.CapHeadersPlus
		}
		return &ast.CaptureClause{Kind: kind, Extra: extra, Pos: startPos}, nil

	case lexer.TokIdent:
		return p.parseCaptureIdent()
	}
	return nil, p.errorf(p.cur.Pos, "expected 'all', 'headers', 'absolute', a layer label, or field path after 'capture', got %s", p.cur.Kind)
}

// parseCaptureIdent dispatches the TokIdent branch by 1-token
// lookahead: `IDENT.IDENT...` → field_path list (CapFields);
// `IDENT == "absolute"` followed by INT → CapAbsolute; bare IDENT
// (optionally `+N`) → CapToLayer.
func (p *parser) parseCaptureIdent() (*ast.CaptureClause, error) {
	ident := p.cur
	startPos := ident.Pos
	if err := p.advance(); err != nil {
		return nil, err
	}

	if ident.Text == "absolute" && p.cur.Kind == lexer.TokInt {
		n := p.cur.Int
		if err := p.advance(); err != nil {
			return nil, err
		}
		return &ast.CaptureClause{Kind: ast.CapAbsolute, Extra: int(n), Pos: startPos}, nil
	}

	if p.cur.Kind == lexer.TokDot {
		first, err := p.parseFieldPathFromHead(ident)
		if err != nil {
			return nil, err
		}
		fields := []*ast.FieldPath{first}
		for p.cur.Kind == lexer.TokComma {
			if err := p.advance(); err != nil {
				return nil, err
			}
			next, err := p.parseFieldPath()
			if err != nil {
				return nil, err
			}
			fields = append(fields, next)
		}
		return &ast.CaptureClause{
			Kind:        ast.CapFields,
			Fields:      fields,
			Unsupported: true, // MVP codegen does not implement field-list capture
			Pos:         startPos,
		}, nil
	}

	extra, _, err := p.parseOptionalPlusInt()
	if err != nil {
		return nil, err
	}
	return &ast.CaptureClause{Kind: ast.CapToLayer, LayerName: ident.Text, Extra: extra, Pos: startPos}, nil
}

// parseOptionalPlusInt consumes `+ INT` when present, returning the
// integer plus a flag for whether the `+` was seen. The flag lets
// the headers branch distinguish CapHeaders ("no plus") from
// CapHeadersPlus ("plus, possibly with N=0").
func (p *parser) parseOptionalPlusInt() (extra int, hadPlus bool, err error) {
	if _, ok, err := p.accept(lexer.TokPlus); err != nil {
		return 0, false, err
	} else if !ok {
		return 0, false, nil
	}
	tok, err := p.expect(lexer.TokInt)
	if err != nil {
		return 0, true, err
	}
	return int(tok.Int), true, nil
}
