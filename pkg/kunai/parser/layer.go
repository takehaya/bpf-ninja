package parser

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/lexer"
)

const maxAltDepth = 16

// parseLayerChain parses one or more layer_items separated by "/".
//
//	layer_chain := layer_item ("/" layer_item)*
func (p *parser) parseLayerChain() ([]*ast.Layer, error) {
	first, err := p.parseLayerItem()
	if err != nil {
		return nil, err
	}
	layers := []*ast.Layer{first}
	for p.cur.Kind == lexer.TokSlash {
		if err := p.advance(); err != nil {
			return nil, err
		}
		next, err := p.parseLayerItem()
		if err != nil {
			return nil, err
		}
		layers = append(layers, next)
	}
	return layers, nil
}

// parseLayerItem wraps a layer_atom with an optional quantifier.
//
//	layer_item := layer_atom quantifier?
func (p *parser) parseLayerItem() (*ast.Layer, error) {
	layer, err := p.parseLayerAtom()
	if err != nil {
		return nil, err
	}
	if isQuantToken(p.cur.Kind) {
		if err := p.parseQuantifier(layer); err != nil {
			return nil, err
		}
	}
	if isQuantToken(p.cur.Kind) {
		return nil, p.errorf(p.cur.Pos, "cannot chain quantifiers; %s follows another quantifier", p.cur.Kind)
	}
	return layer, nil
}

func isQuantToken(k lexer.TokenKind) bool {
	switch k {
	case lexer.TokQuestion, lexer.TokPlus, lexer.TokStar, lexer.TokLBrace:
		return true
	}
	return false
}

func (p *parser) parseQuantifier(layer *ast.Layer) error {
	switch p.cur.Kind {
	case lexer.TokQuestion:
		layer.Quant = ast.QuantOpt
		return p.advance()
	case lexer.TokPlus:
		layer.Quant = ast.QuantPlus
		return p.advance()
	case lexer.TokStar:
		layer.Quant = ast.QuantStar
		return p.advance()
	case lexer.TokLBrace:
		return p.parseQuantRange(layer)
	}
	return p.errorf(p.cur.Pos, "expected quantifier, got %s", p.cur.Kind)
}

// quantifier range: "{" INT ("," INT?)? "}"
func (p *parser) parseQuantRange(layer *ast.Layer) error {
	openTok, err := p.expect(lexer.TokLBrace)
	if err != nil {
		return err
	}
	minT, err := p.expect(lexer.TokInt)
	if err != nil {
		return err
	}
	min := int(minT.Int)
	max := min
	if _, ok, err := p.accept(lexer.TokComma); err != nil {
		return err
	} else if ok {
		if p.cur.Kind == lexer.TokInt {
			maxT, err := p.expect(lexer.TokInt)
			if err != nil {
				return err
			}
			max = int(maxT.Int)
			if max < min {
				return p.errorf(maxT.Pos, "quantifier range max %d less than min %d", max, min)
			}
		} else {
			max = -1 // open upper bound: {n,}
		}
	}
	if _, err := p.expect(lexer.TokRBrace); err != nil {
		return err
	}
	if min < 0 {
		return p.errorf(openTok.Pos, "quantifier range min must be non-negative, got %d", min)
	}
	layer.Quant = ast.QuantRange
	layer.RangeMin = min
	layer.RangeMax = max
	return nil
}

// parseLayerAtom is the fundamental layer unit: either a single
// protocol leaf or a parenthesised alternation group.
//
//	layer_atom := proto_leaf | "(" layer_alt ")"
func (p *parser) parseLayerAtom() (*ast.Layer, error) {
	startPos := p.cur.Pos
	switch p.cur.Kind {
	case lexer.TokIdent:
		return p.parseProtoLeaf(startPos)
	case lexer.TokLParen:
		return p.parseLayerAltGroup(startPos)
	}
	return nil, p.errorf(startPos, "expected protocol name or '(', got %s (%q)", p.cur.Kind, p.cur.Text)
}

// proto_leaf := IDENT ("@" IDENT)? ("[" pred_list "]")?
func (p *parser) parseProtoLeaf(startPos ast.Position) (*ast.Layer, error) {
	nameTok, err := p.expect(lexer.TokIdent)
	if err != nil {
		return nil, err
	}
	layer := &ast.Layer{Kind: ast.LayerProto, ProtoName: nameTok.Text, Pos: startPos}
	if _, ok, err := p.accept(lexer.TokAt); err != nil {
		return nil, err
	} else if ok {
		labelTok, err := p.expect(lexer.TokIdent)
		if err != nil {
			return nil, err
		}
		if p.isReservedLabel(labelTok.Text) {
			return nil, p.errorf(labelTok.Pos, "label %q collides with a reserved action symbol", labelTok.Text)
		}
		layer.Label = labelTok.Text
	}
	if p.cur.Kind == lexer.TokLBracket {
		if err := p.advance(); err != nil {
			return nil, err
		}
		preds, err := p.parsePredicateList()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(lexer.TokRBracket); err != nil {
			return nil, err
		}
		layer.Predicates = preds
	}
	return layer, nil
}

// parseLayerAltGroup expects the leading "(" to still be the current
// token; it consumes it and everything through the matching ")".
//
//	layer_alt := layer_item ("|" layer_item)+
func (p *parser) parseLayerAltGroup(startPos ast.Position) (*ast.Layer, error) {
	if p.depth >= maxAltDepth {
		return nil, p.errorf(startPos, "alternation too deeply nested (max %d)", maxAltDepth)
	}
	p.depth++
	defer func() { p.depth-- }()

	if _, err := p.expect(lexer.TokLParen); err != nil {
		return nil, err
	}
	first, err := p.parseLayerItem()
	if err != nil {
		return nil, err
	}
	alts := []*ast.Layer{first}
	if p.cur.Kind != lexer.TokPipe {
		return nil, p.errorf(p.cur.Pos, "alternation group requires at least two alternatives separated by '|'")
	}
	for p.cur.Kind == lexer.TokPipe {
		if err := p.advance(); err != nil {
			return nil, err
		}
		next, err := p.parseLayerItem()
		if err != nil {
			return nil, err
		}
		alts = append(alts, next)
	}
	if _, err := p.expect(lexer.TokRParen); err != nil {
		return nil, err
	}
	return &ast.Layer{Kind: ast.LayerAltGroup, Alternatives: alts, Pos: startPos}, nil
}
