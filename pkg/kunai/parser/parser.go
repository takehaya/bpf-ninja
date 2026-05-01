// Package parser converts a one-liner DSL expression into an ast.Filter.
// It is a hand-written recursive-descent parser. The where clause uses
// precedence climbing; everything else is straightforward. The parser
// does not perform semantic checks (is this protocol known? does this
// field exist?) — those are the resolver's job in a later PR.
package parser

import (
	"fmt"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/lexer"
)

// Parse reads expr and returns the parsed filter. file is attached to
// error messages and may be empty for one-liner inputs. reservedLabels
// names @label values that must be rejected (typically the keys of
// Capabilities.Action so a host's action symbols cannot collide with
// labels); pass nil to allow any label name.
func Parse(expr string, file string, reservedLabels map[string]bool) (*ast.Filter, error) {
	p := &parser{
		lex:            lexer.New([]byte(expr), file),
		file:           file,
		reservedLabels: reservedLabels,
	}
	// Seed preCurSnap so the speculative LHS-literal probe in
	// parseCmpOrBoolAtom has a defined snapshot even before the very
	// first p.advance().
	p.preCurSnap = p.lex.Save()
	if err := p.advance(); err != nil {
		return nil, err
	}
	return p.parseFilter()
}

type parser struct {
	lex            *lexer.Lexer
	cur            lexer.Token
	preCurSnap     lexer.Snapshot // lexer state at the start of the byte run that produced p.cur; used by speculative re-reads (e.g. LHS network-literal probing in `where`)
	file           string
	depth          int             // alternation nesting depth
	reservedLabels map[string]bool // host-supplied @label rejection set
}

func (p *parser) advance() error {
	snap := p.lex.Save()
	next, err := p.lex.Next()
	if err != nil {
		return err
	}
	p.preCurSnap = snap
	p.cur = next
	return nil
}

// advanceValue consumes the current token and fetches the next one in
// value mode. The lexer's position has already moved past the current
// token by the time we see it in p.cur, so calling NextValue reads
// bytes starting at the first character after that token.
func (p *parser) advanceValue() error {
	var err error
	p.cur, err = p.lex.NextValue()
	return err
}

func (p *parser) expect(k lexer.TokenKind) (lexer.Token, error) {
	if p.cur.Kind != k {
		return lexer.Token{}, p.errorf(p.cur.Pos, "expected %s, got %s (%q)", k, p.cur.Kind, p.cur.Text)
	}
	t := p.cur
	if err := p.advance(); err != nil {
		return lexer.Token{}, err
	}
	return t, nil
}

func (p *parser) accept(k lexer.TokenKind) (lexer.Token, bool, error) {
	if p.cur.Kind != k {
		return lexer.Token{}, false, nil
	}
	t := p.cur
	if err := p.advance(); err != nil {
		return lexer.Token{}, false, err
	}
	return t, true, nil
}

func (p *parser) errorf(pos ast.Position, format string, args ...any) error {
	return &lexer.SyntaxError{File: p.file, Pos: pos, Message: fmt.Sprintf(format, args...)}
}

// parseFilter is the top-level grammar entry.
// filter := layer_chain where_clause? capture_clause*
func (p *parser) parseFilter() (*ast.Filter, error) {
	startPos := p.cur.Pos
	if p.cur.Kind == lexer.TokEOF {
		return nil, p.errorf(startPos, "empty filter expression")
	}
	layers, err := p.parseLayerChain()
	if err != nil {
		return nil, err
	}
	f := &ast.Filter{Layers: layers, Pos: startPos}
	if p.cur.Kind == lexer.TokWhere {
		w, err := p.parseWhereClause()
		if err != nil {
			return nil, err
		}
		f.Where = w
	}
	for p.cur.Kind == lexer.TokCapture {
		c, err := p.parseCaptureClause()
		if err != nil {
			return nil, err
		}
		f.Captures = append(f.Captures, c)
	}
	if p.cur.Kind != lexer.TokEOF {
		return nil, p.errorf(p.cur.Pos, "unexpected trailing token %s (%q)", p.cur.Kind, p.cur.Text)
	}
	return f, nil
}

// isReservedLabel reports whether s cannot be used as an @label
// because the caller pre-declared it reserved (typically the symbolic
// names in Capabilities.Action — e.g. XDP_DROP for an XDP host).
func (p *parser) isReservedLabel(s string) bool {
	return p.reservedLabels[s]
}
