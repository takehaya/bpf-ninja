// Package kunai exposes the P4-based filter DSL for xdp-ninja.
//
// Structure:
//   - ast, lexer, parser: one-liner DSL front end
//   - vocab, vocab/p4lite: .p4 vocabulary loader and subset parser
//   - resolve, ir:         AST → bound IR
//   - codegen:             IR → BPF instructions
//   - protocols:           bundled .p4 files (embed.FS lives there
//     rather than here so the resolver tests can read the embed
//     without importing this package)
//
// Compile is the single entry point callers need.
package kunai

import (
	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
	"github.com/takehaya/xdp-ninja/pkg/kunai/dslvocab"
	"github.com/takehaya/xdp-ninja/pkg/kunai/parser"
	"github.com/takehaya/xdp-ninja/pkg/kunai/resolve"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// Compile parses a DSL expression against the bundled protocol
// vocabulary, resolves it to IR, and produces BPF instructions
// targeting the runFilter ABI documented in
// codegen/codegen.go's package doc.
//
// caps tells the compiler which host-specific atoms are available
// — currently `where action == NAME` clauses and the symbols they
// may reference. The zero value yields a fully target-agnostic
// filter (no action atoms allowed); host adapters live under
// pkg/kunai/host/ — for example, an XDP fexit attach point passes
// xdphost.FexitCapabilities() (where xdphost is
// pkg/kunai/host/xdp).
//
// The returned CaptureInfo carries the compile-time capture
// configuration the wrapper needs to size perf output; a zero
// value means no DSL capture clause was provided.
//
// Errors are returned as-is from each phase so callers can
// distinguish syntax errors (*lexer.SyntaxError) from resolver
// errors and codegen errors (codegen.ErrNotImplemented for valid
// DSL the MVP codegen has not yet emitted).
func Compile(expr string, caps codegen.Capabilities) (codegen.Output, error) {
	v, err := dslvocab.Bundled()
	if err != nil {
		return codegen.Output{}, err
	}
	return CompileWithVocab(expr, v, caps)
}

// CompileWithVocab is Compile against a caller-supplied vocabulary
// map — primarily a test-helper for exercising codegen shapes on
// synthetic .p4 inputs. Production code should prefer Compile.
func CompileWithVocab(expr string, v map[string]*vocab.ProtocolSpec, caps codegen.Capabilities) (codegen.Output, error) {
	f, err := parser.Parse(expr, "", reservedLabels(caps))
	if err != nil {
		return codegen.Output{}, err
	}
	prog, err := resolve.Resolve(f, v, caps.Lang.Action)
	if err != nil {
		return codegen.Output{}, err
	}
	return codegen.Gen(prog, caps)
}

// reservedLabels picks the parser's @label rejection set: caller
// override if Lex.ReservedLabels is non-nil, else derive from
// Lang.Action keys (the common case — a host that exposes XDP_DROP
// probably wants the label "XDP_DROP" reserved too). Returns nil when
// neither source applies, which the parser reads as "no reservations".
func reservedLabels(caps codegen.Capabilities) map[string]bool {
	if caps.Lex.ReservedLabels != nil {
		return caps.Lex.ReservedLabels
	}
	if caps.Lang.Action == nil {
		return nil
	}
	out := make(map[string]bool, len(caps.Lang.Action))
	for k := range caps.Lang.Action {
		out[k] = true
	}
	return out
}
