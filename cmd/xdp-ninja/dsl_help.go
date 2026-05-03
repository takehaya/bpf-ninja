package main

import (
	"io"

	"github.com/takehaya/xdp-ninja/pkg/kunai"
)

const xdpNinjaHelpFooter = `
Pass a DSL expression as the positional arg (DSL is the default
filter syntax). For tcpdump/cBPF syntax, add --cbpf.

  Full reference: docs/ja/dsl-usage.md
  Formal grammar: docs/ja/dsl-grammar.md
  Per-protocol fields: xdp-ninja --dsl-help <proto>

`

// printDSLHelp writes a short DSL reference (grammar + bundled
// protocol catalogue) to w. The reference is meant for terminal use:
// it stays under ~80 columns and skips deep details users get from
// docs/ja/dsl-usage.md.
func printDSLHelp(w io.Writer) error {
	if _, err := io.WriteString(w, "xdp-ninja DSL — quick reference\n\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, kunai.SyntaxHelp); err != nil {
		return err
	}
	if _, err := io.WriteString(w, kunai.ExamplesHelp); err != nil {
		return err
	}
	if err := kunai.WriteProtocolCatalogue(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, xdpNinjaHelpFooter)
	return err
}

// printProtoHelp writes a per-protocol reference (field list +
// dispatch parents/children + variable-layout note) for the named
// bundled protocol. Useful for "what's the field name for IPv4 dst?"
// style questions before writing a DSL filter.
func printProtoHelp(w io.Writer, name string) error {
	return kunai.WriteProtocolHelp(w, name)
}
