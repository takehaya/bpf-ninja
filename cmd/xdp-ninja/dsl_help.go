package main

import (
	"io"

	"github.com/takehaya/xdp-ninja/pkg/kunai"
)

const xdpNinjaHelpFooter = `
Run with --dsl <expr>. Full reference: docs/ja/dsl-usage.md
                       Formal grammar:   docs/ja/dsl-grammar.md

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
