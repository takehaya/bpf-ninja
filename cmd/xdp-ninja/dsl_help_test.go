package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintDSLHelpIncludesGrammarAndVocab(t *testing.T) {
	var buf bytes.Buffer
	if err := printDSLHelp(&buf); err != nil {
		t.Fatalf("printDSLHelp: %v", err)
	}
	out := buf.String()

	// Grammar header and syntax keywords should always be present.
	for _, want := range []string{
		"xdp-ninja DSL — quick reference",
		"Syntax:",
		"layer-chain",
		"capture-clause",
		"Examples:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q section", want)
		}
	}

	// Bundled vocab should at least cover the canonical L2/L3/L4
	// trio plus one chain-friendly protocol; the catalogue ordering
	// is sorted so the substrings are stable.
	for _, proto := range []string{"eth", "ipv4", "tcp", "mpls"} {
		if !strings.Contains(out, "  "+proto+" ") && !strings.Contains(out, "  "+proto+"  ") {
			t.Errorf("vocab list missing %q row", proto)
		}
	}

	// IPv4 should advertise its parent dispatches (eth at minimum).
	if !strings.Contains(out, "ipv4") || !strings.Contains(out, "eth") {
		t.Error("expected ipv4/eth relation in vocab list")
	}
}
