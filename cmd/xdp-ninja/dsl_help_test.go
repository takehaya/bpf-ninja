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

func TestPrintProtoHelpIPv4(t *testing.T) {
	var buf bytes.Buffer
	if err := printProtoHelp(&buf, "ipv4"); err != nil {
		t.Fatalf("printProtoHelp(ipv4): %v", err)
	}
	out := buf.String()

	wantSubstrings := []string{
		"ipv4 — header 20 bytes",
		"variable layout",       // IPv4 walks options via ParserCounter
		"Fields (bit width",
		"src",                   // canonical fields
		"dst",
		"protocol",
		"bit<32>",               // dst is 32 bits
		"Dispatched from:",
		"eth",                   // ipv4 is parented by eth
		"Dispatches to:",
		"via protocol",          // dispatch field
		"tcp",                   // ipv4 → tcp
		"udp",
		"Notes:",
		// Mechanism 1 ("variable trailer") moved to Mechanism 8
		// (parser state machine + ParserCounter byte-bounded walk).
		"parser state machine",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("ipv4 help missing %q\n--- got ---\n%s", s, out)
		}
	}
}

func TestPrintProtoHelpSkipsUnderscoreFields(t *testing.T) {
	// ipv6_ext_h has an internal `_opts` padding field — users
	// shouldn't see it as if it were a selectable selector.
	var buf bytes.Buffer
	if err := printProtoHelp(&buf, "ipv6"); err != nil {
		t.Fatalf("printProtoHelp(ipv6): %v", err)
	}
	if strings.Contains(buf.String(), "_opts") {
		t.Errorf("ipv6 help leaks internal _opts placeholder:\n%s", buf.String())
	}
}

func TestPrintProtoHelpSRv6Stack(t *testing.T) {
	var buf bytes.Buffer
	if err := printProtoHelp(&buf, "srv6"); err != nil {
		t.Fatalf("printProtoHelp(srv6): %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Aux header stacks:",
		"segments[0..", // capacity printed
		"srv6_seg_h",   // element header type
		"addr",         // segment field
		"bit<128>",     // segment addr width
		"static index",
		"dynamic index",
		"quantifier (∃)",
		"quantifier (∀)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("srv6 help missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestPrintProtoHelpGTPAuxAndStack(t *testing.T) {
	var buf bytes.Buffer
	if err := printProtoHelp(&buf, "gtp"); err != nil {
		t.Fatalf("printProtoHelp(gtp): %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Aux headers:",       // single aux section (gtp.opt)
		"opt (gtp_opt_h",     // aux name + header type
		"gated:",             // gated aux
		"next_ext",           // aux field
		"Aux header stacks:", // stack section (gtp.exts)
		"exts[0..",
		"gtp_ext_h",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gtp help missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestPrintProtoHelpTCPOptions(t *testing.T) {
	var buf bytes.Buffer
	if err := printProtoHelp(&buf, "tcp"); err != nil {
		t.Fatalf("printProtoHelp(tcp): %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Options walk",
		"MSS (4 bytes)",
		"WS (3 bytes)",
		"TS (10 bytes)",
		"tcp.options.MSS.<field>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tcp help missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestPrintProtoHelpUnknown(t *testing.T) {
	var buf bytes.Buffer
	err := printProtoHelp(&buf, "bogus")
	if err == nil {
		t.Fatal("expected error for unknown protocol, got nil")
	}
	if !strings.Contains(err.Error(), `unknown protocol "bogus"`) {
		t.Errorf("error message unexpected: %v", err)
	}
	if !strings.Contains(err.Error(), "ipv4") {
		t.Errorf("error message should list bundled names; got: %v", err)
	}
}
