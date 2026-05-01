package kunai

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/takehaya/xdp-ninja/pkg/kunai/dslvocab"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// SyntaxHelp is a short EBNF-style grammar of the DSL, suitable for
// embedding in a CLI --help or man page.
const SyntaxHelp = `Syntax:
  filter        := layer-chain [where-clause] [capture-clause]*
  layer-chain   := layer (/ layer)*
  layer         := proto[@label][quantifier][predicate]*
                |  ( layer (| layer)+ )    # alternation
  quantifier    := ? | + | * | {n} | {n,m}
  predicate     := [ field op value (, field op value)* ]
  op            := == | != | < | <= | > | >=
  value         := integer | ipv4 | ipv6 | ipv4_cidr | ipv6_cidr | mac
  where-clause  := where <expr>
  capture-clause:= capture (all|headers|headers+N) [where <expr>]
`

// ExamplesHelp is a set of representative DSL expressions.
const ExamplesHelp = `Examples:
  eth/ipv4/tcp[dport==443]
  eth/ipv4/tcp[sport==12345, dport==443]      # multi-field AND
  eth/ipv4[src==10.0.0.0/8]/tcp
  eth[dst==de:ad:be:ef:00:01]/ipv4/tcp        # MAC predicate
  eth/ipv6[src==2001:db8::/32]/tcp            # IPv6 CIDR
  eth/vlan?/ipv4/tcp                           # optional VLAN
  eth/mpls{1,4}/ipv4/tcp                       # MPLS 1-4 labels
  eth/ipv4/udp/vxlan/eth/ipv4/tcp              # VXLAN inner
  eth/(vlan|qinq)/ipv4/tcp                     # alternation
  eth/ipv4@outer/udp/gtp/ipv4@inner/tcp        # labelled layers
  eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80
  eth/ipv4/tcp capture headers+64
`

// WriteProtocolCatalogue writes a one-line-per-protocol summary of
// the bundled vocabulary to w: protocol name, header byte size, and
// the parent protocols it can be dispatched from.
func WriteProtocolCatalogue(w io.Writer) error {
	v, err := dslvocab.Bundled()
	if err != nil {
		return fmt.Errorf("loading bundled DSL vocab: %w", err)
	}
	return writeProtocolCatalogue(w, v)
}

func writeProtocolCatalogue(w io.Writer, v map[string]*vocab.ProtocolSpec) error {
	names := make([]string, 0, len(v))
	for n := range v {
		names = append(names, n)
	}
	sort.Strings(names)

	if _, err := fmt.Fprintf(w, "Bundled protocols (%d):\n", len(names)); err != nil {
		return err
	}
	for _, n := range names {
		spec := v[n]
		parents := dispatchParents(spec)
		if _, err := fmt.Fprintf(w, "  %-8s %2d B  from %s\n", n, protocolHeaderBytes(spec), strings.Join(parents, ", ")); err != nil {
			return err
		}
	}
	return nil
}

func protocolHeaderBytes(spec *vocab.ProtocolSpec) int {
	bits := 0
	for _, f := range spec.Fields {
		bits += f.Bits
	}
	return (bits + 7) / 8
}

func dispatchParents(spec *vocab.ProtocolSpec) []string {
	seen := map[string]struct{}{}
	for _, c := range spec.Consts {
		if c.Parent == "" || c.Parent == spec.Name {
			continue
		}
		seen[c.Parent] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
