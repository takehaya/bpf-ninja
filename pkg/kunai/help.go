package kunai

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/takehaya/xdp-ninja/pkg/kunai/dslvocab"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
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
	names := sortedProtocolNames(v)
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

// dispatchChildEdge captures one "parent.field == const → child" edge,
// in the form "field is the discriminator that picks among children".
type dispatchChildEdge struct {
	Field    string
	Children []string // sorted
}

// dispatchChildren returns the dispatch graph rooted at parentName,
// sorted by field name so callers don't need to re-sort. Each edge
// lists the child protocols selected by `parent.field == const` over
// all const values declared on that field.
func dispatchChildren(parentName string, v map[string]*vocab.ProtocolSpec) []dispatchChildEdge {
	byField := map[string]map[string]struct{}{}
	for _, child := range v {
		if child.Name == parentName {
			continue
		}
		for _, c := range child.Consts {
			if c.Parent != parentName {
				continue
			}
			if _, ok := byField[c.FieldName]; !ok {
				byField[c.FieldName] = map[string]struct{}{}
			}
			byField[c.FieldName][child.Name] = struct{}{}
		}
	}
	fields := make([]string, 0, len(byField))
	for f := range byField {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	out := make([]dispatchChildEdge, 0, len(fields))
	for _, f := range fields {
		set := byField[f]
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		out = append(out, dispatchChildEdge{Field: f, Children: names})
	}
	return out
}

// sortedProtocolNames returns the bundled protocol names sorted in
// stable string order. Used by WriteProtocolCatalogue and
// WriteProtocolHelp's unknown-protocol error path.
func sortedProtocolNames(v map[string]*vocab.ProtocolSpec) []string {
	names := make([]string, 0, len(v))
	for n := range v {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// WriteProtocolHelp writes a per-protocol reference for `name`:
// field list (with bit widths and running byte offsets), dispatch
// parents and children, and any variable-layout note. Returns an
// error when the protocol is unknown — message lists the bundled
// names so the user sees which to retry with.
func WriteProtocolHelp(w io.Writer, name string) error {
	v, err := dslvocab.Bundled()
	if err != nil {
		return fmt.Errorf("loading bundled DSL vocab: %w", err)
	}
	spec, ok := v[name]
	if !ok {
		return fmt.Errorf("unknown protocol %q (bundled: %s)", name, strings.Join(sortedProtocolNames(v), ", "))
	}

	bytes := protocolHeaderBytes(spec)
	suffix := ""
	if spec.HasVariableLayout() {
		suffix = " minimum (variable layout, see Notes)"
	}
	if _, err := fmt.Fprintf(w, "%s — header %d bytes%s\n\n", spec.Name, bytes, suffix); err != nil {
		return err
	}

	if _, err := io.WriteString(w, "Fields (bit width, running byte offset):\n"); err != nil {
		return err
	}
	if err := writeFieldRows(w, "  ", len(spec.Fields), vocabFieldRow(spec.Fields)); err != nil {
		return err
	}

	if pm := spec.ParseStateMachine; pm != nil {
		if err := writeAuxHeaders(w, spec.Name, pm); err != nil {
			return err
		}
		if err := writeAuxStacks(w, spec.Name, pm); err != nil {
			return err
		}
		if err := writeOptionsWalk(w, spec.Name, pm); err != nil {
			return err
		}
	}

	parents := dispatchParents(spec)
	if len(parents) > 0 {
		if _, err := fmt.Fprintf(w, "\nDispatched from: %s\n", strings.Join(parents, ", ")); err != nil {
			return err
		}
	}

	children := dispatchChildren(spec.Name, v)
	if len(children) > 0 {
		if _, err := io.WriteString(w, "Dispatches to:\n"); err != nil {
			return err
		}
		for _, edge := range children {
			if _, err := fmt.Fprintf(w, "  via %-12s -> %s\n", edge.Field, strings.Join(edge.Children, ", ")); err != nil {
				return err
			}
		}
	}

	// Notes: emit one line per *present* variability source. Some
	// protocols carry more than one (e.g. ipv4 has both a parser-block
	// pkt.advance trailer AND a parser-machine version self-check), so
	// the branches are independent — switch{first-match} would silently
	// drop the second source.
	if spec.HasVariableLayout() {
		if _, err := io.WriteString(w, "\nNotes:\n"); err != nil {
			return err
		}
		if vs := spec.PrimaryAdvanceSkip(); vs != nil {
			if _, err := fmt.Fprintf(w, "  variable trailer: ((byte@%d & 0x%x) >> %d) * %d - %d bytes past fixed header\n",
				vs.LenByteOff, vs.LenMask, vs.LenShift, vs.Scale, vs.Base); err != nil {
				return err
			}
		}
		if len(spec.FlagTriggers) > 0 {
			if _, err := fmt.Fprintf(w, "  flag-triggered optional fields gated on byte@%d\n", spec.FlagsByteOffset); err != nil {
				return err
			}
		}
		if spec.ParseStateMachine != nil {
			if _, err := io.WriteString(w, "  parser state machine (variable extension headers or self-validation)\n"); err != nil {
				return err
			}
		}
	}

	return nil
}

// writeFieldRows prints one row per field with the standard column
// layout shared by primary header, aux headers, aux stack elements,
// and option entries (name padded 20, bit<N> padded 9, @offset).
//
// Iterator form (count + getter) avoids converting between
// vocab.Field and p4lite.Field at call sites — the two types share
// the (name, bits) pair the helper needs but Go's type system can't
// duck-type that without a wrapper.
//
// Fields whose name starts with "_" are internal padding placeholders
// (e.g. ipv6_ext_h._opts) — skipped from the output but still
// included in the running bit-offset accumulator so subsequent
// field offsets stay correct.
func writeFieldRows(w io.Writer, indent string, count int, get func(i int) (name string, bits int)) error {
	bitOff := 0
	for i := 0; i < count; i++ {
		name, bits := get(i)
		if !strings.HasPrefix(name, "_") {
			byteOff := bitOff / 8
			bitInByte := bitOff % 8
			offDisp := fmt.Sprintf("%d", byteOff)
			if bitInByte != 0 {
				offDisp = fmt.Sprintf("%d+%db", byteOff, bitInByte)
			}
			if _, err := fmt.Fprintf(w, "%s%-20s %-9s @%s\n", indent, name, fmt.Sprintf("bit<%d>", bits), offDisp); err != nil {
				return err
			}
		}
		bitOff += bits
	}
	return nil
}

// vocabFieldRow / p4liteFieldRow adapt the two Field types into the
// (name, bits) pair writeFieldRows needs.
func vocabFieldRow(fs []vocab.Field) func(i int) (string, int) {
	return func(i int) (string, int) { return fs[i].Name, fs[i].Bits }
}
func p4liteFieldRow(fs []p4lite.Field) func(i int) (string, int) {
	return func(i int) (string, int) { return fs[i].Name, fs[i].Bits }
}

// writeAuxHeaders prints the protocol's single-instance auxiliary
// headers (e.g. gtp.opt, the GRE checksum/key/sequence trailers exposed
// via parser-machine extracts). Each aux gets its name, header type,
// byte offset within the layer, and any gating predicate.
func writeAuxHeaders(w io.Writer, protoName string, pm *vocab.ParseStateMachine) error {
	if len(pm.AuxLayouts) == 0 {
		return nil
	}
	names := make([]string, 0, len(pm.AuxLayouts))
	for n := range pm.AuxLayouts {
		names = append(names, n)
	}
	sort.Strings(names)
	if _, err := io.WriteString(w, "\nAux headers:\n"); err != nil {
		return err
	}
	for _, name := range names {
		aux := pm.AuxLayouts[name]
		gating := ""
		if aux.Gating != nil {
			op := "=="
			if aux.Gating.Op == vocab.GatingNe {
				op = "!="
			}
			gating = fmt.Sprintf(" (gated: (byte@%d & 0x%x) %s 0x%x)", aux.Gating.ByteOff, aux.Gating.Mask, op, aux.Gating.Value)
		}
		if _, err := fmt.Fprintf(w, "  %s (%s, %d bytes @ +%d from layer start)%s\n", name, aux.HeaderName, aux.HeaderSize, aux.OffsetInLayer, gating); err != nil {
			return err
		}
		if aux.HeaderRef != nil {
			if err := writeFieldRows(w, "    ", len(aux.HeaderRef.Fields), p4liteFieldRow(aux.HeaderRef.Fields)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "    use: %s.%s.<field>  or  %s[%s.<field> == X]\n", protoName, name, protoName, name); err != nil {
			return err
		}
	}
	return nil
}

// writeAuxStacks prints the protocol's auxiliary header stacks (e.g.
// srv6.segments, ipv6.exts, gtp.exts). Each stack prints capacity,
// element type, fields, and the DSL access patterns the resolver
// supports (static index, dynamic index, any/all quantifier).
func writeAuxStacks(w io.Writer, protoName string, pm *vocab.ParseStateMachine) error {
	if len(pm.StackRefs) == 0 {
		return nil
	}
	names := make([]string, 0, len(pm.StackRefs))
	for n := range pm.StackRefs {
		names = append(names, n)
	}
	sort.Strings(names)
	if _, err := io.WriteString(w, "\nAux header stacks:\n"); err != nil {
		return err
	}
	for _, name := range names {
		st := pm.StackRefs[name]
		if _, err := fmt.Fprintf(w, "  %s[0..%d] (%s × %d bytes each)\n", name, st.Capacity-1, st.HeaderName, st.ElemSize); err != nil {
			return err
		}
		if st.HeaderRef != nil {
			if err := writeFieldRows(w, "    ", len(st.HeaderRef.Fields), p4liteFieldRow(st.HeaderRef.Fields)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "    use: %s.%s[N].<field>            static index\n", protoName, name); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "         %s.%s[<primary_field>].<field>  dynamic index\n", protoName, name); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "         where any(%s.%s.<field> == X)  quantifier (∃)\n", protoName, name); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "         where all(%s.%s.<field> == X)  quantifier (∀)\n", protoName, name); err != nil {
			return err
		}
	}
	return nil
}

// writeOptionsWalk prints the protocol's TLV-walk options (TCP today)
// derived from the parser block: every aux extracted by a sibling
// state inside a multi-state self-loop is addressable via
// `<proto>.options.<NAME>.<field>` (with NAME = upper-case OutParam).
func writeOptionsWalk(w io.Writer, protoName string, pm *vocab.ParseStateMachine) error {
	type opt struct {
		name   string
		layout *vocab.AuxLayout
	}
	var opts []opt
	for _, layout := range pm.AuxLayouts {
		if !layout.IsDynamicEligible {
			continue
		}
		opts = append(opts, opt{name: strings.ToUpper(layout.OutParam), layout: layout})
	}
	if len(opts) == 0 {
		return nil
	}
	sort.Slice(opts, func(i, j int) bool { return opts[i].name < opts[j].name })
	if _, err := fmt.Fprintf(w, "\nOptions walk (parsed by parser block, %d named options):\n", len(opts)); err != nil {
		return err
	}
	for _, o := range opts {
		if _, err := fmt.Fprintf(w, "  %s (%d bytes)\n", o.name, o.layout.HeaderSize); err != nil {
			return err
		}
		if o.layout.HeaderRef != nil {
			if err := writeFieldRows(w, "    ", len(o.layout.HeaderRef.Fields), p4liteFieldRow(o.layout.HeaderRef.Fields)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "    use: %s.options.%s.<field>\n", protoName, o.name); err != nil {
			return err
		}
	}
	return nil
}
