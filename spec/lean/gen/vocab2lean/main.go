// vocab2lean prints the bundled kunai vocabulary as Lean source
// (spec/lean/Kunai/VocabData.lean). It is a development tool for the Lean
// spec and is not part of the bpf-ninja build.
//
//	go run ./spec/lean/gen/vocab2lean > spec/lean/Kunai/VocabData.lean
package main

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/takehaya/bpf-ninja/pkg/kunai/dslvocab"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab/p4lite"
)

func main() {
	specs, err := dslvocab.Bundled()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	names := slices.Sorted(maps.Keys(specs))

	var b strings.Builder
	b.WriteString("import Kunai.Vocab\n\n")
	b.WriteString("/-!\n# Vocabulary data (generated)\n\nGenerated from `pkg/kunai/protocols/*.p4` by `go run ./spec/lean/gen/vocab2lean`.\nDo not edit; regenerate with `make lean-vocab`.\n-/\nnamespace Kunai\n\n")

	var protos, edges []string
	for _, n := range names {
		s := specs[n]
		protos = append(protos, protoLean(s))
		edges = append(edges, edgesLean(s)...)
	}
	fmt.Fprintf(&b, "def vocab : Vocab :=\n  { protos := [\n%s]\n    edges := [\n%s] }\n\nend Kunai\n",
		joinIndent(protos, 6), joinIndent(edges, 6))
	if _, err := os.Stdout.WriteString(b.String()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func joinIndent(items []string, indent int) string {
	pad := strings.Repeat(" ", indent)
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = pad + it
	}
	return strings.Join(out, ",\n") + "\n"
}

func str(s string) string { return strconv.Quote(s) }

func fieldsLean(fs []vocab.Field) string {
	parts := make([]string, 0, len(fs))
	off := 0
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("⟨%s, %d, %d⟩", str(f.Name), off, f.Bits))
		off += f.Bits
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func lenExpr(h *vocab.HeaderLength) string {
	return fmt.Sprintf("{ byteOff := %d, mask := %d, shift := %d, scale := %d, base := %d, addend := %d }",
		h.LenByteOff, h.LenMask, h.LenShift, h.Scale, h.Base, h.Addend)
}

func protoLean(s *vocab.ProtocolSpec) string {
	var parts []string
	parts = append(parts, "name := "+str(s.Name))
	parts = append(parts, "fields := "+fieldsLean(s.Fields))
	parts = append(parts, fmt.Sprintf("fixedLen := %d", vocab.SumBits(s.Fields)/8))
	if hl := declaredLength(s); hl != nil {
		parts = append(parts, "lenRule := some "+lenExpr(hl))
	}
	if req := requires(s); req != "" {
		parts = append(parts, "requires := "+req)
	}
	if s.ChainEnd != nil {
		parts = append(parts, fmt.Sprintf("chainEnd := some (%s, %d)", str(s.ChainEnd.FieldName), s.ChainEnd.Value))
	}
	if s.MaxDepth > 0 {
		parts = append(parts, fmt.Sprintf("maxDepth := %d", s.MaxDepth))
	}
	if s.ParseStateMachine != nil {
		parts = append(parts, "machine := some "+machineLean(s))
	}
	if s.OptionSegment != "" && s.OptionSegment != "options" {
		parts = append(parts, "optionSegment := "+str(s.OptionSegment))
	}
	if len(s.FlagTriggers) > 0 {
		var ft []string
		for _, t := range s.FlagTriggers {
			ft = append(ft, fmt.Sprintf("⟨%s, %d, %d⟩", str(strings.ToLower(t.Name)), t.BitMask, t.LenBytes))
		}
		parts = append(parts, fmt.Sprintf("flagsByteOff := %d", s.FlagsByteOffset))
		parts = append(parts, "flagTriggers := ["+strings.Join(ft, ", ")+"]")
	}
	return "{ " + strings.Join(parts, ",\n        ") + " }"
}

// declaredLength is the primary header's declared-length rule: the
// trailer skip when the loader exposes one, else the region counter the
// entry state seeds from a primary field (`pc.set(((hdr.data_offset - 5)) << 5)`).
func declaredLength(s *vocab.ProtocolSpec) *vocab.HeaderLength {
	m := s.ParseStateMachine
	if m == nil {
		return s.PrimaryAdvanceSkip()
	}
	// With a parser machine, only the entry state's byte counter is the
	// declared length; PrimaryAdvanceSkip picks the first state with an
	// advance, which depends on state order.
	for _, c := range m.States[m.EntryIdx].Counters {
		// Scale ≥ 2 means the set expression carried a `<< S` (bytes);
		// a bare cast (srv6 `last_entry + 1`) counts elements, not bytes.
		if c.Kind == vocab.CounterOpSet && c.Skip != nil && c.Skip.Scale >= 2 {
			return c.Skip
		}
	}
	return nil
}

// requires renders the protocol's self-validation constraint
// (vocab.ProtocolSpec.Requires) as a Lean list of (field, values).
func requires(s *vocab.ProtocolSpec) string {
	var reqs []string
	for _, r := range s.Requires() {
		vals := make([]string, len(r.Values))
		for i, v := range r.Values {
			vals[i] = fmt.Sprintf("%d", v)
		}
		reqs = append(reqs, fmt.Sprintf("(%s, [%s])", str(r.Field), strings.Join(vals, ", ")))
	}
	if len(reqs) == 0 {
		return ""
	}
	return "[" + strings.Join(reqs, ", ") + "]"
}

func edgesLean(s *vocab.ProtocolSpec) []string {
	var out []string
	for i := range s.Consts {
		c := &s.Consts[i]
		switch c.Type {
		case vocab.DispatchField:
			vals := []string{fmt.Sprintf("%d", c.Value)}
			for _, a := range c.AltValues {
				vals = append(vals, fmt.Sprintf("%d", a))
			}
			out = append(out, fmt.Sprintf("⟨%s, %s, .field %s [%s]⟩", str(s.Name), str(c.Parent), str(c.FieldName), strings.Join(vals, ", ")))
		case vocab.DispatchNoCheck:
			out = append(out, fmt.Sprintf("⟨%s, %s, .noCheck⟩", str(s.Name), str(c.Parent)))
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

func target(t int) string {
	switch t {
	case vocab.StateAccept:
		return ".accept"
	case vocab.StateReject:
		return ".reject"
	}
	return fmt.Sprintf("(.state %d)", t)
}

func machineLean(s *vocab.ProtocolSpec) string {
	m := s.ParseStateMachine
	// header type name → out parameter, from extracts and aux layouts.
	outParam := map[string]string{}
	for _, st := range m.States {
		for _, e := range st.Extracts {
			if e.IsStackPush {
				outParam[e.HeaderName] = e.StackName
			} else {
				outParam[e.HeaderName] = e.OutParam
			}
		}
	}
	for _, name := range sortedKeys(m.AuxLayouts) {
		if a := m.AuxLayouts[name]; outParam[a.HeaderName] == "" {
			outParam[a.HeaderName] = name
		}
	}

	var states []string
	for _, st := range m.States {
		var ex, cn, ad []string
		for _, e := range st.Extracts {
			p := e.OutParam
			if e.IsStackPush {
				p = e.StackName
			}
			ex = append(ex, fmt.Sprintf("⟨%s, %s, %d, %v⟩", str(p), str(e.HeaderName), e.HeaderSize/8, e.IsStackPush))
		}
		for _, c := range st.Counters {
			switch {
			case c.Kind == vocab.CounterOpSet:
				cn = append(cn, fmt.Sprintf(".set %s %s", str(c.Counter), lenExpr(c.Skip)))
			case c.DecrementLookaheadByteOffR:
				cn = append(cn, fmt.Sprintf(".decLookahead %s %d", str(c.Counter), c.DecrementLookaheadByteOff))
			case c.DecrementTarget != "":
				cn = append(cn, fmt.Sprintf(".decField %s %s %d", str(c.Counter), str(c.DecrementTarget), c.DecrementByteOff))
			default:
				cn = append(cn, fmt.Sprintf(".decLiteral %s %d", str(c.Counter), c.LiteralBytes))
			}
		}
		for _, a := range st.Advances {
			switch a.Kind {
			case vocab.AdvanceOpLiteral:
				ad = append(ad, fmt.Sprintf(".literal %d", a.LiteralBytes))
			case vocab.AdvanceOpField:
				ad = append(ad, fmt.Sprintf(".field %s %s", str(a.Target), lenExpr(a.Skip)))
			case vocab.AdvanceOpLookahead:
				ad = append(ad, ".lookahead "+lenExpr(a.Skip))
			}
		}
		var trans string
		switch st.Trans.Kind {
		case vocab.TransAccept:
			trans = ".goto .accept"
		case vocab.TransReject:
			trans = ".goto .reject"
		case vocab.TransDirect:
			trans = ".goto " + target(st.Trans.Target)
		case vocab.TransSelect:
			sel := st.Trans.Select
			var keys, cases []string
			for _, k := range sel.Keys {
				switch k.Kind {
				case vocab.SelectKeyField:
					tgt := k.Field.StackName
					if !k.Field.IsStackLast {
						tgt = outParam[k.Field.HeaderName]
					}
					keys = append(keys, fmt.Sprintf(".field %s %v %d %d", str(tgt), k.Field.IsStackLast, k.Field.BitOffset, k.Field.BitWidth))
				case vocab.SelectKeyLookahead:
					keys = append(keys, fmt.Sprintf(".lookahead %d", k.Bits))
				case vocab.SelectKeyCounterIsZero:
					keys = append(keys, ".counterIsZero "+str(k.Counter))
				}
			}
			for _, c := range sel.Cases {
				var vs []string
				for _, v := range c.Values {
					switch {
					case v.IsWildcard:
						vs = append(vs, ".wild")
					case v.IsBool:
						vs = append(vs, fmt.Sprintf(".bool %v", v.Bool))
					default:
						vs = append(vs, fmt.Sprintf(".val %d", v.Value))
					}
				}
				cases = append(cases, fmt.Sprintf("⟨[%s], %s⟩", strings.Join(vs, ", "), target(c.Target)))
			}
			trans = fmt.Sprintf(".select { keys := [%s], cases := [%s], default := %s }",
				strings.Join(keys, ", "), strings.Join(cases, ", "), target(sel.Default))
		}
		states = append(states, fmt.Sprintf("{ name := %s, extracts := [%s], counters := [%s], advances := [%s], trans := %s }",
			str(st.Name), strings.Join(ex, ", "), strings.Join(cn, ", "), strings.Join(ad, ", "), trans))
	}

	// Header types: extracted headers plus stack element headers.
	headerRefs := map[string]*p4lite.Header{}
	for k, v := range m.HeaderRefs {
		headerRefs[k] = v
	}
	for _, st := range m.StackRefs {
		if st.HeaderRef != nil {
			headerRefs[st.HeaderRef.Name] = st.HeaderRef
		}
	}
	var headers []string
	for _, hn := range sortedKeys(headerRefs) {
		h := headerRefs[hn]
		bits := 0
		fs := make([]vocab.Field, 0, len(h.Fields))
		for _, f := range h.Fields {
			fs = append(fs, vocab.Field{Name: f.Name, Bits: f.Bits})
			bits += f.Bits
		}
		headers = append(headers, fmt.Sprintf("⟨%s, %s, %d⟩", str(h.Name), fieldsLean(fs), bits/8))
	}
	var options []string
	for _, on := range sortedKeys(m.AuxLayouts) {
		a := m.AuxLayouts[on]
		kind := "none"
		if a.IsDynamicEligible {
			kind = fmt.Sprintf("some %d", a.DynamicKindByte)
		}
		options = append(options, fmt.Sprintf("{ outParam := %s, header := %s, kindByte := %s }", str(on), str(a.HeaderName), kind))
	}
	var stacks []string
	for _, sn := range sortedKeys(m.StackRefs) {
		st := m.StackRefs[sn]
		stacks = append(stacks, fmt.Sprintf("{ name := %s, header := %s, capacity := %d, elemBytes := %d, ownerOption := %s, offsetAfterOwner := %d }",
			str(sn), str(st.HeaderName), st.Capacity, st.ElemSize, str(st.OwnerOption), st.OffsetAfterOwner))
	}
	var tails, wbs []string
	for _, hn := range sortedKeys(s.HeaderAnnotations) {
		a := s.HeaderAnnotations[hn]
		if a.VariableTail != nil {
			t := a.VariableTail
			// VariableTailSpec.Base is added to the scaled length and MinTotal subtracted
			// from it (parser_trail.go), so they map to LenExpr.addend / base.
			tails = append(tails, fmt.Sprintf("(%s, %s)", str(hn), lenExpr(&vocab.HeaderLength{LenByteOff: t.LenFieldByteOff, LenMask: t.LenMask, LenShift: t.LenShift, Scale: t.Scale, Base: t.MinTotal, Addend: t.Base})))
		}
		if a.WriteBack != nil {
			wbs = append(wbs, fmt.Sprintf("(%s, ⟨%d, %d⟩)", str(hn), a.WriteBack.SourceByteOff, a.WriteBack.ParentByteOff))
		}
	}
	return fmt.Sprintf("{\n          states := [\n            %s],\n          entry := %d,\n          headers := [%s],\n          options := [%s],\n          stacks := [%s],\n          tails := [%s],\n          writebacks := [%s] }",
		strings.Join(states, ",\n            "), m.EntryIdx, strings.Join(headers, ", "), strings.Join(options, ", "),
		strings.Join(stacks, ", "), strings.Join(tails, ", "), strings.Join(wbs, ", "))
}
