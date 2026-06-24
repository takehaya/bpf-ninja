package vocab

import (
	"fmt"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
)

// Annotation names recognised by the loader. Hoisting these to
// constants makes a rename grep-safe across `.p4` files and Go code,
// and surfaces typos at compile time inside the loader itself.
const (
	annKunaiVariableTail = "kunai_variable_tail"
	annKunaiWriteback    = "kunai_writeback"
	annKunaiOptionSeg    = "kunai_option_segment"
	annKunaiLayout       = "kunai_layout"
	annKunaiStackCount   = "kunai_stack_count"
)

// stackLayoutAfterPrimary is the magic identifier the @kunai_layout
// annotation uses to anchor an aux stack at the end of the primary
// header. Future extension: `after=<other_stack>` walks the chain to
// support multiple concurrent declare-only stacks.
const stackLayoutAfterPrimary = "primary"

// readParserParamLayouts walks the parser block's parameter list and
// lowers each @kunai_layout decorator into a StackLayoutSpec keyed by
// the parameter name. Only declare-only aux stacks (= `out X[N] name`
// parameters never pushed inside a parser state) need this; the
// caller filters by the "is this stack pushed somewhere?" criterion
// after both `readParserParamLayouts` and the parser-machine pass
// have run.
//
// The annotation grammar is `@kunai_layout[after=<IDENT>]` where the
// identifier is either the literal `primary` (= anchor at the primary
// header's byte end) or another stack's parameter name (chain — not
// yet supported; reserved for a follow-up that walks dependencies).
func readParserParamLayouts(file *p4lite.File, source string) (map[string]*StackLayoutSpec, error) {
	var out map[string]*StackLayoutSpec
	err := forEachParserParamAnnotation(file, annKunaiLayout, stackLayoutAllowedKeys, source, func(prm *p4lite.Param, ann p4lite.Annotation) error {
		afterVal, ok := ann.KVs["after"]
		if !ok {
			return fmt.Errorf("%s:%s: @%s on parameter %q is missing required key `after`", source, ann.Pos, annKunaiLayout, prm.VarName)
		}
		if afterVal.Kind != p4lite.AnnotationIdent {
			return fmt.Errorf("%s:%s: @%s.after must be an identifier (got %v)", source, ann.Pos, annKunaiLayout, afterVal.Kind)
		}
		if out == nil {
			out = make(map[string]*StackLayoutSpec)
		}
		out[prm.VarName] = &StackLayoutSpec{After: afterVal.Ident}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// resolveStackLayouts fills BaseByteOff on each StackLayoutSpec.
// `after=primary` anchors at the primary header's byte end;
// `after=<other_stack>` references another aux stack and resolves to
// (upstream.BaseByteOff + upstream_capacity * upstream_elem_bytes).
//
// Chains are resolved iteratively (fixed-point) so declaration order
// doesn't matter. A cycle aborts with a clear diagnostic; an unknown
// anchor (= referenced name is neither "primary" nor a declared
// stack) also errors loudly.
func resolveStackLayouts(spec *ProtocolSpec) error {
	if len(spec.StackLayouts) == 0 {
		return nil
	}
	primaryBits := SumBits(spec.Fields)
	if primaryBits%8 != 0 {
		return fmt.Errorf("%s: primary header of %q is %d bits (not byte-aligned); cannot resolve @kunai_layout base", spec.Source, spec.Name, primaryBits)
	}
	primaryBytes := primaryBits / 8

	resolved := make(map[string]bool, len(spec.StackLayouts))
	pending := make(map[string]bool, len(spec.StackLayouts))
	for name := range spec.StackLayouts {
		pending[name] = true
	}

	progress := true
	for len(pending) > 0 && progress {
		progress = false
		for name := range pending {
			layout := spec.StackLayouts[name]
			switch {
			case layout.After == stackLayoutAfterPrimary:
				layout.BaseByteOff = primaryBytes
				resolved[name] = true
				delete(pending, name)
				progress = true
			case spec.StackLayouts[layout.After] != nil:
				if !resolved[layout.After] {
					continue
				}
				upstream := spec.StackLayouts[layout.After]
				span, err := stackSpanBytes(spec, layout.After)
				if err != nil {
					return fmt.Errorf("%s: @kunai_layout on %q (after=%q): %w", spec.Source, name, layout.After, err)
				}
				layout.BaseByteOff = upstream.BaseByteOff + span
				resolved[name] = true
				delete(pending, name)
				progress = true
			default:
				return fmt.Errorf("%s: @kunai_layout on %q references unknown anchor %q (must be %q or another parser-parameter stack name)", spec.Source, name, layout.After, stackLayoutAfterPrimary)
			}
		}
	}
	if len(pending) > 0 {
		names := make([]string, 0, len(pending))
		for n := range pending {
			names = append(names, n)
		}
		return fmt.Errorf("%s: @kunai_layout chain has a cycle or forward reference among %v", spec.Source, names)
	}
	return nil
}

// stackSpanBytes returns the on-wire byte span of a parser-parameter
// stack: capacity × sizeof(its header type). The parser parameter
// list is the source of truth for capacity (= [N]), and file.Headers
// for the per-element bit width.
func stackSpanBytes(spec *ProtocolSpec, stackName string) (int, error) {
	if spec.File == nil {
		return 0, fmt.Errorf("spec %q has no parsed file; cannot compute span of %q", spec.Name, stackName)
	}
	var prm *p4lite.Param
	for _, par := range spec.File.Parsers {
		for i := range par.Params {
			if par.Params[i].VarName == stackName {
				prm = &par.Params[i]
				break
			}
		}
		if prm != nil {
			break
		}
	}
	if prm == nil {
		return 0, fmt.Errorf("stack %q is not a parser parameter", stackName)
	}
	if !prm.IsArray {
		return 0, fmt.Errorf("stack %q is not an array parameter (`out X[N]`)", stackName)
	}
	var hdr *p4lite.Header
	for _, h := range spec.File.Headers {
		if h.Name == prm.TypeName {
			hdr = h
			break
		}
	}
	if hdr == nil {
		return 0, fmt.Errorf("stack %q references unknown header type %q", stackName, prm.TypeName)
	}
	bits := 0
	for _, f := range hdr.Fields {
		bits += f.Bits
	}
	if bits%8 != 0 {
		return 0, fmt.Errorf("header %q is %d bits (not byte-aligned); element size for stack %q is undefined", prm.TypeName, bits, stackName)
	}
	return prm.ArraySize * (bits / 8), nil
}

// validateDeclareOnlyStacks ensures every top-level declare-only aux
// stack carries a @kunai_layout annotation. "Top-level" excludes
// owner-bound stacks (e.g. TCP SACK blocks, IPv4 RR addrs) — those are
// reached via 5-part option-walk paths whose resolver uses the option
// dispatch's slot prelude for the base, not stackBaseOffsetInLayer.
// Only stacks queried via the 3-part `<proto>.<stack>[N].<field>`
// path are at risk of aliasing in resolveStackLayouts/where.go, so the
// annotation requirement is scoped to them.
func validateDeclareOnlyStacks(spec *ProtocolSpec) error {
	if spec.File == nil {
		return nil
	}
	pushed := pushedStackNames(spec)
	owned := ownerBoundStackNames(spec)
	for _, par := range spec.File.Parsers {
		for _, prm := range par.Params {
			if !prm.IsOut || !prm.IsArray {
				continue
			}
			if pushed[prm.VarName] || owned[prm.VarName] {
				continue
			}
			if spec.StackLayouts == nil || spec.StackLayouts[prm.VarName] == nil {
				return fmt.Errorf("%s:%s: top-level declare-only aux stack %q has no @kunai_layout annotation (required so multiple un-pushed stacks don't alias onto the same byte offset; use @kunai_layout[after=primary] for SRv6-style segment lists)", spec.Source, prm.Pos, prm.VarName)
			}
		}
	}
	return nil
}

func pushedStackNames(spec *ProtocolSpec) map[string]bool {
	out := make(map[string]bool)
	if spec.ParseStateMachine == nil {
		return out
	}
	for _, st := range spec.ParseStateMachine.States {
		for _, ex := range st.Extracts {
			if ex.IsStackPush {
				out[ex.StackName] = true
			}
		}
	}
	return out
}

func ownerBoundStackNames(spec *ProtocolSpec) map[string]bool {
	out := make(map[string]bool)
	if spec.ParseStateMachine == nil {
		return out
	}
	for name, stack := range spec.ParseStateMachine.StackRefs {
		if stack.OwnerOption != "" {
			out[name] = true
		}
	}
	return out
}

// Allowed-key sets per parser-param annotation, hoisted to package
// scope so the no-annotation common case (= every protocol except
// srv6 today) doesn't allocate a transient map per loadFile.
var (
	stackLayoutAllowedKeys = map[string]bool{"after": true}
	stackCountAllowedKeys  = map[string]bool{"field": true, "offset": true}
)

// forEachParserParamAnnotation walks each parser parameter's
// @<annName> annotation across all parser blocks in file. The helper
// owns the structural preconditions every param-level kunai annotation
// needs — allowed-key validation, IsOut + IsArray shape check,
// duplicate-per-param dedup — so per-reader callbacks only handle
// annotation-specific key decoding. Returning an error halts
// iteration and propagates up.
func forEachParserParamAnnotation(
	file *p4lite.File,
	annName string,
	allowedKeys map[string]bool,
	source string,
	fn func(prm *p4lite.Param, ann p4lite.Annotation) error,
) error {
	if file == nil {
		return nil
	}
	seen := make(map[string]bool)
	for _, par := range file.Parsers {
		for i := range par.Params {
			prm := &par.Params[i]
			for _, ann := range prm.Annotations {
				if ann.Name != annName {
					continue
				}
				if err := requireKnownKeys(ann, allowedKeys, source); err != nil {
					return err
				}
				if !prm.IsOut || !prm.IsArray {
					return fmt.Errorf("%s:%s: @%s only applies to `out X[N] name` parameters (got %q)", source, ann.Pos, annName, prm.VarName)
				}
				if seen[prm.VarName] {
					return fmt.Errorf("%s:%s: parameter %q has multiple @%s annotations", source, ann.Pos, prm.VarName, annName)
				}
				seen[prm.VarName] = true
				if err := fn(prm, ann); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// readParserParamCounts lowers each @kunai_stack_count decorator on a
// parser parameter into a StackCountSpec keyed by parameter name.
// The annotation names a primary-header field whose byte value (plus
// an optional integer offset) gives the stack's runtime element count
// for `any/all` quantifiers. Resolution requires the primary header's
// field layout, so the caller supplies the parsed `[]Field` slice.
func readParserParamCounts(file *p4lite.File, primaryFields []Field, source string) (map[string]*StackCountSpec, error) {
	var out map[string]*StackCountSpec
	err := forEachParserParamAnnotation(file, annKunaiStackCount, stackCountAllowedKeys, source, func(prm *p4lite.Param, ann p4lite.Annotation) error {
		fieldVal, ok := ann.KVs["field"]
		if !ok {
			return fmt.Errorf("%s:%s: @%s on parameter %q is missing required key `field`", source, ann.Pos, annKunaiStackCount, prm.VarName)
		}
		if fieldVal.Kind != p4lite.AnnotationIdent {
			return fmt.Errorf("%s:%s: @%s.field must be an identifier (got %v)", source, ann.Pos, annKunaiStackCount, fieldVal.Kind)
		}
		bitOff, bits, found := BitOffsetIn(primaryFields, fieldVal.Ident)
		if !found {
			return fmt.Errorf("%s:%s: @%s.field references unknown field %q in primary header", source, ann.Pos, annKunaiStackCount, fieldVal.Ident)
		}
		if bits != 8 || bitOff%8 != 0 {
			return fmt.Errorf("%s:%s: @%s.field %q must be a byte-aligned 8-bit field (got bit offset %d, %d bits wide)", source, ann.Pos, annKunaiStackCount, fieldVal.Ident, bitOff, bits)
		}
		addend := 0
		if oVal, ok := ann.KVs["offset"]; ok {
			if oVal.Kind != p4lite.AnnotationInt {
				return fmt.Errorf("%s:%s: @%s.offset must be an int literal", source, ann.Pos, annKunaiStackCount)
			}
			addend = int(oVal.Int)
		}
		if out == nil {
			out = make(map[string]*StackCountSpec)
		}
		out[prm.VarName] = &StackCountSpec{
			ByteOff: bitOff / 8,
			Addend:  addend,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// deriveStackCountsFromCounters synthesises StackCountSpec entries for
// aux stacks whose runtime element count falls out of an element-driven
// ParserCounter walk — the mechanism that replaces the explicit
// @kunai_stack_count annotation. The shape it recognises is fully
// generic (no protocol name): a state that pushes `extract(<stack>.next)`
// AND decrements a counter by one element per push, where that counter
// was seeded by the bare-cast add form `pc.set((bit<N>)(hdr.<F> + K))`
// (Scale==1). The seed field's byte gives the per-element count base and
// K the addend (SRH: field=last_entry, K=1 → count = last_entry + 1).
//
// Byte-driven counters (Scale==8, e.g. a region-length walk) are
// skipped: their count is a byte length, not an element count, so they
// carry no per-stack element semantics. Returns nil when no stack
// qualifies. Entries here are merged under annotation priority by the
// caller, so an explicit @kunai_stack_count always wins.
func deriveStackCountsFromCounters(machine *ParseStateMachine) map[string]*StackCountSpec {
	if machine == nil {
		return nil
	}
	var out map[string]*StackCountSpec
	for _, st := range machine.States {
		// Find a stack push and an element-granular decrement in the
		// same state (the canonical `consume_seg` shape). The decrement
		// must subtract exactly one (LiteralBytes==1) so the counter
		// counts elements, not bytes.
		var stackName, counterName string
		for _, ex := range st.Extracts {
			if ex.IsStackPush {
				stackName = ex.StackName
				break
			}
		}
		if stackName == "" {
			continue
		}
		for _, op := range st.Counters {
			if op.Kind == CounterOpDecrement && op.LiteralBytes == 1 {
				counterName = op.Counter
				break
			}
		}
		if counterName == "" {
			continue
		}
		// The seeding set op (typically in `start`) for this counter
		// carries the element-count expression. Require the bare-cast
		// add form (Scale==1, no Base subtract) so a byte-driven set is
		// never mistaken for an element count.
		set := counterSetOp(machine.States, counterName)
		if set == nil || set.Skip == nil || set.Skip.Scale != 1 || set.Skip.Base != 0 {
			continue
		}
		if out == nil {
			out = make(map[string]*StackCountSpec)
		}
		out[stackName] = &StackCountSpec{
			ByteOff: set.Skip.LenByteOff,
			Addend:  set.Skip.Addend,
		}
	}
	return out
}

// counterSetOp returns the CounterOpSet for the named counter, or nil.
// Mirrors CounterSetSkipForCounter but returns the whole op so the
// caller can read both the seed field offset and the addend.
func counterSetOp(states []*ParseState, counterName string) *CounterOp {
	for _, s := range states {
		for i := range s.Counters {
			op := &s.Counters[i]
			if op.Kind == CounterOpSet && op.Counter == counterName {
				return op
			}
		}
	}
	return nil
}

// readParserOptionSegment scans the parser block's @-decorators for
// @kunai_option_segment[name=IDENT]. Returns the declared segment
// name or the empty string when no override exists; the loader treats
// empty as "use the default of 'options'".
func readParserOptionSegment(file *p4lite.File, source string) (string, error) {
	if file == nil {
		return "", nil
	}
	allowed := map[string]bool{"name": true}
	for _, par := range file.Parsers {
		for _, ann := range par.Annotations {
			if ann.Name != annKunaiOptionSeg {
				continue
			}
			if err := requireKnownKeys(ann, allowed, source); err != nil {
				return "", err
			}
			v, ok := ann.KVs["name"]
			if !ok {
				return "", fmt.Errorf("%s:%s: @kunai_option_segment is missing required key `name`", source, ann.Pos)
			}
			if v.Kind != p4lite.AnnotationIdent {
				return "", fmt.Errorf("%s:%s: @kunai_option_segment.name must be an identifier", source, ann.Pos)
			}
			return v.Ident, nil
		}
	}
	return "", nil
}

// readHeaderAnnotations walks every header declaration in file and
// lowers kunai-recognised @-decorators into HeaderAnnotations entries
// keyed by header name. Unrecognised annotation names are tolerated
// so authors can pin future-reserved hints without a parser flag day;
// the keys of every recognised annotation are checked strictly so a
// typo fails loudly rather than silently no-op'ing.
//
// Cross-protocol field references inside @kunai_writeback are parsed
// but not resolved — the loader's pass-2 fills ParentByteOff once
// every spec is in scope.
func readHeaderAnnotations(file *p4lite.File, source string) (map[string]*HeaderAnnotations, error) {
	if file == nil {
		return nil, nil
	}
	out := make(map[string]*HeaderAnnotations)
	for _, h := range file.Headers {
		for _, ann := range h.Annotations {
			switch ann.Name {
			case annKunaiVariableTail:
				vt, err := lowerKunaiVariableTail(ann, h, source)
				if err != nil {
					return nil, err
				}
				entry := getOrCreateHeaderAnnotations(out, h.Name)
				if entry.VariableTail != nil {
					return nil, fmt.Errorf("%s:%s: header %q declares @kunai_variable_tail twice", source, ann.Pos, h.Name)
				}
				entry.VariableTail = vt
			case annKunaiWriteback:
				wb, err := lowerKunaiWriteback(ann, h, source)
				if err != nil {
					return nil, err
				}
				entry := getOrCreateHeaderAnnotations(out, h.Name)
				if entry.WriteBack != nil {
					return nil, fmt.Errorf("%s:%s: header %q declares @kunai_writeback twice", source, ann.Pos, h.Name)
				}
				entry.WriteBack = wb
			}
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func getOrCreateHeaderAnnotations(m map[string]*HeaderAnnotations, name string) *HeaderAnnotations {
	if e, ok := m[name]; ok {
		return e
	}
	e := &HeaderAnnotations{}
	m[name] = e
	return e
}

// lowerKunaiVariableTail validates and projects an
// @kunai_variable_tail[len_field=F, scale=S, mask=M, shift=N, base=B]
// decorator into VariableTailSpec. Required keys: len_field, scale.
// Optional keys: mask (defaults to the full field extraction mask),
// shift (defaults to 0), base (defaults to 0). The named field's
// declared bit layout drives the LenFieldByteOff / LenShift /
// field-extraction-mask intersection so authors don't repeat what
// the header schema already states.
func lowerKunaiVariableTail(ann p4lite.Annotation, h *p4lite.Header, source string) (*VariableTailSpec, error) {
	allowed := map[string]bool{"len_field": true, "scale": true, "mask": true, "shift": true, "base": true}
	if err := requireKnownKeys(ann, allowed, source); err != nil {
		return nil, err
	}
	lenFieldVal, ok := ann.KVs["len_field"]
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail on header %q is missing required key `len_field`", source, ann.Pos, h.Name)
	}
	if lenFieldVal.Kind != p4lite.AnnotationIdent {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.len_field must be an identifier (got %v)", source, ann.Pos, lenFieldVal.Kind)
	}
	bitOff, fieldBits, ok := findFieldBitWindow(h, lenFieldVal.Ident)
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.len_field references unknown field %q in header %q", source, ann.Pos, lenFieldVal.Ident, h.Name)
	}
	if (bitOff%8)+fieldBits > 8 {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.len_field %q crosses a byte boundary (bits [%d,%d) — only single-byte fields are supported)", source, ann.Pos, lenFieldVal.Ident, bitOff, bitOff+fieldBits)
	}
	scale, err := readIntAnnotation(ann, "scale", source)
	if err != nil {
		return nil, err
	}
	if scale <= 0 || scale&(scale-1) != 0 {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.scale must be a positive power of two (got %d)", source, ann.Pos, scale)
	}
	bitInByte := bitOff % 8
	lsbShift := 8 - bitInByte - fieldBits
	fieldExtractionMask := ((1 << fieldBits) - 1) << lsbShift
	mask := fieldExtractionMask
	if mTok, ok := ann.KVs["mask"]; ok {
		if mTok.Kind != p4lite.AnnotationInt {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.mask must be an int literal", source, ann.Pos)
		}
		if mTok.Int == 0 {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.mask=0 makes the trail length always zero — unintended", source, ann.Pos)
		}
		if mTok.Int >= (1 << fieldBits) {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.mask=0x%x exceeds the %d-bit field %q (max 0x%x)", source, ann.Pos, mTok.Int, fieldBits, lenFieldVal.Ident, (1<<fieldBits)-1)
		}
		mask = int(mTok.Int) << lsbShift
	}
	shift := lsbShift
	if sTok, ok := ann.KVs["shift"]; ok {
		if sTok.Kind != p4lite.AnnotationInt {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.shift must be an int literal", source, ann.Pos)
		}
		shift = int(sTok.Int)
	}
	base := 0
	if bTok, ok := ann.KVs["base"]; ok {
		if bTok.Kind != p4lite.AnnotationInt {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.base must be an int literal", source, ann.Pos)
		}
		base = int(bTok.Int)
	}
	return &VariableTailSpec{
		LenFieldByteOff: bitOff / 8,
		LenMask:         mask,
		LenShift:        shift,
		Scale:           scale,
		Base:            base,
	}, nil
}

// lowerKunaiWriteback validates @kunai_writeback[source=F, parent=P.F]
// and resolves SourceByteOff against the chained header's layout.
// ParentByteOff is left zero — the loader's pass-2 fills it after
// every protocol's primary header is in scope.
func lowerKunaiWriteback(ann p4lite.Annotation, h *p4lite.Header, source string) (*WriteBackSpec, error) {
	allowed := map[string]bool{"source": true, "parent": true}
	if err := requireKnownKeys(ann, allowed, source); err != nil {
		return nil, err
	}
	srcVal, ok := ann.KVs["source"]
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback on header %q is missing required key `source`", source, ann.Pos, h.Name)
	}
	if srcVal.Kind != p4lite.AnnotationIdent {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback.source must be an identifier", source, ann.Pos)
	}
	bitOff, fieldBits, ok := findFieldBitWindow(h, srcVal.Ident)
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback.source references unknown field %q in header %q", source, ann.Pos, srcVal.Ident, h.Name)
	}
	if fieldBits != 8 || bitOff%8 != 0 {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback.source field %q is not a byte-aligned 8-bit field (writeback is a single byte copy)", source, ann.Pos, srcVal.Ident)
	}
	parentVal, ok := ann.KVs["parent"]
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback on header %q is missing required key `parent`", source, ann.Pos, h.Name)
	}
	if parentVal.Kind != p4lite.AnnotationFieldRef {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback.parent must be a `proto.field` reference (e.g. `ipv6.next_header`)", source, ann.Pos)
	}
	return &WriteBackSpec{
		SourceField:   srcVal.Ident,
		ParentProto:   parentVal.Proto,
		ParentField:   parentVal.Field,
		SourceByteOff: bitOff / 8,
	}, nil
}

// requireKnownKeys errors when an annotation carries a key the
// recognised set doesn't accept. This catches `@kunai_writeback[srce=...]`
// typos at load time instead of silently no-op'ing them.
func requireKnownKeys(ann p4lite.Annotation, allowed map[string]bool, source string) error {
	for k := range ann.KVs {
		if !allowed[k] {
			return fmt.Errorf("%s:%s: @%s does not accept key %q", source, ann.Pos, ann.Name, k)
		}
	}
	return nil
}

func readIntAnnotation(ann p4lite.Annotation, key string, source string) (int, error) {
	v, ok := ann.KVs[key]
	if !ok {
		return 0, fmt.Errorf("%s:%s: @%s is missing required int key %q", source, ann.Pos, ann.Name, key)
	}
	if v.Kind != p4lite.AnnotationInt {
		return 0, fmt.Errorf("%s:%s: @%s.%s must be an int literal", source, ann.Pos, ann.Name, key)
	}
	return int(v.Int), nil
}

// resolveHeaderWritebackTargets fills ParentByteOff on every
// WriteBackSpec across the spec set. Run after every protocol's
// primary header is loaded so cross-protocol field references can be
// satisfied. The field must live in the parent's primary header and
// be a byte-aligned 8-bit slot for the codegen byte copy to land
// without extra masking.
func resolveHeaderWritebackTargets(specs map[string]*ProtocolSpec) error {
	for _, spec := range specs {
		for hname, hann := range spec.HeaderAnnotations {
			wb := hann.WriteBack
			if wb == nil {
				continue
			}
			parent, ok := specs[wb.ParentProto]
			if !ok {
				return fmt.Errorf("%s: @kunai_writeback on %q references unknown protocol %q", spec.Source, hname, wb.ParentProto)
			}
			bitOff, _, found := BitOffsetIn(parent.Fields, wb.ParentField)
			if !found {
				return fmt.Errorf("%s: @kunai_writeback on %q references unknown field %q in protocol %q", spec.Source, hname, wb.ParentField, wb.ParentProto)
			}
			if bitOff%8 != 0 {
				return fmt.Errorf("%s: @kunai_writeback on %q targets non-byte-aligned field %s.%s (bit offset %d)", spec.Source, hname, wb.ParentProto, wb.ParentField, bitOff)
			}
			wb.ParentByteOff = bitOff / 8
			wb.Resolved = true
		}
	}
	return nil
}


