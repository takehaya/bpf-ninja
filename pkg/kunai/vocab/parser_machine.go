package vocab

import (
	"fmt"
	"strings"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
)

// MVP caps for parser-state-machine compilation. These bound the
// codegen-time work and the verifier-side instruction count.
const (
	parserMachineMaxStates = 8 // reachable states (= states declared)
	parserMachineMaxKeys   = 3 // tuple-match keys per `transition select`
)

// buildCtx is the shared context the build helpers thread through —
// instead of taking 4 parameters each, they take this single value.
// The fields are immutable after construction and only the maps may
// be read (no write).
type buildCtx struct {
	headerRefs map[string]*p4lite.Header
	stackRefs  map[string]*HeaderStack
	stateIdx   map[string]int
	source     string
}

// buildParseStateMachine constructs a ParseStateMachine from a
// protocol's parser block, or returns nil when the block is the
// trivial "single state, extract primary header, transition accept"
// shape — codegen routes those through the legacy fixed-size path.
//
// Returns an error when the parser block uses constructs codegen
// does not support; the constraint list lives next to each check.
// The input file.Parsers[0].States slice is left unmodified; the
// resulting ParseStateMachine carries an EntryIdx field that points
// at the "start" state.
func buildParseStateMachine(file *p4lite.File, primary *p4lite.Header, source string) (*ParseStateMachine, error) {
	switch n := len(file.Parsers); n {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, fmt.Errorf("%s: %d parser blocks declared; MVP supports at most one", source, n)
	}
	p := file.Parsers[0]

	headerRefs, stackRefs, err := resolveParserParams(p, file, source)
	if err != nil {
		return nil, err
	}

	stateIdx, entryIdx, err := indexStates(p, source)
	if err != nil {
		return nil, err
	}
	if len(p.States) > parserMachineMaxStates {
		return nil, fmt.Errorf("%s:%s: parser %q has %d states; MVP cap is %d", source, p.Pos, p.Name, len(p.States), parserMachineMaxStates)
	}

	ctx := &buildCtx{
		headerRefs: headerRefs,
		stackRefs:  stackRefs,
		stateIdx:   stateIdx,
		source:     source,
	}
	states := make([]*ParseState, len(p.States))
	for i, s := range p.States {
		ps, err := buildState(s, ctx)
		if err != nil {
			return nil, err
		}
		states[i] = ps
	}

	if err := validateStateGraph(states, source); err != nil {
		return nil, err
	}

	if isTrivialMachine(states, entryIdx, primary) {
		return nil, nil
	}

	if err := assignStateOffsets(states, entryIdx, source); err != nil {
		return nil, err
	}

	auxLayouts, err := computeAuxLayouts(states, entryIdx, headerRefs, primary, source)
	if err != nil {
		return nil, err
	}

	return &ParseStateMachine{
		States:     states,
		StateIdx:   stateIdx,
		EntryIdx:   entryIdx,
		HeaderRefs: headerRefs,
		StackRefs:  stackRefs,
		AuxLayouts: auxLayouts,
	}, nil
}

// computeAuxLayouts walks the state machine to derive each aux header's
// byte offset within the layer and (when the aux is conditionally
// extracted) the gating predicate that decides whether the aux is
// present on a given packet's path. Stacks (out param tracked in
// stackRefs, not headerRefs) are deliberately skipped — they are
// addressed by aux header stack index access (PR-B), not single aux
// predicates.
//
// MVP scope for gating: the extracting state is either the entry
// state (= unconditional, gating nil) or a direct one-hop successor
// of the entry state via a tuple-select whose explicit case's values
// are all concrete zero with a default targeting the extracting
// state. That covers GTP's opt (E|S|PN gate). Other shapes return a
// build error so they cannot silently land as "always-present" auxes.
func computeAuxLayouts(states []*ParseState, entryIdx int, headerRefs map[string]*p4lite.Header, primary *p4lite.Header, source string) (map[string]*AuxLayout, error) {
	if len(headerRefs) == 0 {
		return nil, nil
	}
	out := map[string]*AuxLayout{}
	for outName, hdr := range headerRefs {
		// The primary header's `out` param is always one of headerRefs.
		// It is not an aux from the predicate codegen perspective —
		// primary fields are accessed via the existing 2-part path.
		if hdr == primary {
			continue
		}
		extractStateIdx, headerSizeBits, err := findUniqueAuxExtractor(states, outName, hdr, source)
		if err != nil {
			return nil, err
		}
		if extractStateIdx < 0 {
			// Aux declared but never extracted in any state. Predicate
			// codegen would have nothing to read; record as always-fail
			// gating so user-written predicates produce a clear error
			// rather than a silent miss.
			out[outName] = &AuxLayout{
				OutParam:   outName,
				HeaderName: hdr.Name,
				HeaderRef:  hdr,
				HeaderSize: headerSizeBits / 8,
			}
			continue
		}
		state := states[extractStateIdx]
		if state.OffsetAtEntry < 0 {
			return nil, fmt.Errorf("%s:%s: aux %q extracted at state %q whose static byte offset is undefined (stack-cycle path); single aux predicates require a unique offset", source, state.Pos, outName, state.Name)
		}
		gating, err := computeAuxGating(states, entryIdx, extractStateIdx, primary, source)
		if err != nil {
			return nil, err
		}
		out[outName] = &AuxLayout{
			OutParam:      outName,
			HeaderName:    hdr.Name,
			HeaderRef:     hdr,
			OffsetInLayer: state.OffsetAtEntry,
			HeaderSize:    headerSizeBits / 8,
			Gating:        gating,
		}
	}
	return out, nil
}

// findUniqueAuxExtractor scans all states for the (sole) state that
// performs `pkt.extract(<outName>)` against a non-stack out parameter.
// Returns (-1, headerSizeBits, nil) when the aux is declared but
// never extracted; an error when extracted by more than one state.
func findUniqueAuxExtractor(states []*ParseState, outName string, hdr *p4lite.Header, source string) (int, int, error) {
	idx := -1
	for i, s := range states {
		for _, ex := range s.Extracts {
			if ex.IsStackPush {
				continue
			}
			if ex.HeaderRef == hdr {
				if idx >= 0 {
					return -1, 0, fmt.Errorf("%s:%s: aux %q extracted by multiple states (%q and %q); single aux predicates require a unique extractor", source, s.Pos, outName, states[idx].Name, s.Name)
				}
				idx = i
			}
		}
	}
	return idx, totalBits(hdr), nil
}

// computeAuxGating derives the AuxGating that decides whether the
// extract state is reached on a given packet. Returns nil (no
// gating) when the extract state is the entry state. MVP only
// understands the GTP pattern: a one-hop tuple-select edge from
// entry where every explicit case value is the zero literal and
// the default targets the aux state. Anything else is an error so
// silent "always-present" landings are impossible.
func computeAuxGating(states []*ParseState, entryIdx, extractIdx int, primary *p4lite.Header, source string) (*AuxGating, error) {
	if extractIdx == entryIdx {
		return nil, nil
	}
	entry := states[entryIdx]
	switch entry.Trans.Kind {
	case TransDirect:
		if entry.Trans.Target == extractIdx {
			// Unconditional one-hop: no gating beyond the dispatch
			// that already gated entry into this layer.
			return nil, nil
		}
		return nil, fmt.Errorf("%s:%s: aux state %q is not reachable in one direct hop from entry; multi-hop gating not supported by MVP", source, entry.Pos, states[extractIdx].Name)
	case TransSelect:
		return gatingFromSelect(entry.Trans.Select, extractIdx, primary, source, entry.Pos)
	}
	return nil, fmt.Errorf("%s:%s: entry state transition kind %v cannot derive aux gating", source, entry.Pos, entry.Trans.Kind)
}

// gatingFromSelect handles the entry-state select shape. MVP
// pattern: the extract state is the default target and exactly one
// explicit case targets a non-extract state with all-zero values.
// (Symmetric pattern: extract state is the only explicit case with
// concrete values, default elsewhere.) Other shapes return an
// error.
func gatingFromSelect(sel *SelectOp, extractIdx int, primary *p4lite.Header, source string, pos p4lite.Position) (*AuxGating, error) {
	var explicit []SelectCase
	for _, c := range sel.Cases {
		if c.Target == extractIdx {
			explicit = append(explicit, c)
		}
	}
	defaultTargetsExtract := sel.Default == extractIdx
	switch {
	case defaultTargetsExtract && len(explicit) == 0:
		// Extract is the default branch. Gating: NOT (any explicit
		// case matches). MVP requires exactly one explicit case
		// whose values are all concrete zero, so the negation is
		// "the OR of the keys' bit-fields is non-zero".
		if len(sel.Cases) != 1 {
			return nil, fmt.Errorf("%s:%s: aux gating via default: MVP supports exactly one explicit case (got %d)", source, pos, len(sel.Cases))
		}
		c := sel.Cases[0]
		if len(c.Values) != len(sel.Keys) {
			return nil, fmt.Errorf("%s:%s: aux gating: case value count %d != key count %d", source, pos, len(c.Values), len(sel.Keys))
		}
		for _, v := range c.Values {
			if v.IsWildcard || v.Value != 0 {
				return nil, fmt.Errorf("%s:%s: aux gating via default requires explicit case all-zero, got %+v", source, pos, c.Values)
			}
		}
		return mergeBitFieldsToMask(sel.Keys, primary, GatingNe, 0, source, pos)
	case !defaultTargetsExtract && len(explicit) == 1:
		// Symmetric: extract is the unique explicit case. Gating
		// values must all be concrete (no wildcard).
		c := explicit[0]
		if len(c.Values) != len(sel.Keys) {
			return nil, fmt.Errorf("%s:%s: aux gating: case value count %d != key count %d", source, pos, len(c.Values), len(sel.Keys))
		}
		// MVP: single key with concrete value, single byte field.
		if len(sel.Keys) != 1 {
			return nil, fmt.Errorf("%s:%s: aux gating via explicit case: MVP supports a single key (got %d)", source, pos, len(sel.Keys))
		}
		if c.Values[0].IsWildcard {
			return nil, fmt.Errorf("%s:%s: aux gating via explicit case requires concrete value", source, pos)
		}
		return mergeBitFieldsToMask(sel.Keys, primary, GatingEq, c.Values[0].Value, source, pos)
	}
	return nil, fmt.Errorf("%s:%s: aux gating shape unsupported (default→extract:%v, explicit cases:%d)", source, pos, defaultTargetsExtract, len(explicit))
}

// mergeBitFieldsToMask folds a tuple of single-byte primary-header
// keys into one (byteOffset, mask) pair so codegen can emit a single
// byte read followed by an AND + compare. All keys must live in the
// primary header within the same byte, with no straddle.
func mergeBitFieldsToMask(keys []FieldRef, primary *p4lite.Header, op GatingOp, value uint64, source string, pos p4lite.Position) (*AuxGating, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s:%s: aux gating: no select keys", source, pos)
	}
	byteOff := -1
	var mask uint64
	for i, k := range keys {
		if k.HeaderName != primary.Name {
			return nil, fmt.Errorf("%s:%s: aux gating key %d (%s.%s) is not in the primary header %q", source, pos, i, k.HeaderName, k.FieldName, primary.Name)
		}
		if k.IsStackLast {
			return nil, fmt.Errorf("%s:%s: aux gating key %d uses stack.last; MVP does not support that", source, pos, i)
		}
		bitInByte := k.BitOffset % 8
		if bitInByte+k.BitWidth > 8 {
			return nil, fmt.Errorf("%s:%s: aux gating key %s straddles a byte boundary (bit-off %d, width %d)", source, pos, k.FieldName, k.BitOffset, k.BitWidth)
		}
		keyByte := k.BitOffset / 8
		if byteOff < 0 {
			byteOff = keyByte
		} else if byteOff != keyByte {
			return nil, fmt.Errorf("%s:%s: aux gating keys span multiple bytes (%d vs %d); MVP requires a single byte", source, pos, byteOff, keyByte)
		}
		// Within the byte, the field's most-significant bit sits at
		// bitInByte (counting from the byte's MSB). Network/P4 byte
		// order: the MSB of the byte is the value-bit (1 << 7) when
		// the byte is read as a u8.
		keyMask := ((uint64(1) << k.BitWidth) - 1) << (8 - bitInByte - k.BitWidth)
		if keyMask&mask != 0 {
			return nil, fmt.Errorf("%s:%s: aux gating keys overlap (mask collision %#x)", source, pos, keyMask&mask)
		}
		mask |= keyMask
	}
	if mask == 0 || mask > 0xFF {
		return nil, fmt.Errorf("%s:%s: aux gating mask %#x out of single-byte range", source, pos, mask)
	}
	return &AuxGating{ByteOff: byteOff, Mask: mask, Op: op, Value: value}, nil
}

// assignStateOffsets populates ParseState.OffsetAtEntry for every
// reachable state by DFS from the entry state. Edges that would push
// a stack header (gtp ext, ipv6 ext, srv6 segments) leave the
// destination's per-iteration offset undefined — those states keep
// OffsetAtEntry == -1 so predicate codegen routes through the
// loop-aware path instead of treating offsets as static. Conflicts
// (a state reached via two paths with different cumulative byte
// distances) are surfaced as build errors so silent miscomputes
// cannot ride into codegen.
func assignStateOffsets(states []*ParseState, entryIdx int, source string) error {
	for _, s := range states {
		s.OffsetAtEntry = -1
	}
	type frame struct{ idx, off int }
	stack := []frame{{entryIdx, 0}}
	for len(stack) > 0 {
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if fr.idx < 0 || fr.idx >= len(states) {
			continue
		}
		s := states[fr.idx]
		if s.OffsetAtEntry >= 0 {
			if s.OffsetAtEntry != fr.off {
				return fmt.Errorf("%s:%s: state %q is reachable at two distinct byte offsets (%d vs %d); aux predicate static offsets undefined", source, s.Pos, s.Name, s.OffsetAtEntry, fr.off)
			}
			continue
		}
		s.OffsetAtEntry = fr.off
		// Cumulative byte advance after this state's extracts. Stack
		// pushes (gtp_ext_h.next, ipv6_ext_h.next, ...) advance the
		// physical R4, but successors that are themselves the same
		// state (= self-loop) are deliberately skipped from offset
		// propagation: each iteration starts at the prior iteration's
		// post-extract position, which is dynamic — the static
		// offset model cannot capture it. Same edge taken by direct
		// transitions keeps the linear accumulation valid.
		nextOff, hasStackPush := postExtractOffset(s, fr.off)
		for _, succ := range stateSuccessors(s) {
			if hasStackPush && succ == fr.idx {
				// Self-loop on a stack-pushing state: don't propagate
				// the post-extract offset back to itself, the next
				// iteration's entry offset is dynamic.
				continue
			}
			stack = append(stack, frame{succ, nextOff})
		}
	}
	return nil
}

// postExtractOffset returns the byte distance from layer entry to R4
// after running a state's Extracts. The bool reports whether any of
// the extracts is a stack push (= variable / loop-driven advance from
// the perspective of static offset tracking).
func postExtractOffset(s *ParseState, entryOff int) (int, bool) {
	off := entryOff
	hasStackPush := false
	for _, ex := range s.Extracts {
		off += ex.HeaderSize / 8
		if ex.IsStackPush {
			hasStackPush = true
		}
	}
	return off, hasStackPush
}

// resolveParserParams binds each `out <type> <var>` (or `out <type>[N]
// <var>`) parameter of the parser block to a header in the same .p4
// file. `packet_in` parameters are skipped — they're a P4 type, not a
// header binding.
func resolveParserParams(p *p4lite.Parser, file *p4lite.File, source string) (map[string]*p4lite.Header, map[string]*HeaderStack, error) {
	headerRefs := map[string]*p4lite.Header{}
	stackRefs := map[string]*HeaderStack{}
	for i := range p.Params {
		param := &p.Params[i]
		if param.IsPacketIn {
			continue
		}
		if !param.IsOut {
			return nil, nil, fmt.Errorf("%s:%s: parser param %q has direction other than `out` or `packet_in` (MVP only supports those two)", source, param.Pos, param.VarName)
		}
		h := findHeader(file, param.TypeName)
		if h == nil {
			return nil, nil, fmt.Errorf("%s:%s: parser param %q references unknown header type %q", source, param.Pos, param.VarName, param.TypeName)
		}
		if param.IsArray {
			elemBits := totalBits(h)
			if elemBits%8 != 0 {
				return nil, nil, fmt.Errorf("%s:%s: header %q is %d bits (not byte-aligned), cannot be a parser stack element", source, param.Pos, h.Name, elemBits)
			}
			stackRefs[param.VarName] = &HeaderStack{
				HeaderName: h.Name,
				HeaderRef:  h,
				Capacity:   param.ArraySize,
				ElemSize:   elemBits / 8,
			}
		} else {
			headerRefs[param.VarName] = h
		}
	}
	return headerRefs, stackRefs, nil
}

// indexStates builds a name→index map and locates the entry "start"
// state. The original p.States order is preserved; the returned
// entryIdx points the caller at start.
func indexStates(p *p4lite.Parser, source string) (map[string]int, int, error) {
	idx := map[string]int{}
	for i, s := range p.States {
		if _, dup := idx[s.Name]; dup {
			return nil, 0, fmt.Errorf("%s:%s: duplicate state name %q", source, s.Pos, s.Name)
		}
		idx[s.Name] = i
	}
	startIdx, ok := idx["start"]
	if !ok {
		return nil, 0, fmt.Errorf("%s:%s: parser %q has no `start` state (P4-16 mandatory)", source, p.Pos, p.Name)
	}
	return idx, startIdx, nil
}

// buildState turns one p4lite.State into a ParseState with resolved
// header references, byte-aligned extract sizes, and a TransitionOp
// pointing at concrete state indices.
func buildState(s *p4lite.State, ctx *buildCtx) (*ParseState, error) {
	ps := &ParseState{Name: s.Name, Pos: s.Pos}

	pushCount := 0
	for _, stmt := range s.Stmts {
		es, ok := stmt.(*p4lite.ExtractStmt)
		if !ok {
			return nil, fmt.Errorf("%s:%s: state %q contains an unsupported statement (only `pkt.extract(...)` is allowed)", ctx.source, s.Pos, s.Name)
		}
		op, err := buildExtract(es, ctx)
		if err != nil {
			return nil, err
		}
		if op.IsStackPush {
			pushCount++
		}
		ps.Extracts = append(ps.Extracts, op)
	}
	if pushCount > 1 {
		return nil, fmt.Errorf("%s:%s: state %q pushes %d stack entries; MVP allows at most one stack push per state", ctx.source, s.Pos, s.Name, pushCount)
	}

	trans, err := buildTransition(s.Transition, ctx)
	if err != nil {
		return nil, err
	}
	ps.Trans = trans
	return ps, nil
}

// buildExtract resolves an `obj.extract(<var>)` or
// `obj.extract(<stack>.next)` statement against the parser's `out`
// parameters. The resolved header must be byte-aligned in size — the
// runtime advance / bounds check work in whole bytes.
func buildExtract(es *p4lite.ExtractStmt, ctx *buildCtx) (ExtractOp, error) {
	if es.IsNext {
		st, ok := ctx.stackRefs[es.Target]
		if !ok {
			return ExtractOp{}, fmt.Errorf("%s:%s: extract(%s.next) targets parser variable %q which is not a header stack", ctx.source, es.Pos, es.Target, es.Target)
		}
		bits := totalBits(st.HeaderRef)
		return ExtractOp{
			HeaderName:  st.HeaderName,
			HeaderRef:   st.HeaderRef,
			HeaderSize:  bits,
			IsStackPush: true,
			StackName:   es.Target,
			Pos:         es.Pos,
		}, nil
	}
	h, ok := ctx.headerRefs[es.Target]
	if !ok {
		return ExtractOp{}, fmt.Errorf("%s:%s: extract(%s) targets parser variable %q which is not an `out` header parameter", ctx.source, es.Pos, es.Target, es.Target)
	}
	bits := totalBits(h)
	if bits%8 != 0 {
		return ExtractOp{}, fmt.Errorf("%s:%s: extract target header %q is %d bits (not byte-aligned)", ctx.source, es.Pos, h.Name, bits)
	}
	return ExtractOp{
		HeaderName: h.Name,
		HeaderRef:  h,
		HeaderSize: bits,
		Pos:        es.Pos,
	}, nil
}

// buildTransition resolves accept/reject sentinels, direct state
// names, and `select` keys+cases.
func buildTransition(t *p4lite.Transition, ctx *buildCtx) (TransitionOp, error) {
	if t == nil {
		return TransitionOp{}, fmt.Errorf("%s: state has no transition", ctx.source)
	}
	switch t.Kind {
	case p4lite.TransAccept:
		return TransitionOp{Kind: TransAccept, Target: StateAccept}, nil
	case p4lite.TransReject:
		return TransitionOp{Kind: TransReject, Target: StateReject}, nil
	case p4lite.TransDirect:
		idx, err := resolveTransitionTarget(t.Target, ctx, t.Pos)
		if err != nil {
			return TransitionOp{}, err
		}
		return TransitionOp{Kind: TransDirect, Target: idx}, nil
	case p4lite.TransSelect:
		sel, err := buildSelect(t.Select, ctx)
		if err != nil {
			return TransitionOp{}, err
		}
		return TransitionOp{Kind: TransSelect, Select: sel}, nil
	}
	return TransitionOp{}, fmt.Errorf("%s:%s: unknown transition kind %d", ctx.source, t.Pos, t.Kind)
}

// buildSelect normalises a `transition select(...)` block. Each key
// must resolve to a bit-window inside one of the parser's bound
// headers; each case's value tuple length must equal the key count.
// Default is StateReject when no explicit `default` case is present:
// the P4-16 spec leaves that scenario unspecified, and reject gives
// codegen a deterministic fall-through.
func buildSelect(sel *p4lite.Select, ctx *buildCtx) (*SelectOp, error) {
	if len(sel.Keys) == 0 {
		return nil, fmt.Errorf("%s:%s: `transition select` with no keys", ctx.source, sel.Pos)
	}
	if len(sel.Keys) > parserMachineMaxKeys {
		return nil, fmt.Errorf("%s:%s: `transition select` has %d keys; MVP cap is %d", ctx.source, sel.Pos, len(sel.Keys), parserMachineMaxKeys)
	}
	keys := make([]FieldRef, len(sel.Keys))
	for i, k := range sel.Keys {
		ref, err := resolveFieldRef(k, ctx, sel.Pos)
		if err != nil {
			return nil, err
		}
		keys[i] = ref
	}

	out := &SelectOp{Keys: keys, Default: StateReject, Pos: sel.Pos}
	defaultSeen := false
	for _, c := range sel.Cases {
		target, err := resolveTransitionTarget(c.Target, ctx, c.Pos)
		if err != nil {
			return nil, err
		}
		if c.IsDefault {
			if defaultSeen {
				return nil, fmt.Errorf("%s:%s: `transition select` has two `default` cases", ctx.source, c.Pos)
			}
			out.Default = target
			defaultSeen = true
			continue
		}
		if len(c.Values) != len(keys) {
			return nil, fmt.Errorf("%s:%s: `select` case has %d values but %d keys", ctx.source, c.Pos, len(c.Values), len(keys))
		}
		vals := make([]MatchVal, len(c.Values))
		for i, m := range c.Values {
			vals[i] = MatchVal{IsWildcard: m.IsWildcard, Value: m.Value}
		}
		out.Cases = append(out.Cases, SelectCase{Values: vals, Target: target, Pos: c.Pos})
	}
	return out, nil
}

// resolveTransitionTarget maps "accept" / "reject" / state-name to a
// state index sentinel. Codegen reads the integer directly.
func resolveTransitionTarget(target string, ctx *buildCtx, pos p4lite.Position) (int, error) {
	switch target {
	case "accept":
		return StateAccept, nil
	case "reject":
		return StateReject, nil
	}
	idx, ok := ctx.stateIdx[target]
	if !ok {
		return 0, fmt.Errorf("%s:%s: transition target %q is not a known state", ctx.source, pos, target)
	}
	return idx, nil
}

// resolveFieldRef parses a dotted select-key path
// ("hdr.field" or "stack.last.field") and binds it to a bit-window
// of a known header.
func resolveFieldRef(keyPath string, ctx *buildCtx, pos p4lite.Position) (FieldRef, error) {
	parts := strings.Split(keyPath, ".")
	if len(parts) < 2 {
		return FieldRef{}, fmt.Errorf("%s:%s: select key %q has no field component", ctx.source, pos, keyPath)
	}
	head := parts[0]
	if h, ok := ctx.headerRefs[head]; ok {
		if len(parts) != 2 {
			return FieldRef{}, fmt.Errorf("%s:%s: select key %q references nested field; only `header.field` is supported", ctx.source, pos, keyPath)
		}
		bitOff, bitWidth, found := findFieldBitWindow(h, parts[1])
		if !found {
			return FieldRef{}, fmt.Errorf("%s:%s: select key %q references unknown field %q in header %q", ctx.source, pos, keyPath, parts[1], h.Name)
		}
		return FieldRef{
			HeaderName: h.Name,
			HeaderRef:  h,
			FieldName:  parts[1],
			BitOffset:  bitOff,
			BitWidth:   bitWidth,
		}, nil
	}
	if st, ok := ctx.stackRefs[head]; ok {
		if len(parts) != 3 || parts[1] != "last" {
			return FieldRef{}, fmt.Errorf("%s:%s: select key %q on stack %q must be %s.last.<field>", ctx.source, pos, keyPath, head, head)
		}
		bitOff, bitWidth, found := findFieldBitWindow(st.HeaderRef, parts[2])
		if !found {
			return FieldRef{}, fmt.Errorf("%s:%s: select key %q references unknown field %q in stack header %q", ctx.source, pos, keyPath, parts[2], st.HeaderRef.Name)
		}
		return FieldRef{
			HeaderName:  st.HeaderName,
			HeaderRef:   st.HeaderRef,
			IsStackLast: true,
			StackName:   head,
			FieldName:   parts[2],
			BitOffset:   bitOff,
			BitWidth:    bitWidth,
		}, nil
	}
	return FieldRef{}, fmt.Errorf("%s:%s: select key %q references unknown parser parameter %q", ctx.source, pos, keyPath, head)
}

// validateStateGraph rejects cycles other than self-loops. Self-loops
// (state X transitioning to X) lower naturally to a bpf_loop callback;
// multi-state cycles would need an irreducible CFG that the codegen
// has no reason to support today.
func validateStateGraph(states []*ParseState, source string) error {
	for i, s := range states {
		reachable := map[int]bool{}
		var queue []int
		for _, succ := range stateSuccessors(s) {
			if succ == i {
				continue // self-loop edge from i, ignored for cycle search
			}
			queue = append(queue, succ)
		}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if reachable[cur] {
				continue
			}
			reachable[cur] = true
			if cur == i {
				return fmt.Errorf("%s:%s: state %q is part of a multi-state cycle; MVP only supports self-loops", source, s.Pos, s.Name)
			}
			queue = append(queue, stateSuccessors(states[cur])...)
		}
	}
	return nil
}

// stateSuccessors returns the state indices reachable from one state
// by a single transition. accept / reject sentinels (negative indices)
// are filtered out — they're terminal, not state edges.
func stateSuccessors(s *ParseState) []int {
	switch s.Trans.Kind {
	case TransDirect:
		if s.Trans.Target >= 0 {
			return []int{s.Trans.Target}
		}
	case TransSelect:
		var out []int
		for _, c := range s.Trans.Select.Cases {
			if c.Target >= 0 {
				out = append(out, c.Target)
			}
		}
		if s.Trans.Select.Default >= 0 {
			out = append(out, s.Trans.Select.Default)
		}
		return out
	}
	return nil
}

// isTrivialMachine reports whether the state graph is the "single
// state called 'start' that extracts the primary header and accepts"
// shape — the common case for fixed-size protocols (eth, ipv4, tcp,
// ...). When true the caller stores nil on ProtocolSpec so codegen
// keeps the legacy fixed-size path.
func isTrivialMachine(states []*ParseState, entryIdx int, primary *p4lite.Header) bool {
	if len(states) != 1 || entryIdx != 0 {
		return false
	}
	s := states[0]
	if s.Name != "start" || len(s.Extracts) != 1 {
		return false
	}
	ex := s.Extracts[0]
	if ex.IsStackPush || ex.HeaderRef != primary {
		return false
	}
	return s.Trans.Kind == TransAccept
}

func findHeader(f *p4lite.File, name string) *p4lite.Header {
	for _, h := range f.Headers {
		if h.Name == name {
			return h
		}
	}
	return nil
}

func totalBits(h *p4lite.Header) int {
	total := 0
	for _, f := range h.Fields {
		total += f.Bits
	}
	return total
}

func findFieldBitWindow(h *p4lite.Header, name string) (bitOff, bitWidth int, ok bool) {
	for _, f := range h.Fields {
		if f.Name == name {
			return bitOff, f.Bits, true
		}
		bitOff += f.Bits
	}
	return 0, 0, false
}
