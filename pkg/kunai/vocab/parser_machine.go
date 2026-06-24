package vocab

import (
	"fmt"
	"strings"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
)

// MVP caps for parser-state-machine compilation. These bound the
// codegen-time work and the verifier-side instruction count.
const (
	parserMachineMaxStates = 16 // reachable states (= states declared)
	parserMachineMaxKeys   = 3  // tuple-match keys per `transition select`
)

// buildCtx is the shared context the build helpers thread through —
// instead of taking 4 parameters each, they take this single value.
// The fields are immutable after construction and only the maps may
// be read (no write).
type buildCtx struct {
	headerRefs map[string]*p4lite.Header
	stackRefs  map[string]*HeaderStack
	stateIdx   map[string]int
	counters   []CounterInst // declared ParserCounter instances, source order
	source     string
	primary    *p4lite.Header // pkt.advance must reference this header
}

// hasCounter is the membership test counter ops scope-check against.
// Counter lists are expected to be tiny (1-2 instances per parser),
// so the linear scan is not measurable.
func (ctx *buildCtx) hasCounter(name string) bool {
	for _, c := range ctx.counters {
		if c.Name == name {
			return true
		}
	}
	return false
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

	counters := resolveCounters(p)

	ctx := &buildCtx{
		headerRefs: headerRefs,
		stackRefs:  stackRefs,
		stateIdx:   stateIdx,
		counters:   counters,
		source:     source,
		primary:    primary,
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

	if err := resolveOwnedStacks(states, stackRefs, auxLayouts, source); err != nil {
		return nil, err
	}

	return &ParseStateMachine{
		States:     states,
		StateIdx:   stateIdx,
		EntryIdx:   entryIdx,
		HeaderRefs: headerRefs,
		StackRefs:  stackRefs,
		Counters:   counters,
		AuxLayouts: auxLayouts,
	}, nil
}

// resolveCounters lifts the parser block's ParserCounter instances
// into machine-level CounterInst entries (source order). Duplicate
// names already error in p4lite, so this is a straight copy.
func resolveCounters(p *p4lite.Parser) []CounterInst {
	if len(p.Counters) == 0 {
		return nil
	}
	counters := make([]CounterInst, 0, len(p.Counters))
	for _, c := range p.Counters {
		counters = append(counters, CounterInst{Name: c.Name, Pos: c.Pos})
	}
	return counters
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
			// Aux declared but never extracted. Two cases:
			//
			//   (a) `parse_<outName>` is a sibling state whose body is
			//       advance-only (no extract). The dispatch case that
			//       targets it pins the kind byte just like a standard
			//       TLV walk sibling, and the slot prelude records R3
			//       at sack_start before dispatching. Predicate codegen
			//       reads kind / length / blocks at slot+0 / slot+1 /
			//       slot+2. This is the SACK shape: skipping the
			//       extract avoids the JLT+Sub combo that blows up the
			//       verifier on het-size-alt chains.
			//   (b) No corresponding parse_<outName> state exists.
			//       Record as always-fail gating so user-written
			//       predicates produce a clear error rather than a
			//       silent miss.
			if kind, ok := dispatchedAuxKind(states, outName); ok {
				out[outName] = &AuxLayout{
					OutParam:          outName,
					HeaderName:        hdr.Name,
					HeaderRef:         hdr,
					HeaderSize:        headerSizeBits / 8,
					IsDynamicEligible: true,
					DynamicKindByte:   kind,
				}
				continue
			}
			out[outName] = &AuxLayout{
				OutParam:   outName,
				HeaderName: hdr.Name,
				HeaderRef:  hdr,
				HeaderSize: headerSizeBits / 8,
			}
			continue
		}
		state := states[extractStateIdx]
		// Auxes extracted inside a multi-state self-loop sibling
		// (TLV walk) live at a per-packet dynamic offset. Mark the
		// layout eligible for dynamic-slot recording and recover the
		// kind byte that dispatches to this aux's sibling state.
		// Codegen later allocates a stack slot only when a where /
		// capture clause queries the aux (the demand walker in
		// pkg/kunai/codegen drives slot allocation).
		if IsMultiStateLoopSibling(states, extractStateIdx) {
			kind, ok := dispatchKindForSibling(states, extractStateIdx)
			if !ok {
				return nil, fmt.Errorf("%s:%s: aux %q is extracted by sibling state %q but no parser-block transition select case targets that sibling — TLV-walk vocab invariant violated", source, state.Pos, outName, state.Name)
			}
			out[outName] = &AuxLayout{
				OutParam:          outName,
				HeaderName:        hdr.Name,
				HeaderRef:         hdr,
				HeaderSize:        headerSizeBits / 8,
				IsDynamicEligible: true,
				DynamicKindByte:   kind,
			}
			continue
		}
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

// resolveOwnedStacks binds each `out H[N] x` parser-stack parameter
// that is declared but never extracted (no `extract(x.next)` anywhere)
// to the option aux that "owns" it — a kind+length option header
// followed by a fixed-element trailing array (SACK blocks, IPv4
// Record Route addrs, ...).
//
// A stack is owned by aux A iff some sibling state has exactly one
// non-stack non-primary aux extract AND one trailing AdvanceOpField
// keyed off that same aux. OwnerOption records A's out-param name;
// OffsetAfterOwner is the owner state's pre-trailer extract size
// (= byte distance from owner base to first stack element). At most
// one such sibling state may exist per parser block — multiple
// matches yield a loader error rather than a silent first-wins
// binding. Zero candidates leaves the stack top-level (srv6.segments
// / IPv6 ext shape where the trail begins right after the primary).
func resolveOwnedStacks(states []*ParseState, stackRefs map[string]*HeaderStack, auxLayouts map[string]*AuxLayout, source string) error {
	for stackName, stack := range stackRefs {
		if stackHasPush(states, stackName) {
			continue // stack data comes from per-iteration extracts
		}
		// Find candidate owner siblings. Two shapes:
		//   A. extract(aux) + advance(aux.<len-field>) — explicit
		//      pre-trailer extract; advance keyed off the just-
		//      extracted aux header.
		//   B. advance-only via lookahead, state name = parse_<aux> —
		//      slot prelude records the option base, advance drains
		//      the option without an extract. Used by verifier-
		//      sensitive option-walks where the JLT+Sub combo from
		//      shape A would inflate bpf_loop callback state IDs.
		var owner string
		var ownerStateName string
		for _, s := range states {
			if len(s.Advances) != 1 {
				continue
			}
			candidate := ownerCandidate(s, auxLayouts)
			if candidate == "" {
				continue
			}
			if owner != "" {
				return fmt.Errorf("%s:%s: stack %q is owner-bound ambiguous — sibling states %q and %q both match the option-with-trailing-array shape; explicit binding syntax is not yet supported", source, stack.HeaderRef.Pos, stackName, ownerStateName, s.Name)
			}
			owner = candidate
			ownerStateName = s.Name
		}
		if owner == "" {
			continue // top-level stack (srv6.segments etc.)
		}
		stack.OwnerOption = owner
		stack.OffsetAfterOwner = auxLayouts[owner].HeaderSize
	}
	return nil
}

// parseAuxStatePrefix is the naming convention linking a parser state
// to the `out` aux it dispatches for. parse_sack ↔ aux "sack" — used
// by the dispatched-but-not-extracted aux detection so the loader can
// associate a kind-byte dispatch case with an aux out-param without
// requiring an explicit extract statement.
const parseAuxStatePrefix = "parse_"

// findStateByName returns the state with the given Name and its index,
// or (nil, -1) when none matches.
func findStateByName(states []*ParseState, name string) (*ParseState, int) {
	for i, s := range states {
		if s.Name == name {
			return s, i
		}
	}
	return nil, -1
}

// isAdvanceOnlySibling reports whether the state has zero extracts and
// exactly one AdvanceOpLookahead — the shape parse_<aux> uses to drain
// an option without consuming its kind+length pair.
func isAdvanceOnlySibling(s *ParseState) bool {
	return len(s.Extracts) == 0 && len(s.Advances) == 1 && s.Advances[0].Kind == AdvanceOpLookahead
}

// ownerCandidate returns the aux name a state nominates as the owner
// of a trailing-array stack, or "" when the state's shape doesn't
// match either of the two recognised forms (see resolveOwnedStacks).
func ownerCandidate(s *ParseState, auxLayouts map[string]*AuxLayout) string {
	if len(s.Advances) != 1 {
		return ""
	}
	adv := s.Advances[0]
	switch {
	case len(s.Extracts) == 1 && !s.Extracts[0].IsStackPush && adv.Kind == AdvanceOpField:
		auxName := s.Extracts[0].OutParam
		if _, ok := auxLayouts[auxName]; ok && adv.Target == auxName {
			return auxName
		}
	case isAdvanceOnlySibling(s) && strings.HasPrefix(s.Name, parseAuxStatePrefix):
		// The slot prelude only fires for IsDynamicEligible auxes —
		// dispatchedAuxKind is what marks them so, so this branch
		// runs second and trusts that pre-pass.
		auxName := strings.TrimPrefix(s.Name, parseAuxStatePrefix)
		if layout, ok := auxLayouts[auxName]; ok && layout.IsDynamicEligible {
			return auxName
		}
	}
	return ""
}

// stackHasPush reports whether any state extracts via `<stackName>.next`.
func stackHasPush(states []*ParseState, stackName string) bool {
	for _, s := range states {
		for _, ex := range s.Extracts {
			if ex.IsStackPush && ex.StackName == stackName {
				return true
			}
		}
	}
	return false
}

// dispatchedAuxKind reports the kind-byte dispatch case that targets
// the `parse_<outName>` advance-only sibling, if any. Used to mark a
// declared-but-not-extracted aux as queryable: the slot prelude
// records R3 at sibling entry as the option's per-packet base, and
// predicate codegen reads kind/length/blocks at slot+0/+1/+2 without
// an explicit extract.
func dispatchedAuxKind(states []*ParseState, outName string) (uint64, bool) {
	target, idx := findStateByName(states, parseAuxStatePrefix+outName)
	if target == nil || !isAdvanceOnlySibling(target) {
		return 0, false
	}
	return dispatchKindForSibling(states, idx)
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
// primary header within the same byte, with no straddle. Lookahead
// keys are rejected — the aux-gating model needs an extracted field
// the gating predicate can name, and a lookahead peeks unconsumed
// bytes that don't bind to an aux's presence.
func mergeBitFieldsToMask(keys []SelectKey, primary *p4lite.Header, op GatingOp, value uint64, source string, pos p4lite.Position) (*AuxGating, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s:%s: aux gating: no select keys", source, pos)
	}
	byteOff := -1
	var mask uint64
	for i, sk := range keys {
		if sk.Kind != SelectKeyField {
			return nil, fmt.Errorf("%s:%s: aux gating key %d is a `pkt.lookahead<...>()` peek; aux gating requires a field reference", source, pos, i)
		}
		k := sk.Field
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
			if succ >= 0 && succ < len(states) && IsMultiStateLoopEntry(states, succ) &&
				s.Trans.Kind == TransDirect && s.Trans.Target == succ {
				// Multi-state self-loop entry (TLV walk parse_options
				// shape): a direct edge from a sibling back to the
				// entry is the per-iteration loop-back, which the
				// bpf_loop callback handles dynamically. The first
				// edge into the entry comes from outside the cycle
				// (e.g. start → parse_options) and still propagates
				// normally.
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
		switch v := stmt.(type) {
		case *p4lite.ExtractStmt:
			op, err := buildExtract(v, ctx)
			if err != nil {
				return nil, err
			}
			if op.IsStackPush {
				pushCount++
			}
			ps.Extracts = append(ps.Extracts, op)
		case *p4lite.AdvanceStmt:
			op, err := buildAdvance(v, ctx)
			if err != nil {
				return nil, err
			}
			ps.Advances = append(ps.Advances, op)
		case *p4lite.CounterCallStmt:
			op, err := buildCounter(v, ctx)
			if err != nil {
				return nil, err
			}
			ps.Counters = append(ps.Counters, op)
		default:
			return nil, fmt.Errorf("%s:%s: state %q contains an unsupported statement type %T", ctx.source, s.Pos, s.Name, stmt)
		}
	}
	if pushCount > 1 {
		return nil, fmt.Errorf("%s:%s: state %q pushes %d stack entries; MVP allows at most one stack push per state", ctx.source, s.Pos, s.Name, pushCount)
	}
	if len(ps.Advances) > 0 && len(ps.Extracts) > 0 {
		// Primary-targeted AdvanceField addressing assumes R4 is at
		// primary-end on entry — folding state.OffsetAtEntry into a
		// layer-relative byte load. Mixing it with an extract that
		// has moved R4 already breaks that invariant. Aux-targeted
		// AdvanceField, AdvanceOpLookahead (R4-relative), and
		// AdvanceOpLiteral (fixed) all addr relative to the post-
		// extract R4 so they're safe; the SACK shape (`extract(sack);
		// advance((sack.length - 2) << 3);`) needs this co-residency.
		for _, adv := range ps.Advances {
			if adv.Kind != AdvanceOpField {
				continue
			}
			h := ctx.headerRefs[adv.Target]
			if h == ctx.primary {
				return nil, fmt.Errorf("%s:%s: state %q mixes pkt.extract with primary-targeted pkt.advance; MVP requires the advance to live in its own state (R4 is fixed at primary-end on entry)", ctx.source, s.Pos, s.Name)
			}
		}
	}

	trans, err := buildTransition(s.Transition, ctx)
	if err != nil {
		return nil, err
	}
	ps.Trans = trans
	return ps, nil
}

// buildCounter resolves a `<counter>.set(...)` or
// `<counter>.decrement(<INT>)` call against the parser block's
// ParserCounter instances. The Counter name must match a declared
// instance; the set form shares AdvanceField's cast-and-shift
// lowering so the counter is loaded with the same byte expression
// trailer-skip already understands.
func buildCounter(cs *p4lite.CounterCallStmt, ctx *buildCtx) (CounterOp, error) {
	if !ctx.hasCounter(cs.Counter) {
		return CounterOp{}, fmt.Errorf("%s:%s: counter %q is not declared as a `ParserCounter()` instance in this parser block", ctx.source, cs.Pos, cs.Counter)
	}
	switch cs.Op {
	case p4lite.CounterSet:
		// counter.set permits the bare-cast scale=1 add form
		// (`(bit<N>)(hdr.<F> + K)`) for element counts, so allow a
		// sub-byte scale here (pkt.advance keeps the S ≥ 3 requirement).
		skip, h, err := lowerCastShiftSkip(cs.Target, cs.FieldName, cs.BaseWords, cs.Mask, cs.ScaleLog2, cs.Addend, true, cs.Counter+".set", ctx, cs.Pos)
		if err != nil {
			return CounterOp{}, err
		}
		// Counter set stores its byte expression into a layer-entry-
		// anchored slot, so the source field must live in the primary
		// header. Aux counters would need a different anchoring path.
		if h != ctx.primary {
			return CounterOp{}, fmt.Errorf("%s:%s: %s.set target %q is not the primary header %q", ctx.source, cs.Pos, cs.Counter, h.Name, ctx.primary.Name)
		}
		return CounterOp{
			Kind:      CounterOpSet,
			Counter:   cs.Counter,
			Target:    cs.Target,
			FieldName: cs.FieldName,
			Skip:      skip,
			Pos:       cs.Pos,
		}, nil
	case p4lite.CounterDecrement:
		if cs.DecrementLookaheadBits > 0 {
			byteOff, err := lowerLookaheadByteSlice(cs.DecrementLookaheadBits, cs.DecrementSliceLo, cs.DecrementSliceHi, "counter.decrement", ctx, cs.Pos)
			if err != nil {
				return CounterOp{}, err
			}
			return CounterOp{
				Kind:                       CounterOpDecrement,
				Counter:                    cs.Counter,
				DecrementLookaheadByteOff:  byteOff,
				DecrementLookaheadByteOffR: true,
				Pos:                        cs.Pos,
			}, nil
		}
		if cs.DecrementFieldName != "" {
			byteOff, err := lookupAuxFieldByteOffset(cs.DecrementTarget, cs.DecrementFieldName, ctx, cs.Pos)
			if err != nil {
				return CounterOp{}, err
			}
			return CounterOp{
				Kind:               CounterOpDecrement,
				Counter:            cs.Counter,
				DecrementTarget:    cs.DecrementTarget,
				DecrementFieldName: cs.DecrementFieldName,
				DecrementByteOff:   byteOff,
				Pos:                cs.Pos,
			}, nil
		}
		return CounterOp{
			Kind:         CounterOpDecrement,
			Counter:      cs.Counter,
			LiteralBytes: cs.LiteralBytes,
			Pos:          cs.Pos,
		}, nil
	}
	return CounterOp{}, fmt.Errorf("%s:%s: unknown counter op %d", ctx.source, cs.Pos, cs.Op)
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
			OutParam:    es.Target,
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
		OutParam:   es.Target,
		Pos:        es.Pos,
	}, nil
}

// buildAdvance resolves a `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)`
// statement against the parser block's primary `out` parameter and
// produces an AdvanceOp whose Skip carries the lowered five-tuple
// codegen consumes. The conversion arithmetic:
//
//	ScaleBytes  = 1 << (ScaleLog2 - 3)         // S is in bits, Scale in bytes
//	LenByteOff  = bitOff(F) / 8                // F's byte position
//	bitInByte   = bitOff(F) % 8                // network MSB-first
//	LenShift    = 8 - bitInByte - F.bits       // LSB-numbered shift
//	LenMask     = ((1 << F.bits) - 1) << LenShift
//	Base        = K * ScaleBytes               // = MinimumTotal in variableTailSkip
//
// Three load-time constraints, each rejecting a shape codegen does
// not have a path for:
//   - Target must be the primary header. Aux fields would need a
//     different anchor than the layer-entry slot the trailer emit
//     reads from.
//   - F must exist and fit inside one byte. The variableTailSkip
//     LenMask/LenShift addressing is single-byte only; cross-byte
//     fields would need a different byte-load codegen.
//   - ScaleLog2 ≥ 3 keeps Scale a whole-byte multiplier; codegen
//     advances R4 in bytes, sub-byte shifts have no path.
func buildAdvance(as *p4lite.AdvanceStmt, ctx *buildCtx) (AdvanceOp, error) {
	switch as.Kind {
	case p4lite.AdvanceField:
		return buildAdvanceField(as, ctx)
	case p4lite.AdvanceLookahead:
		return buildAdvanceLookahead(as, ctx)
	case p4lite.AdvanceLiteral:
		return buildAdvanceLiteral(as, ctx)
	}
	return AdvanceOp{}, fmt.Errorf("%s:%s: unknown pkt.advance template kind %d", ctx.source, as.Pos, as.Kind)
}

// lowerLookaheadByteSlice resolves a `((bit<N>)pkt.lookahead<bit<M>>()
// [hi:lo])` template's slice into the byte position the codegen byte
// LDX should target relative to current R3. The slice [hi:lo] must
// align with one byte of the M-bit peek; M is in bits and the peek
// is in network MSB-first order, so the byte position from R3 is
// `(M/8 - 1) - (lo/8)`. Same shape as buildAdvanceLookahead but
// shared so counter.decrement can lift the same template without
// pulling in AdvanceOp's HeaderLength wrapper.
func lowerLookaheadByteSlice(lookaheadBits, sliceLo, sliceHi int, opName string, ctx *buildCtx, pos p4lite.Position) (int, error) {
	if lookaheadBits%8 != 0 {
		return 0, fmt.Errorf("%s:%s: %s lookahead<bit<%d>>() must peek a whole-byte width", ctx.source, pos, opName, lookaheadBits)
	}
	if (sliceHi - sliceLo + 1) != 8 {
		return 0, fmt.Errorf("%s:%s: %s lookahead slice [%d:%d] must select exactly 8 bits", ctx.source, pos, opName, sliceHi, sliceLo)
	}
	if sliceLo%8 != 0 {
		return 0, fmt.Errorf("%s:%s: %s lookahead slice [%d:%d] must start at a byte boundary (lo %% 8 == 0)", ctx.source, pos, opName, sliceHi, sliceLo)
	}
	return (lookaheadBits / 8) - 1 - (sliceLo / 8), nil
}

// lookupAuxFieldByteOffset resolves `<aux>.<field>` (used by
// `<counter>.decrement(<aux>.<field>)`) into the byte offset of the
// field within the aux header. Single-byte fields only — codegen
// emits an unsigned byte LDX + Sub.Reg into the counter slot, with no
// scalar-narrowing or byte-swap. The target must be a non-primary
// `out` aux param; primary-header decrements would need a different
// addressing path (the primary's bytes aren't on R3 at the sibling
// state). Multi-byte support is out of scope until host byte-swap
// handling lands.
func lookupAuxFieldByteOffset(target, fieldName string, ctx *buildCtx, pos p4lite.Position) (int, error) {
	h, ok := ctx.headerRefs[target]
	if !ok {
		return 0, fmt.Errorf("%s:%s: counter.decrement target %q is not an `out` header parameter", ctx.source, pos, target)
	}
	if h == ctx.primary {
		return 0, fmt.Errorf("%s:%s: counter.decrement field-expr target %q is the primary header (use a literal for primary-driven decrements)", ctx.source, pos, target)
	}
	bitOff, fieldBits, ok := findFieldBitWindow(h, fieldName)
	if !ok {
		return 0, fmt.Errorf("%s:%s: counter.decrement references unknown field %q in header %q", ctx.source, pos, fieldName, h.Name)
	}
	if bitOff%8 != 0 || fieldBits != 8 {
		return 0, fmt.Errorf("%s:%s: counter.decrement field %q must be a single byte at a byte boundary (got bit-off %d, %d bits)", ctx.source, pos, fieldName, bitOff, fieldBits)
	}
	return bitOff / 8, nil
}

// lowerCastShiftSkip lowers the `((bit<N>)(hdr.<F> - K)) << S`
// (subtract form, userMask=0) or `((bit<N>)(hdr.<F> & MASK)) << S`
// (mask form, baseWords=0, userMask=MASK) AdvanceField
// template — shared by `pkt.advance` (AdvanceField) and
// `<counter>.set` — into a HeaderLength five-tuple plus the resolved
// header pointer. variableTailSkip consumes the tuple to drive a
// trailer skip; the counter-set path stores the same byte count into
// a stack slot. opName labels the source-level construct so error
// diagnostics still name what the user wrote. The returned header
// lets callers apply their own primary-only check — counter.set
// always wants primary (the layer-entry slot anchors the load),
// pkt.advance permits aux for the SACK-style option-with-trailing-
// array shape.
func lowerCastShiftSkip(target, fieldName string, baseWords, userMask, scaleLog2, addend int, allowSubByteScale bool, opName string, ctx *buildCtx, pos p4lite.Position) (*HeaderLength, *p4lite.Header, error) {
	h, ok := ctx.headerRefs[target]
	if !ok {
		return nil, nil, fmt.Errorf("%s:%s: %s target %q is not an `out` header parameter", ctx.source, pos, opName, target)
	}
	bitOff, fieldBits, ok := findFieldBitWindow(h, fieldName)
	if !ok {
		return nil, nil, fmt.Errorf("%s:%s: %s references unknown field %q in header %q", ctx.source, pos, opName, fieldName, h.Name)
	}
	bitInByte := bitOff % 8
	if bitInByte+fieldBits > 8 {
		return nil, nil, fmt.Errorf("%s:%s: %s field %q crosses a byte boundary (bits [%d,%d) — only single-byte fields are supported)", ctx.source, pos, opName, fieldName, bitOff, bitOff+fieldBits)
	}
	// pkt.advance moves R4 in whole bytes, so a sub-byte scale has no
	// lowering there (require S ≥ 3 = scale ≥ 8). counter.set stores a
	// scalar count rather than advancing R4, so it permits scale=1
	// (S=0): the bare-cast element-count form `(bit<N>)(hdr.<F> + K)`.
	if scaleLog2 < 3 && !allowSubByteScale {
		return nil, nil, fmt.Errorf("%s:%s: %s shift S=%d is sub-byte (codegen advances in whole bytes; require S ≥ 3)", ctx.source, pos, opName, scaleLog2)
	}
	if baseWords != 0 && userMask != 0 {
		return nil, nil, fmt.Errorf("%s:%s: %s combines subtract (-K) and mask (& MASK) forms; only one is supported per advance", ctx.source, pos, opName)
	}
	scaleBytes := 1
	if scaleLog2 >= 3 {
		scaleBytes = 1 << (scaleLog2 - 3)
	}
	lsbShift := 8 - bitInByte - fieldBits
	mask := ((1 << fieldBits) - 1) << lsbShift
	if userMask != 0 {
		// userMask is expressed against the field value; reject anything
		// that doesn't fit so the byte-shifted mask stays inside the
		// field's own bit window. Parser already rejects userMask=0.
		if userMask >= (1 << fieldBits) {
			return nil, nil, fmt.Errorf("%s:%s: %s mask MASK=0x%x exceeds the %d-bit field %q (max 0x%x)", ctx.source, pos, opName, userMask, fieldBits, fieldName, (1<<fieldBits)-1)
		}
		mask = userMask << lsbShift
	}
	return &HeaderLength{
		LenByteOff: bitOff / 8,
		LenMask:    mask,
		LenShift:   lsbShift,
		Scale:      scaleBytes,
		Base:       baseWords * scaleBytes,
		Addend:     addend,
	}, h, nil
}

func buildAdvanceField(as *p4lite.AdvanceStmt, ctx *buildCtx) (AdvanceOp, error) {
	skip, _, err := lowerCastShiftSkip(as.Target, as.FieldName, as.BaseWords, as.Mask, as.ScaleLog2, 0, false, "pkt.advance", ctx, as.Pos)
	if err != nil {
		return AdvanceOp{}, err
	}
	return AdvanceOp{
		Kind:      AdvanceOpField,
		Target:    as.Target,
		FieldName: as.FieldName,
		Skip:      skip,
		Pos:       as.Pos,
	}, nil
}

// scaleBytesFromLog2 keeps AdvanceLookahead's pre-existing call site
// working. Mirrors the scale check inside lowerCastShiftSkip.
func scaleBytesFromLog2(as *p4lite.AdvanceStmt, ctx *buildCtx) (int, error) {
	if as.ScaleLog2 < 3 {
		return 0, fmt.Errorf("%s:%s: pkt.advance shift S=%d is sub-byte (codegen advances in whole bytes; require S ≥ 3)", ctx.source, as.Pos, as.ScaleLog2)
	}
	return 1 << (as.ScaleLog2 - 3), nil
}

// buildAdvanceLookahead handles
// `pkt.advance(((bit<N>)pkt.lookahead<bit<M>>()[hi:lo]) << S)`. The
// slice [hi:lo] must align with one byte of the M-bit peek so the
// codegen path stays a single byte LDX. M is in bits and the peek
// is in network MSB-first order, so the byte position from R4 is
// `(M/8 - 1) - (lo/8)`.
func buildAdvanceLookahead(as *p4lite.AdvanceStmt, ctx *buildCtx) (AdvanceOp, error) {
	if as.LookaheadBits%8 != 0 {
		return AdvanceOp{}, fmt.Errorf("%s:%s: pkt.lookahead<bit<%d>>() must peek a whole-byte width", ctx.source, as.Pos, as.LookaheadBits)
	}
	sliceWidth := as.SliceHi - as.SliceLo + 1
	if sliceWidth != 8 {
		return AdvanceOp{}, fmt.Errorf("%s:%s: pkt.advance lookahead slice [%d:%d] must select exactly 8 bits", ctx.source, as.Pos, as.SliceHi, as.SliceLo)
	}
	if as.SliceLo%8 != 0 {
		return AdvanceOp{}, fmt.Errorf("%s:%s: pkt.advance lookahead slice [%d:%d] must start at a byte boundary (lo %% 8 == 0)", ctx.source, as.Pos, as.SliceHi, as.SliceLo)
	}
	scaleBytes, err := scaleBytesFromLog2(as, ctx)
	if err != nil {
		return AdvanceOp{}, err
	}
	byteOff := (as.LookaheadBits / 8) - 1 - (as.SliceLo / 8)
	return AdvanceOp{
		Kind: AdvanceOpLookahead,
		Skip: &HeaderLength{
			LenByteOff: byteOff,
			LenMask:    0xFF,
			LenShift:   0,
			Scale:      scaleBytes,
			Base:       0,
		},
		Pos: as.Pos,
	}, nil
}

// buildAdvanceLiteral handles `pkt.advance(<INT>)`. The literal is
// the bit count; codegen advances R4 by literal/8 bytes after a
// bounds check. Sub-byte literals are rejected (no whole-byte
// codegen path).
func buildAdvanceLiteral(as *p4lite.AdvanceStmt, ctx *buildCtx) (AdvanceOp, error) {
	if as.LiteralBits%8 != 0 {
		return AdvanceOp{}, fmt.Errorf("%s:%s: pkt.advance(%d) is sub-byte (must be a multiple of 8)", ctx.source, as.Pos, as.LiteralBits)
	}
	if as.LiteralBits <= 0 {
		return AdvanceOp{}, fmt.Errorf("%s:%s: pkt.advance(%d) must advance at least 1 byte", ctx.source, as.Pos, as.LiteralBits)
	}
	return AdvanceOp{
		Kind:         AdvanceOpLiteral,
		LiteralBytes: as.LiteralBits / 8,
		Pos:          as.Pos,
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
	keys := make([]SelectKey, len(sel.Keys))
	for i, k := range sel.Keys {
		switch k.Kind {
		case p4lite.SelectKeyField:
			ref, err := resolveFieldRef(k.Path, ctx, k.Pos)
			if err != nil {
				return nil, err
			}
			keys[i] = SelectKey{Kind: SelectKeyField, Field: ref, Pos: k.Pos}
		case p4lite.SelectKeyLookahead:
			// Codegen loads a lookahead key as the next power-of-two
			// LDX, byte-swaps, and shifts/masks to the key width. It
			// supports byte-multiple widths up to 24 bits (e.g. a
			// Geneve option class+type discriminator); a 24-bit value
			// still fits a JNE.Imm case compare.
			if !allowedLookaheadBits(k.Bits) {
				return nil, fmt.Errorf("%s:%s: `pkt.lookahead<bit<%d>>()` select keys must be 8, 16, or 24 bits; for other widths, slice the value inside a pkt.advance arg or extract a header first", ctx.source, k.Pos, k.Bits)
			}
			keys[i] = SelectKey{Kind: SelectKeyLookahead, Bits: k.Bits, Pos: k.Pos}
		case p4lite.SelectKeyCounterIsZero:
			if !ctx.hasCounter(k.Counter) {
				return nil, fmt.Errorf("%s:%s: select key references undeclared counter %q", ctx.source, k.Pos, k.Counter)
			}
			keys[i] = SelectKey{Kind: SelectKeyCounterIsZero, Counter: k.Counter, Pos: k.Pos}
		default:
			return nil, fmt.Errorf("%s:%s: unknown SelectKey kind %d", ctx.source, k.Pos, k.Kind)
		}
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
			vals[i] = MatchVal{IsWildcard: m.IsWildcard, IsBool: m.IsBool, Bool: m.Bool, Value: m.Value}
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

// IsMultiStateLoopEntry reports whether `idx` is the entry of an
// indirect (multi-state) self-loop suitable for the TLV-walk codegen
// path. The shape is:
//
//   - The entry state has no extracts, advances, or counter ops.
//     Its body is just the dispatch.
//   - Its transition is a select with one of three legal key shapes
//     (see isMultiStateLoopKeyShape): single `pkt.lookahead<bit<8>>()`
//     (kind-byte TLV dispatch), single `<counter>.is_zero()`
//     (counter-driven termination), or the 2-key tuple
//     `(<counter>.is_zero(), pkt.lookahead<bit<8>>())` (counter
//     termination + per-iter kind dispatch — the canonical TNA form
//     for byte-bounded TLV walks like IPv4 options).
//   - Every case (including default) targets either accept/reject
//     OR a "sibling" state whose only transition is a TransDirect
//     back to the entry. Sibling bodies inline into the callback.
//
// Loader and codegen both branch on this shape — the loader to skip
// cycle-internal edges in assignStateOffsets and to relax the gating
// model for sibling auxes, the codegen to absorb sibling bodies into
// the loop callback.
func IsMultiStateLoopEntry(states []*ParseState, idx int) bool {
	if idx < 0 || idx >= len(states) {
		return false
	}
	s := states[idx]
	if len(s.Extracts) != 0 || len(s.Advances) != 0 || len(s.Counters) != 0 {
		return false
	}
	if s.Trans.Kind != TransSelect || s.Trans.Select == nil {
		return false
	}
	sel := s.Trans.Select
	if !isMultiStateLoopKeyShape(sel) {
		return false
	}
	check := func(target int) bool {
		if target == StateAccept || target == StateReject {
			return true
		}
		if target < 0 || target >= len(states) {
			return false
		}
		sib := states[target]
		return sib.Trans.Kind == TransDirect && sib.Trans.Target == idx
	}
	if !check(sel.Default) {
		return false
	}
	for _, k := range sel.Cases {
		if !check(k.Target) {
			return false
		}
	}
	return true
}

// allowedLookaheadBits reports whether a lookahead select-key width is
// one codegen can lower: byte-multiple up to 24 bits (8 = TLV kind
// byte, 24 = Geneve option class+type). The value is loaded as the
// next power-of-two LDX, byte-swapped, then shifted/masked.
func allowedLookaheadBits(bits int) bool {
	return bits == 8 || bits == 16 || bits == 24
}

// isMultiStateLoopKeyShape pins the legal key tuples for a multi-state
// loop entry: one of {Lookahead}, {CounterIsZero},
// or {CounterIsZero, Lookahead} in that order. Foreign shapes
// (unsupported lookahead width, reversed tuple, more than 2 keys)
// reject so the multi-state codegen invariants stay narrow.
func isMultiStateLoopKeyShape(sel *SelectOp) bool {
	switch len(sel.Keys) {
	case 1:
		switch sel.Keys[0].Kind {
		case SelectKeyLookahead:
			return allowedLookaheadBits(sel.Keys[0].Bits)
		case SelectKeyCounterIsZero:
			return true
		}
	case 2:
		return sel.Keys[0].Kind == SelectKeyCounterIsZero &&
			sel.Keys[1].Kind == SelectKeyLookahead &&
			allowedLookaheadBits(sel.Keys[1].Bits)
	}
	return false
}

// multiStateLoopKindKeyIndex returns the position of the lookahead
// kind-byte key within the entry's select tuple, or -1 when the entry
// is counter-only (no kind byte to dispatch on). Callers use this to
// address into a SelectCase's Values for the kind value regardless of
// whether the entry uses the 1-key or 2-key shape.
func multiStateLoopKindKeyIndex(sel *SelectOp) int {
	if sel == nil {
		return -1
	}
	for i, k := range sel.Keys {
		if k.Kind == SelectKeyLookahead {
			return i
		}
	}
	return -1
}

// IsMultiStateLoopSibling reports whether `idx` is a sibling state
// of any multi-state self-loop entry — i.e. a state whose only
// transition is a TransDirect to a multi-state entry that lists
// `idx` as one of its case targets.
func IsMultiStateLoopSibling(states []*ParseState, idx int) bool {
	if idx < 0 || idx >= len(states) {
		return false
	}
	s := states[idx]
	if s.Trans.Kind != TransDirect {
		return false
	}
	target := s.Trans.Target
	if target < 0 || target >= len(states) {
		return false
	}
	if !IsMultiStateLoopEntry(states, target) {
		return false
	}
	entry := states[target]
	for _, k := range entry.Trans.Select.Cases {
		if k.Target == idx {
			return true
		}
	}
	return entry.Trans.Select.Default == idx
}

// dispatchKindForSibling looks up the kind value the multi-state
// loop entry's transition select uses to dispatch to sibling state
// `siblingIdx`. Returns (0, false) when the sibling is the default
// target, when no case targets it, or when the matching case's kind
// slot is wildcard (catch-all branches like `(false, _)` in the
// 2-key counter+lookahead shape don't pin a specific kind).
//
// Drives AuxLayout.DynamicKindByte so codegen's demand-driven slot
// store prelude can match the kind byte against the queried option
// without re-deriving the cascade structure. Counter-only entries
// (no lookahead key) return false — they have no kind byte to
// record.
func dispatchKindForSibling(states []*ParseState, siblingIdx int) (uint64, bool) {
	if siblingIdx < 0 || siblingIdx >= len(states) {
		return 0, false
	}
	s := states[siblingIdx]
	if s.Trans.Kind != TransDirect {
		return 0, false
	}
	entryIdx := s.Trans.Target
	if entryIdx < 0 || entryIdx >= len(states) {
		return 0, false
	}
	entry := states[entryIdx]
	if entry.Trans.Kind != TransSelect || entry.Trans.Select == nil {
		return 0, false
	}
	kindIdx := multiStateLoopKindKeyIndex(entry.Trans.Select)
	if kindIdx < 0 {
		return 0, false
	}
	for _, c := range entry.Trans.Select.Cases {
		if c.Target != siblingIdx {
			continue
		}
		if kindIdx >= len(c.Values) || c.Values[kindIdx].IsWildcard {
			return 0, false
		}
		return c.Values[kindIdx].Value, true
	}
	return 0, false
}

// CounterSetSkipForCounter returns the HeaderLength expression a
// CounterOpSet stores into the named counter slot — i.e. the byte
// count the counter is initialised with. Used by codegen to derive
// a Mechanism-1-equivalent bulk advance when no per-option query
// reaches into the multi-state walk's siblings, sidestepping the
// bpf_loop subprogram entirely.
//
// The MVP assumes one set op per counter (typical: pc.set in start,
// pc.decrement in siblings); returns the first match. Returns nil
// when no set is found (= the counter is read but never written, an
// invalid vocab the loader rejects upstream).
func CounterSetSkipForCounter(states []*ParseState, counterName string) *HeaderLength {
	for _, s := range states {
		for _, op := range s.Counters {
			if op.Kind == CounterOpSet && op.Counter == counterName {
				return op.Skip
			}
		}
	}
	return nil
}

// MultiStateLoopAbsorbedStates returns the set of sibling state
// indices a multi-state self-loop pulls into its callback — every
// non-accept/reject case target plus the default target. Codegen
// uses this to skip emitting standalone code for absorbed siblings.
func MultiStateLoopAbsorbedStates(states []*ParseState, entryIdx int) map[int]bool {
	out := map[int]bool{}
	if !IsMultiStateLoopEntry(states, entryIdx) {
		return out
	}
	sel := states[entryIdx].Trans.Select
	for _, k := range sel.Cases {
		if k.Target >= 0 && k.Target < len(states) {
			out[k.Target] = true
		}
	}
	if sel.Default >= 0 && sel.Default < len(states) {
		out[sel.Default] = true
	}
	return out
}

// validateStateGraph rejects cycles codegen has no path for. Direct
// self-loops (state X → X) lower via the standard self-loop
// callback. Multi-state cycles (X → Y → X) lower via the multi-
// state self-loop callback only when the entry has the TLV-walk
// shape — see IsMultiStateLoopEntry for the predicate. Cycles whose
// entry is anything else are rejected here so the user gets a
// load-time diagnostic instead of an opaque codegen error later.
func validateStateGraph(states []*ParseState, source string) error {
	for i, s := range states {
		reachable := map[int]bool{}
		var queue []int
		for _, succ := range stateSuccessors(s) {
			if succ == i {
				continue // direct self-loop, handled by codegen
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
				if IsMultiStateLoopEntry(states, i) || IsMultiStateLoopSibling(states, i) {
					break // TLV-walk cycle entry or sibling
				}
				return fmt.Errorf("%s:%s: state %q is part of a multi-state cycle codegen has no lowering for; the supported shape is the TLV-walk one (see IsMultiStateLoopEntry)", source, s.Pos, s.Name)
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
