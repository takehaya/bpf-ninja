// Package vocab loads protocol vocabulary from .p4 sources and classifies
// their dispatch constants for downstream one-liner resolution and
// codegen.
package vocab

import (
	"fmt"

	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab/p4lite"
)

// ProtocolSpec is the in-memory representation of one .p4 protocol file
// (e.g. ipv4.p4). The fields below are everything downstream passes
// (resolver / codegen) need; the full p4lite AST is kept on File for
// future use without changing this struct.
type ProtocolSpec struct {
	Name       string          // lowercase, derived from filename (eth, ipv4, ...)
	HeaderName string          // e.g. "ipv4_h"
	Fields     []Field         // header field layout, in declaration order
	Consts     []DispatchConst // classified dispatch constants
	// MaxDepth overrides codegen's default bpf_loop iteration cap for
	// this protocol when it appears as a chained (`+/*/{n,m>4}`)
	// layer. Zero means "use the codegen default". Declared in the
	// .p4 file as `const bit<N> <SELF>_MAX_DEPTH = <n>;`.
	MaxDepth int
	// ChainEnd declares a per-iteration termination condition for
	// chain codegen: when the named field of the just-consumed
	// header equals Value, the bpf_loop callback returns 1 so the
	// chain stops without consuming further bytes. Nil when the
	// vocab declared no <SELF>_CHAIN_END_<FIELD> const.
	ChainEnd *ChainEndConst
	// FlagTriggers is an ordered set of "if a flag bit is set,
	// advance R4 by N bytes" rules used by protocols whose header
	// suffix is not a single declared length but a chain of
	// independent optional 4-byte fields. GRE is the canonical case
	// (Checksum / Key / Sequence each gated by a separate flag bit).
	// When non-empty, FlagsByteOffset names the byte that carries
	// the flag bits within the primary header.
	FlagTriggers    []FlagTrigger
	FlagsByteOffset int
	// ParseStateMachine is a normalised view of the protocol's
	// `parser` block, populated when the block describes more than
	// the trivial "extract primary header; transition accept;"
	// shape. Codegen interprets it to handle protocols with optional
	// blocks (GTP), self-loop chains driven by in-protocol fields
	// (GTP extension headers), or variable-length sub-headers (IPv6
	// extension headers, SRv6 segment list).
	//
	// nil for protocols whose parser block is the trivial single-
	// state extract+accept shape; codegen routes those through the
	// existing fixed-size path with no behaviour change.
	ParseStateMachine *ParseStateMachine
	// HeaderAnnotations records per-header @kunai_* decorators read
	// from the .p4 source. Nil-or-missing entries mean "no kunai
	// annotations on that header"; the primary header may also appear
	// here when it carries cross-cutting kunai metadata that the
	// dispatch-const / parser-block channels can't express.
	HeaderAnnotations map[string]*HeaderAnnotations
	// StackLayouts captures the @kunai_layout annotation on each
	// declare-only `out X[N] stack` parser parameter. The resolver
	// uses these to compute aux-stack base offsets when the parser
	// block doesn't push entries explicitly — without an explicit
	// layout declaration, multiple declare-only stacks would alias
	// onto the same byte offset. Keyed by stack (parameter) name.
	// Empty when every aux stack in the protocol is pushed by some
	// parser-block state (= the standard P4 idiom).
	StackLayouts map[string]*StackLayoutSpec
	// StackCounts captures the @kunai_stack_count annotation on a
	// declare-only aux stack parameter, naming a primary-header byte
	// whose value (plus an optional offset) gives the stack's runtime
	// element count for `any/all` quantifiers. Empty when no parameter
	// carries the annotation; the codegen then falls back to the
	// static Capacity bound.
	StackCounts map[string]*StackCountSpec
	// OptionSegment names the reserved second path segment for 4-/5-part
	// field references like `<proto>.<seg>.<NAME>.<field>` that route to
	// the protocol's parser-declared option walk. Defaults to "options"
	// when no @kunai_option_segment[name=...] decorates the parser
	// block. The non-default value lets a protocol expose its
	// option-walk under a domain-appropriate name (e.g. "tlvs") without
	// a resolver-side code change.
	OptionSegment string
	// selfValidating caches whether the parser block proves the
	// protocol's identity itself (start-state `transition select(...)
	// { ...; default: reject; }` keyed on a primary-header field).
	// Computed once at vocab load (loader.go) and queried per Compile
	// via IsSelfValidating().
	selfValidating bool
	File           *p4lite.File // full AST (for resolver/codegen later)
	Source         string       // original file path, for diagnostics
}

// StackLayoutSpec captures the @kunai_layout[after=...] decorator on
// a parser parameter declaring an aux stack that the parser block
// does not extract into. The byte offset is computed by resolving the
// chain: `after=primary` anchors at the primary header end;
// `after=<other_stack>` walks back to a previously-resolved layout
// (cycle-free by construction since the loader processes parameters
// in declaration order and rejects forward references). The resolved
// BaseByteOff is what the field-path resolver consumes.
type StackLayoutSpec struct {
	After       string // "primary" or another stack's parameter name
	BaseByteOff int    // resolved at load-time
}

// StackCountSpec is the .p4-declared form the codegen's quantifier
// count source consumes for top-level declare-only aux stacks. The
// loader resolves the @kunai_stack_count[field=NAME, offset=N]
// annotation against the primary header's bit layout into the byte
// offset of the named field; the codegen emits a single-byte LDX
// from `layer_entry + CountByteOff`, adds Offset, and uses the
// result as the iteration cap. The field must be byte-aligned and
// exactly 8 bits wide so the LDX hits the whole value in one load.
type StackCountSpec struct {
	ByteOff int // primary-header byte where the raw count value lives
	Addend  int // integer added to the loaded byte to yield the final count (= SRv6 `last_entry + 1` would be Addend=1); intentionally NOT named "Offset" to avoid confusion with the sibling ByteOff
}

// HeaderAnnotations bundles kunai-specific decorators carried on a
// non-primary header within a protocol's vocab. Today these describe
// extension-header chain elements (ipv6_ext_h) whose variable-trailer
// and parent-field write-back behaviour has no native P4 expression.
// Keyed by header name in ProtocolSpec.HeaderAnnotations.
type HeaderAnnotations struct {
	// VariableTail mirrors codegen/parser_trail.go::variableTailSkip
	// for the in-protocol header; nil when the header declares no
	// @kunai_variable_tail.
	VariableTail *VariableTailSpec
	// WriteBack captures the @kunai_writeback decorator: after the
	// extension header is consumed inside a self-loop, copy one byte
	// of its primary back into the parent protocol's named field so
	// the next dispatch sees the inner protocol identifier.
	WriteBack *WriteBackSpec
}

// VariableTailSpec is the .p4-declared form of the same five-tuple
// codegen/parser_trail.go::variableTailSkip carries: a runtime length
// computed as `((<byte at LenFieldByteOff> & LenMask) >> LenShift) *
// Scale + Base`. The kunai-specific @kunai_variable_tail annotation
// names the field; the loader resolves it against the header's bit
// layout the same way pkt.advance's lowerCastShiftSkip does.
type VariableTailSpec struct {
	LenFieldByteOff int
	LenMask         int
	LenShift        int
	Scale           int
	Base            int
}

// WriteBackSpec captures the cross-protocol byte copy a chained
// extension header's parser-loop emits per iteration. Source names
// a field on the chained header (resolved against the header's
// declared layout). Parent identifies the destination via a
// proto.field path the loader resolves to a concrete byte offset
// (ParentByteOff) once every spec is loaded — the resolved offset
// matches the layout codegen already uses, so the write-back stays
// verifier-safe against PTR_TO_MAP_VALUE.
type WriteBackSpec struct {
	SourceField   string
	ParentProto   string
	ParentField   string
	SourceByteOff int // resolved during loadFile against the chained header
	ParentByteOff int // resolved during Load's pass 2 against the parent spec
	// Resolved distinguishes a real ParentByteOff=0 (= writeback target is the
	// first byte of the parent's primary header) from "pass-2 hasn't run yet".
	// Set to true by resolveHeaderWritebackTargets; consumers in codegen panic
	// loudly when WriteBack is non-nil but Resolved is false, surfacing
	// loader-bypassing callers immediately rather than silently writing into
	// byte 0 of a parent that may not be the intended target.
	Resolved bool
}

// HeaderLength is the lowered shape of a primary-header variable
// trailer — the parser-block `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)`
// template the loader resolves into a five-tuple codegen consumes.
// The trailer length in bytes is computed as
//
//	((<byte at LenByteOff> & LenMask) >> LenShift) * Scale - Base
//
// applied past the fixed advance of the primary header. Examples:
//
//   - IPv4 (IHL is the lower 4 bits of byte 0; total length = IHL*4):
//     LenByteOff=0, LenMask=0x0F, LenShift=0, Scale=4, Base=20
//   - TCP (data_offset is the upper 4 bits of byte 12; total = doff*4):
//     LenByteOff=12, LenMask=0xF0, LenShift=4, Scale=4, Base=20
//
// Codegen caps the runtime advance via verifier-friendly scalar
// narrowing so the suffix cannot grow past ScratchBufSize. Carried
// on each AdvanceOp.Skip; see (*ProtocolSpec).PrimaryAdvanceSkip
// for the by-protocol accessor.
type HeaderLength struct {
	LenByteOff int
	LenMask    int
	LenShift   int
	Scale      int
	Base       int // bytes to subtract (i.e. minimum header size in bytes)
	// Addend is added to the scaled value (after Base subtraction). Used
	// by the bare-cast counter.set add form `(bit<N>)(hdr.<F> + K)`
	// where the counter holds an element count (SRH segments =
	// last_entry + 1). Zero for the pkt.advance / shifted counter forms.
	// Base (subtract) and Addend (add) are mutually exclusive in
	// practice, but the codegen applies whichever is non-zero.
	Addend int
}


// FlagTrigger names one optional fixed-length field gated by a flag
// bit in the primary header. Codegen emits roughly
//
//	if (header[FlagsByteOffset] & BitMask) != 0 { R4 += LenBytes; }
//
// per trigger, in declaration order so the offsets line up with
// protocols where field order matters (GRE: Checksum, Key, Sequence).
type FlagTrigger struct {
	Name     string // upper-case suffix from <SELF>_OPT_TRIGGER_<NAME>
	BitMask  int    // applied to the flag byte
	LenBytes int    // bytes to advance when the flag is set
}

// ChainEndConst describes a vocab-declared chain-termination
// signal: "stop iterating when this field of the current header
// equals Value". MPLS uses it for the s-bit; SRv6 / IPv6
// extension headers can declare similar signals later.
type ChainEndConst struct {
	Name      string // original full constant name, for diagnostics
	FieldName string // lowercase field name in this protocol's header
	Value     uint64
	Bits      int // const bit width (matches the field width)
}

// Field describes one header field layout entry.
type Field struct {
	Name string
	Bits int
}

// HasVariableLayout reports whether this protocol's layer body can
// extend past its primary header — via parser-machine aux extracts
// (GTP opt, IPv6 ext, SRv6 segments), a parser-block pkt.advance
// trailer (IPv4 IHL, TCP data_offset), or flag-gated optional
// fields (GRE C/K/S). Codegen consumes this to decide whether
// children must anchor field reads on the layer-entry slot rather
// than on R4. The pkt.advance trailer lives inside the parser
// machine, so the first branch already covers it.
func (p *ProtocolSpec) HasVariableLayout() bool {
	return p.ParseStateMachine != nil || len(p.FlagTriggers) > 0
}

// PrimaryAdvanceSkip returns the protocol's primary-header
// variable-trailer descriptor — the lowered shape of the parser
// block's pkt.advance template — or nil when no state declares
// one. By convention each protocol declares at most one such
// trailer; subsequent advances are reserved for option-walk style
// uses and skipped here.
func (p *ProtocolSpec) PrimaryAdvanceSkip() *HeaderLength {
	if p.ParseStateMachine == nil {
		return nil
	}
	for _, st := range p.ParseStateMachine.States {
		if len(st.Advances) > 0 {
			return st.Advances[0].Skip
		}
	}
	return nil
}


// pushedAuxStackName returns the out-param name of the first aux stack
// the parser machine push-extracts (extract(stack.next)), or ("", false)
// when the machine pushes none. This is the discriminator that separates
// SRv6's segment walk (which pushes srv6_seg_h onto the segments stack)
// from the geneve / ipv4 counter walks (which record single option
// positions but push no stack). SRv6 pushes `segments`.
func (p *ProtocolSpec) pushedAuxStackName() (string, bool) {
	if p.ParseStateMachine == nil {
		return "", false
	}
	for _, st := range p.ParseStateMachine.States {
		for _, ex := range st.Extracts {
			if ex.IsStackPush {
				return ex.StackName, true
			}
		}
	}
	return "", false
}

// AuxWalkSegmentTail synthesises the next-header re-anchor descriptor for
// a counter-driven aux-stack walk from the segment COUNT alone, plus the
// primary header size in bytes. The next header of such a layer sits at
// layer_entry + primaryHS + count*ElemSize, where count is the derived
// stack count (SRv6: last_entry + 1). Per RFC 8754 the SRH variable
// region equals (Last Entry+1)*16 exactly when no TLVs follow the segment
// list, so the count yields the next-header offset for every TLV-free
// SRH. Chaining past a TLV-bearing SRH is unsupported: TLV support is
// optional per RFC 8754 Section 2, and the element walk leaves R4 at the
// segment-list end, short of any trailing TLVs.
//
// The region reuses the five-tuple emitAuxWalkTailReanchor consumes:
// region = count*ElemSize + Addend*ElemSize. The count byte is read whole
// (LenShift 0, no shift); LenMask carries the maximum valid index
// Capacity-1, which emitAuxWalkTailReanchor enforces as a JGT-reject (an
// over-cap count is rejected, not wrapped) so the scaled offset stays
// within a static bound.
//
// Returns (nil, 0, false) for any protocol without a pushed aux stack or
// without a derived stack count: ipv6 / gtp ext stacks self-terminate on
// next_header and carry no count, so they keep their own tail handling.
func (p *ProtocolSpec) AuxWalkSegmentTail() (*VariableTailSpec, int, bool) {
	stack, ok := p.pushedAuxStackName()
	if !ok {
		return nil, 0, false
	}
	cnt := p.StackCounts[stack]
	if cnt == nil || p.ParseStateMachine == nil {
		return nil, 0, false
	}
	st := p.ParseStateMachine.StackRefs[stack]
	if st == nil || st.ElemSize <= 0 || st.Capacity <= 0 {
		return nil, 0, false
	}
	bits := SumBits(p.Fields)
	if bits%8 != 0 {
		return nil, 0, false
	}
	// Bound the count byte to the exact maximum valid index Capacity-1.
	// emitAuxWalkTailReanchor turns LenMask into a JGT-reject (not a
	// bitwise AND), so an over-cap count is rejected outright rather than
	// wrapped, and the region (count*ElemSize) keeps a static upper bound
	// (Capacity*ElemSize) the verifier can prove. Using Capacity-1 directly,
	// rather than rounding up to the next power-of-two mask, enforces the
	// declared capacity precisely even when Capacity is not a power of two
	// (a power-of-two mask would let counts in [Capacity, 2^k-1] slip past
	// the bound check). A valid SRH carries last_entry < Capacity, so it
	// passes; a malformed over-cap frame is rejected at the re-anchor.
	return &VariableTailSpec{
		LenFieldByteOff: cnt.ByteOff,
		LenMask:         st.Capacity - 1,
		LenShift:        0,
		Scale:           st.ElemSize,
		Base:            cnt.Addend * st.ElemSize,
	}, bits / 8, true
}

// IsSelfValidating reports whether the parser block proves the
// protocol's identity itself — i.e. its `start` state's transition
// is `select(...) { ...; default: reject; }` keyed on at least one
// primary-header field. When true, a parent that lacks a Field
// dispatch can still chain to this protocol because the parser
// machine's transition select rejects packets that don't match the
// expected shape (e.g. ipv4's `transition select(hdr.version) { 4:
// accept; default: reject; }`).
//
// Resolver uses this to decide whether to allow `mpls/ipv4`-shaped
// chains without an explicit dispatch const: if the child is
// self-validating, no boundary emit is needed (the parser machine
// validates internally). Cached at vocab load via computeSelfValidating.
func (p *ProtocolSpec) IsSelfValidating() bool {
	return p.selfValidating
}

// computeSelfValidating walks the parser machine to detect the
// "self-validating" shape. Called once per spec from the vocab loader
// (after buildParseStateMachine) so the per-Compile IsSelfValidating
// query is a single field load.
func computeSelfValidating(p *ProtocolSpec) bool {
	if p.ParseStateMachine == nil {
		return false
	}
	m := p.ParseStateMachine
	if m.EntryIdx < 0 || m.EntryIdx >= len(m.States) {
		return false
	}
	start := m.States[m.EntryIdx]
	if start.Trans.Kind != TransSelect || start.Trans.Select == nil {
		return false
	}
	if start.Trans.Select.Default != StateReject {
		return false
	}
	for _, k := range start.Trans.Select.Keys {
		// Lookahead keys peek at unconsumed bytes; they cannot
		// reference an extracted field so they don't contribute to
		// self-validation by definition.
		if k.Kind == SelectKeyField && k.Field.HeaderName == p.HeaderName {
			return true
		}
	}
	return false
}

// FindField returns the named header field and true when present.
// The returned pointer aliases into ProtocolSpec.Fields.
func (p *ProtocolSpec) FindField(name string) (*Field, bool) {
	for i := range p.Fields {
		if p.Fields[i].Name == name {
			return &p.Fields[i], true
		}
	}
	return nil, false
}

// BitOffsetIn walks fields in declaration order, returning the bit
// offset and bit width of the named field. Both codegen (against
// ProtocolSpec.Fields) and the parse-state-machine builder (against
// auxiliary headers converted to []Field) rely on this single
// implementation; if the answer is wrong here the rest of the
// pipeline reads the wrong bytes.
func BitOffsetIn(fields []Field, name string) (bitOff, bits int, ok bool) {
	for _, f := range fields {
		if f.Name == name {
			return bitOff, f.Bits, true
		}
		bitOff += f.Bits
	}
	return 0, 0, false
}

// SumBits returns the total bit width of the named fields. Used by
// codegen for fixed-size header advance and by the parse machine
// for byte-aligned size validation.
func SumBits(fields []Field) int {
	total := 0
	for _, f := range fields {
		total += f.Bits
	}
	return total
}

// DispatchType is how a protocol is selected from its parent.
type DispatchType int

const (
	// DispatchField: parent has an identifying field (e.g. ipv4.protocol),
	// named as KUNAI_<SELF>_<PARENT>_<FIELD> = value. The KUNAI_ marker is
	// mandatory and <PARENT> must be a real protocol: a value-only
	// select-match const (phantom parent) is written *without* KUNAI_ and
	// folds into the select arm instead of becoming a dispatch edge.
	DispatchField DispatchType = iota
	// DispatchNoCheck: blind cast, user-declared trust (e.g. Ethernet
	// payload of MPLS in EoMPLS), named as
	// KUNAI_<SELF>_<PARENT>_NO_CHECK = true.
	DispatchNoCheck
	// DispatchSelfValidating: parent has no Field/NoCheck, but the child's
	// parser block validates itself via `transition select(...) { ...;
	// default: reject; }` (see ProtocolSpec.IsSelfValidating). No const
	// declaration is required and no boundary instructions are emitted —
	// the parser machine's transition select rejects mismatched packets.
	DispatchSelfValidating
)

func (d DispatchType) String() string {
	switch d {
	case DispatchField:
		return "field"
	case DispatchNoCheck:
		return "no-check"
	case DispatchSelfValidating:
		return "self-validating"
	}
	return fmt.Sprintf("DispatchType(%d)", int(d))
}

// DispatchConst is one classified <SELF>_<PARENT>_... constant.
type DispatchConst struct {
	Type      DispatchType
	Name      string // original full constant name, for diagnostics
	Parent    string // lowercase parent protocol name (e.g. "ipv4")
	FieldName string // lowercase field name of the parent; Field only
	Bits      int    // width of the constant; Field only
	Value     uint64 // integer value; Field only
	Bool      bool   // truth value; NoCheck only (must be true to be valid)
}

// --- Parse state machine (within-protocol structure) ---
//
// The types below represent a P4-16 `parser` block in a form the
// codegen can consume directly: every state is a basic block, every
// transition is a labelled jump, and `extract`s carry the byte size
// they advance the offset register by. Set on ProtocolSpec only when
// the block needs more than the trivial single-extract shape (see
// ProtocolSpec.ParseStateMachine for the detection rule).

// State indices used for accept / reject sentinels in transition
// targets; real states are 0 or positive.
const (
	StateAccept = -1
	StateReject = -2
)

// ParseStateMachine is the codegen-ready normalisation of one
// protocol's parser block. EntryIdx is the index of the "start"
// state in States (P4-16 mandates the name "start"); accept /
// reject are not in the slice and transitions point at them via the
// sentinels above.
type ParseStateMachine struct {
	States     []*ParseState
	StateIdx   map[string]int // state name → index in States
	EntryIdx   int            // index of the "start" state
	HeaderRefs map[string]*p4lite.Header
	StackRefs  map[string]*HeaderStack // out-stack param name → resolved stack
	// Counters lists the `ParserCounter() <name>;` instances declared
	// at the parser block scope, in source order. Codegen allocates
	// one stack slot per counter; loader scope-checks every counter
	// op against this list so typos surface as a load error.
	Counters []CounterInst
	// AuxLayouts maps each non-stack `out` parameter name to its byte
	// position within the layer plus the (optional) gating predicate
	// that decides whether the aux is extracted on a given packet's
	// path. Predicate codegen consumes this to read aux header fields
	// at static offsets and, when Gating != nil, gate the read on the
	// gating condition. nil entries are absent — a missing key means
	// the corresponding out parameter is a stack (StackRefs).
	AuxLayouts map[string]*AuxLayout
}

// CounterInst is the in-machine handle for one ParserCounter
// instance. The slot allocator (codegen) maps Name → stack offset;
// the loader only records the declaration order.
type CounterInst struct {
	Name string
	Pos  p4lite.Position
}

// AuxLayout is the per-aux summary needed by predicate codegen.
type AuxLayout struct {
	OutParam      string         // parser out parameter name (e.g. "opt")
	HeaderName    string         // referenced header type name (e.g. "gtp_opt_h")
	HeaderRef     *p4lite.Header // pointer into File.Headers (do not mutate)
	OffsetInLayer int            // bytes from layer-entry slot to aux start
	HeaderSize    int            // bytes; byte-aligned (mirrors ExtractOp.HeaderSize/8)
	// Gating describes the runtime condition that decides whether the
	// aux is present on this packet. nil means "extracted
	// unconditionally on every accepted path". The MVP only models
	// gating reachable from a single tuple-select at the entry state
	// where each key is a single-bit (or otherwise narrow) field of
	// the primary header — that covers GTP's E/S/PN tuple. Other
	// shapes are surfaced as build errors so they cannot silently
	// land as "always-present" auxes.
	Gating *AuxGating
	// IsDynamicEligible is true for auxes extracted by a TLV-walk
	// sibling state (parse_mss / parse_ws / ... in tcp.p4): the
	// option's start position varies per packet, so the static
	// OffsetInLayer / Gating fields above don't apply. Codegen
	// records the position in a per-LayerInstance stack slot
	// (allocated only when a where / capture clause queries this
	// aux — see the demand walker in pkg/kunai/codegen) and where-
	// time access reads the slot back.
	IsDynamicEligible bool
	// DynamicKindByte is the kind value the multi-state loop entry's
	// transition select uses to dispatch to this aux's sibling state.
	// Recovered from the parser block at vocab load time (= the
	// `2: parse_mss` case label pins MSS_KIND = 2). Zero when
	// IsDynamicEligible is false.
	DynamicKindByte uint64
}

// FindField returns the bit window of a named field within the aux
// header. (bitOff, bitWidth) are in bits, relative to the aux
// header's start (= AuxLayout.OffsetInLayer × 8). The bool is false
// when the aux header has no field by that name.
func (a *AuxLayout) FindField(name string) (int, int, bool) {
	if a == nil || a.HeaderRef == nil {
		return 0, 0, false
	}
	bitOff := 0
	for _, f := range a.HeaderRef.Fields {
		if f.Name == name {
			return bitOff, f.Bits, true
		}
		bitOff += f.Bits
	}
	return 0, 0, false
}

// AuxGating expresses "the aux is extracted iff (primary[ByteOff] &
// Mask) <Op> Value". The byte offset is within the primary header
// (= layer-entry slot + ByteOff). MVP: every gating in the bundled
// vocab fits this shape.
type AuxGating struct {
	ByteOff int      // within primary header
	Mask    uint64   // bits looked at; Mask <= 0xFF for the MVP byte read
	Op      GatingOp // Eq | Ne
	Value   uint64
}

// GatingOp is the comparison used in AuxGating.
type GatingOp int

const (
	// GatingEq fires the aux when (primary[ByteOff] & Mask) == Value.
	GatingEq GatingOp = iota
	// GatingNe fires the aux when (primary[ByteOff] & Mask) != Value.
	GatingNe
)

// IsAccept reports whether t terminates the machine in the "accept"
// final state (StateAccept sentinel). Direct/select transitions can
// still target StateAccept; this helper is for the bare TransAccept
// kind only.
func (t TransitionOp) IsAccept() bool { return t.Kind == TransAccept }

// IsReject reports whether t terminates the machine in the "reject"
// final state. Same caveat as IsAccept w.r.t. direct/select target
// sentinels.
func (t TransitionOp) IsReject() bool { return t.Kind == TransReject }

// IsTerminal reports whether t is a bare accept/reject (no successor
// state). Codegen uses it to decide whether to emit a fall-through
// branch or end the basic block.
func (t TransitionOp) IsTerminal() bool { return t.Kind == TransAccept || t.Kind == TransReject }

// HeaderStack is the resolved view of an `out <type>[N] <var>`
// parser parameter — i.e. a fixed-capacity array of header
// instances pushed in turn via `obj.extract(<var>.next)`.
type HeaderStack struct {
	HeaderName string
	HeaderRef  *p4lite.Header
	Capacity   int
	ElemSize   int // bytes; matches the referenced header's byte-aligned size
	// OwnerOption names the AuxLayout this stack rides past — set
	// when the stack is declared but never extracted, and a sibling
	// state has the option-with-trailing-array shape (`extract(aux);
	// advance(aux.<len-field>...)`). The stack base on a given packet
	// is the owner aux's per-packet offset slot value plus
	// OffsetAfterOwner. Empty for top-level stacks (srv6.segments,
	// ipv6.exts) which anchor to the layer entry directly.
	OwnerOption string
	// OffsetAfterOwner caches the byte distance from the owner aux's
	// per-packet base to the first stack element. Derivable from
	// AuxLayouts[OwnerOption].HeaderSize but inlined here so codegen
	// avoids a second map lookup per access. Zero when OwnerOption
	// is empty.
	OffsetAfterOwner int
}

// ParseState is a single state in the machine. Extracts run in
// declaration order, then Trans decides where control goes next.
//
// OffsetAtEntry is the byte distance from the layer's primary header
// start (= layer-entry slot) to where R4 points when control arrives
// at this state. Computed by walking the state graph from "start"
// (where OffsetAtEntry == 0) and accumulating extract sizes along
// each direct/select edge. -1 means "not on a non-cyclic path from
// start" or "the state participates in a stack-push cycle whose
// per-iteration offset is not a single value" — predicate codegen
// must route those through the bpf_loop machinery, not static reads.
type ParseState struct {
	Name          string
	Extracts      []ExtractOp
	Advances      []AdvanceOp
	Counters      []CounterOp
	Trans         TransitionOp
	OffsetAtEntry int
	Pos           p4lite.Position
}

// ExtractOp is one `obj.extract(<var>)` or `obj.extract(<stack>.next)`
// statement in a state. The codegen emits a bounds check + advance
// of `HeaderSize/8` bytes for each.
type ExtractOp struct {
	HeaderName  string         // resolved header name being consumed
	HeaderRef   *p4lite.Header // pointer into File.Headers (do not mutate)
	HeaderSize  int            // bits, byte-aligned
	IsStackPush bool           // true when target is `<stack>.next`
	OutParam    string         // parser out-param name (== StackName when IsStackPush)
	StackName   string         // when IsStackPush, the stack parameter name
	Pos         p4lite.Position
}

// AdvanceOpKind tags AdvanceOp with which p4lite template the loader
// lowered. The active fields differ per kind; the others are
// zero-valued.
type AdvanceOpKind int

const (
	// AdvanceOpField is the layer-entry-relative trailer — lowered
	// from `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)`. Codegen
	// reads the length field from the layer-entry slot via
	// emitVariableTrailInline. Active fields: Target, FieldName, Skip.
	AdvanceOpField AdvanceOpKind = iota
	// AdvanceOpLookahead is the R4-relative trailer — lowered from
	// `pkt.advance(((bit<N>)pkt.lookahead<bit<M>>()[hi:lo]) << S)`.
	// Codegen reads the length byte from R0+R4+Skip.LenByteOff
	// (forward peek, no advance until the value is computed).
	// Active field: Skip.
	AdvanceOpLookahead
	// AdvanceOpLiteral is the fixed advance — lowered from
	// `pkt.advance(<INT>)`. Codegen emits a bounds check followed by
	// `Add.Imm R4, LiteralBytes`. Active field: LiteralBytes.
	AdvanceOpLiteral
)

// AdvanceOp is one of the three pkt.advance variants the loader
// recognises in a parser-state body. For Field and Lookahead kinds
// the Skip carries the resolved (LenByteOff / LenMask / LenShift /
// Scale / Base) tuple codegen consumes; the Kind discriminator
// tells codegen whether Skip.LenByteOff is layer-entry-relative
// (Field) or R4-relative (Lookahead).
type AdvanceOp struct {
	Kind         AdvanceOpKind
	Target       string // AdvanceOpField only — out parameter the field came from
	FieldName    string // AdvanceOpField only — field whose value drives the advance
	Skip         *HeaderLength
	LiteralBytes int // AdvanceOpLiteral only — fixed advance in bytes
	Pos          p4lite.Position
}

// CounterOpKind tags CounterOp with which ParserCounter method the
// loader lowered. See p4lite.CounterCallKind for the source-form
// description; CounterOpSet's Skip mirrors AdvanceOpField's so
// codegen reuses the same byte-expression load path.
type CounterOpKind int

const (
	CounterOpSet CounterOpKind = iota
	CounterOpDecrement
)

// CounterOp is one ParserCounter method call inside a parser-state
// body. Counter must match one of ParseStateMachine.Counters; the
// loader scope-checks so unknown names fail at build time.
type CounterOp struct {
	Kind         CounterOpKind
	Counter      string
	Target       string        // CounterOpSet only
	FieldName    string        // CounterOpSet only
	Skip         *HeaderLength // CounterOpSet only
	LiteralBytes int           // CounterOpDecrement only — literal form
	// DecrementTarget / DecrementFieldName / DecrementByteOff are set
	// for the field-expr decrement form (`pc.decrement(<aux>.<field>)`)
	// and are mutually exclusive with LiteralBytes. Codegen emits a
	// single-byte LDX from R3 + (DecrementByteOff - aux_size) and
	// subtracts the loaded value from the counter slot via Sub.Reg.
	DecrementTarget    string
	DecrementFieldName string
	DecrementByteOff   int
	// DecrementLookaheadByteOffR is true for the lookahead-form
	// decrement (`pc.decrement(((bit<N>)pkt.lookahead<bit<M>>()[hi:lo]))`):
	// the byte sits at R3 + DecrementLookaheadByteOff (no extract has
	// preceded). Mutually exclusive with the field-expr / literal
	// branches. Used by IPv4 RR's dispatched-but-not-extracted shape
	// to avoid the JLT+Sub combo a field-driven trailing advance
	// would emit.
	DecrementLookaheadByteOff  int
	DecrementLookaheadByteOffR bool
	Pos                        p4lite.Position
}

// TransKind enumerates the four shapes of a parser-state
// transition. Mirrors p4lite.TransKind so consumers don't need to
// import p4lite.
type TransKind int

const (
	TransAccept TransKind = iota
	TransReject
	TransDirect
	TransSelect
)

// TransitionOp is the resolved tail of one parser state. Direct
// transitions point at a state index in the parent machine's
// States slice; accept / reject use the StateAccept / StateReject
// sentinels.
type TransitionOp struct {
	Kind   TransKind
	Target int       // valid when Kind == TransDirect
	Select *SelectOp // valid when Kind == TransSelect
}

// SelectOp is a tuple match. Each Case's Values length equals
// len(Keys); on the first case where every key matches (with `_`
// counting as match), control moves to that case's Target.
// Default fires when no case matches.
type SelectOp struct {
	Keys    []SelectKey
	Cases   []SelectCase
	Default int // state index | StateAccept | StateReject
	Pos     p4lite.Position
}

// SelectKeyKind tags one slot of a tuple-select key.
type SelectKeyKind int

const (
	// SelectKeyField reads from an already-extracted header field.
	// The byte offset is negative w.r.t. the current R4 (the load
	// reaches back into the just-extracted bytes).
	SelectKeyField SelectKeyKind = iota
	// SelectKeyLookahead peeks at bytes the parser has not yet
	// consumed. The byte offset is non-negative w.r.t. the current
	// R4 and R4 is unchanged. Codegen supports byte-multiple widths
	// up to 24 bits (e.g. a Geneve option class+type discriminator);
	// the value is loaded as the next power-of-two LDX, byte-swapped,
	// and shifted/masked to the key width.
	SelectKeyLookahead
	// SelectKeyCounterIsZero reads a ParserCounter slot and dispatches
	// on whether it has reached zero. The matching MatchVal slots are
	// IsBool-tagged with Bool == true / false. Codegen folds this into
	// a JEQ on the counter slot.
	SelectKeyCounterIsZero
)

// SelectKey is one slot of a SelectOp's key tuple. The Kind
// discriminator decides which sub-shape is active; the unused
// fields are zero-valued.
type SelectKey struct {
	Kind SelectKeyKind
	// SelectKeyField only.
	Field FieldRef
	// SelectKeyLookahead only.
	Bits int // peek width; byte-multiple, 8/16/24
	// SelectKeyCounterIsZero only — counter instance name.
	Counter string
	Pos     p4lite.Position
}

// SelectCase is one `(v1, v2, ...): target;` line of a `transition
// select(...)`. Values is parallel with the parent SelectOp.Keys.
type SelectCase struct {
	Values []MatchVal // wildcard | concrete
	Target int        // state index | StateAccept | StateReject
	Pos    p4lite.Position
}

// MatchVal is one slot of a SelectCase keyset. IsBool/Bool carry the
// boolean literal cases needed by SelectKeyCounterIsZero; integer
// keysets leave them zero-valued.
type MatchVal struct {
	IsWildcard bool
	IsBool     bool
	Bool       bool
	Value      uint64
}

// FieldRef points at a specific bit-window of an extracted header.
// Used as a select key and (later) as the source of variable-length
// arithmetic in codegen.
type FieldRef struct {
	HeaderName  string         // resolved primary or auxiliary header name
	HeaderRef   *p4lite.Header // pointer into File.Headers
	IsStackLast bool           // true when accessed as `<stack>.last.<field>`
	StackName   string         // when IsStackLast, the stack parameter name
	FieldName   string         // lowercase
	BitOffset   int            // within the referenced header
	BitWidth    int
}

// SelectDispatchConst returns the strongest dispatch const whose
// Parent matches parentName. Preference: Field > NoCheck.
//
// Returns nil when no const matches; the resolver then checks
// IsSelfValidating to decide whether to synthesize a
// DispatchSelfValidating choice or surface a "no dispatch" error.
func (s *ProtocolSpec) SelectDispatchConst(parentName string) *DispatchConst {
	var field, nocheck *DispatchConst
	for i := range s.Consts {
		c := &s.Consts[i]
		if c.Parent != parentName {
			continue
		}
		switch c.Type {
		case DispatchField:
			if field == nil {
				field = c
			}
		case DispatchNoCheck:
			if nocheck == nil {
				nocheck = c
			}
		}
	}
	switch {
	case field != nil:
		return field
	case nocheck != nil:
		return nocheck
	}
	return nil
}
