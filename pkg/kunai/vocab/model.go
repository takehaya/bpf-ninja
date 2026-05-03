// Package vocab loads protocol vocabulary from .p4 sources and classifies
// their dispatch constants for downstream one-liner resolution and
// codegen.
package vocab

import (
	"fmt"
	"strings"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
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
	// OptionWalk describes a TCP/IPv4-style options walk: byte 0 of
	// each option is a kind discriminator, kind=Terminator stops the
	// walk, kind=Padding advances 1 byte, otherwise byte LengthByteOff
	// gives the option's total byte length and the codegen advances
	// by that much. Per-option metadata (kind, total bytes, named
	// header type) lives in Options. nil when the .p4 declared no
	// option-walk consts.
	OptionWalk *OptionWalk
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
	// selfValidating caches whether the parser block proves the
	// protocol's identity itself (start-state `transition select(...)
	// { ...; default: reject; }` keyed on a primary-header field).
	// Computed once at vocab load (loader.go) and queried per Compile
	// via IsSelfValidating().
	selfValidating bool
	File           *p4lite.File // full AST (for resolver/codegen later)
	Source         string       // original file path, for diagnostics
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
}

// OptionWalk carries the metadata codegen needs to walk a TCP/IPv4
// option list and dispatch on per-option kind. The walk starts at
// the layer's variable trailer (= primary header size) and ends at
// the trailer length declared by the parser-block pkt.advance or at
// the first terminator kind, whichever comes first.
type OptionWalk struct {
	TerminatorKind uint64
	PaddingKind    uint64
	LengthByteOff  int
	// Options lists the named options the .p4 declared, in
	// declaration order. Each entry pairs the user-facing name
	// (e.g. "MSS") with its kind discriminator and the aux header
	// the parser block out-bound it to.
	Options []OptionEntry
}

// OptionEntry is one named option's metadata.
type OptionEntry struct {
	Name      string         // upper-case, matches DSL identifier
	Kind      uint64         // kind discriminator
	Size      int            // total option byte size; 0 = variable
	HeaderRef *p4lite.Header // pointer into File.Headers for tcp_opt_<name>_h
}

// FindOption returns the entry matching name (case-insensitive) and
// true when present.
func (w *OptionWalk) FindOption(name string) (*OptionEntry, bool) {
	if w == nil {
		return nil, false
	}
	upper := strings.ToUpper(name)
	for i := range w.Options {
		if w.Options[i].Name == upper {
			return &w.Options[i], true
		}
	}
	return nil, false
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
	// named as <SELF>_<PARENT>_<FIELD> = value.
	DispatchField DispatchType = iota
	// DispatchNoCheck: blind cast, user-declared trust (e.g. Ethernet
	// payload of MPLS in EoMPLS), named as <SELF>_<PARENT>_NO_CHECK = true.
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
	// AuxLayouts maps each non-stack `out` parameter name to its byte
	// position within the layer plus the (optional) gating predicate
	// that decides whether the aux is extracted on a given packet's
	// path. Predicate codegen consumes this to read aux header fields
	// at static offsets and, when Gating != nil, gate the read on the
	// gating condition. nil entries are absent — a missing key means
	// the corresponding out parameter is a stack (StackRefs).
	AuxLayouts map[string]*AuxLayout
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
	// R4 and R4 is unchanged. MVP supports only `bit<8>`
	// lookaheads (single-byte LDX in codegen).
	SelectKeyLookahead
)

// SelectKey is one slot of a SelectOp's key tuple. The Kind
// discriminator decides which sub-shape is active; the unused
// fields are zero-valued.
type SelectKey struct {
	Kind SelectKeyKind
	// SelectKeyField only.
	Field FieldRef
	// SelectKeyLookahead only.
	Bits int // peek width (MVP cap = 8)
	Pos  p4lite.Position
}

// SelectCase is one `(v1, v2, ...): target;` line of a `transition
// select(...)`. Values is parallel with the parent SelectOp.Keys.
type SelectCase struct {
	Values []MatchVal // wildcard | concrete
	Target int        // state index | StateAccept | StateReject
	Pos    p4lite.Position
}

// MatchVal is one slot of a SelectCase keyset.
type MatchVal struct {
	IsWildcard bool
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
