package codegen

import "github.com/cilium/ebpf/asm"

// Capabilities is the thin aggregate a host hands to kunai.Compile. It
// composes three phase-scoped capability groups, each consumed by a
// single pipeline phase, so no phase has to reach into a grab-bag of
// unrelated fields:
//
//   - Lex  → the parser (label reservation)
//   - Lang → the resolver and codegen (action atoms)
//   - Host → codegen (host packet-layout facts)
//
// The zero value yields a fully target-agnostic filter — no action
// atoms, no reservations, VLAN assumed in-band — portable across any
// BPF attach point that supplies the runFilter ABI documented in this
// package's doc comment.
//
// Hosts construct a Capabilities from their own adapter package — e.g.
// pkg/kunai/host/xdp.FexitCapabilities() — and pass it to kunai.Compile.
// The kunai core ships no host-specific helpers itself.
//
// Treat a Capabilities (and its groups) as immutable after
// construction: the compile pipeline only reads the maps and the
// fetcher, so multiple goroutines may share one value safely as long
// as no caller mutates the maps.
type Capabilities struct {
	Lex  LexCaps
	Lang LangCaps
	Host HostLayout
}

// LexCaps carries the capabilities the parser needs.
type LexCaps struct {
	// ReservedLabels names that DSL @labels must not collide with.
	// Typically the keys of LangCaps.Action (so a label named "XDP_DROP"
	// cannot shadow the action symbol); kunai.Compile derives that set
	// automatically when this is nil. nil means no reservations.
	ReservedLabels map[string]bool
}

// LangCaps carries the host-specific language extensions: the action
// atom vocabulary and the fetcher that loads the action value. The
// resolver reads Action (to validate `where action == NAME`); codegen
// reads both (to emit the comparison).
type LangCaps struct {
	// Action: symbolic name → integer constant for `where action == NAME`
	// clauses. Keys (e.g. "XDP_DROP") are the symbols accepted in DSL
	// expressions; values are the integers the action register is
	// compared against. nil disables action atoms entirely — both the
	// resolver (atom validity) and codegen treat `action == ...` as an
	// error.
	//
	// Pair Action with a non-nil ActionFetcher.
	Action map[string]int32

	// ActionFetcher emits 1+ instructions that load the current action
	// value into R3 as a u32. Required iff Action is non-nil. The
	// concrete implementation embeds the host's ABI knowledge (e.g.
	// XDP fexit reads stack[-48] then args[1]); host adapter packages
	// provide ready-made implementations.
	ActionFetcher ActionFetcher

	// SetSlots resolves a `field in @name` predicate to the R10 stack
	// slot where codegen must store the extracted packet field, so the
	// host can look it up in its pinned map after the filter returns.
	// nil disables `in @set` atoms: both the resolver (atom validity)
	// and codegen treat them as an error. See SetSlotResolver.
	SetSlots SetSlotResolver
}

// HasSetAtoms reports whether the lang caps configure a set-slot
// resolver. Used by the resolver to short-circuit `field in @name`
// validation when the host has not opted in. Parallels HasActionAtoms.
func (l LangCaps) HasSetAtoms() bool {
	return l.SetSlots != nil
}

// HasActionAtoms reports whether the lang caps configure an action map
// + fetcher pair. Used by the resolver to short-circuit `action == X`
// validation when the host has not opted in.
func (l LangCaps) HasActionAtoms() bool {
	return l.Action != nil && l.ActionFetcher != nil
}

// HostLayout carries facts about how the host presents packet bytes to
// the filter — independent of the language extensions in LangCaps.
type HostLayout struct {
	// VlanInMetadata declares that at this host the kernel has already
	// extracted the outer VLAN tag into skb metadata (skb->vlan_tci)
	// before the program runs, so it is NOT present in the packet bytes
	// the filter parses. This is the case at the tc (SCHED_CLS) attach
	// point, where skb_vlan_untag fires before the program. The zero
	// value (false) assumes VLAN is in-band — correct for XDP and for
	// the target-agnostic BPF_PROG_TEST_RUN harness, which feed raw
	// frames with the tag present.
	//
	// When true, kunai rejects any chain containing a vlan or qinq
	// layer at compile time rather than silently parsing the wrong
	// bytes. Reading the tag from skb metadata is future work.
	VlanInMetadata bool
}

// ActionFetcher loads the current action value into a register so the
// where-clause codegen can compare it against a constant. The contract
// is: when EmitFetch returns, the destination register holds the action
// as a u32 (zero-extended from however the host stores it).
type ActionFetcher interface {
	EmitFetch(dst asm.Register) asm.Instructions
}

// SetSlotResolver maps a `field in @name` predicate to a host-owned
// stack slot. kunai extracts the packet field and stores it there;
// the host looks up its pinned map against those bytes after the filter
// returns. kunai stays map-agnostic: the resolver returns only an R10
// offset and width, never a map, FD, or BTF.
//
// The returned off MUST be in the host region (> KunaiStackTop, i.e.
// closer to 0), because the extraction is written during the filter and
// read after it; codegen rejects a slot inside kunai's own stack range.
// size is the field width in bytes (1/2/4/8). ok is false for an unknown
// set or a field the set's key does not contain.
type SetSlotResolver interface {
	SlotFor(setName, fieldName string) (off int16, size int, ok bool)
	HasSet(setName string) bool
}
