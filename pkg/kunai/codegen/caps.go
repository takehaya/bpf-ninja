package codegen

import "github.com/cilium/ebpf/asm"

// Capabilities tells the compiler what host-specific DSL extensions
// are available at runtime. The zero value yields a fully
// target-agnostic filter — no action atoms, no host-specific
// reservations, just protocol-stack matching and where/capture
// clauses. That output is portable across any BPF attach point that
// supplies the runFilter ABI documented in this package's doc comment.
//
// Hosts construct a Capabilities value from their own host adapter
// package — for example, pkg/kunai/host/xdp.FexitCapabilities() for
// an XDP fexit attach point — and pass it to kunai.Compile. The
// kunai core ships no host-specific helpers itself; sub-packages
// under pkg/kunai/host/ encapsulate that knowledge.
//
// Treat a Capabilities value as immutable after construction: the
// compile pipeline only reads from the maps and the fetcher; multiple
// goroutines may share the same value safely as long as no caller
// mutates the maps.
//
// Future host-specific operations (e.g. XDP's packet-resize helpers
// or skb metadata access) extend this struct with additional hook
// fields; the contract is always "kunai stays target-agnostic, the
// host adapter contributes the per-target wiring".
type Capabilities struct {
	// Action: symbolic name → integer constant for `where action == NAME`
	// clauses. Keys (e.g. "XDP_DROP") are the symbols accepted in DSL
	// expressions; values are the integers the action register is
	// compared against. nil disables action atoms entirely — both the
	// parser (label reservation) and resolver (atom validity) treat
	// `action == ...` as an error.
	//
	// Pair Action with a non-nil ActionFetcher.
	Action map[string]int32

	// ActionFetcher emits 1+ instructions that load the current action
	// value into R3 as a u32. Required iff Action is non-nil. The
	// concrete implementation embeds the host's ABI knowledge (e.g.
	// XDP fexit reads stack[-48] then args[1]); host adapter packages
	// provide ready-made implementations.
	ActionFetcher ActionFetcher

	// ReservedLabels names that DSL @labels must not collide with.
	// Typically the keys of Action (so a label named "XDP_DROP" cannot
	// shadow the action symbol). nil means no reservations — useful
	// for hosts that disable action atoms entirely.
	ReservedLabels map[string]bool

	// StrictArithLint promotes the F1 overflow-suspect lint
	// (resolve.Options.StrictArithLint) from silent-wrap to a
	// resolver-level error. Off by default so existing hosts keep
	// the typed-OK / silent-wrap contract; opt-in for hosts that
	// prefer to surface arithmetic foot-guns at compile time.
	// dsl-types.md §9.4 row F1.
	StrictArithLint bool
}

// HasActionAtoms reports whether the caps configure an action map +
// fetcher pair. Used by the resolver to short-circuit `action == X`
// validation when the host has not opted in.
func (c Capabilities) HasActionAtoms() bool {
	return c.Action != nil && c.ActionFetcher != nil
}

// ActionFetcher loads the current action value into a register so the
// where-clause codegen can compare it against a constant. The contract
// is: when EmitFetch returns, the destination register holds the action
// as a u32 (zero-extended from however the host stores it).
type ActionFetcher interface {
	EmitFetch(dst asm.Register) asm.Instructions
}
