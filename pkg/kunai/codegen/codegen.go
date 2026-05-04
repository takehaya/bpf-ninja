// Package codegen emits BPF instructions for a resolved DSL program.
//
// The output is a target-portable filter subprogram: a contiguous
// instruction stream that reads packet bytes from a host-supplied
// scratch buffer and writes accept/reject into a host-visible
// register. The kunai library itself does not bind to XDP, tc, or
// any specific BPF attach point; that wiring is the host's
// responsibility (see pkg/kunai/host/ for canonical adapters).
//
// # ABI contract (kunai ↔ host)
//
// The host wraps codegen output with a prologue / epilogue that
// honours the following register and label conventions:
//
//   - Incoming registers (host MUST set before jumping into the
//     filter):
//
//   - R0 = first byte of the packet window (scratch buffer start)
//
//   - R1 = one past the last readable byte (scratch buffer end);
//     used for bounds checks
//
//   - R9 = packet length (= R1 - R0); used by capture sizing, not
//     for filter logic itself
//
//   - Outgoing contract (filter writes before reaching its end):
//
//   - R2 = 1 on accept, 0 on reject
//
//   - Control reaches the "filter_result" label so the host can
//     branch on R2 to its own accept / drop logic.
//
//   - Reserved (kunai-internal):
//
//   - R3, R5 are freely clobbered by codegen as scratch.
//
//   - R4 ("offsetBase") tracks the current layer's byte offset
//     into the scratch buffer; codegen adds a constant on each
//     layer advance.
//
//   - Stack offsets [-56 .. -80] (arith spill) and [-128 .. -104]
//     (bpf_loop ctx) belong to codegen.
//
//   - Untouched: R6, R7, R8 are callee-saved from kunai's
//     perspective. The host typically uses them to hold
//     attach-point-specific pointers (e.g. xdp_buff / data /
//     data_end) but kunai never reads or writes them.
//
// # Action atoms (host capability)
//
// `where action == NAME` clauses depend on the host being able to
// materialise an "action" value (e.g. an XDP retval, a tc verdict)
// at filter evaluation time. The host signals this by passing a
// non-nil Capabilities.Action map and a matching ActionFetcher.
// Hosts that cannot expose an action value pass the zero
// Capabilities and the resolver rejects any action atom early.
//
// On success control falls through "filter_result" with R2 = 1; on
// any layer, dispatch, or predicate failure it jumps to dslReject,
// which sets R2 = 0 and also falls through "filter_result".
package codegen

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// PositionedError prepends an ast.Position (line:col) to an existing
// error so codegen diagnostics line up with the source they came
// from. Inner errors stay reachable via Unwrap, so
// errors.Is(err, ErrNotImplemented) keeps working through the
// position prefix.
//
// Invariant: the inner-most position wins. withPos is a no-op when
// the chain already carries a PositionedError, so a per-predicate
// wrap is preserved across the genLayer / genCondition wrappers
// that would otherwise stamp the enclosing layer's position.
//
// A PositionedError with a zero Pos prints just the wrapped message
// (no "0:0:" eyesore) for the rare case a caller wraps without a
// known source location.
type PositionedError struct {
	Pos     ast.Position
	Wrapped error
}

func (e *PositionedError) Error() string {
	if e.Pos.Line == 0 {
		return e.Wrapped.Error()
	}
	return fmt.Sprintf("%s: %s", e.Pos, e.Wrapped.Error())
}

func (e *PositionedError) Unwrap() error { return e.Wrapped }

// withPos wraps err in a PositionedError. See PositionedError's doc
// for the inner-most-wins invariant.
func withPos(err error, pos ast.Position) error {
	if err == nil {
		return nil
	}
	var pe *PositionedError
	if errors.As(err, &pe) {
		return err
	}
	return &PositionedError{Pos: pos, Wrapped: err}
}

// ErrNotImplemented is returned by Gen when a resolved program is
// well-typed but the BPF emitter does not yet cover the required
// shape. Two flavours coexist under this single error:
//
//   1. Codegen staging declared by docs/ja/dsl-types.md §9.1 — the
//      resolver accepts the program, but the spec deliberately
//      defers the BPF expansion until follow-up work lands. Current
//      staging cases:
//        - Int<N> ordered comparison with N > 64 (F3 in
//          dsl-followups.md): lexicographic cmp not yet wired up,
//        - Int<128> arithmetic binary ops (+, -, *) (F4/F5):
//          register-pair carry propagation not yet wired up.
//      User-visible programs hitting this branch are spec-correct;
//      they need a kernel build with the staged emitter, not an
//      expression rewrite.
//
//   2. MVP gaps that the resolver structurally lets through but
//      codegen has yet to plumb. Examples:
//        - dynamic aux header stack indices outside the static-fold
//          path (fieldRefByteOffset),
//        - TCP / IPv4 option lookups reaching the static-fold path
//          instead of the option-walk emitter,
//        - non-byte-aligned or oversized primary fields (> 8 bytes),
//        - quantifier shapes the resolver accepts but emit has not
//          covered yet.
//      These are codegen TODOs rather than spec'd staging.
//
// Callers can match it with errors.Is to distinguish "valid DSL,
// codegen still to come" from genuine type or vocabulary errors.
// The wrapped reason in each call site identifies which flavour the
// caller hit.
var ErrNotImplemented = errors.New("dsl codegen is not yet fully implemented")

// CaptureInfo summarises the compile-time capture configuration that
// the program wrapper must honour. A zero value means "no DSL capture
// clause was seen" — the caller should fall back to its existing
// default (e.g. libpcap's 1500-byte snaplen).
type CaptureInfo struct {
	// MaxCapLen is the packet prefix length the wrapper should emit to
	// the perf buffer. Zero preserves the caller default.
	MaxCapLen int
}

// Output bundles everything codegen produces for a DSL program. Main
// is the filter body that plugs into the wrapper's runFilter block;
// Callbacks holds any bpf2bpf subprograms (currently only bpf_loop
// chain callbacks) that must be appended *after* the wrapper's final
// Return so they live outside the main control flow. The wrapper
// must also tag its own first instruction with btf.FuncMetadata when
// Callbacks is non-empty — see mainFilterFunc for the canonical
// entry.
type Output struct {
	Main      asm.Instructions
	Callbacks asm.Instructions
	Capture   CaptureInfo
}

// Instructions returns Main concatenated with Callbacks. Callers
// that load the stream directly (no wrapper) can rely on the normal
// encodeFunctionReferences pass to fix up references. The wrapper
// path (internal/program) keeps Main and Callbacks separate so
// callbacks can sit after loadPacketPointers / capture.
func (o Output) Instructions() asm.Instructions {
	if len(o.Callbacks) == 0 {
		return o.Main
	}
	out := make(asm.Instructions, 0, len(o.Main)+len(o.Callbacks))
	out = append(out, o.Main...)
	out = append(out, o.Callbacks...)
	return out
}

// Label placed at the end of a filter block. The runFilter wrapper
// attaches "filter_result" to its JEq R2,0 → exit instruction, so
// a jump to "filter_result" from inside our emitted code lands on it.
const filterResultLabel = "filter_result"

// isConstantFalseCondition reports whether c folds to a literal
// `false`. Used by Gen to short-circuit the always-reject case so
// the kernel verifier doesn't see a chain followed by an
// unreachable accept tail.
func isConstantFalseCondition(c *ir.Condition) bool {
	return c != nil && c.Kind == ast.WAtomBoolLit && !c.BoolLitValue
}

// dslReject sets R2=0 and falls through to filter_result. The constant
// is a fixed string, so two Gen outputs cannot be concatenated into a
// single assembly unit without symbol collision — callers wrap each
// Gen output as its own function (the bpf2bpf callbacks in
// Output.Callbacks already use this pattern).
const dslReject = "dsl_reject"

// KunaiStackTop is the shallowest (closest-to-zero) R10 offset that
// codegen ever writes or reads. Host wrappers may use any slot in
// (KunaiStackTop, 0) for their own scratch (tracing args ptr,
// metadata, etc.) without colliding with kunai. The current
// allocations:
//
//   - kunai: arith spill at -56 .. -112 (8 slots × 8 bytes,
//     maxArithDepth = 8). Slot 4 (-88) is shared with the 128-bit
//     transient stash like every other slot in the region; the
//     64-bit and 128-bit paths never interleave.
//   - kunai: bpf_loop ctx at -144 .. -112 (4 slots × 8 bytes). The
//     top byte of the ctx (layerEntry's upper bound at -112) sits
//     flush against the arith stack's bottom byte at the same
//     offset — the two writes touch disjoint byte ranges so the
//     packing is verifier-safe. The 16-byte gap [-160, -144)
//     below ctx is the contract margin against the where-layer
//     slots.
//   - kunai: per-layer entry slots at -160 .. -160-8*N (where N <
//     whereLayerEntrySlotCap = 12), allocated lazily when the
//     resolver marks a layer NeedsRuntimeOffset (= where / capture
//     references it past a heterogeneous-size alt). Worst-case
//     bottom is -248; total kunai stack consumption is bounded by
//     KunaiStackTop − 248 = 192 bytes, well within the 512-byte
//     BPF stack budget.
//   - host: any subset of [-1, KunaiStackTop+1]; xdp-ninja uses -48
//     for the saved tracing args pointer.
//
// The TestZeroCapsIsHostAgnostic regression check asserts that a
// zero-Capabilities filter never touches any slot above this line.
const KunaiStackTop = int16(-56)

// ScratchBufSize is the prefix length host wrappers must materialise
// in the per-CPU scratch buffer before jumping into the kunai filter.
// 512 bytes covers worst-case verifier-tracked R4 for chains that
// stack two variable advances (e.g. IPv6 ext loop + SRv6 segments +
// TCP options ≈ 320 bytes) with headroom for future stacked layers.
//
// Sizing contract — when you change a vocab LenMask or add a new
// trail-bearing protocol, verify that
//
//	sum(per-protocol max trail) + sum(fixed primary headers) ≤ ScratchBufSize
//
// holds for every reachable chain shape. Per-protocol max trail
// is `(LenMask >> LenShift) << log2(Scale) - MinimumTotal + Base`
// for primary-header pkt.advance trailers, `iter_cap × per-iter advance` for parser-machine
// self-loops (e.g. ipv6_ext_h LenMask=0x03 ⇒ 32 B/iter × 4 iter cap
// = 128 B). Currently every chain in the bundled vocab fits within
// 320 B; the 192 B slack accommodates one more variable-trail layer
// before this constant has to grow.
const ScratchBufSize = 512

// Gen produces BPF instructions for the resolved program. The output
// conforms to the runFilter register protocol described in the package
// doc. caps tells codegen which host-specific atoms (currently
// `where action == NAME`) are available and how to materialise their
// values at runtime. A zero Capabilities yields a host-agnostic
// filter (action atoms cause an error). The returned CaptureInfo
// summarises the program's capture clause so the wrapper can size its
// perf-event output; a zero CaptureInfo tells the caller to keep its
// default.
func Gen(p *ir.Program, caps Capabilities) (Output, error) {
	if p == nil {
		return Output{}, errors.New("codegen: nil program")
	}
	if err := checkUnsupported(p); err != nil {
		return Output{}, err
	}
	capInfo, where, err := computeCapture(p, p.Where)
	if err != nil {
		return Output{}, err
	}

	// `where false` short-circuit: a filter whose where clause is
	// constant-false never accepts a packet, so emit a minimal
	// always-reject program and skip the chain entirely. Without
	// this short-circuit the kernel verifier objects to the chain's
	// bounds-check side effects becoming dead state once where false
	// jumps over the accept tail (dsl-types.md §15.4 known corner
	// case). Capture clauses are dropped because they fire only on
	// the accept path that no packet will ever reach.
	if isConstantFalseCondition(where) {
		// Always-reject: a single Mov + Ja gets us into the host's
		// filter_result tail with R2=0. We deliberately do *not* emit
		// the dsl_reject symbol landing — there's no Ja into it from
		// this minimal stream, so leaving the dead-code Mov triggers
		// the kernel verifier's "unreachable insn" rule.
		return Output{
			Main: asm.Instructions{
				asm.Mov.Imm(asm.R2, 0),
				asm.Ja.Label(filterResultLabel),
			},
			Capture: capInfo,
		}, nil
	}

	insns := asm.Instructions{
		// Initialise the layer offset register to 0 (scratch start).
		// Each layer's genLayer appends its own trailing Add.Imm so
		// optional / repeating layers can advance conditionally.
		asm.Mov.Imm(offsetBase, 0),
	}
	qo := collectQueriedOptions(p)
	var callbacks asm.Instructions
	for i, layer := range p.Layers {
		layerInsns, cb, err := genLayer(layer, i, p.Layers, qo)
		if err != nil {
			return Output{}, err
		}
		insns = append(insns, layerInsns...)
		callbacks = append(callbacks, cb...)
	}

	// Where clause (optional): emit after layers so the chain has
	// already materialised. Failure jumps to dslReject just like a
	// layer-level mismatch. `where` may include conditions merged in
	// from per-capture clauses (see computeCapture).
	if where != nil {
		whereInsns, err := genCondition(where, caps, p, qo, dslReject)
		if err != nil {
			return Output{}, err
		}
		insns = append(insns, whereInsns...)
	}

	// Accept path: R2=1 and jump over the reject block.
	insns = append(insns,
		asm.Mov.Imm(asm.R2, 1),
		asm.Ja.Label(filterResultLabel),
		// Reject path: R2=0 and fall through to filter_result.
		asm.Mov.Imm(asm.R2, 0).WithSymbol(dslReject),
	)

	return Output{Main: insns, Callbacks: callbacks, Capture: capInfo}, nil
}

// Shared BTF primitives for func_info entries. Keeping them at
// package scope lets cilium/ebpf's deduper identify them by pointer
// equality so every bpf2bpf subprogram reuses the same type IDs.
var (
	btfLong    = &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed}
	btfU32     = &btf.Int{Name: "u32", Size: 4, Encoding: btf.Unsigned}
	btfVoidPtr = &btf.Pointer{Target: &btf.Void{}}
)

// MainFilterFuncBTF is the btf.Func the outer tracing program needs
// to advertise when any bpf2bpf subprogram is present. Wrappers that
// splice callbacks after their own body (internal/program) tag their
// first instruction with this metadata; the signature shape is not
// load-bearing for fentry/fexit — the real context comes from
// AttachTarget — but BTF requires the entry to exist.
func MainFilterFuncBTF() *btf.Func {
	return &btf.Func{
		Name:    "xdp_ninja_filter",
		Type:    &btf.FuncProto{Return: btfLong},
		Linkage: btf.GlobalFunc,
	}
}

// loadFunctionRef emits the BPF_PSEUDO_FUNC DWord load that pushes a
// function pointer into dst. cilium/ebpf resolves `symbol` at load
// time, either by finding a matching WithSymbol() in the same stream
// or by failing with ErrUnsatisfiedProgramReference.
func loadFunctionRef(dst asm.Register, symbol string) asm.Instruction {
	return asm.Instruction{
		OpCode:   asm.LoadImmOp(asm.DWord),
		Dst:      dst,
		Src:      asm.PseudoFunc,
		Constant: -1,
	}.WithReference(symbol)
}

// emitFieldDispatchCheck compiles a "<parent.field> == <const>"
// equality jump used by both the main program's genFieldDispatch and
// the chain callback's peek. The caller supplies the instructions
// that materialise the read base in dst (the first byte of the
// layer whose header contains the field); the helper then resolves
// the field metadata, loads it, and jumps to failLabel on mismatch.
func emitFieldDispatchCheck(
	spec *vocab.ProtocolSpec,
	c *vocab.DispatchConst,
	parentHS int,
	dst asm.Register,
	setupAddr asm.Instructions,
	failLabel string,
) (asm.Instructions, error) {
	fieldOff, fieldBytes, err := findFieldByteOffset(spec, c.FieldName)
	if err != nil {
		return nil, err
	}
	size, err := asmSizeFor(fieldBytes)
	if err != nil {
		return nil, err
	}
	expected := int32(byteSwap(c.Value, fieldBytes))
	insns := append(asm.Instructions{}, setupAddr...)
	insns = append(insns,
		asm.LoadMem(dst, dst, int16(fieldOff-parentHS), size),
		asm.JNE.Imm(dst, expected, failLabel),
	)
	return insns, nil
}

// offsetBase is the register that holds the byte offset from R0
// (scratch buffer start) to the current layer's start. Each layer's
// load instructions first compute `R3 = R0 + offsetBase`, then LDX
// with the field's within-layer byte offset as the immediate.
const offsetBase = asm.R4

// emitBoundedLoad emits a packet-pointer-safe `size`-byte load at
// R0+offsetBase+off into dst. The end+JGT+LoadMem(-size) pattern
// is mandatory on PTR_TO_PACKET (verifier rejects through a packet
// pointer + scalar without an explicit bound check) and harmless on
// PTR_TO_MAP_VALUE (the JGT is redundant against the static map
// bound).
func emitBoundedLoad(dst asm.Register, off int16, size asm.Size, failLabel string) asm.Instructions {
	sizeBytes := int32(size.Sizeof())
	return asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Add.Reg(asm.R3, offsetBase),
		asm.Add.Imm(asm.R3, int32(off)+sizeBytes),
		asm.JGT.Reg(asm.R3, asm.R1, failLabel),
		asm.Sub.Imm(asm.R3, sizeBytes),
		asm.LoadMem(dst, asm.R3, 0, size),
	}
}

// foldOffsetIntoScalar emits the scalar-arithmetic preamble that lets
// a subsequent boundedScalarLoad use only positive const offsets when
// the desired packet-relative offset is potentially negative (= reading
// back into a just-passed header). Produces dst = src + off, gating on
// failLabel when off < 0 and src < |off| would underflow.
//
// Required because the verifier conservatively rejects loads through a
// PTR_TO_PACKET that has been advanced by a const negative offset, even
// after a JGT bound check on the access end. Folding the negative byte
// offset into a non-negative scalar before the pkt-pointer arithmetic
// sidesteps the issue.
//
// dst MUST differ from src; the helper writes dst.
func foldOffsetIntoScalar(dst, src asm.Register, off int32, failLabel string) asm.Instructions {
	switch {
	case off < 0:
		return asm.Instructions{
			asm.JLT.Imm(src, -off, failLabel),
			asm.Mov.Reg(dst, src),
			asm.Sub.Imm(dst, -off),
		}
	case off > 0:
		return asm.Instructions{
			asm.Mov.Reg(dst, src),
			asm.Add.Imm(dst, off),
		}
	default:
		return asm.Instructions{asm.Mov.Reg(dst, src)}
	}
}

// boundedScalarLoad emits a `size`-byte load from scratchStart +
// scalar into dst, using the cbpfc-style end-pointer + LoadMem(-size)
// pattern wrapped in a scalar pre-clamp. dst doubles as the pointer
// scratch and final load destination. The scalar MUST be non-negative
// — pair with foldOffsetIntoScalar when the source byte offset can
// go negative.
//
// Two register kinds reach this helper. For PTR_TO_PACKET the end-
// pointer JGT alone is sufficient (the verifier specially narrows
// pkt pointers via find_good_pkt_pointers). For PTR_TO_MAP_VALUE the
// verifier does NOT narrow the variable component through pointer
// comparison, so the access end retains the pre-comparison umax and
// the LDX falls one byte past vs. The pre-clamp `JGT scalar,
// ScratchBufSize - sizeBytes, fail` pins scalar.umax tight enough
// that scratchStart + scalar + sizeBytes stays within vs even when
// the pointer-side JGT propagates nothing — fixes the entry / exit
// hook path which uses a per-CPU map_value scratch.
func boundedScalarLoad(dst, scratchStart, scalar, scratchEnd asm.Register, size asm.Size, failLabel string) asm.Instructions {
	sizeBytes := int32(size.Sizeof())
	return asm.Instructions{
		asm.JGT.Imm(scalar, int32(ScratchBufSize)-sizeBytes, failLabel),
		asm.Mov.Reg(dst, scratchStart),
		asm.Add.Reg(dst, scalar),
		asm.Add.Imm(dst, sizeBytes),
		asm.JGT.Reg(dst, scratchEnd, failLabel),
		asm.LoadMem(dst, dst, int16(-sizeBytes), size),
	}
}

// landingNoop builds a self-Mov that carries `label` so a Ja into
// `label` lands on a real instruction without changing register state.
// The verifier accepts a Mov R3,R3 as a no-op; it's the canonical
// idiom for marker labels (genOptionalLayer's `?`-skip, where.go's
// not/or landings, multiWordRoute's `!=` match landing).
func landingNoop(label string) asm.Instruction {
	return asm.Mov.Reg(asm.R3, asm.R3).WithSymbol(label)
}

// emitBounds verifies that the layer's header fits in the scratch
// buffer, i.e. R0 + offsetBase + hs ≤ R1. On overrun control jumps to
// failLabel (dslReject for mandatory layers, a skip marker for `?`).
func emitBounds(hs int, failLabel string) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Add.Reg(asm.R3, offsetBase),
		asm.Add.Imm(asm.R3, int32(hs)),
		asm.JGT.Reg(asm.R3, asm.R1, failLabel),
	}
}

// emitPredicates walks a layer's predicate list and concatenates each
// one's compiled comparison. Stopping at the first ErrNotImplemented
// keeps the error message close to the offending predicate; the
// per-predicate Pos is attached so users see line:col.
func emitPredicates(preds []*ir.Predicate) (asm.Instructions, error) {
	var out asm.Instructions
	for _, pred := range preds {
		pi, err := genPredicate(pred)
		if err != nil {
			return nil, withPos(err, pred.Pos)
		}
		out = append(out, pi...)
	}
	return out, nil
}

// emitAdvance advances offsetBase past the header we just emitted.
func emitAdvance(hs int) asm.Instruction {
	return asm.Add.Imm(offsetBase, int32(hs))
}

// dispatchParent returns the LayerInstance whose Spec describes the
// header layout the next layer's dispatch reads from. For an alt
// group, picking the first alt is enough because two MVP invariants
// hold by construction:
//
//   - resolve.selectAltParentDispatch enforces every alt agreeing on
//     the *child's* dispatch field (so any alt can stand in for the
//     field-offset lookup that follows).
//   - genAlternation's uniform-size check guarantees every alt has
//     the same header layout (so parentHS computed off the first alt
//     matches what offsetBase already advanced).
//
// Together these mean findFieldByteOffset and genDispatch can read
// off Alternation[0].Spec without ambiguity.
func dispatchParent(parent *ir.LayerInstance) *ir.LayerInstance {
	if parent.Alternation != nil {
		return parent.Alternation[0]
	}
	return parent
}

// checkUnsupported scans the program for nodes the resolver flagged
// Unsupported and for MVP-out-of-scope features. Failing early keeps
// codegen itself simple: every node reaching genLayer is known to be
// representable. Capture and where clauses have their own validation
// downstream (computeCapture / genCondition).
func checkUnsupported(p *ir.Program) error {
	for _, l := range p.Layers {
		if l.Unsupported != "" {
			return withPos(fmt.Errorf("%w: %s", ErrNotImplemented, l.Unsupported), l.Pos)
		}
		switch l.Quant {
		case ast.QuantOne, ast.QuantOpt, ast.QuantPlus, ast.QuantStar, ast.QuantRange:
			// All handled by genLayer (static unroll / bpf_loop).
		default:
			return withPos(fmt.Errorf("%w: quantifier %s on layer %q is not yet supported", ErrNotImplemented, l.Quant, l.Spec.Name), l.Pos)
		}
		// Individual predicates are validated inside genPredicate; any
		// Unsupported marker set by the resolver (PredIn, PredHas) is
		// surfaced there. Alternation groups have their own MVP
		// constraints enforced by genAlternation.
	}
	return nil
}

// genLayer dispatches on the quantifier and emits the layer's own
// R4 advancement. Gen's outer loop no longer touches R4 so optional
// and repeating layers can advance conditionally. The second return
// value holds any bpf2bpf subprogram instructions the chain codegen
// needs appended after the main stream — empty for every non-bpf_loop
// path.
func genLayer(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, qo queriedOptions) (asm.Instructions, asm.Instructions, error) {
	insns, callbacks, err := genLayerInner(layer, index, all, qo)
	return insns, callbacks, withPos(err, layer.Pos)
}

func genLayerInner(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, qo queriedOptions) (asm.Instructions, asm.Instructions, error) {
	if layer.Alternation != nil {
		return genAlternation(layer, index, all, qo)
	}
	switch layer.Quant {
	case ast.QuantOne:
		if layer.Spec.ParseStateMachine != nil {
			return genParserMachine(layer, index, all, qo)
		}
		insns, err := genStaticLayer(layer, index, all)
		return insns, nil, err
	case ast.QuantOpt:
		insns, err := genOptionalLayer(layer, index, all)
		return insns, nil, err
	case ast.QuantRange:
		if staticChainFitsRange(layer.RangeMax) {
			insns, err := genStaticChain(layer, index, all)
			return insns, nil, err
		}
		return genBpfLoopChain(layer, index, all)
	case ast.QuantPlus, ast.QuantStar:
		return genBpfLoopChain(layer, index, all)
	}
	return nil, nil, fmt.Errorf("%w: quantifier %s on layer %q", ErrNotImplemented, layer.Quant, layer.Spec.Name)
}

// genStaticLayer emits the bounds check, dispatch check, predicates,
// and R4 advancement for a layer that is always present. Failure of
// any check jumps to dslReject.
func genStaticLayer(layer *ir.LayerInstance, index int, all []*ir.LayerInstance) (asm.Instructions, error) {
	hs, err := headerSize(layer.Spec)
	if err != nil {
		return nil, err
	}

	insns := emitBounds(hs, dslReject)

	if index > 0 && layer.Dispatch != nil {
		di, err := genLayerDispatch(layer, all[index-1], dslReject)
		if err != nil {
			return nil, err
		}
		insns = append(insns, di...)
	}

	preds, err := emitPredicates(layer.Predicates)
	if err != nil {
		return nil, err
	}
	insns = append(insns, preds...)
	if layer.Spec.HasVariableLayout() {
		// Save this layer's entry offsetBase to the slot before the
		// fixed-prefix advance so children's dispatch can recover the
		// primary-header position regardless of how far the OPT-flag
		// shift moves R4 afterwards. Mirror of parser_machine.go's
		// slot store — see the lifecycle docs there for the
		// read/write ordering invariant.
		insns = append(insns, asm.StoreMem(asm.R10, bpfLoopCtxLayerEntrySlot, offsetBase, asm.DWord))
	}
	if layer.NeedsRuntimeOffset {
		// Resolver flagged this layer as referenced by where / capture
		// past a heterogeneous-size alt. Store R4 (= layer entry byte
		// offset within scratch) into the per-layer slot so downstream
		// where / capture / option-walk loads can address through it
		// instead of the (now-runtime-variable) R0+static_prefix.
		slotEntry, err := whereLayerEntrySlot(layer.LayerPos)
		if err != nil {
			return nil, err
		}
		insns = append(insns, asm.StoreMem(asm.R10, slotEntry, offsetBase, asm.DWord))
	}
	insns = append(insns, emitAdvance(hs))
	if len(layer.Spec.FlagTriggers) > 0 {
		flags, err := emitFlagTriggers(hs, layer.Spec.FlagsByteOffset, layer.Spec.FlagTriggers, dslReject)
		if err != nil {
			return nil, err
		}
		insns = append(insns, flags...)
	}
	return insns, nil
}

// emitFlagTriggers emits one "if flag bit set then advance" block
// per trigger, in declaration order. Reads the flag byte once into
// R5; per trigger isolates the bit into R3 (And.Imm), short-circuits
// past the advance when the bit is zero (JEq), then bumps R4 by the
// trigger's fixed length after a bounds check. The total advance is
// statically bounded by sum(LenBytes) so the verifier can prove the
// running offset stays within ScratchBufSize when the layer's caller
// has already reserved that much.
//
// Caller invariant: emitFlagTriggers is invoked AFTER emitAdvance(hs),
// so offsetBase already points past the fixed primary header. The
// initial flag-byte LDX uses immediate `-fixedHs+flagsByteOff` to
// reach back into the just-passed primary header. If a future caller
// reorders the advance / triggers sequence in genStaticLayer, this
// helper must change to match (or split into a "read flag byte" /
// "emit triggers" pair).
func emitFlagTriggers(fixedHs, flagsByteOff int, triggers []vocab.FlagTrigger, failLabel string) (asm.Instructions, error) {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R5, asm.R0),
		asm.Add.Reg(asm.R5, offsetBase),
		asm.LoadMem(asm.R5, asm.R5, int16(-fixedHs+flagsByteOff), asm.Byte),
	}
	for i, tr := range triggers {
		skipLabel := fmt.Sprintf("dsl_flag_skip_%d_%s", i, tr.Name)
		insns = append(insns,
			asm.Mov.Reg(asm.R3, asm.R5),
			asm.And.Imm(asm.R3, int32(tr.BitMask)),
			asm.JEq.Imm(asm.R3, 0, skipLabel),
			asm.Mov.Reg(asm.R3, asm.R0),
			asm.Add.Reg(asm.R3, offsetBase),
			asm.Add.Imm(asm.R3, int32(tr.LenBytes)),
			asm.JGT.Reg(asm.R3, asm.R1, failLabel),
			asm.Add.Imm(offsetBase, int32(tr.LenBytes)),
			landingNoop(skipLabel),
		)
	}
	return insns, nil
}

// variableTailSkipFromHeaderLength lifts a vocab.HeaderLength into the
// codegen-internal variableTailSkip representation. Primary-header
// suffixes always set MinimumTotal so an undersized length field
// (IHL < 5, data_offset < 5) jumps to dslReject before R5 can wrap.
func variableTailSkipFromHeaderLength(vs *vocab.HeaderLength) variableTailSkip {
	return variableTailSkip{
		LenFieldByteOff: vs.LenByteOff,
		LenMask:         vs.LenMask,
		LenShift:        vs.LenShift,
		Scale:           vs.Scale,
		MinimumTotal:    vs.Base,
	}
}


// genOptionalLayer emits the `?` quantifier: peek the dispatch check
// from the parent; if it fails we skip the layer entirely without
// advancing R4. If it succeeds we do the bounds check, predicates,
// and advance R4. The no-op Mov R3,R3 at the end receives the skip
// label so both the present and absent paths fall through to the
// next layer with R4 pointing at the right place. DispatchNoCheck is
// rejected because there is no way to detect absence when the vocab
// says "don't look".
func genOptionalLayer(layer *ir.LayerInstance, index int, all []*ir.LayerInstance) (asm.Instructions, error) {
	if index == 0 {
		return nil, fmt.Errorf("%w: the first layer cannot be optional", ErrNotImplemented)
	}
	if layer.Dispatch == nil {
		return nil, fmt.Errorf("%w: optional layer %q has no dispatch to peek", ErrNotImplemented, layer.Spec.Name)
	}
	if layer.Dispatch.Type == vocab.DispatchNoCheck {
		return nil, fmt.Errorf("%w: optional %q with no-check dispatch cannot detect absence", ErrNotImplemented, layer.Spec.Name)
	}

	skipLabel := fmt.Sprintf("dsl_skip_%d", index)
	body, err := emitPeekedIterZero(layer, index, all, skipLabel)
	if err != nil {
		return nil, err
	}
	body = append(body, landingNoop(skipLabel))
	return body, nil
}

// emitPeekedIterZero emits a single-layer block with a peek-style
// dispatch: the read is otherwise identical to genStaticLayer but
// dispatch mismatch jumps to peekFailLabel instead of dslReject.
// The caller is responsible for placing peekFailLabel's landing
// somewhere sensible (a no-op for `?`, a marker after the bpf_loop
// call for `*`).
//
// Order note: peek runs before this layer's bounds check (reverse of
// genStaticLayer's bounds-then-dispatch order). That is deliberate —
// the peek reads from the parent's header, which the parent's
// emitBounds has already validated, so it is safe; and skipping the
// current layer's bounds check on the absent path avoids spurious
// dslReject when an optional layer is simply not there.
func emitPeekedIterZero(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, peekFailLabel string) (asm.Instructions, error) {
	if index == 0 || layer.Dispatch == nil {
		return nil, fmt.Errorf("%w: peeked iter-0 on %q requires a parent dispatch", ErrNotImplemented, layer.Spec.Name)
	}
	hs, err := headerSize(layer.Spec)
	if err != nil {
		return nil, err
	}
	peek, err := genLayerDispatch(layer, all[index-1], peekFailLabel)
	if err != nil {
		return nil, err
	}
	preds, err := emitPredicates(layer.Predicates)
	if err != nil {
		return nil, err
	}
	var out asm.Instructions
	out = append(out, peek...)
	out = append(out, emitBounds(hs, dslReject)...)
	out = append(out, preds...)
	out = append(out, emitAdvance(hs))
	return out, nil
}

func genDispatch(current, parent *ir.LayerInstance, parentHS int, failLabel string) (asm.Instructions, error) {
	switch current.Dispatch.Type {
	case vocab.DispatchField:
		return genFieldDispatch(current, parent, parentHS, failLabel)
	case vocab.DispatchNoCheck:
		return genNoCheckDispatch(current)
	case vocab.DispatchSelfValidating:
		// Boundary emits nothing: the child's parser machine validates
		// the layer via its `transition select(...) { ...; default:
		// reject; }`, so we delegate the check entirely to the parser.
		return nil, nil
	}
	return nil, fmt.Errorf("codegen: unknown dispatch type %v", current.Dispatch.Type)
}

// genLayerDispatch is the call-site wrapper for layer-level dispatch
// emission (genStaticLayer / parser_machine entry). It looks at `prev`
// (= the unresolved parent — possibly an alt group) to decide whether
// the current layer's dispatch needs the alt-diverged path (P3-12,
// `(ipv4|ipv6)/tcp` etc., where alts disagree on dispatch field), or
// the existing single-dispatch path (uniform alts or non-alt parent).
//
// For diverged dispatch each alt branch is emitted under a JNE check
// against matchedAltReg (set by genAlternation when `IsAltDiverged`
// holds for the next layer). For non-diverged we keep the historical
// behavior — collapse the alt group to its first member via
// dispatchParent and call genDispatch as before.
func genLayerDispatch(current, prev *ir.LayerInstance, failLabel string) (asm.Instructions, error) {
	if current.Dispatch == nil {
		return nil, nil
	}
	if current.Dispatch.IsAltDiverged {
		if prev.Alternation == nil {
			return nil, fmt.Errorf("codegen: IsAltDiverged dispatch on %q but parent is not an alt group (resolver bug)", current.Spec.Name)
		}
		return genFieldDispatchAltDiverged(current, prev.Alternation, failLabel)
	}
	parent := dispatchParent(prev)
	parentHS, err := headerSize(parent.Spec)
	if err != nil {
		return nil, err
	}
	return genDispatch(current, parent, parentHS, failLabel)
}

// genFieldDispatchAltDiverged emits per-alt dispatch for a layer
// whose alt parents disagree on the dispatch field — e.g. `(ipv4|ipv6)
// /tcp` where IPv4 reads `protocol` at byte 9 and IPv6 reads
// `next_header` at byte 6. Each alt branch is gated on
// `matchedAltReg == i` (set by genAlternation as the alt block falls
// through to altEnd), so only the matched alt's check actually runs.
//
// Layout per branch:
//
//	jne R5, i, dsl_altdisp_skip_<n>          // (omitted for last alt)
//	<setup R3 for this alt's parent>          // R0+R4 or layer-entry slot
//	ldx <field>, jne <const>, failLabel      // single-alt dispatch
//	ja dsl_altdisp_done_<n>                  // (omitted for last alt)
//	dsl_altdisp_skip_<n>:
//	...
//	dsl_altdisp_done_<n>:
//
// The last alt has no skip / ja — matchedAltReg is guaranteed to be
// N-1 if we got here (genAlternation set it before the fall-through).
func genFieldDispatchAltDiverged(current *ir.LayerInstance, altParents []*ir.LayerInstance, failLabel string) (asm.Instructions, error) {
	consts := current.Dispatch.AltConsts
	if len(altParents) != len(consts) {
		return nil, fmt.Errorf("codegen: alt parent count %d != AltConsts count %d (resolver bug)", len(altParents), len(consts))
	}

	doneLabel := nextAltDispatchLabel("done")
	var insns asm.Instructions
	for i, altParent := range altParents {
		var skipLabel string
		if i+1 < len(altParents) {
			skipLabel = nextAltDispatchLabel("skip")
			insns = append(insns, asm.JNE.Imm(matchedAltReg, int32(i), skipLabel))
		}

		var (
			check asm.Instructions
			err   error
		)
		if altParent.Spec.HasVariableLayout() {
			check, err = emitFieldDispatchCheck(
				altParent.Spec,
				consts[i],
				0,
				asm.R3,
				asm.Instructions{
					asm.LoadMem(asm.R3, asm.R10, bpfLoopCtxLayerEntrySlot, asm.DWord),
					asm.Add.Reg(asm.R3, asm.R0),
				},
				failLabel,
			)
		} else {
			altParentHS, herr := headerSize(altParent.Spec)
			if herr != nil {
				return nil, herr
			}
			check, err = emitFieldDispatchCheck(
				altParent.Spec,
				consts[i],
				altParentHS,
				asm.R3,
				asm.Instructions{
					asm.Mov.Reg(asm.R3, asm.R0),
					asm.Add.Reg(asm.R3, offsetBase),
				},
				failLabel,
			)
		}
		if err != nil {
			return nil, err
		}
		insns = append(insns, check...)

		if i+1 < len(altParents) {
			insns = append(insns, asm.Ja.Label(doneLabel))
			// `Mov R0, R0` (rather than landingNoop's `Mov R3, R3`)
			// because the path entering this skip label took JNE on
			// matchedAltReg from an earlier alt — that alt's body may
			// have ended in a parser-machine bpf_loop call, which the
			// helper is allowed to clobber R3 across. R0 is restored
			// from a stack save inside emitSelfLoop, so reading it
			// here is verifier-safe; canonical landingNoop would
			// trip an `R3 !read_ok`.
			insns = append(insns, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(skipLabel))
		}
	}
	// Same R0-vs-R3 reasoning as the skip-label landing above.
	insns = append(insns, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(doneLabel))
	return insns, nil
}

var altDispatchLabelCounter atomic.Uint64

// nextAltDispatchLabel returns a process-unique alt-diverged dispatch
// label in the `dsl_altdisp_<role>_<n>` shape. Atomic so concurrent
// Compile() calls produce non-colliding labels even though label
// uniqueness is only required within a single instruction stream.
func nextAltDispatchLabel(role string) string {
	return fmt.Sprintf("dsl_altdisp_%s_%d", role, altDispatchLabelCounter.Add(1))
}

// genFieldDispatch emits the check that parent.<field> == value.
//
// For fixed-size parent layers the header sits at
// [offsetBase - parentHS, offsetBase), so the field address is
// R0 + offsetBase + (fieldOff - parentHS) and the LDX uses a
// negative immediate.
//
// When the parent itself ran through a parser-state-machine its
// body may have consumed more than `parentHS` bytes (e.g. IPv6 ext
// headers), so the R4 - parentHS arithmetic no longer points at
// the parent's primary header. The parser machine writes the
// parent's *layer-entry* offset to bpfLoopCtxLayerEntrySlot before
// any extracts run; this branch reads that slot to anchor the
// dispatch read at the original ipv6_h byte 6 (next_header), which
// the ext-chain write-back keeps in sync with the final inner
// protocol.
//
// The scratch buffer holds packet bytes in network order but eBPF
// LDX reads them little-endian; rather than emit a BSwap at runtime
// we byte-swap the constant at codegen time so a single JNE suffices.
func genFieldDispatch(current, parent *ir.LayerInstance, parentHS int, failLabel string) (asm.Instructions, error) {
	if parent.Spec.HasVariableLayout() {
		return emitFieldDispatchCheck(
			parent.Spec,
			current.Dispatch.Const,
			0, // parentHS=0 keeps the LDX immediate at fieldOff (anchored on layer entry, not relative to offsetBase).
			asm.R3,
			asm.Instructions{
				asm.LoadMem(asm.R3, asm.R10, bpfLoopCtxLayerEntrySlot, asm.DWord),
				asm.Add.Reg(asm.R3, asm.R0),
			},
			failLabel,
		)
	}
	return emitFieldDispatchCheck(
		parent.Spec,
		current.Dispatch.Const,
		parentHS,
		asm.R3,
		asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R0),
			asm.Add.Reg(asm.R3, offsetBase),
		},
		failLabel,
	)
}


// findFieldBitOffset returns the bit offset (from the start of the
// header) and bit width of the named field, or an error when the
// field is missing. Thin wrapper over vocab.BitOffsetIn that adds
// the protocol-qualified diagnostic. Callers that need byte
// alignment or a size cap layer those checks on top — see
// findFieldByteOffset.
func findFieldBitOffset(spec *vocab.ProtocolSpec, name string) (bitOff, bits int, err error) {
	bitOff, bits, ok := vocab.BitOffsetIn(spec.Fields, name)
	if !ok {
		return 0, 0, fmt.Errorf("codegen: field %s.%s not found", spec.Name, name)
	}
	return bitOff, bits, nil
}

// findFieldByteOffset returns the byte offset and byte width of the
// named field, rejecting non-byte-aligned or oversized fields. Used
// by predicate / dispatch / arithmetic codegen which all read whole
// bytes via LDX.
func findFieldByteOffset(spec *vocab.ProtocolSpec, name string) (int, int, error) {
	bitOff, bits, err := findFieldBitOffset(spec, name)
	if err != nil {
		return 0, 0, err
	}
	if bitOff%8 != 0 {
		return 0, 0, fmt.Errorf("%w: field %s.%s starts at bit %d (not byte-aligned)", ErrNotImplemented, spec.Name, name, bitOff)
	}
	if bits%8 != 0 {
		return 0, 0, fmt.Errorf("%w: field %s.%s is %d bits (not byte-sized)", ErrNotImplemented, spec.Name, name, bits)
	}
	if bits/8 > 8 {
		return 0, 0, fmt.Errorf("%w: field %s.%s is %d bytes (max 8)", ErrNotImplemented, spec.Name, name, bits/8)
	}
	return bitOff / 8, bits / 8, nil
}

// findFieldByteOffset128 is a width-relaxed sibling of
// findFieldByteOffset for the F4 / F3 paths that handle 128-bit
// fields (e.g. ipv6.src / ipv6.dst). The single-load 64-bit
// constraint of the original helper does not apply here because
// the caller emits two LDX-DWord loads and joins the halves into
// a register pair.
func findFieldByteOffset128(spec *vocab.ProtocolSpec, name string) (int, int, error) {
	bitOff, bits, err := findFieldBitOffset(spec, name)
	if err != nil {
		return 0, 0, err
	}
	if bitOff%8 != 0 {
		return 0, 0, fmt.Errorf("%w: field %s.%s starts at bit %d (not byte-aligned)", ErrNotImplemented, spec.Name, name, bitOff)
	}
	if bits != 128 {
		return 0, 0, fmt.Errorf("%w: bit<128> path called with %d-bit field %s.%s", ErrNotImplemented, bits, spec.Name, name)
	}
	return bitOff / 8, bits / 8, nil
}

// fieldRefByteOffset returns the byte offset (relative to the
// owning layer's start, anchored on offsetBase at predicate-emit
// time) and byte width for a FieldRef. Aux references add the aux
// header's OffsetInLayer to the field's bit-window byte offset
// inside that aux header; aux header stack references with a static
// index further add Static * ElemSize so a single immediate offset
// points at the addressed entry's field. Predicate codegen uses
// this in place of findFieldByteOffset whenever the field may
// belong to an aux header.
//
// Dynamic stack indices return ErrNotImplemented from this helper —
// they need a different code shape (runtime field load + multiply +
// add) emitted via emitAuxStackDynamicLoad. Callers wrap this
// helper for the static path only.
func fieldRefByteOffset(ref *ir.FieldRef) (int, int, error) {
	if ref == nil {
		return 0, 0, fmt.Errorf("codegen: nil field ref")
	}
	if ref.Aux == nil {
		off, size, err := findFieldByteOffset(ref.Layer.Spec, ref.Field.Name)
		if err != nil {
			// findFieldByteOffset rejects > 8-byte fields, but a
			// bit-slice may have narrowed an Int<128> down to ≤ 64
			// bits; bypass the check for that path so e.g.
			// `ipv6.src[0:32]` reaches the load.
			if ref.Slice != nil {
				bitOff, bits, ferr := findFieldBitOffset(ref.Layer.Spec, ref.Field.Name)
				if ferr != nil {
					return 0, 0, ferr
				}
				if bitOff%8 != 0 {
					return 0, 0, fmt.Errorf("%w: field %s.%s starts at bit %d (not byte-aligned)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Field.Name, bitOff)
				}
				_ = bits
				off = bitOff / 8
				size = ref.Slice.Bits() / 8
			} else {
				return 0, 0, err
			}
		}
		return applySliceToOffset(ref, off, size)
	}
	if ref.Aux.FieldBitOff%8 != 0 {
		return 0, 0, fmt.Errorf("%w: aux field %s.%s.%s starts at bit %d (not byte-aligned)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.Aux.FieldBitOff)
	}
	if ref.Aux.FieldBitWidth%8 != 0 {
		return 0, 0, fmt.Errorf("%w: aux field %s.%s.%s is %d bits (not byte-sized)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.Aux.FieldBitWidth)
	}
	if ref.Aux.FieldBitWidth/8 > 8 {
		return 0, 0, fmt.Errorf("%w: aux field %s.%s.%s is %d bytes (max 8)", ErrNotImplemented, ref.Layer.Spec.Name, ref.Aux.OutParam, ref.Field.Name, ref.Aux.FieldBitWidth/8)
	}
	off := ref.Aux.OffsetInLayer + ref.Aux.FieldBitOff/8
	if ref.Aux.Stack != nil {
		if !ref.Aux.Stack.IsStatic {
			return 0, 0, fmt.Errorf("%w: dynamic aux header stack index requires runtime offset emit (use emitAuxStackDynamicLoad)", ErrNotImplemented)
		}
		off += int(ref.Aux.Stack.Static) * ref.Aux.HeaderSize
	}
	return applySliceToOffset(ref, off, ref.Aux.FieldBitWidth/8)
}

// applySliceToOffset narrows (off, size) by the field's bit-slice
// when set. For byte-aligned slices the result is exact (off shifts
// to the slice start, size is the slice width in bytes). For
// sub-byte slices we round the load up to the smallest power-of-2
// byte size that covers the slice; the caller is responsible for
// emitting the post-load shift + mask via slicePostAdjust.
func applySliceToOffset(ref *ir.FieldRef, off, size int) (int, int, error) {
	if ref.Slice == nil {
		return off, size, nil
	}
	byteStart := ref.Slice.Lo / 8
	byteEndExclusive := (ref.Slice.Hi + 7) / 8
	cover := byteEndExclusive - byteStart
	loadBytes := nextLDXSize(cover)
	if loadBytes == 0 {
		return 0, 0, fmt.Errorf("%w: bit-slice [%d:%d] needs %d-byte load (max 8)", ErrNotImplemented, ref.Slice.Lo, ref.Slice.Hi, cover)
	}
	off += byteStart
	return off, loadBytes, nil
}

// nextLDXSize returns the smallest LDX-acceptable byte count
// (1 / 2 / 4 / 8) ≥ cover, or 0 if cover > 8. The post-load
// shift + mask narrows the loaded value back down to the slice's
// actual bits.
func nextLDXSize(cover int) int {
	switch {
	case cover <= 1:
		return 1
	case cover <= 2:
		return 2
	case cover <= 4:
		return 4
	case cover <= 8:
		return 8
	}
	return 0
}

// slicePostAdjust returns the shift and mask the caller emits to
// pull the slice's bits out of a freshly-loaded (and byte-swapped)
// register. Returns shift = 0 and mask = 0 when no adjustment is
// needed (= byte-aligned slice that exactly fills the load, or
// no slice at all). The caller emits:
//
//	if shift > 0:  asm.RSh.Imm(R3, int32(shift))
//	if mask  > 0:  asm.LoadImm(R5, int64(mask), DWord); asm.And.Reg(R3, R5)
//	             (or And.Imm if mask fits int32)
//
// Bit numbering: the slice's network bit `lo` lives at host bit
// position `loadBytes*8 - 1 - (lo - byteStart*8)` in the swapped
// register. shift = loadBytes*8 - (hi - byteStart*8) drops the bits
// below the slice; mask = (1<<width) - 1 keeps only the slice bits.
func slicePostAdjust(ref *ir.FieldRef, loadBytes int) (shift int, mask uint64) {
	if ref.Slice == nil {
		return 0, 0
	}
	byteStart := ref.Slice.Lo / 8
	loadBits := loadBytes * 8
	hiInLoad := ref.Slice.Hi - byteStart*8
	width := ref.Slice.Bits()
	// Default: no adjustment when slice exactly equals the load.
	if hiInLoad == loadBits && ref.Slice.Lo == byteStart*8 && width == loadBits {
		return 0, 0
	}
	shift = loadBits - hiInLoad
	mask = (uint64(1) << uint(width)) - 1
	if width >= 64 {
		mask = ^uint64(0)
	}
	return shift, mask
}

// emitAuxGating emits the runtime check that the aux is present on
// this packet's path: reads one byte from primary[Gating.ByteOff],
// masks it with Gating.Mask, and jumps to failLabel when the
// comparison disagrees. The byte address is computed via base —
// predicate-time callers pass r4Anchor() (R4 still equals layer
// entry); where-clause callers pass absAnchor(absOff) where
// absOff = c.layerOffset(layer). nil gating emits no instructions.
func emitAuxGating(g *vocab.AuxGating, base layerAnchor, failLabel string) asm.Instructions {
	if g == nil {
		return nil
	}
	insns := emitFieldLoad(base, g.ByteOff, asm.Byte)
	insns = append(insns, asm.And.Imm(asm.R3, int32(g.Mask)))
	switch g.Op {
	case vocab.GatingNe:
		insns = append(insns, asm.JEq.Imm(asm.R3, int32(g.Value), failLabel))
	case vocab.GatingEq:
		insns = append(insns, asm.JNE.Imm(asm.R3, int32(g.Value), failLabel))
	}
	return insns
}

// emitDynamicStackAddress emits the runtime index source byte read,
// bounds check, and multiply-add address compute for a dynamic aux
// header stack index. After it runs, R5 holds the absolute scratch
// address of the addressed stack entry's start. Callers append one
// or more LDX from R5 with field-relative offsets to read individual
// fields.
//
// `layerBase` describes how the layer's start is anchored:
//   - LayerAnchorR4: R0 + offsetBase = layer start. Used by predicate
//     codegen which runs while R4 still equals layer entry.
//   - LayerAnchorAbsolute(off): R0 + off = layer start. Used by
//     where-clause codegen which runs after R4 has advanced past
//     every layer.
//
// failLabel is where the bounds check jumps when the runtime index
// reaches the stack's declared capacity. R3 is also clobbered; R5
// remains live until the next emitter that touches it.
//
// MVP constraints:
//   - The dynamic index source must be a byte-aligned 1-byte
//     primary-header field of the same layer.
//   - The element size must be ≤127 (single-byte multiplier).
//   - The aux's OffsetInLayer is folded into R5 too: callers'
//     trailing LDX uses field byte offset within the aux, no extra
//     base addition required.
//
// Bounds invariant: this helper does not emit an explicit
// `R5+fieldBytes ≤ R1` check. The verifier accepts the LDX from R5
// because (a) the index byte is narrowed by JGE.Imm to < Capacity,
// (b) the multiplier and OffsetInLayer are constants, and (c) the
// owning layer's outer bounds (emitted by genStaticLayer or the
// parser machine) cover the full stack envelope —
// `Capacity * HeaderSize + OffsetInLayer` bytes — so R5 stays
// within the validated window. Adding a stack to a vocab without
// extending those outer bounds will let R5 escape; the
// ScratchBufSize sizing contract in the package doc must then be
// re-verified.
func emitDynamicStackAddress(ref *ir.FieldRef, base layerAnchor, failLabel string) (asm.Instructions, error) {
	if ref == nil || ref.Aux == nil || ref.Aux.Stack == nil || ref.Aux.Stack.IsStatic {
		return nil, fmt.Errorf("codegen: emitDynamicStackAddress called on non-dynamic ref")
	}
	stack := ref.Aux.Stack
	if stack.Dynamic == nil {
		return nil, fmt.Errorf("codegen: dynamic stack index has no source field")
	}
	if stack.Dynamic.Aux != nil {
		return nil, fmt.Errorf("%w: dynamic index source must be a primary-header field", ErrNotImplemented)
	}
	if stack.Dynamic.Layer != ref.Layer {
		return nil, fmt.Errorf("%w: dynamic index source must live on the same layer as the stack", ErrNotImplemented)
	}
	idxByteOff, idxBytes, err := findFieldByteOffset(stack.Dynamic.Layer.Spec, stack.Dynamic.Field.Name)
	if err != nil {
		return nil, err
	}
	if idxBytes != 1 {
		return nil, fmt.Errorf("%w: dynamic index source %s.%s is %d bytes (only 1-byte sources supported)", ErrNotImplemented, stack.Dynamic.Layer.Spec.Name, stack.Dynamic.Field.Name, idxBytes)
	}
	if ref.Aux.HeaderSize <= 0 || ref.Aux.HeaderSize > 127 {
		return nil, fmt.Errorf("%w: dynamic stack element size %d outside 1..127", ErrNotImplemented, ref.Aux.HeaderSize)
	}
	// Compute R3 = scratch address of the layer's primary-header
	// start, then read the index byte from primary[idxByteOff]. For
	// slot anchors we load the layer-entry offset into R5 first so
	// the post-multiply addition can reuse it without a second slot
	// read; abs / R4 anchors keep the entry offset implicitly in
	// AbsOffset / R4 and add it twice.
	insns := asm.Instructions{}
	switch {
	case base.UseR4:
		insns = append(insns,
			asm.Mov.Reg(asm.R3, asm.R0),
			asm.Add.Reg(asm.R3, offsetBase),
		)
	case base.UseSlot:
		insns = append(insns,
			asm.LoadMem(asm.R5, asm.R10, base.SlotOff, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R0),
			asm.Add.Reg(asm.R3, asm.R5),
		)
	default:
		insns = append(insns,
			asm.Mov.Reg(asm.R3, asm.R0),
			asm.Add.Imm(asm.R3, int32(base.AbsOffset)),
		)
	}
	// Load index byte from primary header at offset idxByteOff.
	insns = append(insns,
		asm.LoadMem(asm.R3, asm.R3, int16(idxByteOff), asm.Byte),
		asm.JGE.Imm(asm.R3, int32(stack.Capacity), failLabel),
		asm.Mul.Imm(asm.R3, int32(ref.Aux.HeaderSize)),
		asm.Add.Imm(asm.R3, int32(ref.Aux.OffsetInLayer)),
	)
	switch {
	case base.UseR4:
		insns = append(insns, asm.Add.Reg(asm.R3, offsetBase))
	case base.UseSlot:
		insns = append(insns, asm.Add.Reg(asm.R3, asm.R5))
	default:
		insns = append(insns, asm.Add.Imm(asm.R3, int32(base.AbsOffset)))
	}
	insns = append(insns,
		asm.Mov.Reg(asm.R5, asm.R0),
		asm.Add.Reg(asm.R5, asm.R3),
	)
	return insns, nil
}

// layerAnchor abstracts how to express "the byte offset of the
// owning layer's start". Three modes:
//
//   - UseR4: R0 + offsetBase = layer start. Used by bracket
//     predicates which run while R4 still equals layer entry.
//   - AbsOffset: R0 + AbsOffset = layer start. Used by where /
//     capture when the layer's runtime position is statically
//     known (no heterogeneous-size alt sits earlier in the chain).
//   - SlotOff: R0 + R10[SlotOff] = layer start. Used by where /
//     capture when a heterogeneous-size alt makes the static prefix
//     unknowable; the layer's emit stores R4 into the slot at entry,
//     downstream readers reload it at use time.
type layerAnchor struct {
	UseR4     bool
	AbsOffset int
	UseSlot   bool
	SlotOff   int16
}

func r4Anchor() layerAnchor         { return layerAnchor{UseR4: true} }
func absAnchor(off int) layerAnchor { return layerAnchor{AbsOffset: off} }
func slotAnchor(slot int16) layerAnchor {
	return layerAnchor{UseSlot: true, SlotOff: slot}
}

// whereLayerEntrySlot returns the stack slot reserved for layer at
// position layerPos (= LayerInstance.LayerPos) in the program. Slots
// descend from -160 in 8-byte steps so they sit below kunai's existing
// allocations (arith spill -56..-80, bpf_loop ctx -96..-128) without
// colliding with the per-layer-entry slot the parser machine uses
// (-104, single shared slot for the immediate next layer's dispatch).
//
// The cap below mirrors the practical chain depth in the bundled
// vocab plus headroom — `eth/ipv4/udp/gtp/ipv4/tcp` is 6 layers, an
// alt + post-alt extra brings you to ~8. 12 slots × 8 bytes = 96
// bytes, fitting comfortably within the 512-byte BPF stack budget.
const whereLayerEntrySlotBase = int16(-160)
const whereLayerEntrySlotCap = 12

func whereLayerEntrySlot(layerPos int) (int16, error) {
	if layerPos < 0 || layerPos >= whereLayerEntrySlotCap {
		return 0, fmt.Errorf("%w: layer position %d exceeds where-slot cap %d (chain too deep for runtime addressing)", ErrNotImplemented, layerPos, whereLayerEntrySlotCap)
	}
	return whereLayerEntrySlotBase - int16(layerPos)*8, nil
}

// emitFieldLoad reads `size` bytes at `fieldOff` from the layer
// anchored by `anchor` into R3. The three anchor modes pick different
// addressing strategies; callers don't need to branch.
//
// All three branches are PTR_TO_PACKET-safe: an explicit
// `JGT (end-of-access), R1, dslReject` precedes the load so the
// verifier propagates `r ≥ size` to the LoadMem. The check is
// mandatory for PTR_TO_PACKET and harmless for PTR_TO_MAP_VALUE.
func emitFieldLoad(anchor layerAnchor, fieldOff int, size asm.Size) asm.Instructions {
	sizeBytes := int32(size.Sizeof())
	switch {
	case anchor.UseSlot:
		return asm.Instructions{
			asm.LoadMem(asm.R3, asm.R10, anchor.SlotOff, asm.DWord),
			asm.Add.Reg(asm.R3, asm.R0),
			asm.Add.Imm(asm.R3, int32(fieldOff)+sizeBytes), // R3 = end-of-access
			asm.JGT.Reg(asm.R3, asm.R1, dslReject),
			asm.LoadMem(asm.R3, asm.R3, int16(-sizeBytes), size), // load at R3 - size
		}
	case anchor.UseR4:
		return emitBoundedLoad(asm.R3, int16(fieldOff), size, dslReject)
	default:
		totalOff := int32(anchor.AbsOffset+fieldOff) + sizeBytes
		return asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R0),
			asm.Add.Imm(asm.R3, totalOff), // R3 = R0 + absOff + fieldOff + size
			asm.JGT.Reg(asm.R3, asm.R1, dslReject),
			asm.LoadMem(asm.R3, asm.R3, int16(-sizeBytes), size),
		}
	}
}

// emitDynamicStackLoad is the single-LDX convenience built on
// emitDynamicStackAddress for predicate-emit-time callers (R4 still
// at layer entry). Multi-byte literals (IPv6, MAC, multi-half CIDR)
// call emitDynamicStackAddress directly so they can issue multiple
// LDX from the same R5 base.
func emitDynamicStackLoad(ref *ir.FieldRef, size asm.Size, failLabel string) (asm.Instructions, error) {
	addr, err := emitDynamicStackAddress(ref, r4Anchor(), failLabel)
	if err != nil {
		return nil, err
	}
	fieldByteOff := ref.Aux.FieldBitOff / 8
	return append(addr, asm.LoadMem(asm.R3, asm.R5, int16(fieldByteOff), size)), nil
}

// headerSize sums the protocol's header field bits, rejecting
// non-byte-aligned totals.
func headerSize(spec *vocab.ProtocolSpec) (int, error) {
	bits := vocab.SumBits(spec.Fields)
	if bits%8 != 0 {
		return 0, fmt.Errorf("%w: protocol %s has %d-bit header (not byte-aligned)", ErrNotImplemented, spec.Name, bits)
	}
	return bits / 8, nil
}

func asmSizeFor(bytes int) (asm.Size, error) {
	switch bytes {
	case 1:
		return asm.Byte, nil
	case 2:
		return asm.Half, nil
	case 4:
		return asm.Word, nil
	case 8:
		return asm.DWord, nil
	}
	return 0, fmt.Errorf("%w: field size %d bytes not supported", ErrNotImplemented, bytes)
}

// byteSwap reverses the bottom `bytes` bytes of v. eBPF LDX reads
// packet bytes little-endian, so comparing a network-order field to a
// byte-swapped constant yields the same result as comparing the
// host-order value to the natural constant — one instruction shorter
// than an explicit BSwap.
func byteSwap(v uint64, bytes int) uint64 {
	var out uint64
	for range bytes {
		out = (out << 8) | (v & 0xFF)
		v >>= 8
	}
	return out
}
