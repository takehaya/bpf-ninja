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

// ErrNotImplemented is returned by Gen when a resolved program uses a
// feature the MVP codegen does not yet support (sanity/no-check
// dispatch, non-integer predicate values, chained layers, alternation,
// where clauses, capture clauses). Callers can match it with errors.Is
// to distinguish "valid DSL, codegen still to come" from other errors.
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

// dslReject is internal to one Gen invocation; it sets R2=0 and falls
// through to filter_result. Unique per compile in case two filter
// programs ever share an assembly unit.
const dslReject = "dsl_reject"

// KunaiStackTop is the shallowest (closest-to-zero) R10 offset that
// codegen ever writes or reads. Host wrappers may use any slot in
// (KunaiStackTop, 0) for their own scratch (tracing args ptr,
// metadata, etc.) without colliding with kunai. The current
// allocations:
//
//   - kunai: arith spill at -56 .. -80 (4 slots × 8 bytes)
//   - kunai: bpf_loop ctx at -128 .. -96 (4 slots × 8 bytes)
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
// for VAREXT, `iter_cap × per-iter advance` for parser-machine
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

	insns := asm.Instructions{
		// Initialise the layer offset register to 0 (scratch start).
		// Each layer's genLayer appends its own trailing Add.Imm so
		// optional / repeating layers can advance conditionally.
		asm.Mov.Imm(offsetBase, 0),
	}
	var callbacks asm.Instructions
	for i, layer := range p.Layers {
		layerInsns, cb, err := genLayer(layer, i, p.Layers)
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
		whereInsns, err := genCondition(where, caps, p, dslReject)
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

// loadFromOffset emits the three-instruction sequence that materialises
// the scratch address `R0 + offsetBase + off` into R3 and loads `size`
// bytes from there into R3.
func loadFromOffset(off int16, size asm.Size) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Add.Reg(asm.R3, offsetBase),
		asm.LoadMem(asm.R3, asm.R3, off, size),
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
func genLayer(layer *ir.LayerInstance, index int, all []*ir.LayerInstance) (asm.Instructions, asm.Instructions, error) {
	insns, callbacks, err := genLayerInner(layer, index, all)
	return insns, callbacks, withPos(err, layer.Pos)
}

func genLayerInner(layer *ir.LayerInstance, index int, all []*ir.LayerInstance) (asm.Instructions, asm.Instructions, error) {
	if layer.Alternation != nil {
		insns, err := genAlternation(layer, index, all)
		return insns, nil, err
	}
	switch layer.Quant {
	case ast.QuantOne:
		if layer.Spec.ParseStateMachine != nil {
			return genParserMachine(layer, index, all)
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
		parent := dispatchParent(all[index-1])
		parentHS, err := headerSize(parent.Spec)
		if err != nil {
			return nil, err
		}
		di, err := genDispatch(layer, parent, parentHS, dslReject)
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
		// primary-header position regardless of how far VAREXT / OPT
		// shifts R4 afterwards. Mirror of parser_machine.go's slot
		// store — see the lifecycle docs there for the read/write
		// ordering invariant.
		insns = append(insns, asm.StoreMem(asm.R10, bpfLoopCtxLayerEntrySlot, offsetBase, asm.DWord))
	}
	insns = append(insns, emitAdvance(hs))
	if vs := layer.Spec.VariableSuffix; vs != nil {
		tail, err := emitVariableTrailInline(hs, variableTailSkipFromSuffix(vs), dslReject)
		if err != nil {
			return nil, err
		}
		insns = append(insns, tail...)
	}
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

// variableTailSkipFromSuffix lifts a vocab.VariableSuffix into the
// codegen-internal variableTailSkip representation. Primary-header
// suffixes always set MinimumTotal so an undersized length field
// (IHL < 5, data_offset < 5) jumps to dslReject before R5 can wrap.
func variableTailSkipFromSuffix(vs *vocab.VariableSuffix) variableTailSkip {
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
func emitPeekedIterZero(layer *ir.LayerInstance, index int, all []*ir.LayerInstance, peekFailLabel string) (asm.Instructions, error) {
	if index == 0 || layer.Dispatch == nil {
		return nil, fmt.Errorf("%w: peeked iter-0 on %q requires a parent dispatch", ErrNotImplemented, layer.Spec.Name)
	}
	hs, err := headerSize(layer.Spec)
	if err != nil {
		return nil, err
	}
	parent := dispatchParent(all[index-1])
	parentHS, err := headerSize(parent.Spec)
	if err != nil {
		return nil, err
	}
	peek, err := genDispatch(layer, parent, parentHS, peekFailLabel)
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
	case vocab.DispatchSanity:
		return genSanityDispatch(current, failLabel)
	case vocab.DispatchNoCheck:
		return genNoCheckDispatch(current)
	}
	return nil, fmt.Errorf("codegen: unknown dispatch type %v", current.Dispatch.Type)
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
