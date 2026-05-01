package resolve

import (
	"strings"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ast"
	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// optionsSegment is the reserved second segment that routes 4-part
// field paths (`<proto>.options.<NAME>.<field>`) into the option-walk
// resolver instead of the aux-stack / single-aux paths.
const optionsSegment = "options"

// resolveWhere converts an ast.WhereExpr tree to ir.Condition, binding
// field references inside arithmetic atoms to layers via FieldRef.
func (r *resolver) resolveWhere(w *ast.WhereExpr) (*ir.Condition, error) {
	if w == nil {
		return nil, nil
	}
	c := &ir.Condition{Kind: w.Kind, Pos: w.Pos}
	switch w.Kind {
	case ast.WOr, ast.WAnd:
		l, err := r.resolveWhere(w.Left)
		if err != nil {
			return nil, err
		}
		rt, err := r.resolveWhere(w.Right)
		if err != nil {
			return nil, err
		}
		c.Left, c.Right = l, rt
	case ast.WNot:
		inner, err := r.resolveWhere(w.Inner)
		if err != nil {
			return nil, err
		}
		c.Inner = inner
	case ast.WAtomArith:
		al, err := r.resolveArith(w.ArithL)
		if err != nil {
			return nil, err
		}
		ar, err := r.resolveArith(w.ArithR)
		if err != nil {
			return nil, err
		}
		c.ArithL, c.ArithR = al, ar
		c.Op = w.Op
		// Type checks: literal fit-check across the full arith tree
		// and static divide/modulo-by-zero detection. See
		// docs/ja/dsl-types.md §6.1, §7.
		if err := checkArithCondition(c); err != nil {
			return nil, err
		}
	case ast.WAtomLiteralCmp:
		ref, err := r.resolveQualifiedField(w.LiteralField)
		if err != nil {
			return nil, err
		}
		if err := checkLiteralWidthShape(ref, w.LiteralValue, w.Pos); err != nil {
			return nil, err
		}
		// Ordered cmp on network literals is forbidden by §6.2.
		// Parser already gates this on the LHS-literal path, but the
		// RHS-literal path admits the operator from parseArithExpr
		// without a kind-aware check; reject here so both paths see
		// the same diagnostic.
		if w.LiteralOp != ast.CmpEq && w.LiteralOp != ast.CmpNeq {
			kind := "CIDR"
			switch w.LiteralValue.Kind {
			case ast.ValIPv4, ast.ValIPv6, ast.ValMAC:
				kind = "address"
			}
			return nil, errOrderedNotAllowed(w.Pos, w.LiteralOp, kind)
		}
		c.LiteralField = ref
		c.LiteralValue = w.LiteralValue
		c.LiteralOp = w.LiteralOp
	case ast.WAtomAction:
		if r.allowedActions == nil {
			return nil, errorf(w.Pos, "`action == %s` is not available on this host (no action atoms declared in caps)", w.ActionValue)
		}
		if _, ok := r.allowedActions[w.ActionValue]; !ok {
			return nil, errUnknownActionLiteral(w.Pos, w.ActionValue, len(r.allowedActions))
		}
		c.ActionValue = w.ActionValue
	case ast.WAny, ast.WAll:
		inner, err := r.resolveWhere(w.Inner)
		if err != nil {
			return nil, err
		}
		c.Inner = inner
		// The inner expression must reference exactly one aux header
		// stack with no explicit index; that stack becomes the
		// iteration target. Single-aux refs and primary fields stay
		// constant within the iteration. We materialise the target
		// here so codegen does not have to walk the IR again.
		target, err := r.findQuantTarget(inner, w.Pos)
		if err != nil {
			return nil, err
		}
		c.QuantTarget = target
	case ast.WAtomBoolLit:
		c.BoolLitValue = w.BoolLitValue
	case ast.WAtomBoolExists:
		// Re-attach the trailing `.exists` segment so resolveQualifiedField
		// dispatches to the existing aux-exists path.
		fpWithExists := &ast.FieldPath{
			Parts: append(append([]string(nil), w.BoolField.Parts...), "exists"),
			Pos:   w.BoolField.Pos,
		}
		if len(w.BoolField.Indices) > 0 {
			fpWithExists.Indices = append([]*ast.IndexExpr(nil), w.BoolField.Indices...)
		}
		ref, err := r.resolveQualifiedField(fpWithExists)
		if err != nil {
			return nil, err
		}
		if !ref.IsExistsCheck() {
			if ref.Aux == nil {
				return nil, errorf(w.Pos, "%s does not name an aux header (`.exists` requires an aux reference)", w.BoolField.String())
			}
			// Resolver returned a field; collapse to the synthetic
			// exists sentinel (Field == nil) for codegen.
			ref.Field = nil
		}
		c.BoolField = ref
	case ast.WAtomBoolEq:
		// Defense in depth: parser already blocks ordered cmp on Bool
		// in maybeBoolEqTail, but a future parser refactor could let
		// it slip past — reject here too so §12 T-Where-BoolEq's
		// op_eq ∈ {==, !=} side condition is enforced at the IR
		// boundary.
		if w.BoolEqOp != ast.CmpEq && w.BoolEqOp != ast.CmpNeq {
			return nil, errOrderedNotAllowed(w.Pos, w.BoolEqOp, "Bool")
		}
		left, err := r.resolveWhere(w.BoolL)
		if err != nil {
			return nil, err
		}
		right, err := r.resolveWhere(w.BoolR)
		if err != nil {
			return nil, err
		}
		c.BoolL = left
		c.BoolR = right
		c.BoolEqOp = w.BoolEqOp
	default:
		return nil, errorf(w.Pos, "internal: unknown where kind %v", w.Kind)
	}
	return c, nil
}

// findQuantTarget locates the aux header stack the inner expression
// iterates over. The inner contains exactly one FieldRef whose
// Aux.Stack is set and IsStatic is false (no explicit index = the
// quantifier's iteration variable). Other field refs inside the
// inner are constants per-iteration. Multiple stack refs or a
// stack ref already carrying a static index inside any/all are
// rejected — the codegen contract requires a single iteration
// dimension.
func (r *resolver) findQuantTarget(c *ir.Condition, pos ast.Position) (*ir.QuantTarget, error) {
	var found *ir.AuxRef
	ir.WalkConditionFieldRefs(c, func(ref *ir.FieldRef) {
		if ref == nil || ref.Aux == nil || ref.Aux.Stack == nil {
			return
		}
		// Iterator refs (no [index] inside any/all) are the
		// quantifier's iteration variable. Static / dynamic
		// indexed refs already pin a specific element and are
		// not iteration targets.
		if !ref.Aux.Stack.IsIterator {
			return
		}
		found = ref.Aux
	})
	if found == nil {
		return nil, errorf(pos, "any/all requires exactly one aux header stack reference inside (e.g. `any(srv6.segments.addr == X)`)")
	}
	return &ir.QuantTarget{
		OutParam:      found.OutParam,
		HeaderName:    found.HeaderName,
		OffsetInLayer: found.OffsetInLayer,
		ElemSize:      found.HeaderSize,
		Capacity:      found.Stack.Capacity,
	}, nil
}


// resolveArith converts an ast.ArithExpr to ir.ArithExpr, binding every
// field reference to its owning layer.
func (r *resolver) resolveArith(a *ast.ArithExpr) (*ir.ArithExpr, error) {
	if a == nil {
		return nil, errorf(ast.Position{}, "internal: nil arithmetic expression")
	}
	out := &ir.ArithExpr{Kind: a.Kind, Pos: a.Pos}
	switch a.Kind {
	case ast.ArithConst:
		out.Const = a.Const
	case ast.ArithField:
		ref, err := r.resolveQualifiedField(a.Field)
		if err != nil {
			return nil, err
		}
		out.Field = ref
	case ast.ArithBinOp:
		l, err := r.resolveArith(a.Left)
		if err != nil {
			return nil, err
		}
		rt, err := r.resolveArith(a.Right)
		if err != nil {
			return nil, err
		}
		out.Left, out.Right = l, rt
		out.Op = a.Op
	default:
		return nil, errorf(a.Pos, "internal: unknown arith kind %v", a.Kind)
	}
	return out, nil
}

// resolveQualifiedField looks up a `<qualifier>.<field>` (primary
// header) or `<qualifier>.<aux>.<field>` / `<qualifier>.<aux>.exists`
// (single auxiliary header) or `<qualifier>.<aux>[N].<field>`
// (auxiliary header stack) path. The qualifier is either a
// user-assigned "@label" or a bare protocol name (the latter only
// when the filter has exactly one instance of that protocol).
func (r *resolver) resolveQualifiedField(fp *ast.FieldPath) (*ir.FieldRef, error) {
	if fp == nil || len(fp.Parts) == 0 {
		return nil, errorf(ast.Position{}, "internal: empty field path")
	}
	if len(fp.Parts) < 2 {
		return nil, errorf(fp.Pos, "field path %q must be qualified (e.g. 'ipv4.src' or '<label>.<field>')", fp.String())
	}
	if len(fp.Parts) > 4 {
		return nil, errorf(fp.Pos, "nested field access %q is not supported (max 4 segments)", fp.String())
	}
	qualifier := fp.Parts[0]
	layer, err := r.lookupByQualifier(qualifier, fp.Pos)
	if err != nil {
		return nil, err
	}
	// Indices on the qualifier itself or the trailing field are not
	// meaningful: only the aux segment may carry an index for stack
	// access. Reject other shapes early so the diagnostic is clear.
	if hasIndexAt(fp, 0) {
		return nil, errorf(fp.Pos, "index on protocol qualifier %q is not supported", qualifier)
	}
	if len(fp.Parts) >= 3 && hasIndexAt(fp, len(fp.Parts)-1) {
		return nil, errorf(fp.Pos, "index on trailing field %q is not supported", fp.Parts[len(fp.Parts)-1])
	}
	// 4-part: `<qualifier>.options.<NAME>.<field|exists>` routes to
	// the protocol's declared OptionWalk.
	if len(fp.Parts) == 4 {
		if fp.Parts[1] != optionsSegment {
			return nil, errorf(fp.Pos, "4-part field path requires the second segment to be %q (got %q)", optionsSegment, fp.Parts[1])
		}
		return resolveOptionField(layer, fp.Parts[2], fp.Parts[3], fp)
	}
	if len(fp.Parts) == 2 {
		if hasIndexAt(fp, 1) {
			return nil, errorf(fp.Pos, "primary-header field %q does not accept an index", fp.Parts[1])
		}
		return resolvePrimaryField(layer, fp.Parts[1], fp)
	}
	if hasIndexAt(fp, 1) {
		return r.resolveAuxStackField(layer, fp.Parts[1], indexAt(fp, 1), fp.Parts[2], fp)
	}
	return resolveAuxField(layer, fp.Parts[1], fp.Parts[2], fp)
}

// resolveOptionField handles `<qualifier>.options.<NAME>.<field>` and
// `<qualifier>.options.<NAME>.exists`. The option name must match
// one of the protocol's OptionWalk entries; the trailing identifier
// is either "exists" (existence check) or a field of the option's
// declared header type (tcp_opt_<name>_h).
func resolveOptionField(layer *ir.LayerInstance, optName, tail string, fp *ast.FieldPath) (*ir.FieldRef, error) {
	if layer.Spec.OptionWalk == nil {
		return nil, errorf(fp.Pos, "protocol %q declares no OPT_ option-walk consts; %q is not addressable via .options.<NAME>", layer.Spec.Name, layer.Spec.Name)
	}
	walk := layer.Spec.OptionWalk
	entry, ok := walk.FindOption(optName)
	if !ok {
		names := make([]string, 0, len(walk.Options))
		for _, e := range walk.Options {
			names = append(names, e.Name)
		}
		return nil, errorf(fp.Pos, "protocol %q has no option named %q (declared options: %v)", layer.Spec.Name, optName, names)
	}
	lookup := &ir.OptionLookup{
		Name:           entry.Name,
		Kind:           entry.Kind,
		OptionSize:     entry.Size,
		TerminatorKind: walk.TerminatorKind,
		PaddingKind:    walk.PaddingKind,
		LengthByteOff:  walk.LengthByteOff,
	}
	if tail == "exists" {
		lookup.ExistsOnly = true
		return &ir.FieldRef{
			Layer: layer,
			Field: nil,
			Aux: &ir.AuxRef{
				OutParam:   strings.ToLower(entry.Name),
				HeaderName: entry.HeaderRef.Name,
				HeaderSize: entry.Size,
				Option:     lookup,
			},
		}, nil
	}
	bitOff := 0
	bitWidth := 0
	for _, f := range entry.HeaderRef.Fields {
		if f.Name == tail {
			bitWidth = f.Bits
			break
		}
		bitOff += f.Bits
	}
	if bitWidth == 0 {
		return nil, errorf(fp.Pos, "option %q has no field %q (header %q)", entry.Name, tail, entry.HeaderRef.Name)
	}
	return &ir.FieldRef{
		Layer: layer,
		Field: &vocab.Field{Name: tail, Bits: bitWidth},
		Aux: &ir.AuxRef{
			OutParam:      strings.ToLower(entry.Name),
			HeaderName:    entry.HeaderRef.Name,
			HeaderSize:    entry.Size,
			FieldBitOff:   bitOff,
			FieldBitWidth: bitWidth,
			Option:        lookup,
		},
	}, nil
}

func hasIndexAt(fp *ast.FieldPath, i int) bool {
	if fp == nil || i < 0 || i >= len(fp.Indices) {
		return false
	}
	return fp.Indices[i] != nil
}

func indexAt(fp *ast.FieldPath, i int) *ast.IndexExpr {
	if !hasIndexAt(fp, i) {
		return nil
	}
	return fp.Indices[i]
}

// resolveAuxStackIterField handles `<qualifier>.<stackName>.<field>`
// without an index — this is the iteration form, valid only inside
// an enclosing any/all quantifier. The returned FieldRef carries
// StackIndex.IsIterator = true; codegen surfaces an error if such a
// ref appears outside a quantifier.
func resolveAuxStackIterField(layer *ir.LayerInstance, stack *vocab.HeaderStack, stackName, fieldName string, fp *ast.FieldPath) (*ir.FieldRef, error) {
	bitOff := 0
	bitWidth := 0
	for _, f := range stack.HeaderRef.Fields {
		if f.Name == fieldName {
			bitWidth = f.Bits
			break
		}
		bitOff += f.Bits
	}
	if bitWidth == 0 {
		return nil, errorf(fp.Pos, "auxiliary header %q has no field %q", stack.HeaderName, fieldName)
	}
	stackOffset, err := stackBaseOffsetInLayer(layer.Spec, stackName, fp)
	if err != nil {
		return nil, err
	}
	return &ir.FieldRef{
		Layer: layer,
		Field: &vocab.Field{Name: fieldName, Bits: bitWidth},
		Aux: &ir.AuxRef{
			OutParam:      stackName,
			HeaderName:    stack.HeaderName,
			OffsetInLayer: stackOffset,
			HeaderSize:    stack.ElemSize,
			FieldBitOff:   bitOff,
			FieldBitWidth: bitWidth,
			Stack: &ir.StackIndex{
				Capacity:   stack.Capacity,
				IsIterator: true,
			},
		},
	}, nil
}

// resolveAuxStackField handles `<qualifier>.<stackName>[index].<field>`.
// The index is either an integer literal (static) or a field path
// resolving to a primary-header byte field (dynamic). Static indices
// must lie within the stack's declared capacity; that's checked here
// so codegen can rely on a verifier-safe constant.
func (r *resolver) resolveAuxStackField(layer *ir.LayerInstance, stackName string, idx *ast.IndexExpr, fieldName string, fp *ast.FieldPath) (*ir.FieldRef, error) {
	psm := layer.Spec.ParseStateMachine
	if psm == nil {
		return nil, errorf(fp.Pos, "protocol %q has no parser state machine that could declare an aux header stack", layer.Spec.Name)
	}
	stack, ok := psm.StackRefs[stackName]
	if !ok {
		// If the name belongs to a single aux, route to the simpler error.
		if _, isSingle := psm.AuxLayouts[stackName]; isSingle {
			return nil, errorf(fp.Pos, "auxiliary header %q is not a stack; drop the [%s] index", stackName, idx.String())
		}
		return nil, errorf(fp.Pos, "protocol %q has no auxiliary header stack %q", layer.Spec.Name, stackName)
	}
	bitOff := 0
	bitWidth := 0
	for _, f := range stack.HeaderRef.Fields {
		if f.Name == fieldName {
			bitWidth = f.Bits
			break
		}
		bitOff += f.Bits
	}
	if bitWidth == 0 {
		return nil, errorf(fp.Pos, "auxiliary header %q has no field %q", stack.HeaderName, fieldName)
	}
	stackOffset, err := stackBaseOffsetInLayer(layer.Spec, stackName, fp)
	if err != nil {
		return nil, err
	}
	stackIdx, err := r.resolveStackIndex(idx, stack.Capacity, fp)
	if err != nil {
		return nil, err
	}
	return &ir.FieldRef{
		Layer: layer,
		Field: &vocab.Field{Name: fieldName, Bits: bitWidth},
		Aux: &ir.AuxRef{
			OutParam:      stackName,
			HeaderName:    stack.HeaderName,
			OffsetInLayer: stackOffset,
			HeaderSize:    stack.ElemSize,
			FieldBitOff:   bitOff,
			FieldBitWidth: bitWidth,
			Stack:         stackIdx,
		},
	}, nil
}

// stackBaseOffsetInLayer locates the byte offset (relative to the
// layer-entry slot) at which the aux header stack starts. Two
// shapes are recognised:
//
//   - The stack is pushed inside a single parser-machine state. We
//     use that state's OffsetAtEntry — already populated by the
//     vocab pass — as the stack's base position. Used by gtp.exts
//     and ipv6.exts whose parser blocks describe the per-iteration
//     extract.
//   - The stack is declared but never pushed by the parser block;
//     codegen handles the post-primary advance via a variable-trail
//     skip (= knownVariableTails entry) and the stack starts
//     immediately after the primary header. Used by srv6.segments
//     where the SRH wrapper carries a length field that drives the
//     opaque skip.
//
// Multiple stack pushes of the same stack across distinct states
// aren't expected in the bundled vocab and are surfaced as build
// errors so silent miscomputes can't slip in.
func stackBaseOffsetInLayer(spec *vocab.ProtocolSpec, stackName string, fp *ast.FieldPath) (int, error) {
	psm := spec.ParseStateMachine
	if psm == nil {
		return 0, errorf(fp.Pos, "protocol %q has no parser machine to locate stack %q", spec.Name, stackName)
	}
	offset := -1
	for _, st := range psm.States {
		for _, ex := range st.Extracts {
			if ex.IsStackPush && ex.StackName == stackName {
				if offset >= 0 && offset != st.OffsetAtEntry {
					return 0, errorf(fp.Pos, "stack %q is pushed by states at distinct byte offsets (%d vs %d); ambiguous base", stackName, offset, st.OffsetAtEntry)
				}
				offset = st.OffsetAtEntry
			}
		}
	}
	if offset >= 0 {
		return offset, nil
	}
	// No state pushes the stack: the stack lives in the protocol's
	// variable trail and starts immediately after the primary header.
	primaryBits := vocab.SumBits(spec.Fields)
	if primaryBits%8 != 0 {
		return 0, errorf(fp.Pos, "primary header of %q is %d bits (not byte-aligned); cannot locate stack %q", spec.Name, primaryBits, stackName)
	}
	return primaryBits / 8, nil
}

// resolveStackIndex turns an ast.IndexExpr into ir.StackIndex,
// validating that static indices fall within the stack capacity.
// Dynamic indices point at a primary-header byte-aligned integer
// field (≤8 bytes); the runtime check that the value falls below
// capacity is emitted by codegen.
func (r *resolver) resolveStackIndex(idx *ast.IndexExpr, capacity int, fp *ast.FieldPath) (*ir.StackIndex, error) {
	if idx.IsInt {
		if idx.Int >= uint64(capacity) {
			return nil, errorf(fp.Pos, "static index %d exceeds stack capacity %d", idx.Int, capacity)
		}
		return &ir.StackIndex{Capacity: capacity, IsStatic: true, Static: idx.Int}, nil
	}
	if idx.Field == nil {
		return nil, errorf(fp.Pos, "internal: empty index expression")
	}
	dyn, err := r.resolveQualifiedField(idx.Field)
	if err != nil {
		return nil, err
	}
	if dyn.Aux != nil {
		return nil, errorf(fp.Pos, "dynamic index %q must reference a primary-header field", idx.Field.String())
	}
	if dyn.Field == nil {
		return nil, errorf(fp.Pos, "dynamic index %q resolves to an unsupported field shape", idx.Field.String())
	}
	if dyn.Field.Bits%8 != 0 || dyn.Field.Bits/8 > 8 {
		return nil, errorf(fp.Pos, "dynamic index field %q must be byte-aligned and ≤ 8 bytes wide (got %d bits)", idx.Field.String(), dyn.Field.Bits)
	}
	return &ir.StackIndex{Capacity: capacity, IsStatic: false, Dynamic: dyn}, nil
}

// resolvePrimaryField handles the 2-part case (`<qualifier>.<field>`).
func resolvePrimaryField(layer *ir.LayerInstance, fieldName string, fp *ast.FieldPath) (*ir.FieldRef, error) {
	f, ok := layer.Spec.FindField(fieldName)
	if !ok {
		return nil, errorf(fp.Pos, "protocol %q has no field %q", layer.Spec.Name, fieldName)
	}
	return &ir.FieldRef{Layer: layer, Field: f}, nil
}

// resolveAuxField handles the 3-part case (`<qualifier>.<aux>.<field>`
// or `<qualifier>.<aux>.exists`). The aux name must match a parser
// out parameter declared in the protocol's parser block; the
// trailing field must either be a field of that aux header or the
// special "exists" sentinel that becomes a gating-only check.
//
// When the aux name is a stack rather than a single aux, the field
// is treated as an iteration variable: the returned FieldRef carries
// StackIndex.IsIterator = true, which is only valid inside an
// enclosing `any(...)` / `all(...)` quantifier. Codegen surfaces an
// error if such a ref escapes a quantifier so silent miscomputes
// can't slip in. Bracket-form predicates do not allow iterator refs
// (the bracket itself does not iterate); resolveBracketPredicate
// detects iterator refs and returns a clear error.
func resolveAuxField(layer *ir.LayerInstance, auxName, tail string, fp *ast.FieldPath) (*ir.FieldRef, error) {
	psm := layer.Spec.ParseStateMachine
	if psm == nil {
		return nil, errorf(fp.Pos, "protocol %q has no auxiliary headers (no parser state machine declares an `out` aux parameter)", layer.Spec.Name)
	}
	if stack, isStack := psm.StackRefs[auxName]; isStack {
		return resolveAuxStackIterField(layer, stack, auxName, tail, fp)
	}
	auxLayout, ok := psm.AuxLayouts[auxName]
	if !ok {
		return nil, errorf(fp.Pos, "protocol %q has no auxiliary header %q (declare `out <type> %s` in the parser block)", layer.Spec.Name, auxName, auxName)
	}
	if tail == "exists" {
		return &ir.FieldRef{
			Layer: layer,
			Field: nil,
			Aux: &ir.AuxRef{
				OutParam:      auxLayout.OutParam,
				HeaderName:    auxLayout.HeaderName,
				OffsetInLayer: auxLayout.OffsetInLayer,
				HeaderSize:    auxLayout.HeaderSize,
				Gating:        auxLayout.Gating,
			},
		}, nil
	}
	bitOff, bitWidth, found := auxLayout.FindField(tail)
	if !found {
		return nil, errorf(fp.Pos, "auxiliary header %q has no field %q", auxLayout.HeaderName, tail)
	}
	// Synthesize a vocab.Field for downstream codegen that treats
	// FieldRef.Field as the unit-of-bit-window. The synthetic Field
	// carries Bits so width-aware diagnostics (value-doesn't-fit
	// checks in resolveBracketPredicate) keep working.
	field := &vocab.Field{Name: tail, Bits: bitWidth}
	return &ir.FieldRef{
		Layer: layer,
		Field: field,
		Aux: &ir.AuxRef{
			OutParam:      auxLayout.OutParam,
			HeaderName:    auxLayout.HeaderName,
			OffsetInLayer: auxLayout.OffsetInLayer,
			HeaderSize:    auxLayout.HeaderSize,
			Gating:        auxLayout.Gating,
			FieldBitOff:   bitOff,
			FieldBitWidth: bitWidth,
		},
	}, nil
}

// lookupByQualifier resolves a name to a layer. User labels and
// auto-indexed keys live in r.labels; a bare protocol name resolves
// only when there is exactly one instance of that protocol.
func (r *resolver) lookupByQualifier(name string, pos ast.Position) (*ir.LayerInstance, error) {
	if li, ok := r.labels[name]; ok {
		return li, nil
	}
	var found *ir.LayerInstance
	count := 0
	for _, li := range r.flatLayers {
		if li.Spec != nil && li.Spec.Name == name {
			found = li
			count++
		}
	}
	switch count {
	case 0:
		return nil, errorf(pos, "unknown label or protocol %q", name)
	case 1:
		return found, nil
	}
	return nil, errorf(pos, "protocol %q is ambiguous (%d instances); qualify with an @label", name, count)
}
