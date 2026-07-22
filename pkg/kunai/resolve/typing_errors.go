package resolve

import (
	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/ir"
)

// typing_errors.go centralises the diagnostic messages produced by the
// type-system checks (docs/ja/dsl-types.md §8). Keeping the format in
// one place makes it cheap to keep error wording consistent and makes
// substring-based test fixtures less brittle than scattered fmt
// calls.

// errFitInField is the bracket-predicate / where-literal-cmp variant:
// the field name is known, so we surface "<field>" in the message to
// help the user spot which side of the comparison overflows.
func errFitInField(pos ast.Position, value uint64, bits int, protoName, fieldName string) error {
	return errorf(pos, "value %d does not fit in %d-bit field %s.%s", value, bits, protoName, fieldName)
}

// errFitInArith is the where-clause arithmetic variant: target width
// is derived from the surrounding arith expression rather than a
// specific field, so we identify the arithmetic context instead.
func errFitInArith(pos ast.Position, value uint64, bits int) error {
	return errorf(pos, "value %d does not fit in bit<%d> (in arithmetic context)", value, bits)
}

// errStaticDivZero reports a literal `0` divisor on `/` or `%`.
func errStaticDivZero(pos ast.Position, op ast.ArithOp) error {
	name := "division"
	if op == ast.ArithMod {
		name = "modulo"
	}
	return errorf(pos, "%s by zero", name)
}

// errLiteralFieldShape covers `<network-literal> ⨀ <field>` where the
// field's declared width does not match the literal's natural shape
// (IPv4=32, IPv6=128, MAC=48, CIDR4=32, CIDR6=128). The field
// reference carries the layer + field metadata that frame the
// diagnostic.
func errLiteralFieldShape(pos ast.Position, kindLabel string, want int, ref *ir.FieldRef) error {
	return errorf(pos, "%s literal needs a bit<%d> field; %s.%s is bit<%d>", kindLabel, want, ref.Layer.Spec.Name, ref.Field.Name, ref.Field.Bits)
}

// errUnknownActionLiteral fires when a where clause names an XDP_*
// symbol that is not in caps.Action. The host-supplied keyset is
// stable per Compile, so we only emit the count rather than echoing
// every entry.
func errUnknownActionLiteral(pos ast.Position, name string, accepted int) error {
	return errorf(pos, "unknown action %q (host accepts %d symbols)", name, accepted)
}

// errOrderedNotAllowed reports an ordered comparison (<, ≤, >, ≥) on
// a kind that lacks a natural total order — Bool, CIDR, Action.
// dsl-types.md §6.2 forbids these. Used by the resolver to mirror
// the parser-side reject for defence in depth.
func errOrderedNotAllowed(pos ast.Position, op ast.CmpOp, kind string) error {
	return errorf(pos, "ordered comparison %s not allowed for %s (%s supports only == and !=)", op, kind, kind)
}

// errArithOverflowSuspect reports an F1 strict-arith violation:
// two-field `+` / `*` whose result almost certainly wraps at the
// field's natural width. Only fires under
// resolve.Options.StrictArithLint.
func errArithOverflowSuspect(pos ast.Position, op ast.ArithOp) error {
	return errorf(pos, "arith %s on two field operands likely overflows the result width (StrictArithLint); cast or rewrite to make the wrap intent explicit", op)
}

// errArithUnderflowSuspect reports an F1 strict-arith violation
// for `field - field` where the RHS is at least as wide as the LHS,
// so the result can underflow into the high bits.
func errArithUnderflowSuspect(pos ast.Position, lhsBits, rhsBits int) error {
	return errorf(pos, "arith - on two field operands (LHS bit<%d>, RHS bit<%d>) likely underflows: RHS is at least as wide as LHS (StrictArithLint)", lhsBits, rhsBits)
}

// errBareIdentValue rejects a bare identifier on the RHS of a
// bracket predicate (e.g. `tcp[dport == true]`,
// `tcp[dport == port]`). Predicate values are restricted to typed
// literals; the previous codegen-side "predicate value type ident"
// ErrNotImplemented was a typing violation, not a missing emit, so
// it surfaces here as a resolver-level error with a position pointing
// at the offending value.
func errBareIdentValue(pos ast.Position, ident string) error {
	return errorf(pos, "predicate value cannot be a bare identifier %q. predicate values must be integer/IPv4/IPv6/MAC/CIDR/range literal. for boolean coercion of an integer field, use 'where <proto>.<field> != 0'", ident)
}
