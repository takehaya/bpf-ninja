package dsltest

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/ast"
	"github.com/takehaya/bpf-ninja/pkg/kunai/parser"
)

// specVectorsPath is written by `make lean-gen` from spec/lean.
const specVectorsPath = "testdata/spec_vectors.json"

// specVector mirrors spec/lean/Kunai/Vectors.lean (Vector.toJson).
// Fields the Go side does not use are left out; encoding/json skips them.
type specVector struct {
	ID       string          `json:"id"`
	Expr     string          `json:"expr"`
	AST      json.RawMessage `json:"ast"`
	Host     string          `json:"host"`
	Action   int64           `json:"action"`
	Packet   string          `json:"packet"` // hex
	Expected specResult      `json:"expected"`
	GoStatus string          `json:"goStatus"` // ok | notImplemented | mismatch
	Note     string          `json:"note"`
}

type specResult struct {
	Kind     string     `json:"kind"` // accept | reject | illTyped
	Captures [][2]int64 `json:"captures"`
	Reason   string     `json:"reason"`
}

// specVectorsGenPath holds mutations of the golden vectors (`gen --generated`).
const specVectorsGenPath = "testdata/spec_vectors_gen.json"

func loadSpecVectors(t testing.TB) []specVector { return loadSpecVectorsFrom(t, specVectorsPath) }

func loadSpecVectorsFrom(t testing.TB, path string) []specVector {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run `make lean-gen`)", path, err)
	}
	var vs []specVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return vs
}

// TestSpecASTRoundTrip checks that the Lean printer and the Go parser
// agree: Parse(expr) re-encoded with the Go mirror of Json.lean must equal
// the AST Lean serialised. Runs without root.
func TestSpecASTRoundTrip(t *testing.T) {
	for _, v := range loadSpecVectors(t) {
		if len(v.AST) == 0 {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			f, err := parser.Parse(v.Expr, "", nil)
			if err != nil {
				t.Fatalf("parse %q: %v", v.Expr, err)
			}
			got := normalizeJSON(t, encFilter(f))
			want := normalizeJSON(t, v.AST)
			if !reflect.DeepEqual(got, want) {
				g, _ := json.Marshal(got)
				w, _ := json.Marshal(want)
				t.Fatalf("AST mismatch for %q\n go:   %s\n lean: %s", v.Expr, g, w)
			}
		})
	}
}

// normalizeJSON round-trips any value through encoding/json so that both
// sides compare as the same generic shape (float64 numbers, nil, maps).
func normalizeJSON(t testing.TB, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// --- Go mirror of spec/lean/Kunai/Json.lean -------------------------------

type obj = map[string]any

func u64(v uint64) string { return strconv.FormatUint(v, 10) }

func encFilter(f *ast.Filter) obj {
	return obj{"layers": encLayers(f.Layers), "where": encWhereOpt(f.Where), "captures": encCaptures(f.Captures)}
}

func encLayers(ls []*ast.Layer) []any {
	out := make([]any, 0, len(ls))
	for _, l := range ls {
		out = append(out, encLayer(l))
	}
	return out
}

func encLayer(l *ast.Layer) obj {
	if l.Kind == ast.LayerAltGroup {
		return obj{"kind": "alt", "alts": encLayers(l.Alternatives)}
	}
	var label any
	if l.Label != "" {
		label = l.Label
	}
	preds := make([]any, 0, len(l.Predicates))
	for _, p := range l.Predicates {
		preds = append(preds, encPred(p))
	}
	return obj{"kind": "proto", "name": l.ProtoName, "label": label, "preds": preds, "quant": encQuant(l)}
}

func encQuant(l *ast.Layer) obj {
	switch l.Quant {
	case ast.QuantOpt:
		return obj{"kind": "opt"}
	case ast.QuantPlus:
		return obj{"kind": "plus"}
	case ast.QuantStar:
		return obj{"kind": "star"}
	case ast.QuantRange:
		var hi any
		if l.RangeMax >= 0 {
			hi = l.RangeMax
		}
		return obj{"kind": "range", "lo": l.RangeMin, "hi": hi}
	}
	return obj{"kind": "one"}
}

func encPred(p *ast.Predicate) obj {
	switch p.Kind {
	case ast.PredIn:
		vals := make([]any, 0, len(p.List))
		for _, v := range p.List {
			vals = append(vals, encValue(v))
		}
		return obj{"kind": "in", "field": encField(p.Field), "values": vals}
	case ast.PredInSet:
		return obj{"kind": "inSet", "field": encField(p.Field), "set": p.SetName}
	case ast.PredHas:
		return obj{"kind": "has", "field": encField(p.Field), "flag": p.FlagName}
	}
	return obj{"kind": "cmp", "field": encField(p.Field), "op": cmpOpText(p.Op), "value": encValue(p.Value)}
}

func encField(f *ast.FieldPath) obj {
	parts := make([]any, 0, len(f.Parts))
	for i, name := range f.Parts {
		var idx any
		if i < len(f.Indices) && f.Indices[i] != nil {
			idx = encIndex(f.Indices[i])
		}
		parts = append(parts, obj{"name": name, "index": idx})
	}
	return obj{"parts": parts}
}

func encIndex(e *ast.IndexExpr) obj {
	switch {
	case e.IsSlice:
		return obj{"kind": "slice", "lo": u64(e.SliceLo), "hi": u64(e.SliceHi)}
	case e.IsInt:
		return obj{"kind": "int", "value": u64(e.Int)}
	}
	parts := make([]any, 0, len(e.Field.Parts))
	for _, p := range e.Field.Parts {
		parts = append(parts, p)
	}
	return obj{"kind": "field", "parts": parts}
}

func encValue(v *ast.Value) obj {
	switch v.Kind {
	case ast.ValIPv4:
		return obj{"kind": "ipv4", "value": ipv4Text(v.V4)}
	case ast.ValIPv6:
		return obj{"kind": "ipv6", "value": ipv6Text(v.V6)}
	case ast.ValMAC:
		return obj{"kind": "mac", "value": macText(v.MAC)}
	case ast.ValCIDR:
		addr := ipv6Text(v.V6)
		if v.AF == 4 {
			addr = ipv4Text(v.V4)
		}
		return obj{"kind": "cidr", "value": addr + "/" + strconv.Itoa(v.Prefix)}
	case ast.ValRange:
		return obj{"kind": "range", "lo": u64(v.RangeLo), "hi": u64(v.RangeHi)}
	case ast.ValIdent:
		return obj{"kind": "ident", "value": v.Ident}
	case ast.ValString:
		return obj{"kind": "string", "value": v.Str}
	}
	return obj{"kind": "int", "value": u64(v.Int), "negative": v.Negative}
}

func ipv4Text(b [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// ipv6Text prints eight 4-digit groups, never compressed, like Print.lean.
func ipv6Text(b [16]byte) string {
	s := ""
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			s += ":"
		}
		s += fmt.Sprintf("%02x%02x", b[i], b[i+1])
	}
	return s
}

func macText(b [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func cmpOpText(op ast.CmpOp) string {
	return [...]string{ast.CmpEq: "==", ast.CmpNeq: "!=", ast.CmpLt: "<", ast.CmpLe: "<=", ast.CmpGt: ">", ast.CmpGe: ">="}[op]
}

func arithOpText(op ast.ArithOp) string {
	return [...]string{ast.ArithAdd: "+", ast.ArithSub: "-", ast.ArithMul: "*", ast.ArithDiv: "/", ast.ArithMod: "%",
		ast.ArithAnd: "&", ast.ArithOr: "|", ast.ArithXor: "^", ast.ArithShl: "<<", ast.ArithShr: ">>"}[op]
}

func encArith(e *ast.ArithExpr) obj {
	switch e.Kind {
	case ast.ArithField:
		return obj{"kind": "field", "field": encField(e.Field)}
	case ast.ArithBinOp:
		return obj{"kind": "bin", "op": arithOpText(e.Op), "left": encArith(e.Left), "right": encArith(e.Right)}
	}
	return obj{"kind": "const", "value": u64(e.Const), "negative": e.Negative}
}

func encWhereOpt(w *ast.WhereExpr) any {
	if w == nil {
		return nil
	}
	return encWhere(w)
}

func encWhere(w *ast.WhereExpr) obj {
	switch w.Kind {
	case ast.WOr:
		return obj{"kind": "or", "left": encWhere(w.Left), "right": encWhere(w.Right)}
	case ast.WAnd:
		return obj{"kind": "and", "left": encWhere(w.Left), "right": encWhere(w.Right)}
	case ast.WNot:
		return obj{"kind": "not", "inner": encWhere(w.Inner)}
	case ast.WAtomArith:
		return obj{"kind": "arith", "left": encArith(w.ArithL), "op": cmpOpText(w.Op), "right": encArith(w.ArithR)}
	case ast.WAtomLiteralCmp:
		return obj{"kind": "litCmp", "field": encField(w.LiteralField), "op": cmpOpText(w.LiteralOp), "value": encValue(w.LiteralValue)}
	case ast.WAtomAction:
		return obj{"kind": "action", "value": w.ActionValue}
	case ast.WAny:
		return obj{"kind": "any", "inner": encWhere(w.Inner)}
	case ast.WAll:
		return obj{"kind": "all", "inner": encWhere(w.Inner)}
	case ast.WAtomBoolLit:
		return obj{"kind": "bool", "value": w.BoolLitValue}
	case ast.WAtomBoolExists:
		return obj{"kind": "exists", "field": encField(w.BoolField)}
	case ast.WAtomBoolEq:
		return obj{"kind": "boolEq", "left": encWhere(w.BoolL), "op": cmpOpText(w.BoolEqOp), "right": encWhere(w.BoolR)}
	}
	return obj{"kind": fmt.Sprintf("WhereKind(%d)", w.Kind)}
}

func encCaptures(cs []*ast.CaptureClause) []any {
	out := make([]any, 0, len(cs))
	for _, c := range cs {
		out = append(out, obj{"spec": encCaptureSpec(c), "where": encWhereOpt(c.Where)})
	}
	return out
}

func encCaptureSpec(c *ast.CaptureClause) obj {
	switch c.Kind {
	case ast.CapAll:
		return obj{"kind": "all"}
	case ast.CapHeaders:
		return obj{"kind": "headers"}
	case ast.CapHeadersPlus:
		return obj{"kind": "headersPlus", "extra": c.Extra}
	case ast.CapToLayer:
		return obj{"kind": "toLayer", "layer": c.LayerName, "extra": c.Extra}
	case ast.CapAbsolute:
		return obj{"kind": "absolute", "extra": c.Extra}
	}
	return obj{"kind": "fields"}
}
