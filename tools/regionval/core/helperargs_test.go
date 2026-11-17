package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestHelperArgsMatchChecker compares helperArgs with pkg/injectcheck's
// independent helperReads table, read from its source: a switch whose cases
// list asm.FnX constants and return a mask of asm.Rn bits, 0, or argRegs
// (r1-r5) by default. For every helper id both must give the same read set:
// a register one of them drops, the other may say is read. The FnX names are
// matched to ids through the helper names in helperargs_gen.go.
func TestHelperArgsMatchChecker(t *testing.T) {
	gen, err := os.ReadFile("helperargs_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int32{} // FnX -> id
	rows := regexp.MustCompile(`(?m)^\s*\d+:`).FindAllIndex(gen, -1)
	for _, m := range regexp.MustCompile(`(?m)^\s*(\d+):\s*\d,\s*// (\w+)$`).FindAllStringSubmatch(string(gen), -1) {
		id, _ := strconv.Atoi(m[1])
		name := "Fn"
		for _, w := range strings.Split(m[2], "_") {
			name += strings.ToUpper(w[:1]) + w[1:]
		}
		ids[name] = int32(id)
	}
	if len(rows) != 211 || len(ids) != 211 || len(helperArgs) != 211 {
		t.Fatalf("%d rows, %d of them parsed, and %d entries in helperArgs, want 211", len(rows), len(ids), len(helperArgs))
	}

	f, err := parser.ParseFile(token.NewFileSet(), "../../../pkg/injectcheck/helpers.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "helperReads" {
			fn = d
		}
	}
	if fn == nil {
		t.Fatal("pkg/injectcheck/helpers.go has no func helperReads")
	}
	reads := map[int32]int{} // id -> registers read, r1 to rN
	def, names := -1, 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		var ret *ast.ReturnStmt
		if len(c.Body) == 1 {
			ret, _ = c.Body[0].(*ast.ReturnStmt)
		}
		if ret == nil || len(ret.Results) != 1 {
			t.Fatalf("case at %v: want one return of one value", c.Pos())
		}
		k := countRegs(t, ret.Results[0])
		if c.List == nil {
			def = k
		}
		for _, e := range c.List {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				t.Fatalf("case at %v: want asm.FnX, got %T", c.Pos(), e)
			}
			id, ok := ids[sel.Sel.Name]
			if !ok {
				t.Fatalf("helperReads names %s, which helperargs_gen.go has no row for", sel.Sel.Name)
			}
			if _, dup := reads[id]; dup {
				t.Fatalf("helperReads names %s twice", sel.Sel.Name)
			}
			reads[id] = k
			names++
		}
		return false
	})
	if def != 5 || len(reads) == 0 || names != len(reads) {
		t.Fatalf("helperReads: default reads %d registers, %d case names, %d ids; want 5 and a switch", def, names, len(reads))
	}
	for id := int32(0); id <= 211; id++ {
		got, ok := reads[id]
		if !ok {
			got = def
		}
		want, ok := helperArgs[id]
		if !ok {
			want = 5
		}
		if got != want {
			t.Errorf("helper %d: helperReads reads r1-r%d, helperArgs r1-r%d", id, got, want)
		}
	}
}

// countRegs returns N for a helperReads result that is a mask of r1 to rN.
func countRegs(t *testing.T, e ast.Expr) int {
	if id, ok := e.(*ast.Ident); ok && id.Name == "argRegs" {
		return 5
	}
	if l, ok := e.(*ast.BasicLit); ok && l.Value == "0" {
		return 0
	}
	var regs []int
	ast.Inspect(e, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			r, err := strconv.Atoi(strings.TrimPrefix(s.Sel.Name, "R"))
			if err != nil {
				t.Fatalf("unexpected %s in a helperReads mask", s.Sel.Name)
			}
			regs = append(regs, r)
			return false
		}
		return true
	})
	for i, r := range regs {
		if r != i+1 {
			t.Fatalf("helperReads mask %v is not r1 to rN", regs)
		}
	}
	return len(regs)
}
