package kunai

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	tchost "github.com/takehaya/bpf-ninja/pkg/kunai/host/tc"
)

// plusChain returns tcp.sport followed by n "+ k" terms: n arith binops
// nested n levels deep.
func plusChain(n int) string {
	var b strings.Builder
	b.WriteString("tcp.sport")
	for i := 1; i <= n; i++ {
		b.WriteString(" + ")
		b.WriteString(strconv.Itoa(i))
	}
	return b.String()
}

// boolEqNest wraps atom in d levels of `(x) == (tcp.dport == 80)`.
func boolEqNest(atom string, d int) string {
	s := atom
	for range d {
		s = "(" + s + ") == (tcp.dport == 80)"
	}
	return s
}

// keySlotCaps declares one set @k whose every key field is width bytes.
func keySlotCaps(width int) func() codegen.Capabilities {
	return func() codegen.Capabilities {
		return codegen.Capabilities{Lang: codegen.LangCaps{SetSlots: keySlots{width}}}
	}
}

type keySlots struct{ width int }

func (keySlots) HasSet(name string) bool { return name == "k" }
func (s keySlots) SlotFor(set, field string) (int16, int, bool) {
	return -40, s.width, set == "k"
}

// TestNotImplementedBoundaries pins the documented limits that refuse a
// well-typed filter with codegen.ErrNotImplemented, each next to the
// shape one step inside the limit, so a doc boundary is tested on both
// sides. want is a substring of the refusal; "" means the filter compiles.
func TestNotImplementedBoundaries(t *testing.T) {
	cases := []struct {
		name string
		expr string
		caps func() codegen.Capabilities
		want string
		doc  string
	}{
		// dsl-usage.md 演算子, dsl-grammar.md: arithmetic nests 16 levels.
		{"arith-depth-17", "eth/ipv4/tcp where " + plusChain(17) + " == 100", nil, "nested deeper than 16 levels", "dsl-usage.md 演算子"},
		{"arith-depth-16", "eth/ipv4/tcp where " + plusChain(16) + " == 100", nil, "", "dsl-usage.md 演算子"},
		{"arith-both-sides-16", "eth/ipv4/tcp where " + plusChain(16) + " == " + plusChain(16), nil, "both sides of the comparison nest 16 levels", "dsl-usage.md 演算子"},
		{"arith-sides-16-15", "eth/ipv4/tcp where " + plusChain(16) + " == " + plusChain(15), nil, "", "dsl-usage.md 演算子"},
		// Each enclosing Bool == Bool costs one level.
		{"arith-depth-16-in-bool-eq", "eth/ipv4/tcp where (" + plusChain(16) + " == 100) == (tcp.dport == 80)", nil, "nested deeper than 15 levels", "dsl-usage.md 演算子"},
		{"arith-depth-15-in-bool-eq", "eth/ipv4/tcp where (" + plusChain(15) + " == 100) == (tcp.dport == 80)", nil, "", "dsl-usage.md 演算子"},
		{"bool-eq-depth-12", "eth/ipv4/tcp where " + boolEqNest("tcp.dport == 80", 12), nil, "bool-eq nested deeper than 11 levels", "dsl-usage.md 演算子"},
		{"bool-eq-depth-11", "eth/ipv4/tcp where " + boolEqNest("tcp.dport == 80", 11), nil, "", "dsl-usage.md 演算子"},
		// dsl-types.md 8.8 and the slice table: a 65-127-bit slice compares
		// only against a slice of the same width.
		{"slice-72-arith", "eth/ipv6/tcp where ipv6.dst[0:72] + 1 == 1", nil, "same width", "dsl-types.md 8.8"},
		{"slice-96-const", "eth/ipv6/tcp where ipv6.src[0:96] == 1", nil, "same width", "dsl-types.md slice"},
		{"slice-96-slice", "eth/ipv6/tcp where ipv6.src[0:96] == ipv6.dst[0:96]", nil, "", "dsl-types.md slice"},
		{"slice-128-const", "eth/ipv6/tcp where ipv6.src[0:128] == 1", nil, "", "dsl-types.md slice"},
		{"slice-128-wide-const", "eth/ipv6/tcp where ipv6.src[0:128] == int<128>(1)", nil, "", "dsl-types.md slice"},
		{"slice-128-field", "eth/ipv6/tcp where ipv6.src[0:128] == ipv6.dst", nil, "", "dsl-types.md slice"},
		{"slice-128-ordered", "eth/ipv6/tcp where ipv6.src[0:128] < ipv6.dst[0:128]", nil, "", "dsl-types.md slice"},
		{"slice-128-arith", "eth/ipv6/tcp where ipv6.src[0:128] + 1 == 1", nil, "", "dsl-types.md slice"},
		{"aux-slice-128-const", "eth/ipv6/srv6/tcp where srv6.segments[0].addr[0:128] == 1", nil, "", "dsl-types.md slice"},
		{"aux-dynamic-slice-128-arith", "eth/ipv6/srv6/tcp where srv6.segments[srv6.last_entry].addr[0:128] + 1 == 1", nil, "", "dsl-types.md slice"},
		{"aux-dynamic-slice-128-const", "eth/ipv6/srv6/tcp where srv6.segments[srv6.last_entry].addr[0:128] == 1", nil, "", "dsl-types.md slice"},
		{"aux-slice-96-plus-128", "eth/ipv6/srv6/tcp where srv6.segments[0].addr[0:96] + ipv6.dst == 1", nil, "srv6.segments[0].addr[0:96] (bit<96>) next to an Int<128> operand: a slice between 65 and 127 bits", "dsl-types.md 型表"},
		{"slice-128-slice", "eth/ipv6/tcp where ipv6.src[0:128] == ipv6.dst[0:128]", nil, "", "dsl-types.md slice"},
		{"field-128-const", "eth/ipv6/tcp where ipv6.src == 1", nil, "", "dsl-types.md slice"},
		{"slice-64-arith", "eth/ipv6/tcp where ipv6.src[64:128] + 1 == 1", nil, "", "dsl-types.md slice"},
		{"slice-96-plus-128", "eth/ipv6/tcp where ipv6.src[0:96] + ipv6.dst == 1", nil, "ipv6.src[0:96] (bit<96>) next to an Int<128> operand: a slice between 65 and 127 bits", "dsl-types.md 型表"},
		// dsl-usage.md capture: field lists are not implemented.
		{"capture-field-list", "eth/ipv4/tcp capture tcp.flags, ipv4.dst", nil, "field-list capture is not yet implemented", "dsl-usage.md capture"},
		// A slice of a field that starts off a byte boundary is not wired,
		// though the spec types it (in @set as for ==).
		{"inset-subbyte-field-slice", "eth/ipv6[traffic_class[0:4] in @k]/tcp", keySlotCaps(1), "not byte-aligned", "dsl-usage.md 集合"},
		{"inset-aux-six-byte-field", "eth/ipv6[exts[0]._opts in @k]/tcp", keySlotCaps(8), "a key window for it is not wired", "dsl-types.md 13.7"},
		{"inset-subbyte-field", "eth/ipv6[traffic_class in @k]/tcp", keySlotCaps(2), "", "dsl-usage.md 集合"},
		// A quantified machine layer unrolls to at most 8 machines.
		{"machine-range-9", "eth/ipv4{1,9}/tcp", nil, "unrolls to 9 parser machines, more than the 8 supported", "spec vector quant-machine-range-nine"},
		{"machine-range-8", "eth/ipv4{1,8}/tcp", nil, "", "spec vector quant-machine-range-nine"},
		// dsl-types.md 12: an optional outer tag compiles at tc, with
		// predicates and reads; only a mandatory one is ErrVlanInMetadata.
		{"tc-optional-vlan-read", "eth/vlan[tci == 100]?/ipv4/tcp where vlan.tci == 100", tchost.EntryCapabilities, "", "dsl-types.md 12"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			caps := codegen.Capabilities{}
			if c.caps != nil {
				caps = c.caps()
			}
			_, err := Compile(c.expr, caps)
			switch {
			case c.want == "" && err != nil:
				t.Errorf("Compile(%q) = %v; want success (%s)", c.expr, err, c.doc)
			case c.want != "" && (!errors.Is(err, codegen.ErrNotImplemented) || !strings.Contains(err.Error(), c.want)):
				t.Errorf("Compile(%q) = %v; want ErrNotImplemented containing %q (%s)", c.expr, err, c.want, c.doc)
			}
		})
	}
}

// docMarkerRe matches a fenced example line in the DSL docs that ends in
// a verdict marker.
var docMarkerRe = regexp.MustCompile(`^(\S.*?)\s+# (ErrNotImplemented|compile できる)\s*$`)

// TestDocMarkedDSLExamples compiles every line inside a code fence of
// docs/ja/dsl-*.md that ends in `# ErrNotImplemented` or `# compile できる`
// and checks the verdict, with no host capabilities. A doc author pins an
// example by appending the marker.
func TestDocMarkedDSLExamples(t *testing.T) {
	paths, err := filepath.Glob("../../docs/ja/dsl-*.md")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		inFence := false
		sc := bufio.NewScanner(f)
		for line := 1; sc.Scan(); line++ {
			text := sc.Text()
			if strings.HasPrefix(strings.TrimSpace(text), "```") {
				inFence = !inFence
				continue
			}
			m := docMarkerRe.FindStringSubmatch(text)
			if !inFence || m == nil {
				continue
			}
			found++
			_, err := compileForTest(m[1])
			where := filepath.Base(path) + ":" + strconv.Itoa(line)
			if m[2] == "ErrNotImplemented" {
				if !errors.Is(err, codegen.ErrNotImplemented) {
					t.Errorf("%s: Compile(%q) = %v; want ErrNotImplemented", where, m[1], err)
				}
			} else if err != nil {
				t.Errorf("%s: Compile(%q) = %v; want success", where, m[1], err)
			}
		}
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	if found == 0 {
		t.Fatal("no marked examples found in docs/ja/dsl-*.md")
	}
}
