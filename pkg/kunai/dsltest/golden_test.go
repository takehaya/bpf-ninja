package dsltest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// The bytecode golden pins what codegen emits for every filter the spec
// vectors compile, plus a curated list: a refactor must leave
// testdata/golden untouched, and a change that means to move bytecode
// regenerates it (`make golden-update`) so the diff shows which filters
// moved. The manifest holds a hash per filter; the curated filters are
// also kept as full text, which is the part a reviewer reads. `make
// golden-diff GOLDEN_BASE=main` prints the full-text diff of every
// filter.
var (
	goldenUpdate = flag.Bool("update", false, "rewrite testdata/golden from the current codegen")
	goldenDump   = flag.String("golden-dump", "", "write every golden filter's canonical text into this directory")
)

const (
	goldenDir      = "testdata/golden"
	goldenManifest = "testdata/golden/manifest.tsv"
)

// goldenCurated are kept as full text. F01-F10 are the evaluation filter
// set (internal/program FilterSet) and T01-T15 the tc load matrix
// (internal/program dslTCEntryExprs), copied because test variables of
// another package cannot be imported; N01-N02 and S01 add a netfilter
// host with its warning and set-key extractions.
var goldenCurated = []struct {
	name, host, expr string
	sets             []specSet
}{
	{"F01", "xdp_entry", "eth/ipv4/tcp where tcp.dport == 443", nil},
	{"F02", "xdp_entry", "eth/ipv4[src==10.0.0.0/8]/tcp where tcp.dport == 80", nil},
	{"F03", "xdp_entry", "eth/ipv6[src==2001:db8::/32]/tcp", nil},
	{"F04", "xdp_entry", "eth/vlan[tci==100]/ipv4/tcp where tcp.dport == 80", nil},
	{"F05", "xdp_entry", "eth/qinq/vlan/ipv4/tcp where tcp.dport == 80", nil},
	{"F06", "xdp_entry", "eth/ipv4/icmp where icmp.type == 8", nil},
	{"F07", "xdp_entry", "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where inner.dst == 10.0.0.1", nil},
	{"F08", "xdp_entry", "eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)", nil},
	{"F09", "xdp_entry", "eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp where inner.dst == 10.0.0.1", nil},
	{"F10", "xdp_entry", "eth/ipv4/tcp where tcp.options.MSS.value == 1460", nil},
	{"T01", "tc_entry", "eth/ipv4+/tcp", nil},
	{"T02", "tc_entry", "eth/ipv4/tcp", nil},
	{"T03", "tc_entry", "eth/ipv4{1,2}/tcp", nil},
	{"T04", "tc_entry", "eth/ipv4/udp", nil},
	{"T05", "tc_entry", "eth/ipv6/tcp", nil},
	{"T06", "tc_entry", "eth/ipv4/tcp[dport==443]", nil},
	{"T07", "tc_entry", "eth/ipv4/tcp where tcp.dport == 443", nil},
	{"T08", "tc_entry", "eth/ipv4/tcp capture headers+64", nil},
	{"T09", "tc_entry", "eth/(ipv4|ipv6)/tcp", nil},
	{"T10", "tc_entry", "eth/mpls+/ipv4/tcp", nil},
	{"T11", "tc_entry", "eth/ipv4/ipv4/tcp", nil},
	{"T12", "tc_entry", "eth/ipv4/udp/gtp/ipv4/tcp", nil},
	{"T13", "tc_entry", "eth/ipv6/srv6/tcp", nil},
	{"T14", "tc_entry", "eth/ipv4/tcp where tcp.options.MSS.value == 1460", nil},
	{"T15", "tc_entry", "eth/ipv4/tcp where any(ipv4.options.RR.addrs.addr == 192.168.0.0/16)", nil},
	{"N01", "netfilter_entry", "ipv4/tcp where tcp.dport == 443", nil},
	{"N02", "netfilter_entry", "eth/ipv4/tcp", nil},
	{"S01", "xdp_entry", "eth/ipv4[src in @hosts]/tcp[dport in @ports]", []specSet{{Name: "hosts", Width: 32}, {Name: "ports", Width: 16}}},
	// A static chain emits its predicates once per header; their labels
	// must stay distinct.
	{"L01", "xdp_entry", "eth/mpls[label in [1..5, 100]]{1,3}/ipv4", nil},
	{"L02", "xdp_entry", "eth/mpls[label in [1..5, 100]]+/ipv4", nil},
}

type goldenFilter struct {
	host, expr string
	sets       []specSet
	curated    string // file name stem, "" for manifest-only filters
}

// setsText spells the declared sets by name and key width, all codegen
// sees of them: members only matter to the host's lookup.
func (g goldenFilter) setsText() string {
	if len(g.sets) == 0 {
		return "-"
	}
	parts := make([]string, len(g.sets))
	for i, d := range g.sets {
		parts[i] = fmt.Sprintf("%s:%d", d.Name, d.Width)
	}
	return strings.Join(parts, ",")
}

func (g goldenFilter) key() string { return g.host + "\t" + g.expr + "\t" + g.setsText() }

// goldenCorpus is every (host, expr, sets) a spec vector expects to
// compile, plus the curated filters, sorted by key. A curated filter the
// vectors also hold keeps its file name.
func goldenCorpus(t *testing.T) []goldenFilter {
	t.Helper()
	byKey := map[string]goldenFilter{}
	for _, v := range loadSpecVectors(t) {
		if v.GoStatus != "ok" || v.Expected.Kind == "illTyped" {
			continue
		}
		g := goldenFilter{host: v.Host, expr: v.Expr, sets: v.Sets}
		byKey[g.key()] = g
	}
	for _, c := range goldenCurated {
		g := goldenFilter{host: c.host, expr: c.expr, sets: c.sets, curated: c.name}
		byKey[g.key()] = g
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]goldenFilter, len(keys))
	for i, k := range keys {
		out[i] = byKey[k]
	}
	return out
}

func compileGolden(g goldenFilter) (codegen.Output, error) {
	caps := specHostCaps[g.host]()
	caps.Lang.SetSlots = newSpecSetSlots(g.sets)
	return kunai.Compile(g.expr, caps)
}

var trailingSpace = regexp.MustCompile(`(?m)[ \t]+$`)

// goldenText is the canonical text of one compiled filter: code is the
// instructions and the BTF functions they declare, meta everything else
// the host consumes.
func goldenText(out codegen.Output) (code, meta string) {
	var c strings.Builder
	fmt.Fprintf(&c, "== Main\n%v== Callbacks\n%v== Funcs\n", out.Main, out.Callbacks)
	for i, ins := range out.Instructions() {
		if fn := btf.FuncMetadata(&ins); fn != nil {
			fmt.Fprintf(&c, "%d: %s\n", i, fn.Name)
		}
	}
	// cilium/ebpf leaves a space after some mnemonics; the repository's
	// hooks strip trailing whitespace, so the golden has none.
	code = trailingSpace.ReplaceAllString(c.String(), "")
	var m strings.Builder
	fmt.Fprintf(&m, "== Capture MaxCapLen=%d FilterMinPrefix=%d\n", out.Capture.MaxCapLen, out.Capture.FilterMinPrefix)
	fmt.Fprintf(&m, "== WireFrame %t\n== Extractions\n", out.WireFrame)
	for _, e := range out.Extractions {
		fmt.Fprintf(&m, "%s %s off=%d size=%d\n", e.SetName, e.FieldName, e.StackOff, e.StoreSize)
	}
	m.WriteString("== Warnings\n")
	for _, w := range out.Warnings {
		m.WriteString(w + "\n")
	}
	return code, m.String()
}

func goldenHeader(g goldenFilter) string {
	return fmt.Sprintf("# host: %s\n# expr: %s\n# sets: %s\n", g.host, g.expr, g.setsText())
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func manifestValue(out codegen.Output, code, meta string) string {
	return fmt.Sprintf("code=%s meta=%s main=%d cb=%d", shortHash(code), shortHash(meta), len(out.Main), len(out.Callbacks))
}

// readManifest maps each manifest key (host, expr, sets) to its value;
// nil when the file does not exist.
func readManifest(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(goldenManifest)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("open %s: %v", goldenManifest, err)
	}
	defer func() { _ = f.Close() }()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		i := strings.LastIndexByte(line, '\t')
		if i < 0 {
			t.Fatalf("%s: malformed line %q", goldenManifest, line)
		}
		if _, dup := m[line[:i]]; dup {
			t.Errorf("%s: %q is listed twice", goldenManifest, line[:i])
		}
		m[line[:i]] = line[i+1:]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", goldenManifest, err)
	}
	return m
}

// firstDiff renders a few lines around the first line where got and want
// differ.
func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	i := 0
	for i < len(w) && i < len(g) && w[i] == g[i] {
		i++
	}
	lo := max(i-3, 0)
	var b strings.Builder
	fmt.Fprintf(&b, "first difference at line %d\n", i+1)
	for j := lo; j < i+6; j++ {
		switch {
		case j < len(w) && j < len(g) && w[j] == g[j]:
			fmt.Fprintf(&b, "  %s\n", w[j])
		default:
			if j < len(w) {
				fmt.Fprintf(&b, "- %s\n", w[j])
			}
			if j < len(g) {
				fmt.Fprintf(&b, "+ %s\n", g[j])
			}
		}
	}
	return b.String()
}

var dumpNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9.@-]+`)

// dumpName names a filter's file under -golden-dump: the curated stem, or
// the host and a readable prefix of the expression, with a hash of the
// key so names stay unique.
func dumpName(g goldenFilter) string {
	if g.curated != "" {
		return g.curated + ".asm"
	}
	expr := dumpNameUnsafe.ReplaceAllString(g.expr, "_")
	if len(expr) > 60 {
		expr = expr[:60]
	}
	return fmt.Sprintf("%s_%s_%s.asm", g.host, expr, shortHash(g.key())[:8])
}

// changedPart names which hash of a manifest value moved.
func changedPart(old, cur string) string {
	field := func(v, name string) string {
		for _, f := range strings.Fields(v) {
			if strings.HasPrefix(f, name+"=") {
				return f
			}
		}
		return ""
	}
	var parts []string
	for _, name := range []string{"code", "meta"} {
		if field(old, name) != field(cur, name) {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, "+")
}

// TestGolden compares codegen's output with testdata/golden. It compiles
// every filter twice and fails if the two texts differ, which would make
// the golden meaningless; label names are compared as emitted, so a label
// numbered from process-wide state fails here. With -update it rewrites
// the golden and prints the filters that moved; with -golden-dump it only
// writes every filter's text into the directory (make golden-diff
// compares two such dumps).
func TestGolden(t *testing.T) {
	// goldenText must cover every field the host reads.
	if n := reflect.TypeFor[codegen.Output]().NumField(); n != 6 {
		t.Fatalf("codegen.Output has %d fields; render the new one in goldenText and update this count", n)
	}
	corpus := goldenCorpus(t)
	want := readManifest(t)
	check := !*goldenUpdate && *goldenDump == ""
	if check && want == nil {
		t.Fatalf("%s is missing; run `make golden-update`", goldenManifest)
	}
	var manifest strings.Builder
	var moved []string
	curated := map[string]bool{}
	for _, g := range corpus {
		old, listed := want[g.key()]
		delete(want, g.key())
		out, err := compileGolden(g)
		if err != nil {
			t.Errorf("%s %q (sets %s): compile: %v", g.host, g.expr, g.setsText(), err)
			continue
		}
		code, meta := goldenText(out)
		again, err := compileGolden(g)
		if err != nil {
			t.Fatalf("%s %q: second compile: %v", g.host, g.expr, err)
		}
		if code2, meta2 := goldenText(again); code2 != code || meta2 != meta {
			t.Errorf("%s %q: two compiles differ, codegen is not deterministic\n%s", g.host, g.expr, firstDiff(code+meta, code2+meta2))
		}
		text := goldenHeader(g) + code + meta
		value := manifestValue(out, code, meta)
		manifest.WriteString(g.key() + "\t" + value + "\n")
		if *goldenDump != "" {
			if err := os.MkdirAll(*goldenDump, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(*goldenDump, dumpName(g)), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		switch {
		case *goldenUpdate && !listed:
			moved = append(moved, fmt.Sprintf("new   %s %q (sets %s): %s", g.host, g.expr, g.setsText(), value))
		case *goldenUpdate && old != value:
			moved = append(moved, fmt.Sprintf("%-5s %s %q (sets %s): %s -> %s", changedPart(old, value), g.host, g.expr, g.setsText(), old, value))
		case check && !listed:
			t.Errorf("%s %q (sets %s) is not in %s; run `make golden-update`", g.host, g.expr, g.setsText(), goldenManifest)
		case check && old != value:
			t.Errorf("%s %q (sets %s) changed (%s): %s -> %s; if intended, run `make golden-update` (`make golden-diff` shows the text)\nmeta now:\n%s",
				g.host, g.expr, g.setsText(), changedPart(old, value), old, value, meta)
		}
		if g.curated == "" {
			continue
		}
		curated[g.curated+".asm"] = true
		path := filepath.Join(goldenDir, g.curated+".asm")
		if *goldenUpdate {
			if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		} else if old, err := os.ReadFile(path); err != nil {
			t.Errorf("%s: %v (run `make golden-update`)", path, err)
		} else if string(old) != text {
			t.Errorf("%s (%s %q) changed; if intended, run `make golden-update`\n%s", path, g.host, g.expr, firstDiff(string(old), text))
		}
	}
	if *goldenDump != "" {
		return
	}
	for k := range want {
		if *goldenUpdate {
			fmt.Printf("gone  %s\n", strings.ReplaceAll(k, "\t", " "))
		} else {
			t.Errorf("%s lists %q, which no spec vector or curated filter compiles; run `make golden-update`", goldenManifest, k)
		}
	}
	files, err := filepath.Glob(filepath.Join(goldenDir, "*.asm"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if curated[filepath.Base(f)] {
			continue
		}
		if *goldenUpdate {
			if err := os.Remove(f); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Errorf("%s belongs to no curated filter; run `make golden-update`", f)
		}
	}
	if *goldenUpdate {
		if err := os.WriteFile(goldenManifest, []byte(manifest.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("golden: %d filters, %d moved or new\n", len(corpus), len(moved))
		for _, m := range moved {
			fmt.Println(m)
		}
	}
}
