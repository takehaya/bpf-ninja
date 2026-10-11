package dsltest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// The bytecode golden pins what codegen emits for every filter the spec
// vectors compile, plus a curated list: a refactor must leave
// testdata/golden untouched, and a change that means to move bytecode
// regenerates it (`make golden-update`) so the diff shows which filters
// moved. The manifest holds a hash per filter; the curated filters are
// also kept as full text, which is the part a reviewer reads. `make
// golden-diff BASE=main` prints the full-text diff of every filter.
var (
	goldenUpdate = flag.Bool("update", false, "rewrite testdata/golden from the current codegen")
	goldenDump   = flag.String("golden-dump", "", "write every golden filter's canonical text into this directory")
)

const (
	goldenDir      = "testdata/golden"
	goldenManifest = "testdata/golden/manifest.tsv"
)

// goldenCurated are kept as full text. F01-F10 are the evaluation filter
// set (internal/program FilterSet); T01-T15 the tc load matrix
// (internal/program dslTCEntryExprs).
var goldenCurated = []struct{ name, host, expr string }{
	{"F01", "xdp_entry", "eth/ipv4/tcp where tcp.dport == 443"},
	{"F02", "xdp_entry", "eth/ipv4[src==10.0.0.0/8]/tcp where tcp.dport == 80"},
	{"F03", "xdp_entry", "eth/ipv6[src==2001:db8::/32]/tcp"},
	{"F04", "xdp_entry", "eth/vlan[tci==100]/ipv4/tcp where tcp.dport == 80"},
	{"F05", "xdp_entry", "eth/qinq/vlan/ipv4/tcp where tcp.dport == 80"},
	{"F06", "xdp_entry", "eth/ipv4/icmp where icmp.type == 8"},
	{"F07", "xdp_entry", "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where inner.dst == 10.0.0.1"},
	{"F08", "xdp_entry", "eth/ipv6/srv6 where any(srv6.segments.addr == fc00::1)"},
	{"F09", "xdp_entry", "eth/ipv4@outer/udp/geneve/eth/ipv4@inner/tcp where inner.dst == 10.0.0.1"},
	{"F10", "xdp_entry", "eth/ipv4/tcp where tcp.options.MSS.value == 1460"},
	{"T01", "tc_entry", "eth/ipv4+/tcp"},
	{"T02", "tc_entry", "eth/ipv4/tcp"},
	{"T03", "tc_entry", "eth/ipv4{1,2}/tcp"},
	{"T04", "tc_entry", "eth/ipv4/udp"},
	{"T05", "tc_entry", "eth/ipv6/tcp"},
	{"T06", "tc_entry", "eth/ipv4/tcp[dport==443]"},
	{"T07", "tc_entry", "eth/ipv4/tcp where tcp.dport == 443"},
	{"T08", "tc_entry", "eth/ipv4/tcp capture headers+64"},
	{"T09", "tc_entry", "eth/(ipv4|ipv6)/tcp"},
	{"T10", "tc_entry", "eth/mpls+/ipv4/tcp"},
	{"T11", "tc_entry", "eth/ipv4/ipv4/tcp"},
	{"T12", "tc_entry", "eth/ipv4/udp/gtp/ipv4/tcp"},
	{"T13", "tc_entry", "eth/ipv6/srv6/tcp"},
	{"T14", "tc_entry", "eth/ipv4/tcp where tcp.options.MSS.value == 1460"},
	{"T15", "tc_entry", "eth/ipv4/tcp where any(ipv4.options.RR.addrs.addr == 192.168.0.0/16)"},
}

type goldenFilter struct {
	host, expr string
	sets       []specSet
	curated    string // file name stem, "" for manifest-only filters
}

func (g goldenFilter) setsText() string {
	if len(g.sets) == 0 {
		return "-"
	}
	b, err := json.Marshal(g.sets)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (g goldenFilter) key() string { return g.host + "\t" + g.expr + "\t" + g.setsText() }

// goldenCorpus is every (host, expr, sets) a spec vector expects to
// compile, plus the curated filters, sorted by key.
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
		g := goldenFilter{host: c.host, expr: c.expr, curated: c.name}
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

// numberedLabel matches the labels codegen numbers from a process-wide
// counter (freshLabel, nextPredicateLabel): the number depends on how
// many filters the process compiled before.
var numberedLabel = regexp.MustCompile(`^(dsl_.*_)(\d+)$`)

var trailingSpace = regexp.MustCompile(`(?m)[ \t]+$`)

// canonicalLabels renumbers every numbered label by order of first
// appearance per prefix across Main and Callbacks, so the text of one
// filter does not depend on what else the process compiled. Labels whose
// number is an index (dsl_pm_tcp_2_0) are renumbered too; the mapping is
// one to one per prefix, so the control flow is kept.
func canonicalLabels(out codegen.Output) (asm.Instructions, asm.Instructions) {
	all := slices.Clone(out.Main)
	all = append(all, out.Callbacks...)
	next := map[string]int{}
	seen := map[string]string{}
	rename := func(label string) string {
		if label == "" {
			return label
		}
		if s, ok := seen[label]; ok {
			return s
		}
		m := numberedLabel.FindStringSubmatch(label)
		if m == nil {
			seen[label] = label
			return label
		}
		next[m[1]]++
		s := m[1] + strconv.Itoa(next[m[1]])
		seen[label] = s
		return s
	}
	for i, ins := range all {
		if sym := ins.Symbol(); sym != "" {
			ins = ins.WithSymbol(rename(sym))
		}
		if ref := ins.Reference(); ref != "" {
			ins = ins.WithReference(rename(ref))
		}
		all[i] = ins
	}
	return all[:len(out.Main)], all[len(out.Main):]
}

// goldenText is the canonical text of one compiled filter: code is the
// instructions, meta everything else the host consumes.
func goldenText(g goldenFilter, out codegen.Output) (code, meta string) {
	mainIns, cbIns := canonicalLabels(out)
	var c strings.Builder
	fmt.Fprintf(&c, "== Main\n%v== Callbacks\n%v", mainIns, cbIns)
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

func manifestLine(g goldenFilter, out codegen.Output, code, meta string) string {
	return fmt.Sprintf("%s\tcode=%s meta=%s main=%d cb=%d", g.key(), shortHash(code), shortHash(meta), len(out.Main), len(out.Callbacks))
}

func readManifest(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(goldenManifest)
	if err != nil {
		t.Fatalf("open %s: %v (run `make golden-update`)", goldenManifest, err)
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

// TestGolden compares codegen's output with testdata/golden. It compiles
// every filter twice and fails if the two texts differ, which would make
// the golden meaningless.
func TestGolden(t *testing.T) {
	corpus := goldenCorpus(t)
	var want map[string]string
	if !*goldenUpdate {
		want = readManifest(t)
	}
	var manifest strings.Builder
	for _, g := range corpus {
		out, err := compileGolden(g)
		if err != nil {
			t.Errorf("%s %q: compile: %v", g.host, g.expr, err)
			continue
		}
		code, meta := goldenText(g, out)
		again, err := compileGolden(g)
		if err != nil {
			t.Fatalf("%s %q: second compile: %v", g.host, g.expr, err)
		}
		if code2, meta2 := goldenText(g, again); code2 != code || meta2 != meta {
			t.Errorf("%s %q: two compiles differ, codegen is not deterministic\n%s", g.host, g.expr, firstDiff(code+meta, code2+meta2))
		}
		text := goldenHeader(g) + code + meta
		line := manifestLine(g, out, code, meta)
		manifest.WriteString(line + "\n")
		if *goldenDump != "" {
			name := strings.ReplaceAll(g.host, "_", "-") + "-" + shortHash(g.key()) + ".asm"
			if err := os.MkdirAll(*goldenDump, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(*goldenDump, name), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if g.curated != "" {
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
		if *goldenUpdate {
			continue
		}
		i := strings.LastIndexByte(line, '\t')
		switch old, ok := want[g.key()]; {
		case !ok:
			t.Errorf("%s %q is not in %s; run `make golden-update`", g.host, g.expr, goldenManifest)
		case old != line[i+1:]:
			t.Errorf("%s %q changed: %s -> %s; if intended, run `make golden-update` (`make golden-diff` shows the text)", g.host, g.expr, old, line[i+1:])
		}
		delete(want, g.key())
	}
	for k := range want {
		t.Errorf("%s lists %q, which no spec vector or curated filter compiles; run `make golden-update`", goldenManifest, k)
	}
	if *goldenUpdate {
		if err := os.WriteFile(goldenManifest, []byte(manifest.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCanonicalLabels checks that two compiles of one filter, which draw
// different numbers from the label counters, give the same text, and
// that renumbering keeps distinct labels distinct.
func TestCanonicalLabels(t *testing.T) {
	g := goldenFilter{host: "xdp_entry", expr: "eth/ipv4[ttl in [1, 3..5]]/tcp[dport in [80, 443]]"}
	a, err := compileGolden(g)
	if err != nil {
		t.Fatal(err)
	}
	b, err := compileGolden(g)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := goldenText(g, a)
	cb, _ := goldenText(g, b)
	if ca != cb {
		t.Fatalf("canonical texts differ\n%s", firstDiff(ca, cb))
	}
	raw := func(o codegen.Output) map[string]bool {
		s := map[string]bool{}
		for _, ins := range o.Instructions() {
			if sym := ins.Symbol(); sym != "" {
				s[sym] = true
			}
		}
		return s
	}
	mainIns, cbIns := canonicalLabels(a)
	canon := map[string]bool{}
	for _, ins := range append(slices.Clone(mainIns), cbIns...) {
		if sym := ins.Symbol(); sym != "" {
			canon[sym] = true
		}
	}
	if len(canon) != len(raw(a)) {
		t.Fatalf("renumbering merged labels: %d symbols became %d", len(raw(a)), len(canon))
	}
	if !strings.Contains(ca, "dsl_pred_") {
		t.Fatalf("filter %q emits no numbered predicate label; pick one that does:\n%s", g.expr, ca)
	}
}
