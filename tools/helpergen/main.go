// Command helpergen generates pkg/inject/helpers_gen.go, the table of BPF
// helper ids with their names and result kinds, and
// tools/regionval/core/helperargs_gen.go, the number of argument registers
// each helper reads, from a Linux kernel tree.
//
//	go run ./tools/helpergen -ksrc <kernel tree> [-out pkg/inject/helpers_gen.go]
//		[-args-out tools/regionval/core/helperargs_gen.go] [-check]
//
// Ids and names come from ___BPF_FUNC_MAPPER in include/uapi/linux/bpf.h.
// Result kinds come from the .ret_type of every struct bpf_func_proto
// initialiser in the tree's .c files (every variant of a name, also under
// #ifdef; none is RET_INTEGER, the kernel's zero value), joined to ids
// through "case BPF_FUNC_x: return &proto;" switch arms. Ids that join no
// prototype, or prototypes of different kinds, take their kind from
// overrides.txt, which must then be one of the joined kinds. An override
// for an id the tree does not have, or a second one for an id, is an error.
// A helper's argument count is the largest N with an .argN_type other than
// ARG_DONTCARE over all prototypes it joins, the union over its variants.
// argoverrides.txt gives the count of an id that joins no prototype and
// raises it where the helper reads registers its prototype does not declare.
package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed overrides.txt
var overridesTxt string

//go:embed argoverrides.txt
var argOverridesTxt string

// Result kinds, spelled as the CalleeRet constants of pkg/inject.
const (
	kindScalar      = "RetScalar"
	kindPointer     = "RetPointer"
	kindVoid        = "RetVoid"
	kindUnsupported = "RetUnsupported"
)

type helper struct {
	ID   int
	Name string // without the bpf_ prefix
	Kind string
	Args int // argument registers read, r1 to rArgs
}

func main() {
	ksrc := flag.String("ksrc", "", "kernel source tree")
	out := flag.String("out", "pkg/inject/helpers_gen.go", "generated kind table")
	argsOut := flag.String("args-out", "tools/regionval/core/helperargs_gen.go", "generated argument table")
	check := flag.Bool("check", false, "compare with -out and -args-out instead of writing them")
	flag.Parse()
	if *ksrc == "" {
		fail("-ksrc is required")
	}
	helpers, version, err := load(*ksrc)
	if err != nil {
		fail(err.Error())
	}
	if *check {
		old, err := os.ReadFile(*out)
		if err != nil {
			fail(err.Error())
		}
		oldArgs, err := os.ReadFile(*argsOut)
		if err != nil {
			fail(err.Error())
		}
		diffs := compare(kindsOnly(helpers), parseTable(string(old)))
		diffs = append(diffs, compare(argsOnly(helpers), parseArgsTable(string(oldArgs)))...)
		for _, d := range diffs {
			fmt.Println(d)
		}
		if len(diffs) > 0 {
			os.Exit(1)
		}
		fmt.Printf("helpergen: %d helpers, kinds and argument counts equal\n", len(helpers))
		return
	}
	src, err := render(helpers, version)
	if err != nil {
		fail(err.Error())
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		fail(err.Error())
	}
	src, err = renderArgs(helpers, version)
	if err != nil {
		fail(err.Error())
	}
	if err := os.WriteFile(*argsOut, src, 0o644); err != nil {
		fail(err.Error())
	}
}

// String names the helper with the column it is compared on.
func (h helper) String() string {
	if h.Kind == "" {
		return fmt.Sprintf("bpf_%s %d args", h.Name, h.Args)
	}
	return fmt.Sprintf("bpf_%s %s", h.Name, h.Kind)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "helpergen:", msg)
	os.Exit(1)
}

// load reads the kernel tree and returns every helper with exactly one kind.
func load(ksrc string) ([]helper, string, error) {
	version, err := kernelVersion(ksrc)
	if err != nil {
		return nil, "", err
	}
	uapi, err := os.ReadFile(filepath.Join(ksrc, "include/uapi/linux/bpf.h"))
	if err != nil {
		return nil, "", err
	}
	helpers, err := parseMapper(string(uapi))
	if err != nil {
		return nil, "", err
	}
	protos := map[string]map[string]bool{} // proto name -> kinds
	protoArgs := map[string]int{}          // proto name -> largest argument count
	joins := map[string]map[string]bool{}  // helper name -> proto names
	err = filepath.WalkDir(ksrc, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch rel, _ := filepath.Rel(ksrc, path); rel {
			case ".git", "tools", "Documentation", "samples":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".c") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Contains(b, []byte("bpf_func_proto")) && !bytes.Contains(b, []byte("BPF_FUNC_")) {
			return nil
		}
		src := string(b)
		for name, kinds := range parseProtos(src) {
			for kind := range kinds {
				add(protos, name, kind)
			}
		}
		for name, n := range parseProtoArgs(src) {
			protoArgs[name] = max(protoArgs[name], n)
		}
		for name, ps := range parseJoins(src) {
			for p := range ps {
				add(joins, name, p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	overrides, err := parseOverrides(overridesTxt)
	if err != nil {
		return nil, "", err
	}
	if err := checkOverrideIDs("overrides.txt", len(helpers), keys(overrides)); err != nil {
		return nil, "", err
	}
	if err := resolve(helpers, protos, joins, overrides); err != nil {
		return nil, "", err
	}
	argOverrides, err := parseArgOverrides(argOverridesTxt)
	if err != nil {
		return nil, "", err
	}
	if err := checkOverrideIDs("argoverrides.txt", len(helpers), keys(argOverrides)); err != nil {
		return nil, "", err
	}
	if err := resolveArgs(helpers, protoArgs, joins, argOverrides); err != nil {
		return nil, "", err
	}
	return helpers, version, nil
}

func keys[V any](m map[int]V) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// checkOverrideIDs fails for an override of an id that is not a helper of
// the tree: id 0 or past its last id (a stale entry).
func checkOverrideIDs(file string, n int, ids []int) error {
	for _, id := range ids {
		if id <= 0 || id >= n {
			return fmt.Errorf("%s: id %d is not a helper of this tree (ids 1-%d)", file, id, n-1)
		}
	}
	return nil
}

func add(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

var (
	versionRE = regexp.MustCompile(`(?m)^(VERSION|PATCHLEVEL|SUBLEVEL) = (\d+)$`)
	mapperRE  = regexp.MustCompile(`FN\((\w+), (\d+), ##ctx\)`)
	protoRE   = regexp.MustCompile(`(?s)struct\s+bpf_func_proto\s+(\w+)\s*=\s*\{(.*?)\};`)
	retTypeRE = regexp.MustCompile(`\.ret_type\s*=\s*([^,}]+)`)
	argTypeRE = regexp.MustCompile(`\.arg([1-5])_type\s*=\s*([^,}]+)`)
	caseRE    = regexp.MustCompile(`(?m)^([ \t]*)case\s+BPF_FUNC_(\w+)\s*:`)
	returnRE  = regexp.MustCompile(`\breturn\b([^;]*);`)
	addrRE    = regexp.MustCompile(`&\s*(\w+)`)
	tableRE   = regexp.MustCompile(`\{"bpf_(\w+)", (Ret\w+)\},\s*// (\d+)`)
	argsRE    = regexp.MustCompile(`(\d+):\s*(\d),\s*// (\w+)`)
)

func kernelVersion(ksrc string) (string, error) {
	b, err := os.ReadFile(filepath.Join(ksrc, "Makefile"))
	if err != nil {
		return "", err
	}
	v := map[string]string{}
	for _, m := range versionRE.FindAllStringSubmatch(string(b), -1) {
		if _, ok := v[m[1]]; !ok {
			v[m[1]] = m[2]
		}
	}
	if len(v) != 3 {
		return "", fmt.Errorf("no VERSION/PATCHLEVEL/SUBLEVEL in %s/Makefile", ksrc)
	}
	return v["VERSION"] + "." + v["PATCHLEVEL"] + "." + v["SUBLEVEL"], nil
}

// parseMapper returns the helpers of ___BPF_FUNC_MAPPER, ids 0..n-1 in order.
func parseMapper(src string) ([]helper, error) {
	start := strings.Index(src, "#define ___BPF_FUNC_MAPPER")
	if start < 0 {
		return nil, fmt.Errorf("no ___BPF_FUNC_MAPPER")
	}
	src = src[start:]
	if end := strings.Index(src, "\n\n"); end >= 0 {
		src = src[:end]
	}
	var hs []helper
	for _, m := range mapperRE.FindAllStringSubmatch(src, -1) {
		id, _ := strconv.Atoi(m[2])
		if id != len(hs) {
			return nil, fmt.Errorf("helper %s has id %d, want %d", m[1], id, len(hs))
		}
		hs = append(hs, helper{ID: id, Name: m[1]})
	}
	if len(hs) == 0 {
		return nil, fmt.Errorf("no helpers in ___BPF_FUNC_MAPPER")
	}
	return hs, nil
}

// parseProtos returns the result kinds of each bpf_func_proto initialiser
// name, over all its variants in src (#ifdef branches define one name more
// than once). An initialiser without .ret_type returns RET_INTEGER, the
// enum's zero value.
func parseProtos(src string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, m := range protoRE.FindAllStringSubmatch(src, -1) {
		ret := "RET_INTEGER"
		if r := retTypeRE.FindStringSubmatch(m[2]); r != nil {
			ret = strings.TrimSpace(r[1])
		}
		switch {
		case ret == "RET_INTEGER":
			add(out, m[1], kindScalar)
		case ret == "RET_VOID":
			add(out, m[1], kindVoid)
		case strings.HasPrefix(ret, "RET_"):
			add(out, m[1], kindPointer)
		}
	}
	return out
}

// parseProtoArgs returns the argument count of each bpf_func_proto
// initialiser: the largest N whose .argN_type is not ARG_DONTCARE.
func parseProtoArgs(src string) map[string]int {
	out := map[string]int{}
	for _, m := range protoRE.FindAllStringSubmatch(src, -1) {
		n := 0
		for _, a := range argTypeRE.FindAllStringSubmatch(m[2], -1) {
			if strings.TrimSpace(a[2]) != "ARG_DONTCARE" {
				n = max(n, int(a[1][0]-'0'))
			}
		}
		out[m[1]] = max(out[m[1]], n)
	}
	return out
}

// parseJoins returns, per helper name, the names whose address a switch arm
// "case BPF_FUNC_x: ... return &y;" returns. Arms returning anything else
// (another call, NULL) join nothing. An arm ends at the next line indented
// like its label that starts with case, default or the switch's closing
// brace, so arms may hold nested switches.
func parseJoins(src string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	labels := caseRE.FindAllStringSubmatchIndex(src, -1)
	for i := 0; i < len(labels); {
		// Stacked labels share one arm.
		indent := src[labels[i][2]:labels[i][3]]
		names := []string{src[labels[i][4]:labels[i][5]]}
		end := labels[i][1]
		for i++; i < len(labels) && strings.TrimSpace(src[end:labels[i][0]]) == ""; i++ {
			names = append(names, src[labels[i][4]:labels[i][5]])
			end = labels[i][1]
		}
		arm := src[end:]
		armEnd := regexp.MustCompile(`\n` + indent + `(case\b|default\b|\})`)
		if loc := armEnd.FindStringIndex(arm); loc != nil {
			arm = arm[:loc[0]]
		}
		for _, r := range returnRE.FindAllStringSubmatch(arm, -1) {
			for _, a := range addrRE.FindAllStringSubmatch(r[1], -1) {
				for _, n := range names {
					add(out, n, a[1])
				}
			}
		}
	}
	return out
}

// parseOverrides reads "id kind # reason" lines, at most one per id.
func parseOverrides(txt string) (map[int]string, error) {
	out := map[int]string{}
	for i, line := range strings.Split(txt, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		id, err := strconv.Atoi(f[0])
		kind := kindOf(f[len(f)-1])
		if len(f) != 2 || err != nil || kind == "" {
			return nil, fmt.Errorf("overrides.txt:%d: want \"id scalar|pointer|void # reason\"", i+1)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("overrides.txt:%d: a second override of id %d", i+1, id)
		}
		out[id] = kind
	}
	return out, nil
}

// parseArgOverrides reads "id count # reason" lines.
func parseArgOverrides(txt string) (map[int]int, error) {
	out := map[int]int{}
	for i, line := range strings.Split(txt, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		id, err := strconv.Atoi(f[0])
		var n int
		if err == nil && len(f) == 2 {
			n, err = strconv.Atoi(f[1])
		}
		if len(f) != 2 || err != nil || n < 0 || n > 5 {
			return nil, fmt.Errorf("argoverrides.txt:%d: want \"id 0-5 # reason\"", i+1)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("argoverrides.txt:%d: a second count of id %d", i+1, id)
		}
		out[id] = n
	}
	return out, nil
}

func kindOf(s string) string {
	switch s {
	case "scalar":
		return kindScalar
	case "pointer":
		return kindPointer
	case "void":
		return kindVoid
	}
	return ""
}

// resolve sets each helper's kind; it fails listing the ids left without
// exactly one kind and overrides that contradict the tree.
func resolve(hs []helper, protos, joins map[string]map[string]bool, overrides map[int]string) error {
	var problems []string
	for i := range hs {
		h := &hs[i]
		if h.ID == 0 {
			h.Kind = kindUnsupported
			continue
		}
		kinds := map[string]bool{}
		var used []string
		for p := range joins[h.Name] {
			for k := range protos[p] {
				kinds[k] = true
				used = append(used, p+"="+k)
			}
		}
		sort.Strings(used)
		o, haveOverride := overrides[h.ID]
		switch {
		case len(kinds) == 1 && haveOverride:
			for k := range kinds {
				if k != o {
					problems = append(problems, fmt.Sprintf("%d %s: override %s contradicts %v", h.ID, h.Name, o, used))
				}
			}
			h.Kind = o
		case len(kinds) == 1:
			for k := range kinds {
				h.Kind = k
			}
		case haveOverride && len(kinds) > 1 && !kinds[o]:
			problems = append(problems, fmt.Sprintf("%d %s: override %s is none of the joined kinds %v", h.ID, h.Name, o, used))
		case haveOverride:
			h.Kind = o
		case len(kinds) == 0:
			problems = append(problems, fmt.Sprintf("%d %s: no prototype joined", h.ID, h.Name))
		default:
			problems = append(problems, fmt.Sprintf("%d %s: prototypes disagree: %v", h.ID, h.Name, used))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d ids need an override in tools/helpergen/overrides.txt:\n\t%s",
			len(problems), strings.Join(problems, "\n\t"))
	}
	return nil
}

// resolveArgs sets each helper's argument count, the union over the
// prototypes it joins, or its override. It fails for an id that joins no
// prototype and has no override, and for an override that reads fewer
// registers than a prototype declares. Id 0 is not a helper and stays 0.
func resolveArgs(hs []helper, protoArgs map[string]int, joins map[string]map[string]bool, overrides map[int]int) error {
	var problems []string
	for i := range hs {
		h := &hs[i]
		if h.ID == 0 {
			continue
		}
		n := -1
		for p := range joins[h.Name] {
			if a, ok := protoArgs[p]; ok {
				n = max(n, a)
			}
		}
		o, haveOverride := overrides[h.ID]
		switch {
		case haveOverride && o < n:
			problems = append(problems, fmt.Sprintf("%d %s: override %d reads fewer registers than its prototypes (%d)", h.ID, h.Name, o, n))
		case haveOverride:
			h.Args = o
		case n < 0:
			problems = append(problems, fmt.Sprintf("%d %s: no prototype joined", h.ID, h.Name))
		default:
			h.Args = n
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d ids need a count in tools/helpergen/argoverrides.txt:\n\t%s",
			len(problems), strings.Join(problems, "\n\t"))
	}
	return nil
}

func render(hs []helper, version string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("// Code generated by tools/helpergen; DO NOT EDIT.\n\n")
	b.WriteString("package inject\n\n")
	fmt.Fprintf(&b, "// helperTable is indexed by helper id. Generated from Linux %s.\n", version)
	b.WriteString("var helperTable = [...]helperRow{\n")
	for _, h := range hs {
		fmt.Fprintf(&b, "{%q, %s}, // %d\n", "bpf_"+h.Name, h.Kind, h.ID)
	}
	b.WriteString("}\n")
	return format.Source(b.Bytes())
}

func renderArgs(hs []helper, version string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("// Code generated by tools/helpergen; DO NOT EDIT.\n\n")
	b.WriteString("package core\n\n")
	fmt.Fprintf(&b, "// helperArgs is the number of argument registers each helper reads, by id,\n")
	fmt.Fprintf(&b, "// generated from Linux %s: the largest argN_type over the helper's\n", version)
	b.WriteString("// prototypes, or the count in tools/helpergen/argoverrides.txt. Id 0 is not\n")
	b.WriteString("// a helper and is absent, so a call to it reads r1-r5.\n")
	b.WriteString("var helperArgs = map[int32]int{\n")
	for _, h := range hs {
		if h.ID != 0 {
			fmt.Fprintf(&b, "%d: %d, // %s\n", h.ID, h.Args, h.Name)
		}
	}
	b.WriteString("}\n")
	return format.Source(b.Bytes())
}

// parseTable reads the rows of a generated file.
func parseTable(src string) []helper {
	var hs []helper
	for _, m := range tableRE.FindAllStringSubmatch(src, -1) {
		id, _ := strconv.Atoi(m[3])
		hs = append(hs, helper{ID: id, Name: m[1], Kind: m[2]})
	}
	return hs
}

// parseArgsTable reads the rows of a generated argument table.
func parseArgsTable(src string) []helper {
	var hs []helper
	for _, m := range argsRE.FindAllStringSubmatch(src, -1) {
		id, _ := strconv.Atoi(m[1])
		n, _ := strconv.Atoi(m[2])
		hs = append(hs, helper{ID: id, Name: m[3], Args: n})
	}
	return hs
}

// kindsOnly and argsOnly project the helpers onto the columns of the kind
// table and of the argument table, which has no row for id 0.
func kindsOnly(hs []helper) []helper {
	out := make([]helper, len(hs))
	for i, h := range hs {
		out[i] = helper{ID: h.ID, Name: h.Name, Kind: h.Kind}
	}
	return out
}

func argsOnly(hs []helper) []helper {
	var out []helper
	for _, h := range hs {
		if h.ID != 0 {
			out = append(out, helper{ID: h.ID, Name: h.Name, Args: h.Args})
		}
	}
	return out
}

// compare lists the differences between the tree's helpers and a table.
func compare(tree, table []helper) []string {
	var diffs []string
	for i := 0; i < max(len(tree), len(table)); i++ {
		switch {
		case i >= len(table):
			diffs = append(diffs, fmt.Sprintf("%d: tree has %s, table has no row", tree[i].ID, tree[i]))
		case i >= len(tree):
			diffs = append(diffs, fmt.Sprintf("%d: table has %s, tree has no helper", table[i].ID, table[i]))
		case tree[i] != table[i]:
			diffs = append(diffs, fmt.Sprintf("%d: tree has %s, table has %d %s", tree[i].ID, tree[i], table[i].ID, table[i]))
		}
	}
	return diffs
}
