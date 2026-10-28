// --list-maps: the maps each function of a reachable program uses, read from
// the translated instructions of the loaded program.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
)

// funcMapsJSON is one function of a program with its calls and map uses.
type funcMapsJSON struct {
	Func      string       `json:"func"`
	Calls     []string     `json:"calls,omitempty"`
	Callbacks []string     `json:"callbacks,omitempty"`
	Uses      []mapUseJSON `json:"uses"`
}

// mapUseJSON is one map reference; pc is the translated instruction index.
type mapUseJSON struct {
	ID      uint32 `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Op      string `json:"op"`
	Inlined bool   `json:"inlined,omitempty"`
	File    string `json:"file,omitempty"`
	Line    uint32 `json:"line,omitempty"`
	PC      int    `json:"pc"`
	// Site and Reason come from --lookups-json: the load-time pc of the
	// same call and why it cannot be instrumented.
	Site   *uint32 `json:"site,omitempty"`
	Reason string  `json:"reason,omitempty"`
}

// loadCall is one entry of a lookups file's calls list.
type loadCall struct {
	Kind    string `json:"kind"`
	PC      uint32 `json:"pc"`
	Map     string `json:"map"`
	Func    string `json:"func"`
	File    string `json:"file"`
	Line    uint32 `json:"line"`
	Reason  string `json:"reason"`
	Generic bool   `json:"generic"`
}

// readLoadCalls reads the calls of every program in a file inject-run
// --lookups-json wrote, by entry function. A program loaded more than once
// keeps its last load.
func readLoadCalls(path string) (map[string][]loadCall, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file struct {
		Version  int `json:"version"`
		Programs []struct {
			Func  string     `json:"func"`
			Calls []loadCall `json:"calls"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if file.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d", path, file.Version)
	}
	calls := map[string][]loadCall{}
	for _, p := range file.Programs {
		calls[p.Func] = p.Calls
	}
	return calls, nil
}

// nodeMaps is one program's map uses, with the load-time call matched to
// each use (nil when none matched), indexed like maps.Funcs[i].Maps[j].
type nodeMaps struct {
	maps  attach.ProgMaps
	sites [][]*loadCall
}

// matchLoadCalls pairs map uses with load-time calls. Instruction indexes
// differ between the two, since the verifier rewrites and inlines calls, so
// a use matches the call with the same op, map, function, file and line, the
// n-th use with the n-th such call.
func matchLoadCalls(maps attach.ProgMaps, calls []loadCall) [][]*loadCall {
	type key struct {
		op, mapName, fn, file string
		line                  uint32
	}
	byKey := map[key][]*loadCall{}
	for i := range calls {
		c := &calls[i]
		k := key{c.Kind, c.Map, c.Func, c.File, c.Line}
		byKey[k] = append(byKey[k], c)
	}
	sites := make([][]*loadCall, len(maps.Funcs))
	for i, fn := range maps.Funcs {
		sites[i] = make([]*loadCall, len(fn.Maps))
		for j, u := range fn.Maps {
			k := key{u.Op, u.MapName, fn.Name, u.File, u.Line}
			if list := byKey[k]; len(list) > 0 {
				sites[i][j], byKey[k] = list[0], list[1:]
			}
		}
	}
	return sites
}

// mapsLister reads the map uses of programs, opening the kernel symbol
// table once. load holds the load-time calls of --lookups-json by entry
// function, nil without it.
type mapsLister struct {
	syms *attach.KernelSymbols
	load map[string][]loadCall
}

func newMapsLister(lookupsPath string) (*mapsLister, error) {
	// An unreadable kallsyms only leaves helper ops unknown.
	syms, _ := attach.LoadKernelSymbols()
	l := &mapsLister{syms: syms}
	if lookupsPath != "" {
		load, err := readLoadCalls(lookupsPath)
		if err != nil {
			return nil, fmt.Errorf("--lookups-json: %w", err)
		}
		l.load = load
	}
	return l, nil
}

// list returns the map uses of the program with progID; prog may be nil to
// open it here. An unreadable program yields a note instead of an error, so
// one node does not abort the listing.
func (l *mapsLister) list(progID uint32, prog *ebpf.Program) nodeMaps {
	if prog == nil {
		opened, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
		if err != nil {
			return nodeMaps{maps: attach.ProgMaps{Note: fmt.Sprintf("opening program: %v", err)}}
		}
		defer func() { _ = opened.Close() }()
		prog = opened
	}
	maps, err := attach.ProgramMaps(prog, l.syms)
	if err != nil {
		return nodeMaps{maps: attach.ProgMaps{Note: err.Error()}}
	}
	n := nodeMaps{maps: maps}
	if l.load != nil && len(maps.Funcs) > 0 {
		if calls, ok := l.load[maps.Funcs[0].Name]; ok {
			n.sites = matchLoadCalls(maps, calls)
		}
	}
	return n
}

// site is the load-time call matched to use j of function i, if any.
func (n nodeMaps) site(i, j int) *loadCall {
	if n.sites == nil {
		return nil
	}
	return n.sites[i][j]
}

func mapsToJSON(n nodeMaps) []funcMapsJSON {
	out := make([]funcMapsJSON, 0, len(n.maps.Funcs))
	for i, fn := range n.maps.Funcs {
		f := funcMapsJSON{Func: fn.Name, Calls: fn.Calls, Callbacks: fn.Callbacks, Uses: []mapUseJSON{}}
		for j, u := range fn.Maps {
			use := mapUseJSON{ID: u.MapID, Name: u.MapName, Type: u.MapType.String(), Op: u.Op,
				Inlined: u.Inlined, File: u.File, Line: u.Line, PC: u.PC}
			if c := n.site(i, j); c != nil {
				use.Site, use.Reason = &c.PC, c.Reason
			}
			f.Uses = append(f.Uses, use)
		}
		out = append(out, f)
	}
	return out
}

// treeNode is one line of the --list-maps text tree and the lines under it.
type treeNode struct {
	text string
	kids []treeNode
}

// printTree prints n and, with box-drawing branches, everything under it.
func printTree(w io.Writer, n treeNode) {
	_, _ = fmt.Fprintln(w, n.text)
	printKids(w, n.kids, "")
}

func printKids(w io.Writer, kids []treeNode, prefix string) {
	for i, k := range kids {
		branch, next := "├─ ", "│  "
		if i == len(kids)-1 {
			branch, next = "└─ ", "   "
		}
		_, _ = fmt.Fprintf(w, "%s%s%s\n", prefix, branch, k.text)
		printKids(w, k.kids, prefix+next)
	}
}

// progTree builds the tree of program id: its functions with their map
// uses, then the programs it reaches. edge says how the parent reaches it.
func (l *mapsLister) progTree(id uint32, name, edge string, prog *ebpf.Program, byParent map[uint32][]attach.ReachableProgram) treeNode {
	return progNode(id, name, edge, l.list(id, prog), byParent[id], func(c attach.ReachableProgram, edge string) treeNode {
		return l.progTree(c.ProgID, c.ProgName, edge, nil, byParent)
	})
}

// progNode builds the tree of one program from its map uses and reached
// programs; child builds the subtree of each reached program.
func progNode(id uint32, name, edge string, n nodeMaps, children []attach.ReachableProgram, child func(attach.ReachableProgram, string) treeNode) treeNode {
	node := treeNode{text: fmt.Sprintf("prog %d  %s%s", id, name, edge)}
	if n.maps.Note != "" {
		node.kids = append(node.kids, treeNode{text: "(" + n.maps.Note + ")"})
	}
	// Columns line up within a program.
	var width [4]int
	mapNames := map[uint32]string{}
	for _, fn := range n.maps.Funcs {
		for _, u := range fn.Maps {
			for c, v := range useColumns(u) {
				width[c] = max(width[c], len(v))
			}
			mapNames[u.MapID] = u.MapName
		}
	}
	for i, fn := range n.maps.Funcs {
		f := treeNode{text: "func " + fn.Name}
		var extra []string
		if len(fn.Calls) > 0 {
			extra = append(extra, "calls: "+strings.Join(fn.Calls, ", "))
		}
		if len(fn.Callbacks) > 0 {
			extra = append(extra, "callbacks: "+strings.Join(fn.Callbacks, ", "))
		}
		if len(extra) > 0 {
			f.text += "  (" + strings.Join(extra, "; ") + ")"
		}
		for j, u := range fn.Maps {
			cols := useColumns(u)
			text := "map " + fmt.Sprintf("%-*s", width[0], cols[0])
			for c, v := range cols[1:] {
				text += fmt.Sprintf("  %-*s", width[c+1], v)
			}
			for _, part := range []string{n.status(i, j, u, children), useDetails(u, n.site(i, j))} {
				if part != "" {
					text += "  " + part
				}
			}
			f.kids = append(f.kids, treeNode{text: strings.TrimRight(text, " ")})
		}
		node.kids = append(node.kids, f)
	}
	for _, c := range children {
		node.kids = append(node.kids, child(c, edgeText(c, mapNames)))
	}
	return node
}

// useColumns are the aligned columns of a map use: name, type, op, place.
func useColumns(u attach.MapUse) [4]string {
	name := u.MapName
	if name == "" {
		name = fmt.Sprintf("id=%d", u.MapID)
	}
	typ := "unknown"
	if u.MapType != ebpf.UnspecifiedMap {
		typ = u.MapType.String()
	}
	place := ""
	if u.Line != 0 {
		place = fmt.Sprintf("%s:%d", filepath.Base(u.File), u.Line)
	}
	return [4]string{name, typ, u.Op, place}
}

// status says where a tail call or redirect goes and, with --lookups-json,
// whether a map call (a lookup, update, delete, push, pop or peek) can be
// instrumented.
func (n nodeMaps) status(i, j int, u attach.MapUse, children []attach.ReachableProgram) string {
	switch u.Op {
	case attach.MapOpTailCall, attach.MapOpRedirect:
		var targets []string
		for _, c := range children {
			if slices.ContainsFunc(c.Maps, func(m attach.MapKeys) bool { return m.MapID == u.MapID }) {
				targets = append(targets, fmt.Sprintf("prog %d", c.ProgID))
			}
		}
		if len(targets) == 0 {
			return ""
		}
		return "→ " + strings.Join(targets, ", ")
	case attach.MapOpLookup, attach.MapOpUpdate, attach.MapOpDelete, attach.MapOpPush, attach.MapOpPop, attach.MapOpPeek:
	default:
		return ""
	}
	if n.sites == nil {
		return ""
	}
	c := n.site(i, j)
	switch {
	case c == nil:
		return "? not in the lookups file"
	case c.Reason == "":
		return "✓ injectable"
	case c.Generic:
		return "✓ injectable (generic hook)"
	}
	// "lookup is not in the entry function; ctx belongs to ..." reads
	// "not in the entry function".
	reason, _, _ := strings.Cut(c.Reason, ";")
	return "✗ " + strings.TrimPrefix(reason, u.Op+" is ")
}

// useDetails is the parenthesized tail of a map use line.
func useDetails(u attach.MapUse, c *loadCall) string {
	var parts []string
	if u.Inlined {
		parts = append(parts, "inlined")
	}
	if c != nil {
		parts = append(parts, fmt.Sprintf("pc %d", c.PC))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// edgeText says how a reachable program is entered, after its name: each
// map that reaches it with that map's keys.
func edgeText(c attach.ReachableProgram, mapNames map[uint32]string) string {
	var slots []string
	for _, m := range c.Maps {
		name := mapNames[m.MapID]
		if name == "" {
			name = fmt.Sprintf("map id=%d", m.MapID)
		}
		slots = append(slots, fmt.Sprintf("%s[%s]", name, formatKeyRanges(m.Keys)))
	}
	switch c.Via {
	case "tailcall":
		return fmt.Sprintf("  (tail call: %s)", strings.Join(slots, ", "))
	case "freplace":
		return "  (freplace)"
	}
	return fmt.Sprintf("  (%s redirect: %s)", c.Via, strings.Join(slots, ", "))
}
