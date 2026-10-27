// --list-maps: the maps each function of a reachable program uses, read from
// the translated instructions of the loaded program.
package main

import (
	"encoding/json"
	"fmt"
	"os"
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
	Kind   string `json:"kind"`
	PC     uint32 `json:"pc"`
	Map    string `json:"map"`
	Func   string `json:"func"`
	File   string `json:"file"`
	Line   uint32 `json:"line"`
	Reason string `json:"reason"`
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

// printMaps prints the functions of a program with their calls and map uses
// (text mode).
func printMaps(n nodeMaps, indent string) {
	maps := n.maps
	if maps.Note != "" {
		fmt.Fprintf(os.Stderr, "%s(%s)\n", indent, maps.Note)
	}
	for i, fn := range maps.Funcs {
		fmt.Fprintf(os.Stderr, "%s%s\n", indent, fn.Name)
		if len(fn.Calls) > 0 {
			fmt.Fprintf(os.Stderr, "%s  calls %s\n", indent, strings.Join(fn.Calls, ", "))
		}
		if len(fn.Callbacks) > 0 {
			fmt.Fprintf(os.Stderr, "%s  callbacks %s\n", indent, strings.Join(fn.Callbacks, ", "))
		}
		for j, u := range fn.Maps {
			fmt.Fprintf(os.Stderr, "%s  %s%s\n", indent, u, siteText(n.site(i, j)))
		}
	}
}

// siteText renders a matched load-time call for text listings.
func siteText(c *loadCall) string {
	switch {
	case c == nil:
		return ""
	case c.Reason != "":
		return fmt.Sprintf(" site=%d [%s]", c.PC, c.Reason)
	}
	return fmt.Sprintf(" site=%d", c.PC)
}
