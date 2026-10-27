// --list-maps: the maps each function of a reachable program uses, read from
// the translated instructions of the loaded program.
package main

import (
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
}

// mapsLister reads the map uses of programs, opening the kernel symbol
// table once.
type mapsLister struct {
	syms *attach.KernelSymbols
}

func newMapsLister() *mapsLister {
	// An unreadable kallsyms only leaves helper ops unknown.
	syms, _ := attach.LoadKernelSymbols()
	return &mapsLister{syms: syms}
}

// list returns the map uses of the program with progID; prog may be nil to
// open it here. An unreadable program yields a note instead of an error, so
// one node does not abort the listing.
func (l *mapsLister) list(progID uint32, prog *ebpf.Program) attach.ProgMaps {
	if prog == nil {
		opened, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
		if err != nil {
			return attach.ProgMaps{Note: fmt.Sprintf("opening program: %v", err)}
		}
		defer func() { _ = opened.Close() }()
		prog = opened
	}
	maps, err := attach.ProgramMaps(prog, l.syms)
	if err != nil {
		return attach.ProgMaps{Note: err.Error()}
	}
	return maps
}

func mapsToJSON(maps attach.ProgMaps) []funcMapsJSON {
	out := make([]funcMapsJSON, 0, len(maps.Funcs))
	for _, fn := range maps.Funcs {
		f := funcMapsJSON{Func: fn.Name, Calls: fn.Calls, Callbacks: fn.Callbacks, Uses: []mapUseJSON{}}
		for _, u := range fn.Maps {
			f.Uses = append(f.Uses, mapUseJSON{ID: u.MapID, Name: u.MapName, Type: u.MapType.String(), Op: u.Op,
				Inlined: u.Inlined, File: u.File, Line: u.Line, PC: u.PC})
		}
		out = append(out, f)
	}
	return out
}

// printMaps prints the functions of a program with their calls and map uses
// (text mode).
func printMaps(maps attach.ProgMaps, indent string) {
	if maps.Note != "" {
		fmt.Fprintf(os.Stderr, "%s(%s)\n", indent, maps.Note)
	}
	for _, fn := range maps.Funcs {
		fmt.Fprintf(os.Stderr, "%s%s\n", indent, fn.Name)
		if len(fn.Calls) > 0 {
			fmt.Fprintf(os.Stderr, "%s  calls %s\n", indent, strings.Join(fn.Calls, ", "))
		}
		if len(fn.Callbacks) > 0 {
			fmt.Fprintf(os.Stderr, "%s  callbacks %s\n", indent, strings.Join(fn.Callbacks, ", "))
		}
		for _, u := range fn.Maps {
			fmt.Fprintf(os.Stderr, "%s  %s\n", indent, u)
		}
	}
}
