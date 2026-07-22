// JSON shapes for the --list-progs / --list-funcs / --list-params commands,
// emitted on stdout when --json is set so the discovery output can be piped
// into jq or another tool instead of scraping the human-readable text.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

// funcJSON is one BTF function of a program.
type funcJSON struct {
	Name    string `json:"name"`
	Linkage string `json:"linkage"`
}

// progNodeJSON is one node of a program's reachable tree. Funcs is a pointer
// so the combined --list-funcs view can emit "funcs": [] (requested, none
// found) distinctly from omitting the key (funcs not requested at all).
type progNodeJSON struct {
	ID     uint32      `json:"id"`
	Name   string      `json:"name,omitempty"`
	Via    string      `json:"via,omitempty"`
	Keys   []uint32    `json:"keys,omitempty"`
	Depth  int         `json:"depth,omitempty"`
	Parent uint32      `json:"parent,omitempty"`
	Funcs  *[]funcJSON `json:"funcs,omitempty"`
}

// progsTargetJSON is one -p / -i target: its entry (root) plus the reachable
// tree. Funcs is the root's functions when --list-funcs is combined; a
// pointer for the same present-but-empty vs absent distinction as the nodes.
type progsTargetJSON struct {
	ID        uint32         `json:"id"`
	Func      string         `json:"func"`
	Funcs     *[]funcJSON    `json:"funcs,omitempty"`
	Reachable []progNodeJSON `json:"reachable"`
}

// funcsTargetJSON is one target's BTF function list (--list-funcs alone).
type funcsTargetJSON struct {
	ID    uint32     `json:"id"`
	Funcs []funcJSON `json:"funcs"`
}

// paramJSON is one filterable function parameter.
type paramJSON struct {
	Name   string `json:"name"`
	Index  int    `json:"index"`
	Size   uint32 `json:"size"`
	Signed bool   `json:"signed"`
}

// paramsTargetJSON is one attach pair's filterable parameters.
type paramsTargetJSON struct {
	Func   string      `json:"func"`
	ID     uint32      `json:"id"`
	Params []paramJSON `json:"params"`
}

// funcsToJSON converts resolved BTF functions to their JSON shape.
func funcsToJSON(funcs []attach.FuncInfo) []funcJSON {
	out := make([]funcJSON, len(funcs))
	for i, f := range funcs {
		out[i] = funcJSON{Name: f.Name, Linkage: f.Linkage}
	}
	return out
}

// emitJSON writes v to stdout as indented JSON. list output is a deliberate
// program result, so it goes to stdout (not the stderr the text form uses).
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}
