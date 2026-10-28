//go:build linux && amd64

// JSON shape of inject-run --lookups-json: the lookups and maps of every XDP
// and tc program the target loads, with a rule to start from, so the maps to
// instrument can be picked before a second run.
package main

import (
	"cmp"
	"slices"

	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

// lookupsJSONVersion changes only when a field changes meaning or goes away.
const lookupsJSONVersion = 1

// lookupsRuleHook is the hook name the suggested rules use.
const lookupsRuleHook = "ninja"

type lookupsFileJSON struct {
	Version  int                  `json:"version"`
	Programs []discoveredProgJSON `json:"programs"`
}

// discoveredProgJSON is one program load. Calls lists every map helper call
// the transform knows, with the op as kind; Reason and Generic are as for a
// lookup.
// Rule instruments every named map with lookups; its stack_lowest_offset is
// null because only the caller can audit the stack, so the rule is refused
// until it is filled in.
type discoveredProgJSON struct {
	Program string              `json:"program"`
	Func    string              `json:"func"`
	Type    string              `json:"type"`
	CtxType string              `json:"ctx_type"`
	Maps    []discoveredMapJSON `json:"maps"`
	Lookups []hookSiteJSON      `json:"lookups"`
	Calls   []hookSiteJSON      `json:"calls"`
	Rule    syscallhook.Rule    `json:"rule"`
}

// discoveredMapJSON is one map the program references, with the PCs of its
// lookups and the ops the program calls on it; a map the program only passes
// to other helpers has neither.
type discoveredMapJSON struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Sites []uint32 `json:"sites"`
	Ops   []string `json:"ops"`
}

func discoveryJSON(d syscallhook.Discovery) discoveredProgJSON {
	out := discoveredProgJSON{Program: d.Program, Func: d.Func, Type: d.Type.String(), CtxType: inject.ContextType(d.Type),
		Maps: []discoveredMapJSON{}, Lookups: []hookSiteJSON{}, Calls: []hookSiteJSON{}}
	index := map[string]int{}
	addMap := func(name string) int {
		i, ok := index[name]
		if !ok {
			i = len(out.Maps)
			index[name] = i
			out.Maps = append(out.Maps, discoveredMapJSON{Name: name, Type: d.Maps[name].String(), Sites: []uint32{}, Ops: []string{}})
		}
		return i
	}
	for _, site := range d.Lookups {
		out.Lookups = append(out.Lookups, discoveredSiteJSON(site))
		if site.MapName == "" {
			continue
		}
		if _, ok := index[site.MapName]; !ok {
			out.Rule.Maps = append(out.Rule.Maps, site.MapName)
		}
		i := addMap(site.MapName)
		out.Maps[i].Sites = append(out.Maps[i].Sites, site.SitePC)
	}
	// Then the maps without lookups, by name so the output is stable.
	var rest []string
	for name := range d.Maps {
		if _, ok := index[name]; !ok && name != "" {
			rest = append(rest, name)
		}
	}
	slices.Sort(rest)
	for _, name := range rest {
		addMap(name)
	}
	for _, site := range d.Calls {
		out.Calls = append(out.Calls, discoveredSiteJSON(site))
		if i, ok := index[site.MapName]; ok && !slices.Contains(out.Maps[i].Ops, string(site.Op)) {
			out.Maps[i].Ops = append(out.Maps[i].Ops, string(site.Op))
		}
	}
	out.Rule.Program = cmp.Or(d.Func, d.Program)
	out.Rule.Auto = true
	out.Rule.Hook = lookupsRuleHook
	return out
}

func discoveredSiteJSON(site inject.LookupSite) hookSiteJSON {
	s := siteJSON(site.Op, site)
	s.Generic = site.Generic
	return s
}

// lookupsWriter rewrites path with every discovered load so far.
type lookupsWriter struct {
	path string
	file lookupsFileJSON
}

func newLookupsWriter(path string) (*lookupsWriter, error) {
	w := &lookupsWriter{path: path, file: lookupsFileJSON{Version: lookupsJSONVersion, Programs: []discoveredProgJSON{}}}
	return w, writeJSONFile(w.path, w.file)
}

func (w *lookupsWriter) add(d syscallhook.Discovery) error {
	w.file.Programs = append(w.file.Programs, discoveryJSON(d))
	return writeJSONFile(w.path, w.file)
}
