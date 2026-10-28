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

// discoveredProgJSON is one program load. Rule instruments every named map
// with lookups; its stack_lowest_offset is null because only the caller can
// audit the stack, so the rule is refused until it is filled in.
type discoveredProgJSON struct {
	Program string              `json:"program"`
	Func    string              `json:"func"`
	Type    string              `json:"type"`
	CtxType string              `json:"ctx_type"`
	Maps    []discoveredMapJSON `json:"maps"`
	Lookups []hookSiteJSON      `json:"lookups"`
	Rule    syscallhook.Rule    `json:"rule"`
}

// discoveredMapJSON is one map the program references, with the PCs of its
// lookups; a map the program only passes to other helpers has none.
type discoveredMapJSON struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Sites []uint32 `json:"sites"`
}

func discoveryJSON(d syscallhook.Discovery) discoveredProgJSON {
	out := discoveredProgJSON{Program: d.Program, Func: d.Func, Type: d.Type.String(), CtxType: inject.ContextType(d.Type),
		Maps: []discoveredMapJSON{}, Lookups: []hookSiteJSON{}}
	index := map[string]int{}
	for _, site := range d.Lookups {
		out.Lookups = append(out.Lookups, siteJSON(inject.HookLookup, site))
		if site.MapName == "" {
			continue
		}
		i, ok := index[site.MapName]
		if !ok {
			i = len(out.Maps)
			index[site.MapName] = i
			out.Maps = append(out.Maps, discoveredMapJSON{Name: site.MapName, Type: d.Maps[site.MapName].String()})
			out.Rule.Maps = append(out.Rule.Maps, site.MapName)
		}
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
		out.Maps = append(out.Maps, discoveredMapJSON{Name: name, Type: d.Maps[name].String(), Sites: []uint32{}})
	}
	out.Rule.Program = cmp.Or(d.Func, d.Program)
	out.Rule.Auto = true
	out.Rule.Hook = lookupsRuleHook
	return out
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
