//go:build linux && amd64

// JSON shape of inject-run --lookups-json: the lookups and maps of every XDP,
// tc and cgroup_skb program the target loads, with a rule to start from, so the maps to
// instrument can be picked before a second run.
package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

// lookupsJSONVersion changes only when a field changes meaning or goes away.
// Version 3 made rule a hook_prefix rule that names every listed kind.
const lookupsJSONVersion = 3

// lookupsRuleHook is the hook name the suggested rules use.
const lookupsRuleHook = "ninja"

// lookupsKinds are the kinds --lookups-kinds takes: lookups and the other map
// calls, helper and kernel-function calls, tail calls and the entry. They
// choose the arrays added in version 3 and what rule names; maps, lookups and
// calls are always written.
var lookupsKinds = []string{"lookups", "map_calls", "helpers", "kfuncs", "tail_calls", "entry"}

// parseLookupsKinds reads a comma-separated --lookups-kinds value; empty is every kind.
func parseLookupsKinds(value string) (map[string]bool, error) {
	kinds := map[string]bool{}
	if value == "" {
		for _, k := range lookupsKinds {
			kinds[k] = true
		}
		return kinds, nil
	}
	for _, k := range strings.Split(value, ",") {
		if !slices.Contains(lookupsKinds, k) {
			return nil, fmt.Errorf("unknown kind %q; kinds are %s", k, strings.Join(lookupsKinds, ", "))
		}
		kinds[k] = true
	}
	return kinds, nil
}

type lookupsFileJSON struct {
	Version  int                  `json:"version"`
	Programs []discoveredProgJSON `json:"programs"`
}

// discoveredProgJSON is one program load. Calls lists every map helper call
// the transform knows, with the op as kind; Reason and Generic are as for a
// lookup. Build is the listing fingerprint (inject.ListingFingerprint).
// Callees, CallSites and TailCalls list the helper and kernel-function calls
// and the tail calls of the listed kinds; every site carries a label.
// With the kinds lookups alone, Rule instruments every named map with lookups,
// as a hook rule. Otherwise it is a hook_prefix rule naming everything of the
// listed kinds it can hook (see readyRule). The stack block records the
// trial load's verifier-backed per-function floors.
type discoveredProgJSON struct {
	Program   string              `json:"program"`
	Func      string              `json:"func"`
	Type      string              `json:"type"`
	CtxType   string              `json:"ctx_type"`
	Build     string              `json:"build,omitempty"`
	Maps      []discoveredMapJSON `json:"maps"`
	Lookups   []hookSiteJSON      `json:"lookups"`
	Calls     []hookSiteJSON      `json:"calls"`
	Callees   []calleeJSON        `json:"callees,omitempty"`
	CallSites []hookSiteJSON      `json:"call_sites,omitempty"`
	TailCalls []hookSiteJSON      `json:"tail_calls,omitempty"`
	Rule      syscallhook.Rule    `json:"rule"`
	Stack     *inject.StackReport `json:"stack,omitempty"`
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

// calleeJSON is one helper or kernel function the program calls (see
// inject.Callee). Callees without a Reason may be named in a rule's calls,
// Typed ones with their typed hook; Reason says why another gets no hook.
type calleeJSON struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Module int16    `json:"module,omitempty"`
	Ret    string   `json:"ret,omitempty"`
	Typed  bool     `json:"typed"`
	Sites  []uint32 `json:"sites"`
	Reason string   `json:"reason,omitempty"`
}

func discoveryJSON(d syscallhook.Discovery, kinds map[string]bool) discoveredProgJSON {
	out := discoveredProgJSON{Program: d.Program, Func: d.Func, Type: d.Type.String(), CtxType: inject.ContextType(d.Type),
		Build: d.CallSites.Fingerprint, Maps: []discoveredMapJSON{}, Lookups: []hookSiteJSON{}, Calls: []hookSiteJSON{}}
	if d.Stack.Source != "" {
		out.Stack = &d.Stack
	}
	floors := make(map[string]int16, len(d.Stack.Functions))
	for _, frame := range d.Stack.Functions {
		floors[frame.Name] = frame.Floor
	}
	setFrame := func(site *hookSiteJSON, name string) {
		site.Label = d.CallSites.Labels[site.PC]
		floor, ok := floors[name]
		if out.Stack == nil || name == "" || !ok {
			return
		}
		site.Frame, site.Floor = name, &floor
	}
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
	// A site in a function with no usable floor is listed as Auto skips it.
	audit := inject.StackAudit{Frames: d.Stack.Frames(), Source: d.Stack.Source}
	mark := audit.MarkUnaudited
	if d.Stack.Source == "unavailable" {
		// inject-run does not transform a load whose trial load failed.
		mark = func(sites []inject.LookupSite) []inject.LookupSite {
			sites = slices.Clone(sites)
			for i := range sites {
				sites[i].Reason, sites[i].Generic = "stack audit unavailable", false
			}
			return sites
		}
	}
	for _, site := range mark(d.Lookups) {
		s := discoveredSiteJSON(site)
		setFrame(&s, site.FuncName)
		out.Lookups = append(out.Lookups, s)
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
	for _, site := range mark(d.Calls) {
		s := discoveredSiteJSON(site)
		setFrame(&s, site.FuncName)
		out.Calls = append(out.Calls, s)
		if i, ok := index[site.MapName]; ok && !slices.Contains(out.Maps[i].Ops, string(site.Op)) {
			out.Maps[i].Ops = append(out.Maps[i].Ops, string(site.Op))
		}
	}
	calleeKind := map[uint32]string{}
	for _, c := range d.CallSites.Callees {
		for _, pc := range c.Sites {
			calleeKind[pc] = c.Kind
		}
		if kinds[c.Kind+"s"] {
			out.Callees = append(out.Callees, calleeJSON{Name: c.Name, Kind: c.Kind, Module: c.Module, Ret: string(c.Ret),
				Typed: c.Typed, Sites: c.Sites, Reason: c.Reason})
		}
	}
	for _, site := range mark(d.CallSites.Sites) {
		if kinds[calleeKind[site.SitePC]+"s"] {
			s := discoveredSiteJSON(site)
			setFrame(&s, site.FuncName)
			out.CallSites = append(out.CallSites, s)
		}
	}
	if kinds["tail_calls"] {
		for _, site := range mark(d.CallSites.TailCalls) {
			s := discoveredSiteJSON(site)
			setFrame(&s, site.FuncName)
			out.TailCalls = append(out.TailCalls, s)
		}
	}
	out.Rule.Program = cmp.Or(d.Func, d.Program)
	out.Rule.Auto = true
	if len(kinds) == 1 && kinds["lookups"] {
		out.Rule.Hook = lookupsRuleHook
		return out
	}
	out.Rule = readyRule(out, d, kinds)
	return out
}

// readyRule is the hook_prefix rule that names everything of the listed kinds
// out can hook: each named map with a call of a listed op, and those ops as
// op:any; the callees without a reason (with a call-table row, or a helper
// that may be hooked); the entry; and the tail calls
// when the program has one. A key left out hooks nothing of its kind.
func readyRule(out discoveredProgJSON, d syscallhook.Discovery, kinds map[string]bool) syscallhook.Rule {
	rule := syscallhook.Rule{Program: cmp.Or(d.Func, d.Program), Auto: true, HookPrefix: lookupsRuleHook,
		Entry: kinds["entry"], TailCalls: kinds["tail_calls"] && len(d.CallSites.TailCalls) != 0}
	listed := func(op string) bool { return kinds["lookups"] && op == "lookup" || kinds["map_calls"] && op != "lookup" }
	var ops []string
	for _, m := range out.Maps {
		if m.Name == "" || !slices.ContainsFunc(m.Ops, listed) {
			continue
		}
		rule.Maps = append(rule.Maps, m.Name)
		for _, op := range m.Ops {
			if listed(op) && !slices.Contains(ops, op) {
				ops = append(ops, op)
			}
		}
	}
	for _, op := range []string{"lookup", "update", "delete", "push", "pop", "peek"} {
		if slices.Contains(ops, op) {
			rule.Ops = append(rule.Ops, op+":any")
		}
	}
	for _, c := range out.Callees {
		if c.Reason == "" {
			rule.Calls = append(rule.Calls, c.Name)
		}
	}
	return rule
}

func discoveredSiteJSON(site inject.LookupSite) hookSiteJSON {
	s := siteJSON(site.Op, site)
	s.Generic = site.Generic
	return s
}

// lookupsWriter rewrites path with every discovered load so far.
type lookupsWriter struct {
	path  string
	kinds map[string]bool
	file  lookupsFileJSON
}

func newLookupsWriter(path string, kinds map[string]bool) (*lookupsWriter, error) {
	w := &lookupsWriter{path: path, kinds: kinds, file: lookupsFileJSON{Version: lookupsJSONVersion, Programs: []discoveredProgJSON{}}}
	return w, writeJSONFile(w.path, w.file)
}

func (w *lookupsWriter) add(d syscallhook.Discovery) error {
	w.file.Programs = append(w.file.Programs, discoveryJSON(d, w.kinds))
	return writeJSONFile(w.path, w.file)
}
