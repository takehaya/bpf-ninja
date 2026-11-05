//go:build linux && amd64

// JSON shape of inject-run --hooks-json: the hooks each injected program
// calls, so a tracer can find what to attach to without scraping the log.
package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

// hooksJSONVersion changes only when a field changes meaning or goes away.
const hooksJSONVersion = 2

type hooksFileJSON struct {
	Version  int                `json:"version"`
	Programs []injectedProgJSON `json:"programs"`
}

// injectedProgJSON is one successful injected load. ProgID is zero when the
// tracee could not query it.
type injectedProgJSON struct {
	Program  string               `json:"program"`
	Func     string               `json:"func"`
	Type     string               `json:"type"`
	ProgID   uint32               `json:"prog_id"`
	CtxType  string               `json:"ctx_type"`
	HookForm syscallhook.HookForm `json:"hook_form"`
	Hooks    []hookJSON           `json:"hooks"`
	Skipped  []hookSiteJSON       `json:"skipped"`
	Stack    *inject.StackReport  `json:"stack,omitempty"`
	// DeadCheckError names hook comparisons that failed. Those hooks and any
	// site they may report stay unmarked; independent known results remain.
	DeadCheckError string `json:"dead_check_error,omitempty"`
}

// hookJSON is one hook function. A dispatch hook is one entry carrying every
// site it reports; the entry call is the site inject.DispatchEntrySite. When
// is the results that call the hook: hit, miss or any for lookups, error or
// any for updates, deletes, pushes, pops and peeks. A dispatch hook's When is
// its lookups'; its other map call sites carry their own.
type hookJSON struct {
	Name           string         `json:"name"`
	Kind           string         `json:"kind"`
	When           string         `json:"when,omitempty"`
	Map            string         `json:"map,omitempty"`
	Sites          []hookSiteJSON `json:"sites"`
	Untrusted      bool           `json:"untrusted"`
	Copied         bool           `json:"copied"`
	Static         bool           `json:"static"`
	ReadOnly       bool           `json:"read_only"`
	DeadInThisLoad bool           `json:"dead_in_this_load,omitempty"`
	DeadCause      string         `json:"dead_cause,omitempty"`
}

// hookSiteJSON is one instrumented (or, with Reason, skipped) helper call.
type hookSiteJSON struct {
	Kind      string `json:"kind"`
	PC        uint32 `json:"pc"`
	Map       string `json:"map,omitempty"`
	Func      string `json:"func,omitempty"`
	File      string `json:"file,omitempty"`
	Line      uint32 `json:"line,omitempty"`
	CtxSource string `json:"ctx_source,omitempty"`
	Frame     string `json:"frame,omitempty"`
	Floor     *int16 `json:"floor,omitempty"`
	Reason    string `json:"reason,omitempty"`
	When      string `json:"when,omitempty"`
	// Generic is set only in the lookups file: auto instruments the lookup
	// through the generic hook despite Reason.
	Generic        bool   `json:"generic,omitempty"`
	DeadInThisLoad bool   `json:"dead_in_this_load,omitempty"`
	DeadCause      string `json:"dead_cause,omitempty"`
}

const deadHookCause = "the verifier removed this generated hook as unreachable in this load"

func markDeadHooks(out *injectedProgJSON, availability map[string]attach.FuncAvailability) []hookSiteJSON {
	type siteKey struct {
		kind, mapName, funcName string
		pc                      uint32
	}
	type siteState struct {
		refs        []*hookSiteJSON
		hooks, dead int
	}
	sites := map[siteKey]*siteState{}
	for i := range out.Hooks {
		hook := &out.Hooks[i]
		dead := availability[hook.Name].Reason == attach.FuncAbsent
		if dead {
			hook.DeadInThisLoad = true
			hook.DeadCause = deadHookCause
		}
		for j := range hook.Sites {
			site := &hook.Sites[j]
			key := siteKey{kind: site.Kind, pc: site.PC, mapName: site.Map, funcName: site.Func}
			state := sites[key]
			if state == nil {
				state = &siteState{}
				sites[key] = state
			}
			state.refs = append(state.refs, site)
			state.hooks++
			if dead {
				state.dead++
			}
		}
	}
	var notices []hookSiteJSON
	for _, state := range sites {
		if state.hooks == 0 || state.dead != state.hooks {
			continue
		}
		for _, site := range state.refs {
			site.DeadInThisLoad = true
			site.DeadCause = deadHookCause
		}
		notices = append(notices, *state.refs[0])
	}
	slices.SortFunc(notices, func(a, b hookSiteJSON) int {
		return cmp.Or(cmp.Compare(a.PC, b.PC), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Map, b.Map), cmp.Compare(a.Func, b.Func))
	})
	return notices
}

func applyDeadHookAvailability(out *injectedProgJSON, availability map[string]attach.FuncAvailability, err error) []hookSiteJSON {
	if err != nil {
		out.DeadCheckError = err.Error()
	}
	return markDeadHooks(out, availability)
}

func loadedHookAvailabilities(progID uint32, names []string) (map[string]attach.FuncAvailability, error) {
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = prog.Close() }()
	info := attach.ProgInfo{ProgID: progID, Program: prog}
	out := make(map[string]attach.FuncAvailability, len(names))
	var errs []error
	for _, name := range names {
		if _, ok := out[name]; ok {
			continue
		}
		a := info.FuncAvailability(name)
		out[name] = a
		if a.Reason == attach.FuncUnknown || a.Reason == attach.FuncMissing || a.Reason == attach.FuncNotInTarget {
			errs = append(errs, fmt.Errorf("hook %s: %s", name, a.Explain()))
		}
	}
	return out, errors.Join(errs...)
}

func siteJSON(kind inject.HookKind, site inject.LookupSite) hookSiteJSON {
	return hookSiteJSON{Kind: string(kind), PC: site.SitePC, Map: site.MapName, Func: site.FuncName, File: site.File, Line: site.Line, CtxSource: site.CtxSource, Reason: site.Reason}
}

// hookKind is typed, generic, entry, tail_call or dispatch. The sites of a
// typed or generic hook say which map helper it observes.
func hookKind(hook inject.LookupHook) string {
	switch {
	case hook.Dispatch:
		return "dispatch"
	case hook.Generic:
		return "generic"
	case hook.Kind != inject.HookEntry && hook.Kind != inject.HookTailCall:
		return "typed"
	}
	return string(hook.Kind)
}

func injectionJSON(inj syscallhook.Injection) injectedProgJSON {
	out := injectedProgJSON{HookForm: inj.HookForm, Program: inj.Program, Func: inj.Func, Type: inj.Type.String(), ProgID: inj.ProgID,
		CtxType: inject.ContextType(inj.Type), Hooks: []hookJSON{}, Skipped: []hookSiteJSON{}}
	floors := make(map[string]int16, len(inj.Stack.Functions))
	for _, frame := range inj.Stack.Functions {
		floors[frame.Name] = frame.Floor
	}
	if inj.Stack.Source != "" {
		out.Stack = &inj.Stack
	}
	setFrame := func(site *hookSiteJSON, name string) {
		if out.Stack == nil || name == "" {
			return
		}
		floor, ok := floors[name]
		if !ok {
			return
		}
		site.Frame, site.Floor = name, &floor
	}
	dispatch := -1
	for _, hook := range inj.Hooks {
		var sites []hookSiteJSON
		if hook.Dispatch && hook.Kind == inject.HookEntry {
			site := hookSiteJSON{Kind: string(inject.HookEntry), PC: inject.DispatchEntrySite}
			setFrame(&site, inj.Func)
			sites = append(sites, site)
		}
		for _, site := range hook.Sites {
			s := siteJSON(hook.Kind, site)
			setFrame(&s, site.FuncName)
			if hook.Dispatch && hook.Kind.MapCall() {
				s.When = hook.When
			}
			sites = append(sites, s)
		}
		when := hook.When
		if hook.Dispatch && hook.Kind != inject.HookLookup {
			when = ""
		}
		// Dispatch hooks share one name; merge them into one function.
		if hook.Dispatch && dispatch >= 0 {
			out.Hooks[dispatch].Sites = append(out.Hooks[dispatch].Sites, sites...)
			if when != "" {
				out.Hooks[dispatch].When = when
			}
			continue
		}
		h := hookJSON{Name: hook.Name, Kind: hookKind(hook), When: when, Sites: sites, Untrusted: hook.Untrusted, Copied: hook.Copied, Static: hook.Static, ReadOnly: hook.ReadOnly}
		if !hook.Dispatch {
			h.Map = hook.MapName
		}
		if h.Sites == nil {
			h.Sites = []hookSiteJSON{}
		}
		if hook.Dispatch {
			dispatch = len(out.Hooks)
		}
		out.Hooks = append(out.Hooks, h)
	}
	// The merged groups are per map and kind; order them as the program runs:
	// the entry call first, then by PC.
	if dispatch >= 0 {
		rank := func(site hookSiteJSON) int64 {
			if site.Kind == string(inject.HookEntry) {
				return -1
			}
			return int64(site.PC)
		}
		slices.SortStableFunc(out.Hooks[dispatch].Sites, func(a, b hookSiteJSON) int { return cmp.Compare(rank(a), rank(b)) })
	}
	for _, site := range inj.Skipped {
		kind := site.Op
		if kind == "" {
			kind = inject.HookLookup
		}
		s := siteJSON(kind, site)
		setFrame(&s, site.FuncName)
		out.Skipped = append(out.Skipped, s)
	}
	return out
}

// hooksWriter rewrites path with every injection so far.
type hooksWriter struct {
	path     string
	file     hooksFileJSON
	lastDead []hookSiteJSON
}

func newHooksWriter(path string) (*hooksWriter, error) {
	w := &hooksWriter{path: path, file: hooksFileJSON{Version: hooksJSONVersion, Programs: []injectedProgJSON{}}}
	return w, w.write()
}

func (w *hooksWriter) add(inj syscallhook.Injection) error {
	out := injectionJSON(inj)
	w.lastDead = nil
	if inj.ProgID == 0 {
		out.DeadCheckError = "program ID unavailable; func_info was not checked"
	} else {
		names := make([]string, len(out.Hooks))
		for i := range out.Hooks {
			names[i] = out.Hooks[i].Name
		}
		availability, err := loadedHookAvailabilities(inj.ProgID, names)
		w.lastDead = applyDeadHookAvailability(&out, availability, err)
	}
	w.file.Programs = append(w.file.Programs, out)
	return w.write()
}

func (w *hooksWriter) write() error { return writeJSONFile(w.path, w.file) }

// writeJSONFile replaces path with v as indented JSON. The rename makes each
// version appear whole to a reader polling the file.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	// CreateTemp's 0600 would hide the file from an unprivileged reader.
	err = tmp.Chmod(0o644)
	if err == nil {
		_, err = tmp.Write(append(data, '\n'))
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}
