//go:build linux && amd64

// JSON shape of inject-run --hooks-json: the hooks each injected program
// calls, so a tracer can find what to attach to without scraping the log.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

// hooksJSONVersion changes only when a field changes meaning or goes away.
const hooksJSONVersion = 1

type hooksFileJSON struct {
	Version  int                `json:"version"`
	Programs []injectedProgJSON `json:"programs"`
}

// injectedProgJSON is one successful injected load. ProgID is zero when the
// tracee could not query it.
type injectedProgJSON struct {
	Program string         `json:"program"`
	Func    string         `json:"func"`
	Type    string         `json:"type"`
	ProgID  uint32         `json:"prog_id"`
	CtxType string         `json:"ctx_type"`
	Hooks   []hookJSON     `json:"hooks"`
	Skipped []hookSiteJSON `json:"skipped"`
}

// hookJSON is one hook function. A dispatch hook is one entry carrying every
// site it reports; the entry call is the site inject.DispatchEntrySite.
type hookJSON struct {
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	Map       string         `json:"map,omitempty"`
	Sites     []hookSiteJSON `json:"sites"`
	Untrusted bool           `json:"untrusted"`
	Copied    bool           `json:"copied"`
	Static    bool           `json:"static"`
	ReadOnly  bool           `json:"read_only"`
}

// hookSiteJSON is one instrumented (or, with Reason, skipped) helper call.
type hookSiteJSON struct {
	Kind   string `json:"kind"`
	PC     uint32 `json:"pc"`
	Map    string `json:"map,omitempty"`
	Func   string `json:"func,omitempty"`
	File   string `json:"file,omitempty"`
	Line   uint32 `json:"line,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func siteJSON(kind inject.HookKind, site inject.LookupSite) hookSiteJSON {
	return hookSiteJSON{Kind: string(kind), PC: site.SitePC, Map: site.MapName, Func: site.FuncName, File: site.File, Line: site.Line, Reason: site.Reason}
}

// hookKind is typed, generic, entry, tail_call or dispatch.
func hookKind(hook inject.LookupHook) string {
	switch {
	case hook.Dispatch:
		return "dispatch"
	case hook.Generic:
		return "generic"
	case hook.Kind == inject.HookLookup:
		return "typed"
	}
	return string(hook.Kind)
}

func injectionJSON(inj syscallhook.Injection) injectedProgJSON {
	out := injectedProgJSON{Program: inj.Program, Func: inj.Func, Type: inj.Type.String(), ProgID: inj.ProgID,
		CtxType: inject.ContextType(inj.Type), Hooks: []hookJSON{}, Skipped: []hookSiteJSON{}}
	dispatch := -1
	for _, hook := range inj.Hooks {
		var sites []hookSiteJSON
		if hook.Dispatch && hook.Kind == inject.HookEntry {
			sites = append(sites, hookSiteJSON{Kind: string(inject.HookEntry), PC: inject.DispatchEntrySite})
		}
		for _, site := range hook.Sites {
			sites = append(sites, siteJSON(hook.Kind, site))
		}
		// Dispatch hooks share one name; merge them into one function.
		if hook.Dispatch && dispatch >= 0 {
			out.Hooks[dispatch].Sites = append(out.Hooks[dispatch].Sites, sites...)
			continue
		}
		h := hookJSON{Name: hook.Name, Kind: hookKind(hook), Sites: sites, Untrusted: hook.Untrusted, Copied: hook.Copied, Static: hook.Static, ReadOnly: hook.ReadOnly}
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
	for _, site := range inj.Skipped {
		out.Skipped = append(out.Skipped, siteJSON(inject.HookLookup, site))
	}
	return out
}

// hooksWriter rewrites path with every injection so far. The rename makes
// each version appear whole to a reader polling the file.
type hooksWriter struct {
	path string
	file hooksFileJSON
}

func newHooksWriter(path string) (*hooksWriter, error) {
	w := &hooksWriter{path: path, file: hooksFileJSON{Version: hooksJSONVersion, Programs: []injectedProgJSON{}}}
	return w, w.write()
}

func (w *hooksWriter) add(inj syscallhook.Injection) error {
	w.file.Programs = append(w.file.Programs, injectionJSON(inj))
	return w.write()
}

func (w *hooksWriter) write() error {
	data, err := json.MarshalIndent(w.file, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding hooks JSON: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(w.path), "."+filepath.Base(w.path)+".*")
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
		err = os.Rename(tmp.Name(), w.path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}
