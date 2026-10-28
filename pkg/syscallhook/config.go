// Package syscallhook supervises an unmodified loader at the bpf syscall boundary.
package syscallhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// Rule selects exactly one lookup unless AllMatches or SitePCs widens it (see
// inject.LookupSelector). With Auto, every supported lookup is instrumented,
// the selector fields must be empty, and Hook is the prefix of the per-map
// hook names (see inject.LookupRequest); Maps limits Auto to the named maps.
// Entry and TailCalls add the Hook_entry and Hook_tail_call hooks and allow a
// rule without lookups.
// CopyReadOnly passes stack copies of BPF_F_RDONLY_PROG map values to typed
// hooks, and StaticUntrusted gives the hooks that would take arg:untrusted
// pointers static linkage (see inject.LookupRequest). Dispatch sends every
// site to one hook named Hook (see inject.LookupRequest.Dispatch); a lookup or
// tail-call site then needs a fourth spill slot in a frame that also calls the
// hook, so stack_lowest_offset must be at least -448 unless the rule has only
// entry.
// Ops picks the map operations a rule's hooks observe, as op or op:when:
// "lookup" or "lookup:hit", "lookup:miss" or "lookup:any" (see
// inject.LookupRequest.Lookups), "update" or "update:error", "update:any",
// and the same for "delete", "push", "pop" and "peek" (see
// inject.LookupRequest.Updates and Pushes). Without ops a rule observes
// lookup hits; with ops it observes only the ops listed. Every op but lookup
// needs auto, and an update needs one spill slot more (two with dispatch).
// StackLowestOffset is the caller's audit of all stack accesses, including
// aliases and callees (see inject.StackAudit).
type Rule struct {
	Program           string   `json:"program"`
	Auto              bool     `json:"auto,omitempty"`
	Maps              []string `json:"maps,omitempty"`
	Entry             bool     `json:"entry,omitempty"`
	TailCalls         bool     `json:"tail_calls,omitempty"`
	CopyReadOnly      bool     `json:"copy_read_only,omitempty"`
	StaticUntrusted   bool     `json:"static_untrusted,omitempty"`
	Dispatch          bool     `json:"dispatch,omitempty"`
	Ops               []string `json:"ops,omitempty"`
	Map               string   `json:"map,omitempty"`
	Func              string   `json:"func,omitempty"`
	Line              uint32   `json:"line,omitempty"`
	AllMatches        bool     `json:"all_matches,omitempty"`
	SitePCs           []uint32 `json:"site_pcs,omitempty"`
	Hook              string   `json:"hook"`
	StackLowestOffset *int16   `json:"stack_lowest_offset"`
}

// request is the raw transform request r stands for; every field but Program,
// which selects the load, is forwarded (TestRuleRequestForwardsOptions guards
// against a dropped field).
func (r Rule) request() inject.LookupRequestRaw {
	var lo int16
	if r.StackLowestOffset != nil {
		lo = *r.StackLowestOffset
	}
	ops, _ := parseOps(r.Ops) // Validate reports the error
	return inject.LookupRequestRaw{
		Site:            inject.LookupSelector{MapName: r.Map, FuncName: r.Func, Line: r.Line, AllMatches: r.AllMatches, SitePCs: r.SitePCs},
		Auto:            r.Auto,
		Maps:            r.Maps,
		Entry:           r.Entry,
		TailCalls:       r.TailCalls,
		CopyReadOnly:    r.CopyReadOnly,
		StaticUntrusted: r.StaticUntrusted,
		Dispatch:        r.Dispatch,
		Lookups:         ops.lookups,
		Updates:         ops.updates,
		Deletes:         ops.deletes,
		Pushes:          ops.pushes,
		Pops:            ops.pops,
		Peeks:           ops.peeks,
		HookName:        r.Hook,
		Stack:           inject.StackAudit{LowestOffset: lo},
	}
}

// ruleOps is Rule.Ops as the results each op's hooks observe.
type ruleOps struct {
	lookups                               inject.LookupWhen
	updates, deletes, pushes, pops, peeks inject.CallWhen
}

// parseOps reads Rule.Ops. No ops observes lookup hits; a list without
// lookup observes no lookup.
func parseOps(ops []string) (ruleOps, error) {
	if len(ops) == 0 {
		return ruleOps{}, nil
	}
	parsed := ruleOps{lookups: inject.LookupNone}
	seen := map[string]bool{}
	for _, op := range ops {
		name, when, _ := strings.Cut(op, ":")
		if seen[name] {
			return ruleOps{}, fmt.Errorf("op %s is given twice", name)
		}
		seen[name] = true
		switch name {
		case "lookup":
			switch w := inject.LookupWhen(when); w {
			case "":
				parsed.lookups = inject.LookupHit
			case inject.LookupHit, inject.LookupMiss, inject.LookupAny:
				parsed.lookups = w
			default:
				return ruleOps{}, fmt.Errorf("op %q: lookup takes hit, miss or any", op)
			}
		case "update", "delete", "push", "pop", "peek":
			w := inject.CallWhen(when)
			switch w {
			case "":
				w = inject.CallError
			case inject.CallError, inject.CallAny:
			default:
				return ruleOps{}, fmt.Errorf("op %q: %s takes error or any", op, name)
			}
			*map[string]*inject.CallWhen{"update": &parsed.updates, "delete": &parsed.deletes,
				"push": &parsed.pushes, "pop": &parsed.pops, "peek": &parsed.peeks}[name] = w
		default:
			return ruleOps{}, fmt.Errorf("unknown op %q", op)
		}
	}
	return parsed, nil
}

func Validate(rules []Rule) error {
	if len(rules) == 0 {
		return fmt.Errorf("at least one injection rule is required")
	}
	seen := make(map[string]bool)
	for i, r := range rules {
		if r.Program == "" || (r.Map == "" && !r.Auto && !r.Entry && !r.TailCalls) {
			return fmt.Errorf("rule %d: program and one of map, auto, entry or tail_calls are required", i)
		}
		if (r.Auto || r.Map == "") && (r.Func != "" || r.Line != 0 || r.AllMatches || len(r.SitePCs) > 0) {
			return fmt.Errorf("rule %d: func, line, all_matches and site_pcs filter map and cannot be used with auto or without map", i)
		}
		if len(r.Maps) != 0 && !r.Auto {
			return fmt.Errorf("rule %d: maps filters auto and needs it", i)
		}
		if _, err := parseOps(r.Ops); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if len(r.Ops) != 0 && r.Map == "" && !r.Auto {
			return fmt.Errorf("rule %d: ops applies to the hooks of map or auto", i)
		}
		if r.Auto && r.Map != "" {
			return fmt.Errorf("rule %d: auto selects every supported lookup; map must be empty", i)
		}
		if seen[r.Program] {
			return fmt.Errorf("rule %d: only one rule per program is supported", i)
		}
		seen[r.Program] = true
		if r.AllMatches && len(r.SitePCs) > 0 {
			return fmt.Errorf("rule %d: all_matches and site_pcs are mutually exclusive", i)
		}
		if r.StackLowestOffset == nil {
			return fmt.Errorf("rule %d: audited stack_lowest_offset is required", i)
		}
		// The hook-name and stack limits come from inject, so Validate cannot
		// drift from the transform. The generic-hook map slot, a CopyReadOnly
		// value copy and call-chain limits are program-dependent and are
		// enforced during the transform.
		if err := inject.ValidateRaw(r.request()); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return nil
}

// ParseConfig reads a strict JSON array. Unknown keys and trailing data are errors.
func ParseConfig(r io.Reader) ([]Rule, error) {
	data, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("injection config: %w", err)
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("injection config exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var rules []Rule
	if err := d.Decode(&rules); err != nil {
		return nil, fmt.Errorf("injection config: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("injection config: expected one JSON array")
	}
	if err := Validate(rules); err != nil {
		return nil, err
	}
	return rules, nil
}
