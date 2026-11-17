// Package syscallhook supervises an unmodified loader at the bpf syscall boundary.
// Run must not be called from a process that has other children it waits for,
// because its ptrace wait loop can consume their status.
package syscallhook

import (
	"bytes"
	"cmp"
	"encoding/hex"
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
// rule without lookups. Calls names helpers and kernel functions; each named
// callee gets one hook, Hook_<name>, after every call of it, and also allows a
// rule without lookups. A name that is not a helper is checked against the
// kernel BTF of the load, not here.
// CopyReadOnly passes stack copies of BPF_F_RDONLY_PROG map values to typed
// hooks, and StaticUntrusted gives the hooks that would take arg:untrusted
// pointers static linkage (see inject.LookupRequest); without it, Run probes
// the running kernel once and gives them static linkage only if the kernel
// rejects arg:untrusted (see HookForm). Dispatch sends every
// site to one hook named Hook (see inject.LookupRequest.Dispatch); a lookup or
// tail-call site then needs a fourth spill slot in a frame that also calls the
// hook. Auto checks that larger bound after discovery and skips groups that do
// not fit; an explicit selection is checked against its function's verifier floor.
// Ops picks the map operations a rule's hooks observe, as op or op:when:
// "lookup" or "lookup:hit", "lookup:miss" or "lookup:any" (see
// inject.LookupRequest.Lookups), "update" or "update:error", "update:any",
// and the same for "delete", "push", "pop" and "peek" (see
// inject.LookupRequest.Updates and Pushes). Without ops a rule observes
// lookup hits; with ops it observes only the ops listed. Every op but lookup
// needs auto, and an update needs one spill slot more (two with dispatch).
// MapBTF pins an ELF source for a BTF-less map and optionally selects exact
// BTF names to fill untyped sides; already typed sides accept only the same type.
//
// HookPrefix is Hook in a rule that states every kind explicitly: in such a
// rule a missing or empty maps, ops or calls selects none of that kind, so
// deleting a name never adds a hook. A rule written with Hook keeps the
// meanings above. A rule may carry both only when they are equal.
//
// Sites narrows a hook_prefix rule to sites of one listing (see Sites); it
// does not combine with map, func, line, all_matches or site_pcs.
type Rule struct {
	Program             string          `json:"program"`
	Auto                bool            `json:"auto,omitempty"`
	Maps                []string        `json:"maps,omitempty"`
	Entry               bool            `json:"entry,omitempty"`
	TailCalls           bool            `json:"tail_calls,omitempty"`
	Calls               []string        `json:"calls,omitempty"`
	CopyReadOnly        bool            `json:"copy_read_only,omitempty"`
	StaticUntrusted     bool            `json:"static_untrusted,omitempty"`
	Dispatch            bool            `json:"dispatch,omitempty"`
	Ops                 []string        `json:"ops,omitempty"`
	MapBTF              *MapBTF         `json:"map_btf,omitempty"`
	Map                 string          `json:"map,omitempty"`
	Func                string          `json:"func,omitempty"`
	Line                uint32          `json:"line,omitempty"`
	AllMatches          bool            `json:"all_matches,omitempty"`
	SitePCs             []uint32        `json:"site_pcs,omitempty"`
	Hook                string          `json:"hook,omitempty"`
	HookPrefix          string          `json:"hook_prefix,omitempty"`
	Sites               *Sites          `json:"sites,omitempty"`
	StackLowestOffset   json.RawMessage `json:"stack_lowest_offset,omitempty"`
	LegacyFrameRounding json.RawMessage `json:"frame_rounding,omitempty"`
}

// MapBTF pins the ELF supplying missing map BTF types to a SHA-256 digest.
// KeyType and ValueType optionally select exact names with fill-only semantics.
type MapBTF struct {
	ELF       string `json:"elf"`
	SHA256    string `json:"sha256"`
	KeyType   string `json:"key_type,omitempty"`
	ValueType string `json:"value_type,omitempty"`
}

// request forwards the transform options; the supervisor handles Program and
// the map type source before calling the transform.
func (r Rule) request() inject.LookupRequestRaw {
	ops, _ := parseOps(r.Ops) // Validate reports the error
	maps := r.Maps
	if r.HookPrefix != "" && r.Map == "" && (len(r.Ops) == 0 || len(r.Maps) == 0) {
		// An explicit rule without ops or maps observes no map call; a map
		// rule names its one site itself and observes it without ops.
		maps, ops = nil, ruleOps{lookups: inject.LookupNone}
	}
	return inject.LookupRequestRaw{
		Site:            inject.LookupSelector{MapName: r.Map, FuncName: r.Func, Line: r.Line, AllMatches: r.AllMatches, SitePCs: r.SitePCs},
		Auto:            r.Auto,
		Maps:            maps,
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
		HookName:        cmp.Or(r.HookPrefix, r.Hook),
		Calls:           r.Calls,

		// An explicit rule skips a maps name with no call of its ops.
		SkipUnmatchedMaps: r.HookPrefix != "",
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
		if r.Hook != "" && r.HookPrefix != "" && r.Hook != r.HookPrefix {
			return fmt.Errorf("rule %d: hook and hook_prefix are both given and differ (%q and %q); keep hook_prefix", i, r.Hook, r.HookPrefix)
		}
		if r.Hook == "" && r.HookPrefix == "" {
			return fmt.Errorf("rule %d: hook_prefix is required", i)
		}
		if r.Program == "" || (r.Map == "" && !r.Auto && !r.Entry && !r.TailCalls && len(r.Calls) == 0) {
			return fmt.Errorf("rule %d: program and one of map, auto, entry, tail_calls or calls are required", i)
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
		if err := r.validateMapTypes(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if r.Auto && r.Map != "" {
			return fmt.Errorf("rule %d: auto selects every supported lookup; map must be empty", i)
		}
		if err := r.validateSites(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if seen[r.Program] {
			return fmt.Errorf("rule %d: only one rule per program is supported", i)
		}
		seen[r.Program] = true
		if r.AllMatches && len(r.SitePCs) > 0 {
			return fmt.Errorf("rule %d: all_matches and site_pcs are mutually exclusive", i)
		}
		if r.StackLowestOffset != nil {
			return fmt.Errorf("rule %d: stack_lowest_offset is no longer accepted; inject-run takes the stack floor from the verifier; remove the field", i)
		}
		if r.LegacyFrameRounding != nil {
			return fmt.Errorf("rule %d: frame_rounding is no longer accepted; inject-run detects the running kernel's frame rounding; remove the field", i)
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
	// The key hook_prefix marks a rule that states every kind; empty, it would
	// read as a hook rule, whose empty maps and ops select everything.
	var keys []map[string]json.RawMessage
	_ = json.Unmarshal(data, &keys) // decoded above
	for i, rule := range keys {
		if v, ok := rule["hook_prefix"]; ok && (string(v) == `""` || string(v) == "null") {
			return nil, fmt.Errorf("rule %d: hook_prefix is empty; give the prefix or remove the key", i)
		}
	}
	if err := Validate(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (r Rule) validateMapTypes() error {
	if r.MapBTF == nil {
		return nil
	}
	if r.MapBTF.ELF == "" {
		return fmt.Errorf("map_btf.elf is required when map_btf is present")
	}
	if r.Map == "" || r.Auto || inject.KernelObjName(r.Map) != r.Map {
		return fmt.Errorf("map_btf.elf requires a single explicit map kernel name (1-15 bytes), without auto")
	}
	if r.Dispatch {
		return fmt.Errorf("map_btf.elf requires typed lookup hooks; dispatch uses a generic signature")
	}
	for _, op := range r.Ops {
		if name, _, _ := strings.Cut(op, ":"); name != "lookup" {
			return fmt.Errorf("map_btf.elf supports lookup hooks only")
		}
	}
	hash, err := hex.DecodeString(r.MapBTF.SHA256)
	if err != nil || len(hash) != 32 {
		return fmt.Errorf("map_btf.sha256 must contain exactly 64 hexadecimal digits")
	}
	return nil
}
