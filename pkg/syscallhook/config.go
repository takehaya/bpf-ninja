// Package syscallhook supervises an unmodified loader at the bpf syscall boundary.
package syscallhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// Rule selects exactly one lookup unless AllMatches or SitePCs widens it (see
// inject.LookupSelector). With Auto, every supported lookup is instrumented,
// the selector fields must be empty, and Hook is the prefix of the per-map
// hook names (see inject.LookupRequest). Entry and TailCalls add the
// Hook_entry and Hook_tail_call hooks and allow a rule without lookups.
// CopyReadOnly passes stack copies of BPF_F_RDONLY_PROG map values to typed
// hooks, and StaticUntrusted gives the hooks that would take arg:untrusted
// pointers static linkage (see inject.LookupRequest). Dispatch sends every
// site to one hook named Hook (see inject.LookupRequest.Dispatch); a lookup or
// tail-call site then needs a fourth spill slot in a frame that also calls the
// hook, so stack_lowest_offset must be at least -448 unless the rule has only
// entry.
// StackLowestOffset is the caller's audit of all stack accesses, including
// aliases and callees (see inject.StackAudit).
type Rule struct {
	Program           string   `json:"program"`
	Auto              bool     `json:"auto,omitempty"`
	Entry             bool     `json:"entry,omitempty"`
	TailCalls         bool     `json:"tail_calls,omitempty"`
	CopyReadOnly      bool     `json:"copy_read_only,omitempty"`
	StaticUntrusted   bool     `json:"static_untrusted,omitempty"`
	Dispatch          bool     `json:"dispatch,omitempty"`
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
	return inject.LookupRequestRaw{
		Site:            inject.LookupSelector{MapName: r.Map, FuncName: r.Func, Line: r.Line, AllMatches: r.AllMatches, SitePCs: r.SitePCs},
		Auto:            r.Auto,
		Entry:           r.Entry,
		TailCalls:       r.TailCalls,
		CopyReadOnly:    r.CopyReadOnly,
		StaticUntrusted: r.StaticUntrusted,
		Dispatch:        r.Dispatch,
		HookName:        r.Hook,
		Stack:           inject.StackAudit{LowestOffset: lo},
	}
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
