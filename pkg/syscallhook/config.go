// Package syscallhook supervises an unmodified loader at the bpf syscall boundary.
package syscallhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// Rule selects exactly one lookup unless AllMatches or SitePCs widens it (see
// inject.LookupSelector). With Auto, every supported lookup is instrumented,
// the selector fields must be empty, and Hook is the prefix of the per-map
// hook names (see inject.LookupRequest). Entry and TailCalls add the
// Hook_entry and Hook_tail_call hooks and allow a rule without lookups.
// CopyReadOnly passes stack copies of BPF_F_RDONLY_PROG map values to typed
// hooks (see inject.LookupRequest).
// StackLowestOffset is the caller's audit of all stack accesses, including
// aliases and callees (see inject.StackAudit).
type Rule struct {
	Program           string   `json:"program"`
	Auto              bool     `json:"auto,omitempty"`
	Entry             bool     `json:"entry,omitempty"`
	TailCalls         bool     `json:"tail_calls,omitempty"`
	CopyReadOnly      bool     `json:"copy_read_only,omitempty"`
	Map               string   `json:"map,omitempty"`
	Func              string   `json:"func,omitempty"`
	Line              uint32   `json:"line,omitempty"`
	AllMatches        bool     `json:"all_matches,omitempty"`
	SitePCs           []uint32 `json:"site_pcs,omitempty"`
	Hook              string   `json:"hook"`
	StackLowestOffset *int16   `json:"stack_lowest_offset"`
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Validate(rules []Rule) error {
	if len(rules) == 0 {
		return fmt.Errorf("at least one injection rule is required")
	}
	seen := make(map[string]bool)
	for i, r := range rules {
		if r.Program == "" || (r.Map == "" && !r.Auto && !r.Entry && !r.TailCalls) || !identifier.MatchString(r.Hook) || len(r.Hook) > 127 {
			return fmt.Errorf("rule %d: program, a C identifier hook (at most 127 bytes) and one of map, auto, entry or tail_calls are required", i)
		}
		if (r.Auto || r.Map == "") && (r.Func != "" || r.Line != 0 || r.AllMatches || len(r.SitePCs) > 0) {
			return fmt.Errorf("rule %d: func, line, all_matches and site_pcs filter map and cannot be used with auto or without map", i)
		}
		// The transform appends these suffixes; auto also appends _MAP or _N.
		for _, suffix := range []struct {
			on   bool
			name string
		}{{r.Entry, "_entry"}, {r.TailCalls, "_tail_call"}, {r.Auto, "_0"}} {
			if suffix.on && len(r.Hook)+len(suffix.name) > 127 {
				return fmt.Errorf("rule %d: hook %q with suffix %q exceeds 127 bytes", i, r.Hook, suffix.name)
			}
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
		if r.StackLowestOffset == nil || *r.StackLowestOffset < -488 || *r.StackLowestOffset > 0 {
			return fmt.Errorf("rule %d: audited stack_lowest_offset in [-488, 0] is required (24 bytes reserved for the hook)", i)
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
