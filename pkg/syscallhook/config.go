// Package syscallhook supervises an unmodified loader at the bpf syscall boundary.
package syscallhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// Rule selects exactly one lookup. StackLowestOffset is the caller's audit of
// all stack accesses, including aliases and callees (see inject.StackAudit).
type Rule struct {
	Program           string `json:"program"`
	Map               string `json:"map"`
	Func              string `json:"func,omitempty"`
	Line              uint32 `json:"line,omitempty"`
	Hook              string `json:"hook"`
	StackLowestOffset *int16 `json:"stack_lowest_offset"`
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Validate(rules []Rule) error {
	if len(rules) == 0 {
		return fmt.Errorf("at least one injection rule is required")
	}
	seen := make(map[string]bool)
	for i, r := range rules {
		if r.Program == "" || r.Map == "" || !identifier.MatchString(r.Hook) || len(r.Hook) > 127 {
			return fmt.Errorf("rule %d: program, map and a C identifier hook (at most 127 bytes) are required", i)
		}
		if seen[r.Program] {
			return fmt.Errorf("rule %d: only one rule per program is supported", i)
		}
		seen[r.Program] = true
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
