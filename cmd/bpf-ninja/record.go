package main

import (
	"fmt"
	"os"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
	"github.com/urfave/cli/v3"
)

// recordRequest is the parsed --record / --record-max pair.
type recordRequest struct{ opt recordbuild.Options }

func parseRecordFlags(cmd *cli.Command) (recordRequest, error) {
	mode, err := record.ParseMode(cmd.String("record"))
	if err != nil {
		return recordRequest{}, err
	}
	maxBytes := int(cmd.Int("record-max"))
	if maxBytes < 0 || maxBytes > record.MaxBytesLimit {
		return recordRequest{}, fmt.Errorf("--record-max %d: must be 0..%d", maxBytes, record.MaxBytesLimit)
	}
	if cmd.IsSet("record-max") && mode != record.ModeEntry {
		return recordRequest{}, fmt.Errorf("--record-max only applies to --record entry")
	}
	return recordRequest{recordbuild.Options{Mode: mode, Explicit: cmd.IsSet("record"), MaxBytes: maxBytes}}, nil
}

// unsupported refuses an explicit --record where nothing can be recorded
// and turns the default off there.
func (r *recordRequest) unsupported(where string) error {
	if r.opt.Explicit && r.opt.Mode != record.ModeNone {
		return fmt.Errorf("--record %s does not apply to %s; use --record none", r.opt.Mode, where)
	}
	r.opt.Mode = record.ModeNone
	return nil
}

// layouts returns one layout per target, or nil when no target records
// anything (the capture then keeps the plain layout).
func (r recordRequest) layouts(targets []attach.Target, filters []filter.TargetFilters) ([]*record.Layout, error) {
	if r.opt.Mode == record.ModeNone {
		return nil, nil
	}
	// One interface per target needs a site id in 1..255. The default turns
	// itself off past that; an explicit --record refuses.
	if len(targets) > 255 {
		if r.opt.Explicit {
			return nil, fmt.Errorf("--record supports at most 255 targets, %d resolved", len(targets))
		}
		return nil, nil
	}
	out := make([]*record.Layout, len(targets))
	found := false
	for i, t := range targets {
		var tf filter.TargetFilters
		if filters != nil {
			tf = filters[i]
		}
		l, err := recordbuild.Build(t, tf, r.opt)
		if err != nil {
			return nil, fmt.Errorf("func %s (id=%d): %w", t.FuncName, t.ProgID, err)
		}
		out[i] = l
		found = found || l != nil
	}
	if !found {
		if r.opt.Explicit {
			fmt.Fprintf(os.Stderr, "warning: --record %s: no target has anything to record; writing the plain layout\n", r.opt.Mode)
		}
		return nil, nil
	}
	return out, nil
}

// layout builds the layout of one target a capture that records follows
// later (follow.go).
func (r recordRequest) layout(t attach.Target, tf filter.TargetFilters) (*record.Layout, error) {
	return recordbuild.Build(t, tf, r.opt)
}

// omitted describes, per generated target, each condition the default
// filter layout tests but does not record (a path through a bpf_* struct).
func (r recordRequest) omitted(targets []attach.Target, filters []filter.TargetFilters) []string {
	if r.opt.Mode != record.ModeFilter || r.opt.Explicit || filters == nil {
		return nil
	}
	var out []string
	for i, t := range targets {
		if !recordbuild.Generated(t) {
			continue
		}
		for _, name := range recordbuild.OmittedFields(filters[i]) {
			out = append(out, fmt.Sprintf("record filter at %s (id=%d): %s is tested but not recorded (inside a bpf_* struct)", t.FuncName, t.ProgID, name))
		}
	}
	return out
}

// recordOutput switches cfg to the per-site hook layout: one interface per
// target, named after its function; each EPB of a recording site carries
// the site's decision state as its opt_comment. The hook layout has no
// per-verdict interfaces, so an exit capture puts the return value first in
// every comment instead.
func recordOutput(cfg *output.Config, targets []attach.Target, layouts []*record.Layout, attached []int, isFexit bool) {
	count := map[string]int{}
	for _, t := range targets {
		count[t.FuncName]++
	}
	active := make([]bool, len(targets))
	for _, i := range attached {
		active[i] = true
	}
	cfg.IsFexit, cfg.RawReturn, cfg.Actions, cfg.MultiPoint = false, false, nil, false
	cfg.Hooks, cfg.Records, cfg.NoRunIDs = make([]string, len(targets)), layouts, true
	cfg.RecordReturn = isFexit
	for i, t := range targets {
		cfg.Hooks[i] = t.FuncName
		if count[t.FuncName] > 1 {
			cfg.Hooks[i] = fmt.Sprintf("%s@%d", t.FuncName, t.ProgID)
		}
		if !active[i] {
			cfg.Hooks[i] = "SKIPPED:" + cfg.Hooks[i]
		}
	}
}
