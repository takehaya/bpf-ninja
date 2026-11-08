package regionval

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	"github.com/takehaya/bpf-ninja/tools/regionval/dafny/contract"
	rd "github.com/takehaya/bpf-ninja/tools/regionval/dafny/regionvaldafny"
)

// Result is the output for one load (README.md, Output). Window start/end are decoded
// indices of the transformed stream. Every bool defaults to false, so a
// partly filled result never reads as validated.
type Result struct {
	Load      string         `json:"load"`
	Validated bool           `json:"validated"`
	Structure Structure      `json:"structure"`
	Windows   []WindowResult `json:"windows"`
	Counts    Counts         `json:"counts"`
	TimeMs    int64          `json:"time_ms"`
	TimeUs    int64          `json:"time_us"` // the same duration in µs
}

type Structure struct {
	KappaOK bool   `json:"kappa_ok"`
	EdgesOK bool   `json:"edges_ok"`
	OK      bool   `json:"ok"`
	Stage   string `json:"failed_stage,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// WindowResult is the verdict on one window. Validated is the Dafny core's
// verdict (contract.Validate); Rule, Reason and Paths come from the Go core
// (core.Check), except that a window only the Go core validates has rule
// "dafny" and the Dafny core's reason. A window only the Dafny core
// validates keeps the Go core's rule and reason; Disagree marks both cases.
type WindowResult struct {
	Kind     string `json:"kind"`
	CoreKind string `json:"core_kind"` // the obligation kind the core judged (windowKind)
	Func     string `json:"func"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	core.Verdict
	GoValidated bool   `json:"go_validated"`
	DafnyReason string `json:"dafny_reason,omitempty"`
	Disagree    bool   `json:"disagree"` // the two cores' verdicts differ
}

type Counts struct {
	Windows      int            `json:"windows"`
	Validated    int            `json:"validated"`
	NotValidated int            `json:"not_validated"`
	Disagree     int            `json:"disagree"`
	ByKind       map[string]int `json:"by_kind"`
}

// Run checks one capture file. The load is validated only if the structure
// checks pass and the Dafny core validates every window.
func Run(path string) (r Result) { // named: the deferred timing must reach the caller
	t0 := time.Now()
	r = Result{Load: path, Counts: Counts{ByKind: map[string]int{}}}
	defer func() { d := time.Since(t0); r.TimeMs, r.TimeUs = d.Milliseconds(), d.Microseconds() }()
	c, err := LoadCapture(path)
	var l *Layout
	if err == nil {
		l, err = Analyze(c)
	}
	if err != nil {
		var se *StructError
		r.Structure.Stage, r.Structure.Reason = "load", err.Error()
		if errors.As(err, &se) {
			r.Structure.Stage, r.Structure.Reason = se.Stage, se.Msg
			r.Structure.KappaOK = !slices.Contains([]string{"decode", "funcs", "floors", "kappa"}, se.Stage)
			r.Structure.EdgesOK = r.Structure.KappaOK && se.Stage != "windows" && se.Stage != "edges"
		}
		return r
	}
	r.Structure = Structure{KappaOK: true, EdgesOK: true, OK: true}
	r.judgeWindows(l)
	return r
}

// judgeWindows judges every window of l and sets the window results, the
// counts and the load verdict.
func (r *Result) judgeWindows(l *Layout) {
	all := true
	for _, w := range l.Windows {
		wr := judge(l, w)
		r.Windows = append(r.Windows, wr)
		r.Counts.Windows++
		r.Counts.ByKind[w.Kind]++
		if wr.Disagree {
			r.Counts.Disagree++
		}
		if wr.Validated {
			r.Counts.Validated++
		} else {
			r.Counts.NotValidated++
			all = false
		}
	}
	r.Validated = r.Structure.OK && all
}

// judge runs both cores on window w. The verdict is the Dafny core's.
func judge(l *Layout, w Window) WindowResult {
	cw := l.CoreWindow(w)
	insns, body, helper := l.WindowBytes(w)
	wr := WindowResult{Kind: w.Kind, CoreKind: cw.Kind, Func: w.Func, Start: w.Start, End: w.End}
	wr.merge(core.Check(cw), contract.Validate(cw, insns, body, helper))
	return wr
}

// merge sets the verdict fields from the Go core's verdict g and the Dafny
// core's verdict d.
func (wr *WindowResult) merge(g core.Verdict, d rd.Verdict) {
	wr.Verdict, wr.GoValidated, wr.Disagree = g, g.Validated, g.Validated != d.Validated
	wr.Validated = d.Validated
	if !d.Validated {
		wr.DafnyReason = d.Reason
		if d.PC >= 0 {
			wr.DafnyReason = fmt.Sprintf("insn %d: %s", d.PC, d.Reason)
		}
		if g.Validated {
			wr.Rule, wr.Reason = "dafny", "dafny: "+wr.DafnyReason
		}
	}
}
