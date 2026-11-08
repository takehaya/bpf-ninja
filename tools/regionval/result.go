package regionval

import (
	"errors"
	"slices"
	"time"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
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

type WindowResult struct {
	Kind     string `json:"kind"`
	CoreKind string `json:"core_kind"` // the obligation kind the core judged (windowKind)
	Func     string `json:"func"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	core.Verdict
}

type Counts struct {
	Windows      int            `json:"windows"`
	Validated    int            `json:"validated"`
	NotValidated int            `json:"not_validated"`
	ByKind       map[string]int `json:"by_kind"`
}

// Run checks one capture file. The load is validated only if the structure
// checks pass and every window is validated by core.Check.
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
	all := true
	for _, w := range l.Windows {
		cw := l.CoreWindow(w)
		v := core.Check(cw)
		r.Windows = append(r.Windows, WindowResult{Kind: w.Kind, CoreKind: cw.Kind, Func: w.Func, Start: w.Start, End: w.End, Verdict: v})
		r.Counts.Windows++
		r.Counts.ByKind[w.Kind]++
		if v.Validated {
			r.Counts.Validated++
		} else {
			r.Counts.NotValidated++
			all = false
		}
	}
	r.Validated = r.Structure.OK && all
	return r
}
