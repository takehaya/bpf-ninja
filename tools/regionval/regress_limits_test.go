package regionval

// Limits and coverage. A path of exactly MaxSteps executed instructions is
// within the limit; MaxSteps+1 is not.

import (
	"errors"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	"github.com/takehaya/bpf-ninja/tools/regionval/interp"
)

func TestStepLimitBoundary(t *testing.T) {
	window := func(n int) core.Window { // n × `r1 = r1`, then fall through
		w := core.Window{Kind: core.KindEntry, HasFloor: true}
		for i := 0; i < n; i++ {
			w.Insns = append(w.Insns, core.Insn{Op: 0xbf, Dst: 1, Src: 1})
		}
		return w
	}
	run := func(n int) core.Verdict { return core.Check(window(n)) }

	// Same-program control: the same window gives the same verdict twice.
	if a, b := run(core.MaxSteps), run(core.MaxSteps); a != b || !a.Validated {
		t.Fatalf("exactly %d steps: %+v / %+v, want validated twice", core.MaxSteps, a, b)
	}
	// Order swap: the verdict follows the length, not the position.
	for _, arms := range [][2]int{{core.MaxSteps, core.MaxSteps + 1}, {core.MaxSteps + 1, core.MaxSteps}} {
		a, b := run(arms[0]), run(arms[1])
		for i, v := range []core.Verdict{a, b} {
			if n := arms[i]; v.Validated != (n <= core.MaxSteps) || (!v.Validated && v.Rule != "limit") {
				t.Fatalf("order %v: %d steps gave %+v", arms, n, v)
			}
		}
	}
	if v := run(core.MaxSteps - 1); !v.Validated {
		t.Fatalf("%d steps refused: %+v", core.MaxSteps-1, v)
	}
	// Tool-free reference: the concrete interpreter runs the 4096-instruction
	// window to normal termination with exactly 4096 executed instructions.
	var in interp.Input
	in.Oracle = func(int) uint64 { return 0 }
	if out, err := interp.Run(window(core.MaxSteps), in); err != nil || len(out.Locs) != core.MaxSteps {
		t.Fatalf("reference run: %d instructions, %v", len(out.Locs), err)
	}
}

// S3-assigned (every inserted instruction lies in
// exactly one window) was unreachable through Run, because window
// extraction and the call checks refuse the inputs first. These cases call
// checkCalls directly on a layout whose call checks pass (no calls, no
// inserted functions), so only the coverage rule can refuse them.
//
// T has 8 instructions; κ = {0, 7} are originals, 1-6 are inserted. TFuncs[0]
// = [4, 7) stands for a wrapper W_i reached through a P8 window's Callee.
func TestS3Assigned(t *testing.T) {
	win := func(start, end, callee int) Window {
		return Window{Kind: "gap", Start: start, End: end, Center: -1, Orig: -1, Callee: callee}
	}
	cases := []struct {
		name    string
		windows []Window
		want    int // inserted instructions not in exactly one window
	}{
		{"all assigned", []Window{win(1, 4, 0)}, 0},
		{"all assigned, window holds originals", []Window{win(0, 4, 0)}, 0},
		{"unassigned", []Window{win(1, 3, 0)}, 1},                          // T[3] in no window
		{"unassigned wrapper", []Window{win(1, 4, -1)}, 3},                 // W_i in no window
		{"double, overlapping", []Window{win(1, 4, 0), win(3, 4, -1)}, 1},  // T[3] twice
		{"double, wrapper twice", []Window{win(1, 3, 0), win(3, 4, 0)}, 3}, // W_i twice
		{"double, wrapper also a window", []Window{win(1, 4, 0), win(4, 7, -1)}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := &Layout{T: make([]core.Insn, 8), Kappa: []int{0, 7},
				TFuncs: []Func{{Name: "w", Start: 4, End: 7}}, Windows: c.windows}
			if got := l.unassigned(); got != c.want {
				t.Fatalf("unassigned() = %d, want %d", got, c.want)
			}
			err := l.checkCalls(nil)
			if c.want == 0 {
				if err != nil {
					t.Fatalf("control refused: %v", err)
				}
				return
			}
			var se *StructError
			if !errors.As(err, &se) || se.Stage != "calls" || !strings.Contains(se.Msg, "not in exactly one window") {
				t.Fatalf("checkCalls = %v, want S3-assigned refusal", err)
			}
		})
	}
}
