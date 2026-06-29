package program

// Verifier-load coverage for the B4 filter-only drop builder
// (program_xdpdrop.go). Loads the program for the floor / accept-all
// paths and for every FilterSet entry on the kunai path plus a cbpfc
// representative; no attach, so a plain root environment (or vimto)
// is enough.

import (
	"os"
	"testing"
)

func TestBpfXDPDropLoads(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	type tc struct {
		name   string
		expr   string
		useDSL bool
		floor  bool
	}
	cases := []tc{
		{name: "floor", floor: true},
		{name: "accept_all"},
		{name: "cbpfc_F1", expr: "tcp dst port 443"},
	}
	for _, fs := range FilterSet {
		cases = append(cases, tc{name: "kunai_" + fs.ID, expr: fs.Expr, useDSL: true})
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bench, err := newXDPDropBench(c.expr, c.useDSL, c.floor)
			if err != nil {
				t.Fatalf("newXDPDropBench(%q): %v", c.expr, err)
			}
			_ = bench.Close()
		})
	}
}
