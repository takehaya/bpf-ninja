package kunai

import (
	"strings"
	"testing"

	xdphost "github.com/takehaya/bpf-ninja/pkg/kunai/host/xdp"
)

// TestExamplesHelpCompiles pins that every expression --dsl-help prints
// as an example compiles, so the help cannot drift from the grammar.
func TestExamplesHelpCompiles(t *testing.T) {
	caps := xdphost.FexitCapabilities()
	caps.Lang.SetSlots = fakeSetSlots{}
	n := 0
	for _, line := range strings.Split(ExamplesHelp, "\n") {
		expr := strings.TrimSpace(line)
		if !strings.HasPrefix(expr, "eth") {
			continue
		}
		if i := strings.Index(expr, " #"); i >= 0 {
			expr = strings.TrimSpace(expr[:i])
		}
		n++
		if _, err := Compile(expr, caps); err != nil {
			t.Errorf("example %q: %v", expr, err)
		}
	}
	if n == 0 {
		t.Fatal("no examples found in ExamplesHelp")
	}
}
