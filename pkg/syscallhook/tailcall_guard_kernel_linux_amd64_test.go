//go:build linux && amd64

package syscallhook

import (
	"errors"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfTailCallReachabilityProbe(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	err := probeTailCallReachability()
	if err != nil && !errors.Is(err, errTailCallReachability) {
		t.Fatal(err)
	}
	if err != nil {
		t.Logf("affected kernel: %v", err)
	}
}
