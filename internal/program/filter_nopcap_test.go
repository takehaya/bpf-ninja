//go:build !enable_libpcap

package program

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func TestCBPFUnavailable(t *testing.T) {
	for _, pt := range []ebpf.ProgramType{ebpf.XDP, ebpf.SchedCLS, ebpf.CGroupSKB, ebpf.Netfilter} {
		if _, err := compileFilter("tcp port 80", false, false, pt); !errors.Is(err, ErrCBPFUnavailable) {
			t.Errorf("%s: got %v, want ErrCBPFUnavailable", pt, err)
		}
	}
	// Existing internal callers use useDSL=false even without a filter.
	if _, err := compileFilter("", false, false, ebpf.XDP); err != nil {
		t.Fatalf("empty filter: %v", err)
	}
}
