package program

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// argFilterTestSource defines a noinline function with an extra u32 parameter.
// Compiler barriers keep both ctx and filter_id in the actual call ABI.
const argFilterTestSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Test function called with filter_id=42. Filters matching 42 receive events.

__attribute__((noinline))
int process_with_id(struct xdp_md *ctx, __u32 filter_id) {
    asm volatile("" : "+r"(ctx), "+r"(filter_id));
    volatile __u32 id = filter_id;
    return (id > 0) ? 2 : 1;
}

SEC("xdp")
int xdp_argfilter_test(struct xdp_md *ctx) {
    // Always pass 42 as the filter_id
    __u32 id = 42;
    asm volatile("" : "+r"(id));
    return process_with_id(ctx, id);
}

char _license[] SEC("license") = "GPL";
`

func loadArgFilterTestCollection(t *testing.T) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, argFilterTestSource))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}

	var objs struct {
		XDP *ebpf.Program `ebpf:"xdp_argfilter_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = objs.XDP.Close() })

	return objs.XDP
}

// TestBpfArgFilter verifies that argument filtering works correctly.
// The noinline function process_with_id is always called with filter_id=42.
func TestBpfArgFilter(t *testing.T) {
	xdpProg := loadArgFilterTestCollection(t)

	// First verify we can get the function parameters
	params, err := attach.GetFuncParams(xdpProg, "process_with_id")
	if err != nil {
		t.Fatalf("GetFuncParams: %v", err)
	}
	t.Logf("Found %d filterable parameters", len(params))
	for _, p := range params {
		t.Logf("  %s: index=%d, size=%d, signed=%v", p.Name, p.Index, p.Size, p.Signed)
	}

	if len(params) == 0 {
		t.Fatal("fixture lost its filterable parameters")
	}

	// Find the filter_id parameter
	var filterIDParam *attach.FuncParamInfo
	for i := range params {
		if params[i].Name == "filter_id" {
			filterIDParam = &params[i]
			break
		}
	}
	if filterIDParam == nil {
		t.Fatal("fixture lost filter_id in BTF")
	}

	t.Run("no_filter", func(t *testing.T) {
		count := countEventsTestRun(t, xdpProg, "process_with_id", nil, 3)
		if count != 3 {
			t.Fatalf("expected 3 events without filter, got %d", count)
		}
		t.Logf("received %d events (no filter)", count)
	})

	// makeFilter builds a single-element ArgFilter slice from filterIDParam.
	makeFilter := func(op filter.ArgFilterOp, value uint64, maxValue ...uint64) []filter.ArgFilter {
		f := filter.ArgFilter{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         op,
			Value:      value,
		}
		if len(maxValue) > 0 {
			f.MaxValue = maxValue[0]
		}
		return []filter.ArgFilter{f}
	}

	tests := []struct {
		name    string
		filters []filter.ArgFilter
		wantHit bool // true = expect events, false = expect 0
	}{
		{"exact_match_hit", makeFilter(filter.OpEqual, 42), true},
		{"exact_match_miss", makeFilter(filter.OpEqual, 99), false},
		{"range_hit", makeFilter(filter.OpRange, 40, 50), true},
		{"range_miss", makeFilter(filter.OpRange, 100, 200), false},
		{"greater_equal_hit", makeFilter(filter.OpGreaterEqual, 40), true},
		{"greater_equal_miss", makeFilter(filter.OpGreaterEqual, 100), false},
		{"less_equal_hit", makeFilter(filter.OpLessEqual, 50), true},
		{"less_equal_miss", makeFilter(filter.OpLessEqual, 10), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := countEventsTestRun(t, xdpProg, "process_with_id", tt.filters, 3)
			if tt.wantHit && count != 3 {
				t.Fatalf("expected 3 events with filter %v, got %d", tt.filters[0].String(), count)
			}
			if !tt.wantHit && count != 0 {
				t.Fatalf("expected 0 events with filter %v, got %d", tt.filters[0].String(), count)
			}
			t.Logf("received %d events (%s)", count, tt.filters[0].String())
		})
	}
}
