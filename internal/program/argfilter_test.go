package program

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/filter"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// argFilterTestSource defines a noinline function with an extra u32 parameter.
// The parameter value is derived from packet data so we can control it via ping.
const argFilterTestSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Test function called with filter_id=42. Filters matching 42 receive events.

__attribute__((noinline))
int process_with_id(struct xdp_md *ctx, __u32 filter_id) {
    volatile __u32 id = filter_id; // prevent optimization
    return (id > 0) ? 2 : 1;
}

SEC("xdp")
int xdp_argfilter_test(struct xdp_md *ctx) {
    // Always pass 42 as the filter_id
    return process_with_id(ctx, 42);
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

// setupVethForArgFilter creates a veth pair and attaches the given XDP program.
func setupVethForArgFilter(t *testing.T, xdpProg *ebpf.Program) string {
	t.Helper()
	return setupVeth(t, xdpProg, "argtest0", "argtest1", "10.88.0.1", "10.88.0.2")
}

// countArgFilterEvents attaches fentry with arg filters, sends packets, and counts events.
func countArgFilterEvents(t *testing.T, targetProg *ebpf.Program, funcName, iface string, argFilters []filter.ArgFilter) int {
	t.Helper()
	return countEvents(t, targetProg, funcName, iface, "10.88.0.2", false, argFilters, 3, 3)
}

// TestArgFilter verifies that argument filtering works correctly.
// The noinline function process_with_id is always called with filter_id=42.
func TestArgFilter(t *testing.T) {
	xdpProg := loadArgFilterTestCollection(t)
	iface := setupVethForArgFilter(t, xdpProg)

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
		t.Skip("No filterable parameters found (BTF may not include parameter names)")
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
		t.Skip("filter_id parameter not found in BTF")
	}

	t.Run("no_filter", func(t *testing.T) {
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, nil)
		if count == 0 {
			t.Fatal("expected events without filter, got 0")
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
			count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, tt.filters)
			if tt.wantHit && count == 0 {
				t.Fatalf("expected events with filter %v, got 0", tt.filters[0].String())
			}
			if !tt.wantHit && count != 0 {
				t.Fatalf("expected 0 events with filter %v, got %d", tt.filters[0].String(), count)
			}
			t.Logf("received %d events (%s)", count, tt.filters[0].String())
		})
	}
}
