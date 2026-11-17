package inject

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// uncalled lists the functions of insns after the entry that no call or
// function reference names: the kernel finds no such subprogram and refuses
// the func_info that lists it.
func uncalled(insns asm.Instructions) []string {
	var refs, funcs []string
	for i := range insns {
		if fn := btf.FuncMetadata(&insns[i]); fn != nil && i != 0 {
			funcs = append(funcs, fn.Name)
		}
		if ref := insns[i].Reference(); ref != "" {
			refs = append(refs, ref)
		}
	}
	return slices.DeleteFunc(funcs, func(name string) bool { return slices.Contains(refs, name) })
}

// mixedCallFixture looks up sessions and other, then calls
// bpf_ktime_get_ns twice and bpf_get_numa_node_id once.
func mixedCallFixture() *ebpf.CollectionSpec {
	var insns asm.Instructions
	insns = append(insns, asm.Mov.Reg(asm.R6, asm.R1))
	for i, m := range []string{"sessions", "other"} {
		insns = append(insns, asm.StoreImm(asm.RFP, int16(-4*(i+1)), 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, int32(-4*(i+1))),
			asm.LoadMapPtr(asm.R1, 0).WithReference(m), asm.FnMapLookupElem.Call(), asm.Mov.Imm(asm.R0, 0))
	}
	for _, fn := range []asm.BuiltinFunc{asm.FnKtimeGetNs, asm.FnGetNumaNodeId, asm.FnKtimeGetNs} {
		insns = append(insns, fn.Call(), asm.Mov.Imm(asm.R0, 0))
	}
	spec := callFixtureSpec(ebpf.XDP, append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return()))
	for _, m := range []string{"sessions", "other"} {
		spec.Maps[m] = &ebpf.MapSpec{Name: m, Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 1}
	}
	return spec
}

// stackCallFixture is subTailCallerFixture whose entry calls
// bpf_ktime_get_ns before the tail-calling subprogram.
func stackCallFixture() *ebpf.CollectionSpec {
	spec := subTailCallerFixture()
	entry := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Imm(asm.R0, 0), asm.FnKtimeGetNs.Call(), asm.Mov.Imm(asm.R0, 0),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Call.Label("sub"), asm.Return()}
	entry[0] = btf.WithFuncMetadata(entry[0].WithSymbol("caller").WithSource(asm.Comment("entry")), xdpFunc("caller"))
	spec.Programs["caller"].Instructions = append(entry, spec.Programs["caller"].Instructions[2:]...)
	return spec
}

// manyFuncsFixture calls bpf_get_numa_node_id and bpf_jiffies64 and n
// static functions.
func manyFuncsFixture(n int) *ebpf.CollectionSpec {
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.FnGetNumaNodeId.Call(), asm.Mov.Imm(asm.R0, 2), asm.FnJiffies64.Call(), asm.Mov.Imm(asm.R0, 2)}
	for i := range n {
		insns = append(insns, asm.Call.Label(fmt.Sprintf("f%d", i)), asm.Mov.Imm(asm.R0, 2))
	}
	insns = append(insns, asm.Return())
	for i := range n {
		name := fmt.Sprintf("f%d", i)
		insns = append(insns, btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(name).WithSource(asm.Comment(name)), staticFunc(name)), asm.Return())
	}
	return callFixtureSpec(ebpf.XDP, insns)
}

// dropOf maps every site of spec's program p that keep rejects to "dropped".
func dropOf(t *testing.T, spec *ebpf.CollectionSpec, req LookupRequest, drop func(LookupSite) bool) map[uint32]string {
	t.Helper()
	sites, err := discoverSites(spec.Programs[req.ProgramName].Instructions, spec.Programs[req.ProgramName].Type, elfLookupMaps(spec), req)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint32]string{}
	for _, site := range sites {
		if drop(site.LookupSite) {
			out[site.SitePC] = "dropped"
		}
	}
	return out
}

// No path that removes a whole group, call or map group, leaves its hook
// function behind: the drop list (which the load retry uses in RetryRank
// order), the kernel's function limit and a broken stack limit.
func TestNoUncalledHook(t *testing.T) {
	mixed := func() LookupRequest {
		req := callReq("bpf_ktime_get_ns", "bpf_get_numa_node_id")
		req.Auto = true
		return req
	}
	for _, tc := range []struct {
		name    string
		spec    func() *ebpf.CollectionSpec
		req     func(t *testing.T, spec *ebpf.CollectionSpec) LookupRequest
		hooks   []string
		skipped int
	}{
		{"drop list, call group", mixedCallFixture, func(t *testing.T, spec *ebpf.CollectionSpec) LookupRequest {
			req := mixed()
			req.Drop = dropOf(t, spec, req, func(s LookupSite) bool { return s.Call == "bpf_ktime_get_ns" })
			return req
		}, []string{"obs_sessions", "obs_other", "obs_bpf_get_numa_node_id"}, 2},
		{"drop list, map group", mixedCallFixture, func(t *testing.T, spec *ebpf.CollectionSpec) LookupRequest {
			req := mixed()
			req.Drop = dropOf(t, spec, req, func(s LookupSite) bool { return s.MapName == "sessions" })
			return req
		}, []string{"obs_other", "obs_bpf_ktime_get_ns", "obs_bpf_get_numa_node_id"}, 1},
		{"drop list, every site", mixedCallFixture, func(t *testing.T, spec *ebpf.CollectionSpec) LookupRequest {
			req := mixed()
			req.Entry = true
			req.Drop = dropOf(t, spec, req, func(LookupSite) bool { return true })
			return req
		}, []string{"obs_entry"}, 5},
		{"function limit", func() *ebpf.CollectionSpec { return manyFuncsFixture(254) }, func(*testing.T, *ebpf.CollectionSpec) LookupRequest {
			return callReq("bpf_get_numa_node_id", "bpf_jiffies64")
		}, []string{"obs_bpf_jiffies64"}, 1},
		{"stack limit, call group", stackCallFixture, func(*testing.T, *ebpf.CollectionSpec) LookupRequest {
			return LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Calls: []string{"bpf_ktime_get_ns"}, Stack: StackAudit{LowestOffset: -208}}
		}, []string{"obs_entry"}, 1},
		{"stack limit, map group", staleTailFixture, func(*testing.T, *ebpf.CollectionSpec) LookupRequest {
			return LookupRequest{ProgramName: "caller", Auto: true, Entry: true, HookName: "obs", Stack: StackAudit{LowestOffset: -208}}
		}, []string{"obs_entry"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec()
			req := tc.req(t, spec)
			plan, err := transformLookup(spec, req)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, h := range plan.hooks {
				names = append(names, h.Name)
			}
			if !slices.Equal(names, tc.hooks) || len(plan.skipped) != tc.skipped {
				t.Fatalf("hooks %v skipped %+v", names, plan.skipped)
			}
			if left := uncalled(spec.Programs[req.ProgramName].Instructions); len(left) != 0 {
				t.Fatalf("functions nothing calls: %v", left)
			}
		})
	}
}

// Past the kernel's 256 functions with no call group left to drop, the
// transform refuses instead of emitting a program the kernel rejects.
func TestFunctionLimitWithoutCallGroups(t *testing.T) {
	req := callReq("bpf_get_numa_node_id", "bpf_jiffies64")
	req.Entry = true
	plan, err := transformLookup(manyFuncsFixture(255), req)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "the program would have 257 functions, more than the kernel's 256") || len(plan.skipped) != 2 {
		t.Fatalf("err %v skipped %+v", err, plan.skipped)
	}
	// One function fewer fits with the entry hook alone.
	if plan, err := transformLookup(manyFuncsFixture(254), req); err != nil || len(plan.hooks) != 1 || plan.hooks[0].Kind != HookEntry {
		t.Fatalf("err %v hooks %+v", err, plan.hooks)
	}
}

// A drop list that removes every map site of a rule with nothing else to
// hook is refused with that cause.
func TestDropEveryMapSite(t *testing.T) {
	for _, req := range []LookupRequest{
		{ProgramName: "p", HookName: "obs", Auto: true, Stack: StackAudit{LowestOffset: -64}},
		{ProgramName: "p", HookName: "obs", Auto: true, Updates: CallAny, Stack: StackAudit{LowestOffset: -64}},
	} {
		spec := mixedCallFixture()
		req.Drop = dropOf(t, spec, req, func(s LookupSite) bool { return s.Op != HookCall })
		if _, err := transformLookup(spec, req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no supported lookup sites: Drop removes all 2") {
			t.Errorf("%+v: %v", req, err)
		}
	}
	// One site left out of the drop list keeps its hook.
	spec := mixedCallFixture()
	req := LookupRequest{ProgramName: "p", HookName: "obs", Auto: true, Stack: StackAudit{LowestOffset: -64}}
	req.Drop = dropOf(t, spec, req, func(s LookupSite) bool { return s.MapName == "sessions" })
	if plan, err := transformLookup(spec, req); err != nil || len(plan.hooks) != 1 {
		t.Fatalf("err %v hooks %+v", err, plan.hooks)
	}
}

// uncalled finds a function nothing calls.
func TestUncalled(t *testing.T) {
	insns := slices.Clone(stackCallFixture().Programs["caller"].Instructions)
	if left := uncalled(insns); len(left) != 0 {
		t.Fatalf("fixture: %v", left)
	}
	insns = append(insns, btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("orphan"), staticFunc("orphan")), asm.Return())
	if left := uncalled(insns); !slices.Equal(left, []string{"orphan"}) {
		t.Fatalf("got %v", left)
	}
}
