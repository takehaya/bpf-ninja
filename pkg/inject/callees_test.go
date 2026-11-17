package inject

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// calleesRaw is the raw load of an XDP program p that looks up key 0 in map
// fd lookupFD, reads the clock (a row), reads the NUMA node (no row), takes
// a spin lock (denied) and tail-calls through map fd progsFD.
func calleesRaw(t *testing.T, lookupFD, progsFD int64) RawProgram {
	t.Helper()
	u32 := &btf.Int{Name: "u32", Size: 4}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	ctx := &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24, Members: []btf.Member{{Name: "data", Type: u32}}}}
	pFn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: i32, Params: []btf.FuncParam{{Name: "ctx", Type: ctx}}}}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("p").WithSource(asm.Comment("entry")), pFn),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, int(lookupFD)), asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R0, 0), asm.FnKtimeGetNs.Call(),
		asm.Mov.Imm(asm.R0, 0), asm.FnGetNumaNodeId.Call(),
		asm.Mov.Imm(asm.R0, 0), asm.FnKtimeGetNs.Call(),
		asm.Mov.Reg(asm.R1, asm.R10), asm.FnSpinLock.Call(),
		asm.Mov.Reg(asm.R1, asm.R6), asm.LoadMapPtr(asm.R2, int(progsFD)), asm.Mov.Imm(asm.R3, 0), asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	builder := new(btf.Builder)
	fi, li, err := btf.MarshalExtInfos(insns, builder)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	types, err := btf.LoadSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := insns.Marshal(&buf, rawByteOrder()); err != nil {
		t.Fatal(err)
	}
	raw, err := asm.AppendInstructions(nil, &buf, rawByteOrder(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	return RawProgram{Instructions: raw, Type: ebpf.XDP, BTF: types, FuncInfo: fi, LineInfo: li, Maps: map[int32]RawMap{
		int32(lookupFD): {Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, Key: u32, Value: u32},
		int32(progsFD):  {Name: "progs", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4},
	}}
}

func TestDiscoverCallSitesRaw(t *testing.T) {
	raw := calleesRaw(t, 7, 8)
	mapCalls, err := DiscoverMapCallsRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DiscoverCallSitesRaw(raw, mapCalls)
	if err != nil {
		t.Fatal(err)
	}
	want := []Callee{
		{Name: "bpf_ktime_get_ns", Kind: "helper", Ret: RetScalar, Sites: []uint32{8, 12}},
		{Name: "bpf_get_numa_node_id", Kind: "helper", Ret: RetScalar, Sites: []uint32{10}},
		{Name: "bpf_spin_lock", Kind: "helper", Ret: RetVoid, Sites: []uint32{14}, Reason: "takes or releases a lock or a critical section"},
	}
	if !slices.EqualFunc(d.Callees, want, func(a, b Callee) bool {
		return a.Name == b.Name && a.Kind == b.Kind && a.Ret == b.Ret && a.Typed == b.Typed && slices.Equal(a.Sites, b.Sites) && a.Reason == b.Reason
	}) {
		t.Errorf("callees %+v, want %+v", d.Callees, want)
	}
	// A hookable callee's site carries the transform's reason, none here (a lock blocks nothing), and its context source.
	if len(d.Sites) != 4 || d.Sites[0].Call != "bpf_ktime_get_ns" || d.Sites[0].Reason != "" || d.Sites[1].Reason != "" || d.Sites[1].CtxSource != "entry" ||
		d.Sites[3].Reason != "takes or releases a lock or a critical section" {
		t.Errorf("sites %+v", d.Sites)
	}
	if len(d.TailCalls) != 1 || d.TailCalls[0].SitePC != 19 || d.TailCalls[0].Op != HookTailCall {
		t.Errorf("tail calls %+v", d.TailCalls)
	}
	wantLabels := map[uint32]string{6: "sessions@p+6", 8: "bpf_ktime_get_ns@p+8", 10: "bpf_get_numa_node_id@p+10",
		12: "bpf_ktime_get_ns@p+12", 14: "bpf_spin_lock@p+14", 19: "tail_call@p+19"}
	if !maps.Equal(d.Labels, wantLabels) {
		t.Errorf("labels %v, want %v", d.Labels, wantLabels)
	}
	if len(d.Funcs) != 1 || d.Funcs[0] != (FuncRange{Name: "p", Start: 0, End: 22}) {
		t.Errorf("funcs %+v", d.Funcs)
	}
	// Map fds differ per load; the fingerprint does not.
	other, err := DiscoverCallSitesRaw(calleesRaw(t, 11, 12), mapCalls)
	if err != nil || other.Fingerprint != d.Fingerprint || len(d.Fingerprint) != len("sha256:")+64 {
		t.Errorf("fingerprint %s, with other fds %s: %v", d.Fingerprint, other.Fingerprint, err)
	}
	renamed := calleesRaw(t, 7, 8)
	m := renamed.Maps[7]
	m.Name = "flows"
	renamed.Maps[7] = m
	if again, _ := DiscoverCallSitesRaw(renamed, mapCalls); again.Fingerprint == d.Fingerprint {
		t.Error("fingerprint ignores the map name")
	}
}

func TestSiteLabels(t *testing.T) {
	funcs := []FuncRange{{Name: "f", Start: 0, End: 10}, {Name: "g", Start: 10, End: 30}}
	sites := []LookupSite{
		{Op: HookCall, Call: "bpf_fib_lookup", FuncName: "f", Line: 88, SitePC: 7},
		{Op: HookCall, Call: "bpf_fib_lookup", FuncName: "f", Line: 88, SitePC: 3},
		{Op: HookUpdate, MapName: "sessions", FuncName: "g", Line: 5, SitePC: 12},
		{Op: HookLookup, FuncName: "g", SitePC: 15},
		{Op: HookCall, Call: "bpf_fib_lookup", FuncName: "f", Line: 88, SitePC: 9},
		{Op: HookTailCall, FuncName: "g", SitePC: 20},
	}
	want := map[uint32]string{3: "bpf_fib_lookup@f:88#1", 7: "bpf_fib_lookup@f:88#2", 9: "bpf_fib_lookup@f:88#3",
		12: "sessions.update@g:5", 15: "any@g+5", 20: "tail_call@g+10"}
	if got := SiteLabels(funcs, sites); !maps.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
}

// The listing calls a callee typed exactly when the transform gives it a
// typed hook: a fib lookup on its own stack with one size, not one with two
// sizes, a socket lookup (pointer result) or a callee without an argument.
func TestCalleeTyped(t *testing.T) {
	second := fibCall(ebpf.XDP)
	i := slices.IndexFunc(second, func(ins asm.Instruction) bool { return ins.Dst == asm.R3 && ins.Constant == 64 })
	second[i] = asm.Mov.Imm(asm.R3, 48)
	twoSizes := append(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, fibCall(ebpf.XDP)...)
	twoSizes = append(append(twoSizes, second...), fibVerdict(ebpf.XDP)...)
	for _, tc := range []struct {
		name   string
		spec   *ebpf.CollectionSpec
		callee string
		typed  bool
	}{
		{"fib", fibFixture(ebpf.XDP), "bpf_fib_lookup", true},
		{"fib with two sizes", callFixtureSpec(ebpf.XDP, twoSizes), "bpf_fib_lookup", false},
		{"socket lookup", skLookupFixture(ebpf.XDP, 1), "bpf_sk_lookup_tcp", false},
		{"no argument", scalarFixture(), "bpf_jiffies64", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := rawLookupFixtureBTF(t, tc.spec, "p", true)
			mapCalls, err := DiscoverMapCallsRaw(raw)
			if err != nil {
				t.Fatal(err)
			}
			d, err := DiscoverCallSitesRaw(raw, mapCalls)
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(d.Callees, func(c Callee) bool { return c.Name == tc.callee })
			if i < 0 || d.Callees[i].Typed != tc.typed || d.Callees[i].Reason != "" {
				t.Fatalf("callees %+v", d.Callees)
			}
		})
	}
}
