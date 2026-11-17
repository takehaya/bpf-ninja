package inject

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
)

// kfuncKernelSpec is a kernel BTF with kernel functions of every result
// kind: k_int (int), k_u64, k_bool, k_enum (a typedef of a 4-byte enum),
// k_ptr (struct foo *), k_voidp (void *), k_void, k_cb (takes a callback
// through a typedef), and the denied bpf_iter_x_new (int).
func kfuncKernelSpec(t testing.TB) *btf.Spec {
	t.Helper()
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	ret := map[string]btf.Type{
		"k_int":          i32,
		"k_u64":          &btf.Int{Name: "unsigned long long", Size: 8},
		"k_bool":         &btf.Int{Name: "_Bool", Size: 1, Encoding: btf.Bool},
		"k_enum":         &btf.Typedef{Name: "kind_t", Type: &btf.Enum{Name: "kind", Size: 4, Values: []btf.EnumValue{{Name: "A", Value: 0}}}},
		"k_ptr":          &btf.Pointer{Target: &btf.Struct{Name: "foo", Size: 4, Members: []btf.Member{{Name: "x", Type: i32}}}},
		"k_voidp":        &btf.Pointer{Target: &btf.Void{}},
		"k_void":         &btf.Void{},
		"bpf_iter_x_new": i32,
	}
	var types []btf.Type
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range ret {
			if !yield(k) {
				return
			}
		}
	}) {
		types = append(types, &btf.Func{Name: name, Type: &btf.FuncProto{Return: ret[name]}, Linkage: btf.GlobalFunc})
	}
	cb := &btf.Typedef{Name: "cb_t", Type: &btf.Pointer{Target: &btf.FuncProto{Return: i32}}}
	types = append(types, &btf.Func{Name: "k_cb", Type: &btf.FuncProto{Return: i32, Params: []btf.FuncParam{{Name: "cb", Type: cb}}}, Linkage: btf.GlobalFunc})
	return specOf(t, types...)
}

// Every result kind of a kernel function without a row, by name.
func TestKfuncRow(t *testing.T) {
	kernel := kfuncKernelSpec(t)
	for _, tc := range []struct {
		name    string
		ptr     bool
		size    uint32
		signed  bool
		reason  string
		noFound bool
	}{
		{name: "k_int", size: 4, signed: true},
		{name: "k_u64"},
		{name: "k_bool", size: 1},
		{name: "k_enum", size: 4},
		{name: "k_ptr", ptr: true},
		{name: "k_voidp", ptr: true},
		{name: "k_void", reason: "returns nothing"},
		{name: "k_cb", reason: "runs or registers a callback"},
		{name: "bpf_iter_x_new", reason: "an iterator: the verifier forks and prunes loop states at its next"},
		{name: "k_missing", noFound: true},
	} {
		row, reason := namedCall(tc.name, kernel, nil)
		switch {
		case tc.noFound && (row != nil || reason != ""):
			t.Errorf("%s: row %+v reason %q, want neither", tc.name, row, reason)
		case tc.reason != "" && (row != nil || reason != tc.reason):
			t.Errorf("%s: row %+v reason %q, want %q", tc.name, row, reason, tc.reason)
		case tc.reason == "" && !tc.noFound && (row == nil || row.Name != tc.name || row.Helper != 0 || row.ArgReg != 0 || row.RetPtr != tc.ptr || row.RetSize != tc.size || row.RetSigned != tc.signed):
			t.Errorf("%s: row %+v reason %q, want RetPtr %v RetSize %d", tc.name, row, reason, tc.ptr, tc.size)
		}
	}
	if row, reason := kfuncRow("k_x", nil); row != nil || reason != "its prototype is not in the kernel BTF at hand" {
		t.Errorf("no prototype: row %+v reason %q", row, reason)
	}
}

// A Calls name that is neither a helper nor a kernel function the load
// passes is no refusal, with kernel BTF (the transform) or without it (a
// configuration check): it has no site in the program. A name the kernel BTF
// has but cannot hook is refused.
func TestKfuncNameCheck(t *testing.T) {
	kernel := kfuncKernelSpec(t)
	module := specOf(t, &btf.Func{Name: "m_int", Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}}, Linkage: btf.GlobalFunc})
	for _, tc := range []struct {
		calls   []string
		kernel  *btf.Spec
		modules map[int16]*btf.Spec
		want    string
	}{
		{[]string{"k_missing"}, kernel, nil, ""},
		{[]string{"m_int"}, kernel, nil, ""},
		{[]string{"m_int"}, kernel, map[int16]*btf.Spec{1: module}, ""},
		{[]string{"k_missing", "k_void"}, nil, nil, ""},
		{[]string{"k_void"}, kernel, nil, `Calls name "k_void" cannot be hooked: returns nothing`},
		{[]string{"k_cb"}, kernel, nil, `Calls name "k_cb" cannot be hooked: runs or registers a callback`},
		{[]string{"k_int", "k_voidp", "bpf_get_numa_node_id"}, kernel, nil, ""},
	} {
		req := callReq(tc.calls...)
		req.Kernel, req.Modules = tc.kernel, tc.modules
		err := checkOps(req)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%v kernel %v modules %d: %v, want %q", tc.calls, tc.kernel != nil, len(tc.modules), err, tc.want)
		}
	}
}

// kfuncCallsFixture (XDP) calls k_int, k_voidp and the module kfunc m_int
// (fd_array offset 1) by BTF id, storing each result in an out slot, and
// returns XDP_PASS.
func kfuncCallsFixture(t *testing.T, kernel, module *btf.Spec) *ebpf.CollectionSpec {
	m := testKfunc(t, module, "m_int")
	m.Offset = 1
	var insns asm.Instructions
	for i, call := range []asm.Instruction{testKfunc(t, kernel, "k_int"), testKfunc(t, kernel, "k_voidp"), m} {
		insns = append(append(insns, asm.Mov.Imm(asm.R1, 0), call), outStore(int16(i), asm.R0)...)
	}
	return callFixtureSpec(ebpf.XDP, append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return()))
}

// Kernel functions without a row get result-only hooks: the scalar form
// with RetSize and its decl tag for a narrow integer, the pointer form for
// void *, and a module kfunc named through Modules the same way.
func TestCallKfuncResultOnly(t *testing.T) {
	kernel := kfuncKernelSpec(t)
	module := specOf(t, &btf.Func{Name: "m_int", Type: &btf.FuncProto{Return: &btf.Int{Name: "unsigned short", Size: 2}}, Linkage: btf.GlobalFunc})
	spec := kfuncCallsFixture(t, kernel, module)
	req := callReq("k_int", "k_voidp", "m_int")
	req.Kernel, req.Modules = kernel, map[int16]*btf.Spec{1: module}
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 3 || len(plan.skipped) != 0 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	byCall := map[string]LookupHook{}
	for _, h := range plan.hooks {
		byCall[h.Call] = h
	}
	insns := spec.Programs["p"].Instructions
	for name, size := range map[string]uint32{"k_int": 4, "m_int": 2} {
		h := byCall[name]
		fn, params := callHookFn(t, insns, h.Name)
		if h.RetPtr || h.Untrusted || h.RetSize != size || !slices.Equal(params, []string{"ctx", "site", "ret"}) ||
			!slices.Contains(fn.Tags, hookabi.SizeTag("ret", size)) || hookabi.SizeTags(fn.Tags)["ret"] != size ||
			slices.Contains(fn.Tags, hookabi.RetSignedTag) != (name == "k_int") {
			t.Errorf("%s: hook %+v params %v tags %v", name, h, params, fn.Tags)
		}
	}
	if h := byCall["k_voidp"]; !h.RetPtr || !h.Untrusted || h.RetSize != 0 {
		t.Errorf("k_voidp: hook %+v", h)
	}
	// Without the module BTF the module kfunc cannot be named: its site is
	// skipped with that reason and the rule keeps its other hooks.
	req.Modules = nil
	plan, err = transformLookup(kfuncCallsFixture(t, kernel, module), req)
	if err != nil || len(plan.hooks) != len(req.Calls)-1 || len(plan.skipped) != 1 ||
		plan.skipped[0].Reason != "call: a kernel-function call that cannot be named" {
		t.Errorf("without Modules: err %v hooks %+v skipped %+v", err, plan.hooks, plan.skipped)
	}
}

// rawOf is the raw load of insns, an XDP program whose first instruction
// carries its BTF function.
func rawOf(t *testing.T, insns asm.Instructions) RawProgram {
	t.Helper()
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
	return RawProgram{Instructions: raw, Type: ebpf.XDP, BTF: types, FuncInfo: fi, LineInfo: li}
}

// The listing gives a hookable kernel function without a row no reason, so
// the ready rule names it, and its site the transform's reasons; a void one
// keeps "returns nothing".
func TestDiscoverKfuncCallees(t *testing.T) {
	kernel := kfuncKernelSpec(t)
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("p").WithSource(asm.Comment("entry")), xdpFunc("p")),
		testKfunc(t, kernel, "k_int"),
		asm.Mov.Imm(asm.R0, 0), testKfunc(t, kernel, "k_void"),
		testKfunc(t, kernel, "k_int"),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	raw := rawOf(t, insns)
	raw.Kernel = kernel
	d, err := DiscoverCallSitesRaw(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Callees) != 2 || d.Callees[0].Name != "k_int" || d.Callees[0].Reason != "" || d.Callees[0].Ret != RetScalar || d.Callees[0].Typed ||
		d.Callees[1].Name != "k_void" || d.Callees[1].Reason != "returns nothing" {
		t.Fatalf("callees %+v", d.Callees)
	}
	// The first k_int site is hookable (context from the entry); the second directly follows a call: the transform's reason.
	if len(d.Sites) != 3 || d.Sites[0].Reason != "" || d.Sites[0].CtxSource != "entry" || !strings.HasPrefix(d.Sites[2].Reason, "call: ") {
		t.Fatalf("sites %+v", d.Sites)
	}
}

// Without kernel BTF two different kernel functions are listed apart, each
// under its stand-in name and with labels of its own.
func TestDiscoverUnnamedKfuncs(t *testing.T) {
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("p").WithSource(asm.Comment("entry")), xdpFunc("p")),
		kfuncCall(7), asm.Mov.Imm(asm.R0, 0), kfuncCall(9), asm.Mov.Imm(asm.R0, 0), kfuncCall(7),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	d, err := DiscoverCallSitesRaw(rawOf(t, insns), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Callees) != 2 || d.Callees[0].Name != "kfunc_0_7" || d.Callees[1].Name != "kfunc_0_9" || len(d.Callees[0].Sites) != 2 ||
		d.Callees[0].Reason != "a kernel-function call that cannot be named" {
		t.Fatalf("callees %+v", d.Callees)
	}
	if len(d.Sites) != 3 || d.Sites[0].Call != "kfunc_0_7" || d.Sites[1].Call != "kfunc_0_9" || d.Sites[0].Reason == "" {
		t.Fatalf("sites %+v", d.Sites)
	}
	if got := []string{d.Labels[1], d.Labels[3], d.Labels[5]}; !slices.Equal(got, []string{"kfunc_0_7@p+1", "kfunc_0_9@p+3", "kfunc_0_7@p+5"}) {
		t.Fatalf("labels %v", got)
	}
}

// A load whose original program calls a denied helper or kernel function
// anywhere names those callees once each; one without names none.
func TestPremiseCalls(t *testing.T) {
	kernel := kfuncKernelSpec(t)
	insns := asm.Instructions{
		asm.FnKtimeGetNs.Call(), asm.FnSpinLock.Call(), testKfunc(t, kernel, "bpf_iter_x_new"),
		asm.FnSpinLock.Call(), testKfunc(t, kernel, "k_int"), asm.FnLoop.Call(), asm.FnMapLookupElem.Call(),
		testKfunc(t, kernel, "k_cb"), asm.FnPerfEventRead.Call(), asm.FnPerfEventReadValue.Call(),
	}
	if got := PremiseCalls(insns, kernel, nil); !slices.Equal(got, []string{"bpf_spin_lock", "bpf_iter_x_new", "bpf_loop", "k_cb",
		"bpf_perf_event_read", "bpf_perf_event_read_value"}) {
		t.Errorf("premise calls %v", got)
	}
	// Without kernel BTF the kernel-function calls cannot be named, and say so once.
	if got := PremiseCalls(insns, nil, nil); !slices.Equal(got, []string{"bpf_spin_lock", UnnamedKfunc, "bpf_loop", "bpf_perf_event_read", "bpf_perf_event_read_value"}) {
		t.Errorf("without kernel BTF: %v", got)
	}
	if got := PremiseCalls(insns[:1], kernel, nil); got != nil {
		t.Errorf("clean program: %v", got)
	}
}

// A rewritten program names the same denied callees as its original: a
// program that takes a spin lock, hooked outside the locked region.
func TestPremiseCallsAfterTransform(t *testing.T) {
	req := LookupRequestRaw{HookName: "obs", Calls: []string{"bpf_get_numa_node_id"}, Stack: StackAudit{LowestOffset: -64}}
	raw := rawLookupFixture(t, spinLockFixture(), "p", true)
	got, err := TransformLookupRaw(raw, req)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bpf_spin_lock", "bpf_spin_unlock"}
	if before, after := PremiseCalls(raw.Instructions, nil, nil), PremiseCalls(got.Instructions, nil, nil); !slices.Equal(before, want) || !slices.Equal(after, want) {
		t.Errorf("premise calls before %v, after %v", before, after)
	}
}
