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
		reason  string
		noFound bool
	}{
		{name: "k_int", size: 4},
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
		case tc.reason == "" && !tc.noFound && (row == nil || row.Name != tc.name || row.Helper != 0 || row.ArgReg != 0 || row.RetPtr != tc.ptr || row.RetSize != tc.size):
			t.Errorf("%s: row %+v reason %q, want RetPtr %v RetSize %d", tc.name, row, reason, tc.ptr, tc.size)
		}
	}
	if row, reason := kfuncRow("k_x", nil); row != nil || reason != "its prototype is not in the kernel BTF at hand" {
		t.Errorf("no prototype: row %+v reason %q", row, reason)
	}
}

// A Calls name that is neither a helper nor a kernel function is refused
// where kernel BTF is at hand (the transform), and accepted by a
// configuration check without it; a kernel function found only in a module
// BTF the program passes is accepted.
func TestKfuncNameCheck(t *testing.T) {
	kernel := kfuncKernelSpec(t)
	module := specOf(t, &btf.Func{Name: "m_int", Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}}, Linkage: btf.GlobalFunc})
	for _, tc := range []struct {
		calls   []string
		kernel  *btf.Spec
		modules map[int16]*btf.Spec
		want    string
	}{
		{[]string{"k_missing"}, kernel, nil, `Calls name "k_missing" is not supported: it is neither a helper nor a kernel function of the running kernel or of a module BTF the program passes`},
		{[]string{"m_int"}, kernel, nil, `Calls name "m_int" is not supported`},
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
			!slices.Contains(fn.Tags, hookabi.SizeTag("ret", size)) || hookabi.SizeTags(fn.Tags)["ret"] != size {
			t.Errorf("%s: hook %+v params %v tags %v", name, h, params, fn.Tags)
		}
	}
	if h := byCall["k_voidp"]; !h.RetPtr || !h.Untrusted || h.RetSize != 0 {
		t.Errorf("k_voidp: hook %+v", h)
	}
	// Without the module BTF the module kfunc cannot be named, so no call site is hooked.
	req.Modules = nil
	if _, err := transformLookup(kfuncCallsFixture(t, kernel, module), req); err == nil || !strings.Contains(err.Error(), "m_int") {
		t.Errorf("without Modules: %v", err)
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
