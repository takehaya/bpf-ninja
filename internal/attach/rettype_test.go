package attach

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
)

// specFrom marshals types and loads them back as a spec.
func specFrom(t *testing.T, types ...btf.Type) *btf.Spec {
	t.Helper()
	b, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// fakeKernelBTF makes RetPointee search vmlinux and the named modules
// instead of the running kernel's BTF.
func fakeKernelBTF(t *testing.T, vmlinux *btf.Spec, modules map[string]*btf.Spec) {
	t.Helper()
	oldV, oldM, oldN := loadVmlinuxBTF, loadModuleBTF, moduleBTFNames
	retPointeeMu.Lock()
	retPointeeCache = map[string]btf.Type{}
	retPointeeMu.Unlock()
	loadVmlinuxBTF = func() (*btf.Spec, error) { return vmlinux, nil }
	loadModuleBTF = func(name string) (*btf.Spec, error) {
		if s, ok := modules[name]; ok {
			return s, nil
		}
		return nil, errors.New("no such module")
	}
	moduleBTFNames = func() ([]string, error) {
		var names []string
		for name := range modules {
			names = append(names, name)
		}
		return names, nil
	}
	t.Cleanup(func() {
		loadVmlinuxBTF, loadModuleBTF, moduleBTFNames = oldV, oldM, oldN
		retPointeeMu.Lock()
		retPointeeCache = map[string]btf.Type{}
		retPointeeMu.Unlock()
	})
}

// retHookSpec is a call hook PREFIX(ctx, u32 site, const void *ret) with tags.
func retHookSpec(t *testing.T, tags ...string) *btf.Spec {
	t.Helper()
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: []btf.FuncParam{
		{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 4}}},
		{Name: "site", Type: &btf.Int{Name: "u32", Size: 4}},
		{Name: "ret", Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}}}}}
	return specFrom(t, &btf.Func{Name: "obs_bpf_xdp_ct_lookup", Linkage: btf.GlobalFunc, Type: proto, Tags: tags})
}

// kernelConn is a vmlinux BTF with struct nf_conn { u32 mark; struct { u16 zone; } z; u32 bits:3; u64 status; }.
func kernelConn(t *testing.T) *btf.Spec {
	u16 := &btf.Int{Name: "u16", Size: 2}
	u32 := &btf.Int{Name: "u32", Size: 4}
	conn := &btf.Struct{Name: "nf_conn", Size: 24, Members: []btf.Member{
		{Name: "mark", Type: u32},
		{Name: "z", Offset: 32, Type: &btf.Struct{Name: "zone_t", Size: 2, Members: []btf.Member{{Name: "zone", Type: u16}}}},
		{Name: "bits", Offset: 64, Type: u32, BitfieldSize: 3},
		{Name: "status", Offset: 128, Type: &btf.Typedef{Name: "u64", Type: &btf.Int{Name: "unsigned long", Size: 8}}},
	}}
	return specFrom(t, conn)
}

// A tagged ret of a generated hook resolves members from kernel BTF with
// the argument rules; a null test still works.
func TestRetTypeMembers(t *testing.T) {
	fakeKernelBTF(t, kernelConn(t), nil)
	params, err := GetFuncParamsFromSpec(retHookSpec(t, hookabi.HookTag, hookabi.RetTypeTag("nf_conn")), "obs_bpf_xdp_ct_lookup")
	if err != nil || len(params) != 2 {
		t.Fatalf("params %+v %v", params, err)
	}
	ret := params[1]
	if ret.Kind != "ptr-struct" || ret.TypeName != "nf_conn" || ArgTypeName(ret.Type) != "struct nf_conn *" {
		t.Fatalf("ret %+v (%s)", ret, ArgTypeName(ret.Type))
	}
	for expr, want := range map[string]struct {
		off, size uint32
	}{"ret->mark": {0, 4}, "ret->z.zone": {4, 2}, "ret->status": {16, 8}} {
		p, err := ResolveArg(expr, params)
		if err != nil || !p.Deref || p.Index != 2 || p.Offset != want.off || p.Size != want.size {
			t.Errorf("%s: %+v %v", expr, p, err)
		}
	}
	for expr, want := range map[string]string{
		"ret->bits": "bitfield member", "ret->z": "final member must be an integer", "ret->nope": "member \"nope\" not found", "ret": "is a pointer",
	} {
		if _, err := ResolveArg(expr, params); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", expr, err, want)
		}
	}
	if p, err := ResolvePointerArg("ret", params); err != nil || p.Size != 8 {
		t.Errorf("ret null test: %+v %v", p, err)
	}
	members, _ := ListArgMembers(ret, DefaultMembersDepth)
	var exprs []string
	for _, m := range members {
		exprs = append(exprs, m.Expression)
		for _, c := range m.Members {
			exprs = append(exprs, c.Expression)
		}
	}
	if got := strings.Join(exprs, " "); got != "ret->mark ret->z ret->z.zone ret->bits ret->status" {
		t.Errorf("members %s", got)
	}
}

// Without the tag, on a function inject-run did not generate, or when the
// kernel BTF lacks the type, ret stays const void *: a null test only.
func TestRetTypeUntyped(t *testing.T) {
	fakeKernelBTF(t, kernelConn(t), nil)
	for name, spec := range map[string]*btf.Spec{
		"no tag":        retHookSpec(t, hookabi.HookTag),
		"not generated": retHookSpec(t, hookabi.RetTypeTag("nf_conn")),
		"unknown type":  retHookSpec(t, hookabi.HookTag, hookabi.RetTypeTag("no_such")),
	} {
		params, err := GetFuncParamsFromSpec(spec, "obs_bpf_xdp_ct_lookup")
		if err != nil || len(params) != 2 || params[1].Kind != "ptr" {
			t.Fatalf("%s: params %+v %v", name, params, err)
		}
		if _, err := ResolveArg("ret->mark", params); err == nil {
			t.Errorf("%s: ret->mark resolved", name)
		}
		if _, err := ResolvePointerArg("ret", params); err != nil {
			t.Errorf("%s: ret null test: %v", name, err)
		}
	}
}

// A type vmlinux lacks comes from the one module BTF that defines it; two
// modules defining it leave ret untyped.
func TestRetPointeeModules(t *testing.T) {
	empty := specFrom(t, &btf.Int{Name: "int", Size: 4})
	fakeKernelBTF(t, empty, map[string]*btf.Spec{"nf_conntrack": kernelConn(t), "other": empty})
	if typ, ok := RetPointee("nf_conn").(*btf.Struct); !ok || typ.Size != 24 {
		t.Errorf("module type: %v", typ)
	}
	fakeKernelBTF(t, empty, map[string]*btf.Spec{"a": kernelConn(t), "b": kernelConn(t)})
	if typ := RetPointee("nf_conn"); typ != nil {
		t.Errorf("ambiguous module type: %v", typ)
	}
	fakeKernelBTF(t, kernelConn(t), map[string]*btf.Spec{"a": kernelConn(t)})
	if typ := RetPointee("nf_conn"); typ == nil {
		t.Error("vmlinux type not found")
	}
}
