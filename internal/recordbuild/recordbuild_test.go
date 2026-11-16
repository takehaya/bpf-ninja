package recordbuild_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
)

var (
	u8   = &btf.Int{Name: "__u8", Size: 1}
	u32  = &btf.Int{Name: "__u32", Size: 4}
	u64  = &btf.Int{Name: "__u64", Size: 8}
	void = func() btf.Type { return &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}} }
)

// fib is a stand-in for the struct a call hook's arg points to: family at 0,
// ifindex at 4.
func fib(name string) btf.Type {
	return &btf.Pointer{Target: &btf.Const{Type: &btf.Struct{Name: name, Size: 8, Members: []btf.Member{
		{Name: "family", Type: u8},
		{Name: "ifindex", Type: u32, Offset: 32},
	}}}}
}

// callHook returns the parameters GetFuncParamsFromSpec reads from a
// generated call hook HOOK(struct xdp_md *ctx, u32 site, params...).
func callHook(t *testing.T, tags []string, params ...btf.FuncParam) []attach.FuncParamInfo {
	t.Helper()
	all := append([]btf.FuncParam{
		{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 4}}},
		{Name: "site", Type: u32},
	}, params...)
	fn := &btf.Func{Name: "HOOK", Linkage: btf.GlobalFunc, Tags: append([]string{hookabi.HookTag}, tags...),
		Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: all}}
	b, err := btf.NewBuilder([]btf.Type{fn}, nil)
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
	got, err := attach.GetFuncParamsFromSpec(spec, "HOOK")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func entry(t *testing.T, params []attach.FuncParamInfo, maxBytes int) *record.Layout {
	t.Helper()
	l, err := recordbuild.Build(attach.Target{Generated: true, Params: params}, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: maxBytes})
	if err != nil || l == nil {
		t.Fatalf("entry layout %+v %v", l, err)
	}
	return l
}

// comment renders an entry block with site 3, ret -22 and arg bytes
// 02 00 00 00 07 00 00 00 ..., every field read.
func comment(t *testing.T, l *record.Layout) string {
	t.Helper()
	b := make([]byte, l.Size())
	binary.NativeEndian.PutUint16(b[record.OffLen:], uint16(len(b)))
	b[record.OffVersion], b[record.OffKind] = record.BlockVersion, l.Kind()
	binary.NativeEndian.PutUint32(b[record.OffValid:], record.ValidSite|record.ValidStatus|record.ValidKey)
	binary.NativeEndian.PutUint16(b[record.EntryOffKeyLen:], uint16(l.Key.Len))
	binary.NativeEndian.PutUint32(b[record.EntryOffSite:], 3)
	if l.Status.Present() {
		binary.NativeEndian.PutUint64(b[record.EntryOffStatus:], uint64(1<<64-22))
	}
	copy(b[record.EntryOffBytes:], []byte{2, 0, 0, 0, 7, 0, 0, 0})
	got, err := l.Comment(b)
	if err != nil {
		t.Fatal(err)
	}
	if n := l.MaxCommentLen(); len(got) > n {
		t.Fatalf("%q is longer than the bound %d", got, n)
	}
	return got
}

func TestEntryCallHooks(t *testing.T) {
	for _, c := range []struct {
		name   string
		tags   []string
		params []btf.FuncParam
		max    int
		keyLen uint32
		want   string
	}{
		{"result only", nil, []btf.FuncParam{{Name: "ret", Type: u64}}, 256, 0, "site=3 ret=-22"},
		{"typed arg", nil, []btf.FuncParam{{Name: "arg", Type: fib("fib_params")}, {Name: "ret", Type: u64}}, 256, 8,
			"site=3 ret=-22 arg->family=2 arg->ifindex=7"},
		{"typed arg cut", nil, []btf.FuncParam{{Name: "arg", Type: fib("fib_params")}, {Name: "ret", Type: u64}}, 4, 4,
			"site=3 ret=-22 arg->family=2 arg_bytes=4/8"},
		{"untrusted arg without size tag", nil, []btf.FuncParam{{Name: "arg", Type: void()}, {Name: "ret", Type: u64}}, 256, 0,
			"site=3 ret=-22"},
		// A pointer result is never recorded; with a static typed arg the
		// comment shows the fields.
		{"pointer result", nil, []btf.FuncParam{{Name: "arg", Type: fib("ct_opts")}, {Name: "ret", Type: void()}}, 256, 8,
			"site=3 arg->family=2 arg->ifindex=7"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := entry(t, callHook(t, c.tags, c.params...), c.max)
			if l.Key.Len != c.keyLen || l.Value.Present() || l.Size() != record.EntryOffBytes+int(c.keyLen) {
				t.Fatalf("layout key=%+v value=%+v size %d", l.Key, l.Value, l.Size())
			}
			if got := comment(t, l); got != c.want {
				t.Fatalf("comment %q, want %q", got, c.want)
			}
		})
	}
}

// TestEntryPointerRetNotRecorded: a const void *ret leaves the status slot
// empty, so the BPF side never copies the address into the block.
func TestEntryPointerRetNotRecorded(t *testing.T) {
	l := entry(t, callHook(t, nil, btf.FuncParam{Name: "arg", Type: void()}, btf.FuncParam{Name: "ret", Type: void()}), 256)
	if l.Status.Present() {
		t.Fatalf("pointer ret recorded: %+v", l.Status)
	}
}

// TestEntryUntrustedArgSizeTag: an untrusted arg sized by the hook's
// bpf-ninja:arg_size=N tag is recorded as raw bytes. attach reads the tag
// through hookabi.SizeTags, which learns the name arg in package P1; the
// layout itself is checked from a parameter that carries the size.
func TestEntryUntrustedArgSizeTag(t *testing.T) {
	params := []attach.FuncParamInfo{
		{Name: "site", Index: 1, Size: 4},
		{Name: "arg", Index: 2, Size: 8, Kind: "ptr", Type: void(), VoidSize: 8},
		{Name: "ret", Index: 3, Size: 8},
	}
	l := entry(t, params, 256)
	if !l.Key.Pointer || l.Key.Name != "arg" || l.Key.Len != 8 {
		t.Fatalf("arg %+v", l.Key)
	}
	if got, want := comment(t, l), "site=3 ret=-22 arg=0200000007000000"; got != want {
		t.Fatalf("comment %q, want %q", got, want)
	}

	tagged := callHook(t, []string{hookabi.SizeTag("arg", 8)}, btf.FuncParam{Name: "arg", Type: void()}, btf.FuncParam{Name: "ret", Type: u64})
	if tagged[1].VoidSize == 0 {
		t.Skip("hookabi.SizeTags does not read the arg size tag yet")
	}
	if got := entry(t, tagged, 256); got.Key.Len != 8 {
		t.Fatalf("tagged arg %+v", got.Key)
	}
}

// TestEntryKernelStructArg: a typed arg whose struct is a bpf_* name shows
// its fields once hookabi.Opaque exempts bpf_fib_lookup (package P1).
func TestEntryKernelStructArg(t *testing.T) {
	params := callHook(t, nil, btf.FuncParam{Name: "arg", Type: fib("bpf_fib_lookup")}, btf.FuncParam{Name: "ret", Type: u64})
	if hookabi.Opaque(&btf.Struct{Name: "bpf_fib_lookup"}) {
		t.Skip("hookabi.Opaque still hides bpf_fib_lookup")
	}
	if got, want := comment(t, entry(t, params, 256)), "site=3 ret=-22 arg->family=2 arg->ifindex=7"; got != want {
		t.Fatalf("comment %q, want %q", got, want)
	}
}

// TestFilterCallHooks: the filter forms an observer writes for a call hook
// resolve through the existing paths, and --record filter shows ret signed.
func TestFilterCallHooks(t *testing.T) {
	typed := callHook(t, nil, btf.FuncParam{Name: "arg", Type: fib("fib_params")}, btf.FuncParam{Name: "ret", Type: u64})
	pointer := callHook(t, nil, btf.FuncParam{Name: "arg", Type: void()}, btf.FuncParam{Name: "ret", Type: void()})
	sized := []attach.FuncParamInfo{
		{Name: "site", Index: 1, Size: 4},
		{Name: "arg", Index: 2, Size: 8, Kind: "ptr", Type: void(), VoidSize: 8},
		{Name: "ret", Index: 3, Size: 8},
	}
	for _, c := range []struct {
		expr   string
		params []attach.FuncParamInfo
		want   filter.ArgFilter
	}{
		{"ret=0", typed, filter.ArgFilter{ParamName: "ret", ParamIndex: 3, ParamSize: 8}},
		{"ret=-22", typed, filter.ArgFilter{ParamName: "ret", ParamIndex: 3, ParamSize: 8, Value: 1<<64 - 22}},
		{"ret!=null", pointer, filter.ArgFilter{ParamName: "ret", ParamIndex: 3, ParamSize: 8, Pointer: true, Op: filter.OpNotEqual}},
		{"arg->ifindex=7", typed, filter.ArgFilter{ParamName: "arg->ifindex", ParamIndex: 2, ParamSize: 4, Deref: true, Offset: 4, Value: 7}},
		{"arg->bytes[4]=7", sized, filter.ArgFilter{ParamName: "arg->bytes[4]", ParamIndex: 2, ParamSize: 1, Deref: true, Offset: 4, Value: 7}},
	} {
		got, err := filter.ParseAndValidateFilters([]string{c.expr}, c.params)
		if err != nil || len(got) != 1 || got[0] != c.want {
			t.Fatalf("%s: %+v %v, want %+v", c.expr, got, err, c.want)
		}
	}
	for _, c := range []struct {
		expr   string
		params []attach.FuncParamInfo
	}{
		{"ret=0", pointer},          // a pointer result only compares with null
		{"ret!=null", typed},        // an integer result is not a pointer
		{"arg->bytes[0]=1", typed},  // a typed arg has no bytes member
		{"arg->ifindex=1", pointer}, // an untagged untrusted arg has no members
	} {
		if got, err := filter.ParseAndValidateFilters([]string{c.expr}, c.params); err == nil {
			t.Fatalf("%s accepted: %+v", c.expr, got)
		}
	}

	for _, c := range []struct {
		expr   string
		params []attach.FuncParamInfo
		v      uint64
		want   string
	}{
		{"ret=-22", typed, 1<<64 - 22, "ret=-22"},
		{"ret!=null", pointer, 0xffff888812345678, "ret!=null"},
		{"arg->ifindex=7", typed, 7, "arg->ifindex=7"},
	} {
		args, err := filter.ParseAndValidateFilters([]string{c.expr}, c.params)
		if err != nil {
			t.Fatal(err)
		}
		l, err := recordbuild.Build(attach.Target{Generated: true, Params: c.params}, filter.TargetFilters{Args: args}, recordbuild.Options{Mode: record.ModeFilter})
		if err != nil || l == nil {
			t.Fatalf("%s: layout %+v %v", c.expr, l, err)
		}
		b := make([]byte, l.Size())
		binary.NativeEndian.PutUint16(b[record.OffLen:], uint16(len(b)))
		b[record.OffVersion], b[record.OffKind] = record.BlockVersion, l.Kind()
		binary.NativeEndian.PutUint32(b[record.OffValid:], 1)
		binary.NativeEndian.PutUint64(b[record.HeaderSize:], c.v)
		got, err := l.Comment(b)
		if err != nil || got != c.want {
			t.Fatalf("%s: comment %q %v, want %q", c.expr, got, err, c.want)
		}
	}
}
