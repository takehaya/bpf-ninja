package record_test

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
	"github.com/takehaya/bpf-ninja/internal/setmap"
)

// updateHook is the parameter list of PREFIX_pol_update(ctx, u32 site,
// const struct pol_key *key, const struct pol *value, u64 status) with
// struct pol_key { __u32 policy_index; } and struct pol { __u32 pol_rc;
// __u16 port; __s32 delta:4; __u8 tag[2]; void *p; }.
func updateHook() []attach.FuncParamInfo {
	u32 := &btf.Int{Name: "__u32", Size: 4}
	key := &btf.Struct{Name: "pol_key", Size: 4, Members: []btf.Member{{Name: "policy_index", Type: u32}}}
	value := &btf.Struct{Name: "pol", Size: 24, Members: []btf.Member{
		{Name: "pol_rc", Type: u32},
		{Name: "port", Type: &btf.Int{Size: 2}, Offset: 32},
		{Name: "delta", Type: &btf.Int{Size: 4, Encoding: btf.Signed}, Offset: 48, BitfieldSize: 4},
		{Name: "tag", Type: &btf.Array{Type: &btf.Int{Size: 1}, Nelems: 2}, Offset: 56},
		{Name: "p", Type: &btf.Pointer{Target: &btf.Void{}}, Offset: 128},
	}}
	ptr := func(t btf.Type) btf.Type { return &btf.Pointer{Target: &btf.Const{Type: t}} }
	return []attach.FuncParamInfo{
		{Name: "site", Index: 1, Size: 4},
		{Name: "key", Index: 2, Size: 8, Kind: "ptr-struct", Type: ptr(key)},
		{Name: "value", Index: 3, Size: 8, Kind: "ptr-struct", Type: ptr(value)},
		{Name: "status", Index: 4, Size: 8},
	}
}

func block(l *record.Layout, valid uint32, fill func(b []byte)) []byte {
	b := make([]byte, l.Size())
	binary.NativeEndian.PutUint16(b[record.OffLen:], uint16(len(b)))
	b[record.OffVersion], b[record.OffKind] = record.BlockVersion, l.Kind()
	binary.NativeEndian.PutUint32(b[record.OffValid:], valid)
	if l.Mode == record.ModeEntry {
		binary.NativeEndian.PutUint16(b[record.EntryOffKeyLen:], uint16(l.Key.Len))
		binary.NativeEndian.PutUint16(b[record.EntryOffValueLen:], uint16(l.Value.Len))
	}
	fill(b)
	return b
}

func TestBuild(t *testing.T) {
	hook := attach.Target{Generated: true, Params: updateHook()}
	tf := filter.TargetFilters{
		Args: []filter.ArgFilter{
			{ParamName: "value->pol_rc", ParamIndex: 3, ParamSize: 4, Deref: true},
			{ParamName: "value->pol_rc", ParamIndex: 3, ParamSize: 4, Deref: true, Op: filter.OpNotEqual},
			{ParamName: "value", ParamIndex: 3, ParamSize: 8, Pointer: true},
		},
		Sets: []filter.SetFilter{{Fields: []filter.SetKeyField{{ParamName: "key->policy_index", ParamIdx: 2, ParamSize: 4, Deref: true}}}},
	}
	l, err := recordbuild.Build(hook, tf, recordbuild.Options{Mode: record.ModeFilter})
	if err != nil || len(l.Fields) != 3 || l.Fields[2].Name != "key->policy_index" || l.Size() != 32 {
		t.Fatalf("filter %+v %v", l, err)
	}
	ordinary := attach.Target{Params: []attach.FuncParamInfo{{Name: "q", Index: 1, Size: 8, Kind: "ptr-struct"}}}
	for _, c := range []struct {
		t   attach.Target
		tf  filter.TargetFilters
		opt recordbuild.Options
		nil bool
	}{
		{hook, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeFilter}, true}, // nothing referenced
		{ordinary, tf, recordbuild.Options{Mode: record.ModeFilter}, true},                 // default: hooks only
		{ordinary, tf, recordbuild.Options{Mode: record.ModeFilter, Explicit: true}, false},
		{hook, tf, recordbuild.Options{Mode: record.ModeNone}, true},
	} {
		if l, err := recordbuild.Build(c.t, c.tf, c.opt); err != nil || (l == nil) != c.nil {
			t.Fatalf("%+v: %+v %v", c.opt, l, err)
		}
	}

	e, err := recordbuild.Build(hook, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 8})
	if err != nil || e.Site.ParamIndex != 1 || e.Status.ParamIndex != 4 || e.Key.Len != 4 || e.Value.Len != 8 || e.Value.Size != 24 || e.Size() != record.EntryOffBytes+12 {
		t.Fatalf("entry %+v %v", e, err)
	}
	void := &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}}
	generic, err := recordbuild.Build(attach.Target{Generated: true, Params: []attach.FuncParamInfo{
		{Name: "info", Index: 1, Size: 8}, {Name: "key", Index: 2, Size: 8, Kind: "ptr", Type: void},
	}}, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 64})
	if err != nil || generic.Site.Name != "info" || generic.Status.Name != "info" || generic.Key.Len != 0 {
		t.Fatalf("generic %+v %v", generic, err)
	}
	if _, err := recordbuild.Build(hook, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: record.MaxBytesLimit + 1}); err == nil {
		t.Fatal("accepted oversized --record-max")
	}
}

// TestBuildTooManyFieldsDefaultOff: a default (non-explicit) capture with more
// than MaxFields filter fields turns itself off; an explicit one errors.
func TestBuildTooManyFieldsDefaultOff(t *testing.T) {
	var args []filter.ArgFilter
	for i := 0; i <= record.MaxFields; i++ {
		args = append(args, filter.ArgFilter{ParamName: "value", ParamIndex: 3, ParamSize: 8, Deref: true, Offset: uint32(i) * 8})
	}
	hook := attach.Target{Generated: true, Params: updateHook()}
	tf := filter.TargetFilters{Args: args}
	if l, err := recordbuild.Build(hook, tf, recordbuild.Options{Mode: record.ModeFilter}); err != nil || l != nil {
		t.Fatalf("default over-limit: %+v %v", l, err)
	}
	if _, err := recordbuild.Build(hook, tf, recordbuild.Options{Mode: record.ModeFilter, Explicit: true}); err == nil {
		t.Fatal("explicit over-limit accepted")
	}
}

func TestComment(t *testing.T) {
	f := &record.Layout{Mode: record.ModeFilter, Fields: []record.Field{
		{Name: "key->delta", Size: 4, Signed: true, Deref: true},
		{Name: "value", Size: 8, Pointer: true},
		{Name: "site", Size: 4},
	}}
	got, err := f.Comment(block(f, 0b011, func(b []byte) {
		binary.NativeEndian.PutUint64(b[8:], 0xfffffffffffffffd)
		binary.NativeEndian.PutUint64(b[24:], 24)
	}))
	if want := "key->delta=-3 value=null site=?"; err != nil || got != want {
		t.Fatalf("filter %q %v, want %q", got, err, want)
	}

	for _, c := range []struct {
		max   int
		valid uint32
		want  string
	}{
		{256, record.ValidSite | record.ValidStatus | record.ValidKey | record.ValidValue, "site=24 status=0x00000000fffffff9 key->policy_index=1 value->pol_rc=2 value->port=8080 value->delta=-3 value->tag=abcd"},
		{4, record.ValidSite | record.ValidKey | record.ValidValue, "site=24 status=? key->policy_index=1 value->pol_rc=2 value_bytes=4/24"},
		{256, record.ValidSite, "site=24 status=? key=? value=?"},
	} {
		e, err := recordbuild.Build(attach.Target{Generated: true, Params: updateHook()}, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: c.max})
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Comment(block(e, c.valid, func(b []byte) {
			binary.NativeEndian.PutUint32(b[record.EntryOffSite:], 24)
			binary.NativeEndian.PutUint64(b[record.EntryOffStatus:], 4294967289)
			binary.NativeEndian.PutUint32(b[record.EntryOffBytes:], 1)
			v := b[record.EntryOffBytes+4:]
			binary.NativeEndian.PutUint32(v, 2)
			if len(v) > 4 {
				binary.NativeEndian.PutUint16(v[4:], 8080)
				v[6], v[7], v[8] = 0x0d, 0xab, 0xcd
				binary.NativeEndian.PutUint64(v[16:], 0xffff888812345678) // never rendered
			}
		}))
		if err != nil || got != c.want {
			t.Fatalf("entry max=%d: %q %v\nwant %q", c.max, got, err, c.want)
		}
	}

	bad := block(f, 0, func([]byte) {})
	bad[record.OffKind] = record.KindEntry
	if _, err := f.Comment(bad); err == nil {
		t.Fatal("accepted a block of another kind")
	}
}

func TestEntryVoidSizeTag(t *testing.T) {
	void := &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}}
	// A per-map untrusted hook: key sized by a decl tag, value left untagged.
	hook := attach.Target{Generated: true, Params: []attach.FuncParamInfo{
		{Name: "site", Index: 1, Size: 4},
		{Name: "status", Index: 2, Size: 8},
		{Name: "key", Index: 3, Size: 8, Kind: "ptr", Type: void, VoidSize: 4},
		{Name: "value", Index: 4, Size: 8, Kind: "ptr", Type: void}, // no size tag
	}}
	l, err := recordbuild.Build(hook, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 256})
	if err != nil {
		t.Fatal(err)
	}
	if !l.Key.Pointer || l.Key.Len != 4 || l.Value.Len != 0 {
		t.Fatalf("void sizes: key=%+v value=%+v", l.Key, l.Value)
	}
	key := []byte{0xde, 0xad, 0xbe, 0xef}
	got, err := l.Comment(block(l, record.ValidSite|record.ValidKey, func(b []byte) {
		binary.NativeEndian.PutUint32(b[record.EntryOffSite:], 5)
		copy(b[record.EntryOffBytes:], key)
	}))
	if err != nil || got != "site=5 status=? key=deadbeef" {
		t.Fatalf("void comment %q %v", got, err)
	}
}

func TestCommentSkipsPointersAndSpecialFields(t *testing.T) {
	u32 := &btf.Int{Name: "__u32", Size: 4}
	timer := &btf.Struct{Name: "bpf_timer", Size: 16, Members: []btf.Member{{Name: "__opaque", Type: &btf.Array{Type: u32, Nelems: 4}}}}
	u8 := &btf.Int{Size: 1}
	ptr := func() btf.Type { return &btf.Pointer{Target: &btf.Void{}} }
	con := func(vt btf.Type) btf.Type { return &btf.Const{Type: vt} }
	mk := func(vt btf.Type) *record.Layout {
		return &record.Layout{Mode: record.ModeEntry, Site: record.Scalar{ParamIndex: -1}, Status: record.Scalar{ParamIndex: -1},
			Key:   record.Bytes{Name: "key", ParamIndex: -1},
			Value: record.Bytes{Name: "value", ParamIndex: 3, Pointer: true, Size: 24, Len: 24, Type: con(vt)}}
	}
	// struct v { __u32 rc; bpf_timer t@8; void *p@16; __u8 tag[2]@20; }
	v := &btf.Struct{Name: "v", Size: 24, Members: []btf.Member{
		{Name: "rc", Type: u32},
		{Name: "t", Type: timer, Offset: 64},
		{Name: "p", Type: ptr(), Offset: 128},
		{Name: "tag", Type: &btf.Array{Type: u8, Nelems: 2}, Offset: 160},
	}}
	l := mk(v)
	got, err := l.Comment(block(l, record.ValidValue, func(b []byte) {
		d := b[record.EntryOffBytes:]
		binary.NativeEndian.PutUint32(d, 7)                       // rc
		copy(d[8:16], []byte{0xff, 0xff, 0x88, 0x88, 1, 2, 3, 4}) // timer storage
		binary.NativeEndian.PutUint64(d[16:], 0xffff888812340000) // pointer p
		d[20], d[21] = 0xab, 0xcd                                 // tag
	}))
	if err != nil || got != "value->rc=7 value->tag=abcd" {
		t.Fatalf("leaked pointer/timer bytes: %q %v", got, err)
	}

	// The same shapes as members: struct { __u32 rc; struct bpf_timer ts[1];
	// void *ps[2]; union { void *p; __u64 x; } u; union { void *q; __u64 y; }; }.
	pu := func(p, x string) btf.Type {
		return &btf.Union{Size: 8, Members: []btf.Member{{Name: p, Type: ptr()}, {Name: x, Type: &btf.Int{Name: "u64", Size: 8}}}}
	}
	members := &btf.Struct{Name: "m", Size: 56, Members: []btf.Member{
		{Name: "rc", Type: u32},
		{Name: "ts", Type: &btf.Array{Type: timer, Nelems: 1}, Offset: 64},
		{Name: "ps", Type: &btf.Array{Type: ptr(), Nelems: 2}, Offset: 192},
		{Name: "u", Type: pu("p", "x"), Offset: 320},
		{Type: pu("q", "y"), Offset: 384},
	}}
	ml := &record.Layout{Mode: record.ModeEntry, Site: record.Scalar{ParamIndex: -1}, Status: record.Scalar{ParamIndex: -1},
		Key:   record.Bytes{Name: "key", ParamIndex: -1},
		Value: record.Bytes{Name: "value", ParamIndex: 3, Pointer: true, Size: 56, Len: 56, Type: members}}
	got, err = ml.Comment(block(ml, record.ValidValue, func(b []byte) {
		d := b[record.EntryOffBytes:]
		binary.NativeEndian.PutUint32(d, 7)
		for o := 8; o < 56; o += 8 {
			binary.NativeEndian.PutUint64(d[o:], 0xffff888812340000)
		}
	}))
	if err != nil || got != "value->rc=7" {
		t.Fatalf("leaked member pointer/timer bytes: %q %v", got, err)
	}

	// Each of these top-level shapes carries a pointer and must render nothing.
	for name, vt := range map[string]btf.Type{
		"pointer-array":  &btf.Array{Type: ptr(), Nelems: 3},
		"kptr-array":     &btf.Array{Type: &btf.Pointer{Target: &btf.TypeTag{Value: "kptr", Type: &btf.Struct{Name: "task_struct"}}}, Nelems: 2},
		"list-array":     &btf.Array{Type: &btf.Struct{Name: "bpf_list_head", Size: 16}, Nelems: 1},
		"pointer-union":  &btf.Union{Name: "u", Size: 8, Members: []btf.Member{{Name: "p", Type: ptr()}, {Name: "x", Type: &btf.Int{Name: "u64", Size: 8}}}},
		"top-pointer":    ptr(),
		"struct-pointer": &btf.Struct{Name: "s", Size: 8, Members: []btf.Member{{Name: "p", Type: ptr()}}},
	} {
		l := mk(vt)
		got, err := l.Comment(block(l, record.ValidValue, func(b []byte) {
			binary.NativeEndian.PutUint64(b[record.EntryOffBytes:], 0xffff888812340000)
			binary.NativeEndian.PutUint64(b[record.EntryOffBytes+8:], 0xffff888812340000)
		}))
		if err != nil || got != "" {
			t.Fatalf("%s leaked: %q %v", name, got, err)
		}
	}
}

func TestCommentRecordMaxZero(t *testing.T) {
	l, err := recordbuild.Build(attach.Target{Generated: true, Params: updateHook()}, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 0})
	if err != nil {
		t.Fatal(err)
	}
	if l.Key.Len != 0 || l.Value.Len != 0 {
		t.Fatalf("not fully capped: %+v", l)
	}
	got, err := l.Comment(block(l, record.ValidSite, func(b []byte) {
		binary.NativeEndian.PutUint32(b[record.EntryOffSite:], 24)
	}))
	if err != nil || got != "site=24 status=? key_bytes=0/4 value_bytes=0/24" {
		t.Fatalf("record-max 0 marker: %q %v", got, err)
	}
}

// A function named like a hook but without inject-run's hook tag, such as
// f(ctx, u32 key), is not a generated hook: the default records nothing there.
func TestGeneratedRequiresTag(t *testing.T) {
	named := attach.Target{FuncName: "f", Params: []attach.FuncParamInfo{{Name: "key", Index: 1, Size: 4}}}
	if recordbuild.Generated(named) {
		t.Fatal("untagged f(ctx, u32 key) treated as a generated hook")
	}
	tf := filter.TargetFilters{Args: []filter.ArgFilter{{ParamName: "key", ParamIndex: 1, ParamSize: 4, Op: filter.OpEqual, Value: 1}}}
	if l, err := recordbuild.Build(named, tf, recordbuild.Options{Mode: record.ModeFilter}); err != nil || l != nil {
		t.Fatalf("default recorded at an untagged function: %+v %v", l, err)
	}
	named.Generated = true
	if l, err := recordbuild.Build(named, tf, recordbuild.Options{Mode: record.ModeFilter}); err != nil || l == nil {
		t.Fatalf("tagged hook did not record: %+v %v", l, err)
	}
}

// valueTarget is a hook taking only const T *value.
func valueTarget(t btf.Type) attach.Target {
	return attach.Target{Generated: true, Params: []attach.FuncParamInfo{
		{Name: "value", Index: 1, Size: 8, Kind: "ptr-struct", Type: &btf.Pointer{Target: &btf.Const{Type: t}}}}}
}

// The comment bound counts only the recorded bytes, so --record-max decides
// whether an explicit entry capture of a wide value fits.
func TestEntryBoundFollowsRecordMax(t *testing.T) {
	u8 := &btf.Int{Name: "__u8", Size: 1}
	// struct { __u32 n; __u8 buf[40000]; }: one hex blob past any cap.
	wide := &btf.Struct{Name: "wide", Size: 40004, Members: []btf.Member{
		{Name: "n", Type: &btf.Int{Name: "__u32", Size: 4}},
		{Name: "buf", Type: &btf.Array{Type: u8, Nelems: 40000}, Offset: 32}}}
	// 4096 named __u8 members: about 200 KB of comment if all are recorded.
	many := &btf.Struct{Name: "many", Size: 4096}
	for i := range 4096 {
		many.Members = append(many.Members, btf.Member{Name: fmt.Sprintf("member_%013d", i), Type: u8, Offset: btf.Bits(8 * i)})
	}
	for _, c := range []struct {
		name string
		typ  btf.Type
		max  int
		ok   bool
	}{
		{"wide-0", wide, 0, true}, {"wide-16", wide, 16, true}, {"wide-4096", wide, 4096, true},
		{"many-16", many, 16, true}, {"many-4096", many, 4096, false},
	} {
		l, err := recordbuild.Build(valueTarget(c.typ), filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, Explicit: true, MaxBytes: c.max})
		if c.ok && (err != nil || l == nil) {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "lower --record-max")) {
			t.Errorf("%s: want a --record-max refusal, got %+v %v", c.name, l, err)
		}
	}
}

// The bound keeps room for the exit-mode return= prefix, and a filter
// layout that does not fit is told to filter fewer fields.
func TestFilterBoundReservesReturnPrefix(t *testing.T) {
	build := func(total int) (*record.Layout, error) {
		// 32 fields cost 32*(name + "=" + 20 digits) + 31 separators.
		names := total - (32*21 + 31)
		var args []filter.ArgFilter
		for i := range 32 {
			n := names / 32
			if i == 0 {
				n += names % 32
			}
			args = append(args, filter.ArgFilter{ParamName: strings.Repeat("v", n), ParamIndex: 1, ParamSize: 8, Deref: true, Offset: uint32(8 * i)})
		}
		return recordbuild.Build(attach.Target{Generated: true}, filter.TargetFilters{Args: args}, recordbuild.Options{Mode: record.ModeFilter, Explicit: true})
	}
	fit := record.MaxCommentBytes - record.ReturnPrefixLen
	if l, err := build(fit); err != nil || l == nil || l.MaxCommentLen() != fit {
		t.Fatalf("a layout at the limit was refused: %+v %v", l, err)
	}
	if _, err := build(fit + 1); err == nil || !strings.Contains(err.Error(), "filter fewer fields") {
		t.Fatalf("a layout past the limit: %v", err)
	}
}

// A plain anonymous union is flattened under the --arg-filter names; one
// holding a pointer is skipped.
func TestCommentFlattensAnonymousUnion(t *testing.T) {
	u32, u16 := &btf.Int{Name: "__u32", Size: 4}, &btf.Int{Name: "__u16", Size: 2}
	v := &btf.Struct{Name: "v", Size: 16, Members: []btf.Member{
		{Name: "a", Type: u32},
		{Type: &btf.Union{Size: 4, Members: []btf.Member{{Name: "b", Type: u32}, {Name: "c", Type: u16}}}, Offset: 32},
		{Type: &btf.Union{Size: 8, Members: []btf.Member{{Name: "p", Type: &btf.Pointer{Target: &btf.Void{}}}, {Name: "x", Type: &btf.Int{Name: "u64", Size: 8}}}}, Offset: 64},
	}}
	l, err := recordbuild.Build(valueTarget(v), filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.Comment(block(l, record.ValidValue, func(b []byte) {
		d := b[record.EntryOffBytes:]
		binary.NativeEndian.PutUint32(d, 1)
		binary.NativeEndian.PutUint32(d[4:], 2)
		binary.NativeEndian.PutUint64(d[8:], 0xffff888812340000)
	}))
	if err != nil || got != "value->a=1 value->b=2 value->c=2" {
		t.Fatalf("anonymous unions: %q %v", got, err)
	}
}

// Keys built on the uapi LPM trie key structs show their prefix length;
// the zero-size data[] member shows nothing.
func TestCommentLPMKeys(t *testing.T) {
	u32, u8 := &btf.Int{Name: "__u32", Size: 4}, &btf.Int{Name: "__u8", Size: 1}
	flex := &btf.Array{Type: u8, Nelems: 0}
	hdr := &btf.Struct{Name: "bpf_lpm_trie_key_hdr", Size: 4, Members: []btf.Member{{Name: "prefixlen", Type: u32}}}
	legacy := &btf.Struct{Name: "bpf_lpm_trie_key", Size: 4, Members: []btf.Member{{Name: "prefixlen", Type: u32}, {Name: "data", Type: flex, Offset: 32}}}
	keyU8 := &btf.Struct{Name: "bpf_lpm_trie_key_u8", Size: 4, Members: []btf.Member{
		{Type: &btf.Union{Size: 4, Members: []btf.Member{{Name: "hdr", Type: hdr}, {Name: "prefixlen", Type: u32}}}},
		{Name: "data", Type: flex, Offset: 32}}}
	wrap := func(name string, inner btf.Type) btf.Type {
		return &btf.Struct{Name: "k", Size: 8, Members: []btf.Member{
			{Name: name, Type: inner}, {Name: "addr", Type: &btf.Array{Type: u8, Nelems: 4}, Offset: 32}}}
	}
	for _, c := range []struct {
		typ  btf.Type
		want string
	}{
		{wrap("hdr", hdr), "value->hdr.prefixlen=24 value->addr=0a000001"},
		{wrap("lpm_key", legacy), "value->lpm_key.prefixlen=24 value->addr=0a000001"},
		{wrap("lpm_key", keyU8), "value->lpm_key.hdr.prefixlen=24 value->lpm_key.prefixlen=24 value->addr=0a000001"},
		{keyU8, "value->hdr.prefixlen=24 value->prefixlen=24"},
	} {
		l, err := recordbuild.Build(valueTarget(c.typ), filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: 64})
		if err != nil {
			t.Fatal(err)
		}
		got, err := l.Comment(block(l, record.ValidValue, func(b []byte) {
			d := b[record.EntryOffBytes:]
			binary.NativeEndian.PutUint32(d, 24)
			if len(d) >= 8 {
				copy(d[4:], []byte{10, 0, 0, 1})
			}
		}))
		if err != nil || got != c.want {
			t.Errorf("lpm key: %q %v, want %q", got, err, c.want)
		}
	}
}

// One rule for each top-level key or value shape, shared by the renderer
// and the bound.
func TestCommentTopLevelShapes(t *testing.T) {
	u32 := &btf.Int{Name: "__u32", Size: 4}
	u8 := &btf.Int{Name: "__u8", Size: 1}
	ptr := &btf.Pointer{Target: &btf.Void{}}
	noBTF := &btf.Struct{Size: 8, Members: []btf.Member{{Name: "bytes", Type: &btf.Array{Type: u8, Nelems: 8}}}}
	for _, c := range []struct {
		name string
		typ  btf.Type
		size uint32 // for an untyped value
		len  int
		want string
	}{
		{"int", u32, 0, 4, "value[0]=1"},
		{"int cut", u32, 0, 2, "value_bytes=2/4"},
		{"enum", &btf.Enum{Name: "e", Size: 4}, 0, 4, "value[0]=1"},
		{"plain array", &btf.Array{Type: u32, Nelems: 2}, 0, 8, "value=0100000002000000"},
		{"plain array cut", &btf.Array{Type: u32, Nelems: 2}, 0, 4, "value=01000000 value_bytes=4/8"},
		{"plain union", &btf.Union{Size: 4, Members: []btf.Member{{Name: "a", Type: u32}}}, 0, 4, "value=01000000"},
		{"zero-length array", &btf.Array{Type: u32, Nelems: 0}, 0, 0, ""},
		{"pointer", ptr, 0, 8, ""},
		{"pointer array", &btf.Array{Type: ptr, Nelems: 1}, 0, 8, ""},
		{"opaque struct", &btf.Struct{Name: "bpf_timer", Size: 8, Members: []btf.Member{{Name: "__opaque", Type: &btf.Int{Name: "u64", Size: 8}}}}, 0, 8, ""},
		{"plain struct", &btf.Struct{Name: "s", Size: 4, Members: []btf.Member{{Name: "a", Type: u32}}}, 0, 4, "value->a=1"},
		{"no BTF at a typed hook", noBTF, 0, 8, "value=0100000002000000"},
		{"no BTF at a typed hook, cut", noBTF, 0, 4, "value=01000000 value_bytes=4/8"},
		{"untyped void", &btf.Void{}, 8, 4, "value=01000000 value_bytes=4/8"},
	} {
		target := valueTarget(c.typ)
		target.Params[0].VoidSize = c.size
		l, err := recordbuild.Build(target, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: c.len})
		if err != nil {
			t.Fatal(err)
		}
		got, err := l.Comment(block(l, record.ValidValue, func(b []byte) {
			d := b[record.EntryOffBytes:]
			for i := 0; i+4 <= len(d); i += 4 {
				binary.NativeEndian.PutUint32(d[i:], uint32(i/4+1))
			}
		}))
		if err != nil || got != c.want || len(got) > l.MaxCommentLen() {
			t.Errorf("%s: %q (bound %d) %v, want %q", c.name, got, l.MaxCommentLen(), err, c.want)
		}
	}
}

// A side whose read failed still writes NAME=?, so the bound counts it: a
// key sized so the bound is exactly at the limit, with a value whose members
// all hide, renders within the limit when the value read fails.
func TestBoundCountsFailedRead(t *testing.T) {
	u64 := &btf.Int{Name: "u64", Size: 8}
	value := &btf.Struct{Name: "v", Size: 8, Members: []btf.Member{{Name: "p", Type: &btf.Pointer{Target: u64}}}}
	key := &btf.Struct{Name: "k", Size: 4096}
	for i := range 512 {
		key.Members = append(key.Members, btf.Member{Name: fmt.Sprintf("m%03d", i), Type: u64, Offset: btf.Bits(64 * i)})
	}
	params := func() []attach.FuncParamInfo {
		ptr := func(t btf.Type) btf.Type { return &btf.Pointer{Target: &btf.Const{Type: t}} }
		return []attach.FuncParamInfo{{Name: "key", Index: 1, Size: 8, Kind: "ptr-struct", Type: ptr(key)},
			{Name: "value", Index: 2, Size: 8, Kind: "ptr-struct", Type: ptr(value)}}
	}
	opt := recordbuild.Options{Mode: record.ModeEntry, Explicit: true, MaxBytes: 4096}
	l, err := recordbuild.Build(attach.Target{Generated: true, Params: params()}, filter.TargetFilters{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	// Pad the first member name until the bound plus the return= prefix is
	// exactly the pcapng option limit.
	key.Members[0].Name += strings.Repeat("x", record.MaxCommentBytes-record.ReturnPrefixLen-l.MaxCommentLen())
	if l, err = recordbuild.Build(attach.Target{Generated: true, Params: params()}, filter.TargetFilters{}, opt); err != nil {
		t.Fatalf("a layout at the limit was refused: %v", err)
	}
	if n := l.MaxCommentLen() + record.ReturnPrefixLen; n != record.MaxCommentBytes {
		t.Fatalf("bound %d, want %d", n, record.MaxCommentBytes)
	}
	got, err := l.AppendComment([]byte("return=0x00000000"), block(l, record.ValidKey, func(b []byte) {
		for k := record.EntryOffBytes; k+8 <= record.EntryOffBytes+4096; k += 8 {
			binary.NativeEndian.PutUint64(b[k:], 0xc000000000000000)
		}
	}))
	if err != nil || len(got) > record.MaxCommentBytes || !strings.HasSuffix(string(got), " value=?") {
		t.Fatalf("comment %d bytes (limit %d) %v, ends %q", len(got), record.MaxCommentBytes, err, got[max(0, len(got)-20):])
	}
}

// randType builds a random key or value type mixing every shape the decoder
// handles, plain or not. A tight type uses only 64-bit integers, so filled
// with their widest values its comment reaches the bound.
func randType(r *rand.Rand, depth int, tight bool) btf.Type {
	ints := []*btf.Int{{Name: "u64", Size: 8}, {Name: "s64", Size: 8, Encoding: btf.Signed}}
	if !tight {
		ints = append(ints, &btf.Int{Name: "u8", Size: 1}, &btf.Int{Name: "s16", Size: 2, Encoding: btf.Signed},
			&btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "bool", Size: 1, Encoding: btf.Bool})
	}
	switch k := r.IntN(10); {
	case k < 4 || depth > 2 || k == 4 && tight:
		return ints[r.IntN(len(ints))]
	case k == 4:
		return &btf.Enum{Name: "e", Size: 4, Signed: r.IntN(2) == 0}
	case k == 5:
		return &btf.Array{Type: randType(r, depth+1, tight), Nelems: uint32(r.IntN(6))}
	case k == 6:
		return &btf.Pointer{Target: &btf.Void{}}
	case k == 7:
		return &btf.Struct{Name: "bpf_timer", Size: 16, Members: []btf.Member{{Name: "__opaque", Type: &btf.Array{Type: ints[0], Nelems: 2}}}}
	case k == 8:
		u := &btf.Union{Name: "u"}
		for i := range 1 + r.IntN(3) {
			m := randType(r, depth+1, tight)
			size, _ := btf.Sizeof(m)
			u.Size = max(u.Size, uint32(size))
			u.Members = append(u.Members, btf.Member{Name: fmt.Sprintf("u%d", i), Type: m})
		}
		return u
	}
	s := &btf.Struct{Name: "s"}
	var off uint32 // bits
	for i := range 1 + r.IntN(6) {
		m := btf.Member{Name: fmt.Sprintf("member%d_%s", i, strings.Repeat("x", r.IntN(12)))}
		if !tight && r.IntN(4) == 0 { // bitfield
			m.Type, m.BitfieldSize, m.Offset = &btf.Int{Name: "u32", Size: 4}, btf.Bits(1+r.IntN(31)), btf.Bits(off)
			off += uint32(m.BitfieldSize)
		} else {
			m.Type = randType(r, depth+1, tight)
			size, _ := btf.Sizeof(m.Type)
			off = (off + 63) &^ 63
			m.Offset = btf.Bits(off)
			off += 8 * uint32(size)
			switch m.Type.(type) {
			case *btf.Struct, *btf.Union:
				if r.IntN(2) == 0 {
					m.Name = "" // anonymous
				}
			}
		}
		s.Members = append(s.Members, m)
	}
	s.Size = (off + 63) / 64 * 8
	return s
}

// No comment, with the writer's exit-mode prefix, is longer than the bound
// Build checks, for any layout, recorded length and block contents. Tight
// cases fill every 64-bit field with a 20-character value, so they also
// catch a bound that undercounts by a byte per field.
func TestCommentWithinBound(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	prefix := []byte("return=0x00000000")
	tightSlack := map[int]int{}
	for i := range 4000 {
		tight := i%2 == 0
		typ := randType(r, 0, tight)
		size, err := btf.Sizeof(typ)
		if err != nil {
			continue
		}
		maxBytes := []int{0, 1, 3, size / 2, size, r.IntN(size + 1)}[r.IntN(6)]
		params := []attach.FuncParamInfo{{Name: "site", Index: 1, Size: 4}}
		if tight { // a u32 site has 10 digits of slack
			params, maxBytes = nil, size
		}
		params = append(params, attach.FuncParamInfo{Name: "key", Index: 2, Size: 8},
			attach.FuncParamInfo{Name: "value", Index: 3, Size: 8, Kind: "ptr-struct", Type: &btf.Pointer{Target: typ}},
			attach.FuncParamInfo{Name: "status", Index: 4, Size: 8})
		var args []filter.ArgFilter
		for j := range r.IntN(4) {
			args = append(args, filter.ArgFilter{ParamName: strings.Repeat("f", r.IntN(30)), ParamIndex: 3, ParamSize: 8,
				Deref: j > 0 || tight, Pointer: j == 0 && !tight, Signed: r.IntN(2) == 0, Offset: uint32(8 * j)})
		}
		for _, mode := range []record.Mode{record.ModeEntry, record.ModeFilter} {
			l, err := recordbuild.Build(attach.Target{Generated: true, Params: params}, filter.TargetFilters{Args: args}, recordbuild.Options{Mode: mode, MaxBytes: maxBytes})
			if err != nil || l == nil {
				continue
			}
			valid := r.Uint32()
			if tight { // every field read, or one side's read failed
				valid = ^uint32(0) &^ []uint32{0, record.ValidKey, record.ValidValue}[r.IntN(3)]
			}
			b := block(l, valid, func(b []byte) {
				for k := record.HeaderSize; k < len(b); k++ {
					b[k] = byte(r.Uint32())
				}
				if tight || r.IntN(2) == 0 { // 13835058055282163712 or -4611686018427387904
					for k := record.HeaderSize; k+8 <= len(b); k += 8 {
						binary.NativeEndian.PutUint64(b[k:], 0xc000000000000000)
					}
				}
				if mode == record.ModeEntry {
					binary.NativeEndian.PutUint16(b[record.EntryOffKeyLen:], uint16(l.Key.Len))
					binary.NativeEndian.PutUint16(b[record.EntryOffValueLen:], uint16(l.Value.Len))
				}
			})
			got, err := l.AppendComment(append([]byte(nil), prefix...), b)
			if err != nil {
				t.Fatalf("case %d %s: %v", i, mode, err)
			}
			bound := l.MaxCommentLen() + record.ReturnPrefixLen
			if len(got) > bound {
				t.Fatalf("case %d %s: comment %d bytes over bound %d: %q", i, mode, len(got), bound, got)
			}
			if tight {
				tightSlack[bound-len(got)]++
			}
		}
	}
	t.Logf("tight cases by bound slack (bytes: count): %v", tightSlack)
}

// A filter on a member inside a bpf_* struct is tested but never recorded:
// the default layout leaves it out, an explicit --record filter refuses it.
func TestFilterOmitsOpaquePaths(t *testing.T) {
	u32, u64 := &btf.Int{Name: "__u32", Size: 4}, &btf.Int{Name: "__u64", Size: 8}
	work := &btf.Struct{Name: "bpf_task_work", Size: 8, Members: []btf.Member{{Name: "__opaque", Type: u64}}}
	v := &btf.Struct{Name: "v", Size: 16, Members: []btf.Member{{Name: "rc", Type: u32}, {Name: "tw", Type: work, Offset: 64}}}
	target := valueTarget(v)
	args, err := filter.ParseAndValidateFilters([]string{"value->rc==1", "value->tw.__opaque==2"}, target.Params)
	if err != nil {
		t.Fatal(err)
	}
	// The same two fields as a --set key: key(rc=arg:value->rc, op=arg:value->tw.__opaque).
	set := &setmap.Set{SpecRef: setmap.SpecRef{Name: "s", Mapping: []setmap.MapEntry{
		{Field: "rc", Source: "arg:value->rc"}, {Field: "op", Source: "arg:value->tw.__opaque"}}},
		Def: &setmap.Definition{KeySize: 16, Fields: []setmap.KeyField{{Name: "rc", Size: 4}, {Name: "op", Off: 8, Size: 8}},
			ValFields: []setmap.KeyField{{Name: setmap.ValFieldTag, Size: 4}}}}
	sets, err := filter.ResolveSetFilters([]*setmap.Set{set}, []string{"s"}, target.Params)
	if err != nil {
		t.Fatal(err)
	}
	for name, tf := range map[string]filter.TargetFilters{"--arg-filter": {Args: args}, "--set": {Sets: sets}} {
		if got := recordbuild.OmittedFields(tf); len(got) != 1 || got[0] != "value->tw.__opaque" {
			t.Fatalf("%s: omitted %q", name, got)
		}
		l, err := recordbuild.Build(target, tf, recordbuild.Options{Mode: record.ModeFilter})
		if err != nil || l == nil || len(l.Fields) != 1 || l.Fields[0].Name != "value->rc" {
			t.Fatalf("%s: default layout %+v %v", name, l, err)
		}
		got, err := l.Comment(block(l, 1, func(b []byte) { binary.NativeEndian.PutUint64(b[record.HeaderSize:], 1) }))
		if err != nil || got != "value->rc=1" {
			t.Fatalf("%s: comment %q %v", name, got, err)
		}
		if _, err := recordbuild.Build(target, tf, recordbuild.Options{Mode: record.ModeFilter, Explicit: true}); err == nil || !strings.Contains(err.Error(), "bpf_* struct") {
			t.Fatalf("%s: explicit --record filter: %v", name, err)
		}
		if l, err := recordbuild.Build(target, tf, recordbuild.Options{Mode: record.ModeNone, Explicit: true}); err != nil || l != nil {
			t.Fatalf("%s: --record none: %+v %v", name, l, err)
		}
	}
}

// An integer key or value passed by value is recorded whole or not at all.
func TestEntryIntegerWholeOrNothing(t *testing.T) {
	target := attach.Target{Generated: true, Params: []attach.FuncParamInfo{
		{Name: "key", Index: 1, Size: 4}, {Name: "value", Index: 2, Size: 8}}}
	for _, c := range []struct {
		max         int
		key, value  uint32
		wantComment string
	}{
		{3, 0, 0, "key_bytes=0/4 value_bytes=0/8"},
		{7, 4, 0, "key=7 value_bytes=0/8"},
		{8, 4, 8, "key=7 value=9"},
	} {
		l, err := recordbuild.Build(target, filter.TargetFilters{}, recordbuild.Options{Mode: record.ModeEntry, MaxBytes: c.max})
		if err != nil || l.Key.Len != c.key || l.Value.Len != c.value {
			t.Fatalf("--record-max %d: %+v %v", c.max, l, err)
		}
		got, err := l.Comment(block(l, record.ValidKey|record.ValidValue, func(b []byte) {
			d := b[record.EntryOffBytes:]
			if l.Key.Len > 0 {
				binary.NativeEndian.PutUint32(d, 7)
			}
			if l.Value.Len > 0 {
				binary.NativeEndian.PutUint64(d[l.Key.Len:], 9)
			}
		}))
		if err != nil || got != c.wantComment {
			t.Errorf("--record-max %d: %q %v, want %q", c.max, got, err, c.wantComment)
		}
	}
}
