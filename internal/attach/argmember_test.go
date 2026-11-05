package attach

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
)

func memberTestParams(t *testing.T) []FuncParamInfo {
	t.Helper()
	u64 := &btf.Int{Name: "u64", Size: 8}
	i32 := &btf.Int{Name: "i32", Size: 4, Encoding: btf.Signed}
	query := &btf.Struct{Name: "classifier_query", Size: 64, Members: []btf.Member{
		{Name: "imsi", Type: u64},
		{Name: "target", Offset: 64, Type: &btf.Typedef{Name: "target_t", Type: &btf.Struct{Size: 8, Members: []btf.Member{
			{Name: "pdr_id", Type: i32, Offset: 32},
		}}}},
		{Offset: 128, Type: &btf.Union{Size: 8, Members: []btf.Member{
			{Name: "seid", Type: u64},
			{Name: "tag", Type: &btf.Enum{Name: "tag", Size: 4, Signed: true}},
		}}},
		{Name: "bits", Type: i32, Offset: 192, BitfieldSize: 3},
		{Name: "next", Type: &btf.Pointer{Target: i32}, Offset: 256},
		{Name: "array", Type: &btf.Array{Type: i32, Index: i32, Nelems: 2}, Offset: 320},
		{Name: "odd", Type: &btf.Int{Name: "odd", Size: 3}, Offset: 384},
		{Name: "small", Type: &btf.Int{Name: "i8", Size: 1, Encoding: btf.Signed}, Offset: 416},
		{Name: "half", Type: &btf.Int{Name: "u16", Size: 2}, Offset: 432},
	}}
	ptr := &btf.Typedef{Name: "query_ptr", Type: &btf.Const{Type: &btf.Pointer{Target: &btf.Volatile{Type: query}}}}
	fn := &btf.Func{Name: "sdf_classify", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: i32, Params: []btf.FuncParam{
		{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 4}}},
		{Name: "q", Type: ptr}, {Name: "n", Type: i32},
		{Name: "u", Type: &btf.Pointer{Target: &btf.Union{Name: "choice", Size: 8, Members: []btf.Member{{Name: "value", Type: u64}}}}},
	}}}
	builder, err := btf.NewBuilder([]btf.Type{fn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	params, err := GetFuncParamsFromSpec(spec, "sdf_classify")
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func TestMemberParamDiscovery(t *testing.T) {
	params := memberTestParams(t)
	if len(params) != 3 || params[0].Kind != "ptr-struct" || params[0].TypeName != "classifier_query" || params[0].Index != 1 || params[2].Kind != "ptr-union" {
		t.Fatalf("params: %+v", params)
	}
	if want := (FuncParamInfo{Name: "n", Index: 2, Size: 4, Signed: true}); !reflect.DeepEqual(params[1], want) {
		t.Fatalf("integer metadata changed: %+v", params[1])
	}
}

func TestResolveArgMember(t *testing.T) {
	params := memberTestParams(t)
	for _, tt := range []struct {
		expr         string
		offset, size uint32
		signed       bool
	}{
		{"q->imsi", 0, 8, false}, {"q->target.pdr_id", 12, 4, true},
		{"q->seid", 16, 8, false}, {"q->tag", 16, 4, true},
		{"q->small", 52, 1, true}, {"q->half", 54, 2, false},
		{"u->value", 0, 8, false},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := ResolveArg(tt.expr, params)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Deref || got.Name != tt.expr || got.Offset != tt.offset || got.Size != tt.size || got.Signed != tt.signed {
				t.Fatalf("resolved: %+v", got)
			}
		})
	}
	for _, tt := range []struct{ expr, want string }{
		{"q", "select an integer member"}, {"n->imsi", "must be a pointer"},
		{"missing->imsi", "available parameters: [q n u]"},
		{"q->missing", "available members: [imsi target seid tag bits next array odd small half]"},
		{"q->target.bad", "available members: [pdr_id]"},
		{"q->bits", "bitfield"}, {"q->next", "integer or enum"},
		{"q->next.value", `cannot select member "value" from pointer (only one dereference is supported); expected struct/union`}, {"q->target", "integer or enum"},
		{"q->array", "integer or enum"}, {"q->odd", "unsupported member size 3"},
		{"q->", "invalid argument expression"}, {"q->target..pdr_id", "invalid argument expression"},
		{"q->next->value", "invalid argument expression"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			_, err := ResolveArg(tt.expr, params)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// A member path through a bpf_* struct resolves as before but is marked
// ThroughOpaque, also when an anonymous bpf_* member promotes it; the LPM
// key structs are not opaque.
func TestResolveArgMarksBPFStructs(t *testing.T) {
	u32, u64 := &btf.Int{Name: "__u32", Size: 4}, &btf.Int{Name: "__u64", Size: 8}
	work := &btf.Struct{Name: "bpf_task_work", Size: 8, Members: []btf.Member{{Name: "__opaque", Type: u64}}}
	hdr := &btf.Struct{Name: "bpf_lpm_trie_key_hdr", Size: 4, Members: []btf.Member{{Name: "prefixlen", Type: u32}}}
	value := &btf.Struct{Name: "v", Size: 24, Members: []btf.Member{
		{Name: "rc", Type: u32}, {Name: "hdr", Type: hdr, Offset: 32}, {Name: "tw", Type: work, Offset: 64},
		{Type: work, Offset: 128}}} // anonymous: promotes __opaque at offset 16
	ptr := func(t btf.Type) btf.Type { return &btf.Pointer{Target: &btf.Const{Type: t}} }
	params := []FuncParamInfo{
		{Name: "value", Index: 1, Size: 8, Kind: "ptr-struct", Type: ptr(value)},
		{Name: "w", Index: 2, Size: 8, Kind: "ptr-struct", Type: ptr(work)},
	}
	for _, c := range []struct {
		expr    string
		offset  uint32
		through bool
	}{
		{"value->rc", 0, false}, {"value->hdr.prefixlen", 4, false},
		{"value->tw.__opaque", 8, true}, {"value->__opaque", 16, true}, {"w->__opaque", 0, true},
	} {
		got, err := ResolveArg(c.expr, params)
		if err != nil || got.Offset != c.offset || got.ThroughOpaque != c.through {
			t.Errorf("%s: %+v %v, want offset %d through %v", c.expr, got, err, c.offset, c.through)
		}
	}
}

func TestResolveEchoMembers(t *testing.T) {
	params := memberTestParams(t)
	got, err := ResolveEchoArgs(nil, params)
	if err != nil || len(got) != 1 || got[0].Name != "n" {
		t.Fatalf("default echo: %+v, %v", got, err)
	}
	got, err = ResolveEchoArgs([]string{"q->imsi", "n", "q->target.pdr_id"}, params)
	if err != nil || len(got) != 3 || !got[0].Deref || got[1].Deref || !got[2].Signed {
		t.Fatalf("selected echo: %+v, %v", got, err)
	}
	if _, err := ResolveEchoArgs([]string{"q->bad"}, params); err == nil {
		t.Fatal("invalid member accepted")
	}
}

func TestScalarPointerDiscovery(t *testing.T) {
	u32 := &btf.Typedef{Name: "__u32", Type: &btf.Int{Name: "unsigned int", Size: 4}}
	fn := &btf.Func{Name: "scalar_hook", Type: &btf.FuncProto{Return: &btf.Int{Size: 4}, Params: []btf.FuncParam{
		{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 4}}},
		{Name: "value", Type: &btf.Pointer{Target: &btf.Const{Type: u32}}},
		{Name: "opaque", Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}}},
		{Name: "choice", Type: &btf.Pointer{Target: &btf.Union{Name: "choice", Size: 4}}},
	}}}
	builder, err := btf.NewBuilder([]btf.Type{fn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	params, err := GetFuncParamsFromSpec(spec, "scalar_hook")
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 3 || params[0].Kind != "ptr" || params[1].Kind != "ptr" || params[2].Kind != "ptr-union" {
		t.Fatalf("params: %+v", params)
	}
	got, err := ResolveArg("value[0]", params)
	if err != nil || !got.Deref || got.Size != 4 || got.Offset != 0 || got.Index != 1 {
		t.Fatalf("resolved: %+v %v", got, err)
	}
	rows, truncated := ListArgMembers(params[0], 3)
	if len(rows) != 1 || rows[0].Expression != "value[0]" || rows[0].Type != "const __u32" || !rows[0].Filterable || truncated != "" {
		t.Fatalf("members: %+v %s", rows, truncated)
	}
	for _, name := range []string{"value", "opaque", "choice"} {
		if _, err := ResolvePointerArg(name, params); err != nil {
			t.Fatal(err)
		}
	}
	echo, err := ResolveEchoArgs([]string{"value[0]"}, params)
	if err != nil || len(echo) != 1 || !echo[0].Deref {
		t.Fatalf("echo: %+v %v", echo, err)
	}
	for _, expr := range []string{"value", "value[1]", "value[-1]", "opaque[0]", "value->member", "choice[0]"} {
		if _, err := ResolveArg(expr, params); err == nil {
			t.Errorf("accepted %s", expr)
		}
	}
	if _, err := ResolveArg("opaque[0]", params); err == nil || err.Error() != `"opaque[0]": final member must be an integer or enum, got void` {
		t.Fatalf("void pointee diagnostic: %v", err)
	}
}

// A sized untyped pointer reads as struct { u8 bytes[N]; }, as a static hook
// declares it; without a size it has no members.
func TestResolveArgSizedVoid(t *testing.T) {
	void := &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}}
	params := []FuncParamInfo{{Name: "value", Index: 3, Kind: "pointer", Type: void, VoidSize: 8}, {Name: "key", Index: 2, Kind: "pointer", Type: void}}
	for _, tc := range []struct {
		expr   string
		offset uint32
	}{{"value->bytes[0]", 0}, {"value->bytes[7]", 7}} {
		p, err := ResolveArg(tc.expr, params)
		if err != nil || !p.Deref || p.Offset != tc.offset || p.Size != 1 || p.Index != 3 {
			t.Fatalf("%s: %+v %v", tc.expr, p, err)
		}
	}
	for _, expr := range []string{"value->bytes[8]", "value[0]", "key->bytes[0]"} {
		if _, err := ResolveArg(expr, params); err == nil {
			t.Errorf("accepted %s", expr)
		}
	}
}

// buildSpec marshals one FUNC with a void* value parameter and loads it back,
// the way inject-run's BTF reaches the capture.
// buildSpec round-trips one func named rec_hook per tag list.
func buildSpec(t *testing.T, tags ...[]string) *btf.Spec {
	t.Helper()
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: []btf.FuncParam{
		{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 4, Members: []btf.Member{{Name: "data", Type: &btf.Int{Name: "u32", Size: 4}}}}}},
		{Name: "value", Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}}},
	}}
	var fns []btf.Type
	for _, tg := range tags {
		fns = append(fns, &btf.Func{Name: "rec_hook", Linkage: btf.StaticFunc, Type: proto, Tags: tg})
	}
	b, err := btf.NewBuilder(fns, nil)
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

// IsGeneratedHook and the void size are read from a round-tripped BTF spec;
// an untagged function is not generated, and its size tags are ignored.
func TestGeneratedHookRoundTrip(t *testing.T) {
	tagged := buildSpec(t, []string{hookabi.HookTag, "bpf-ninja:value_size=16"})
	if !IsGeneratedHook(tagged, "rec_hook") {
		t.Fatal("tagged func not recognised as generated")
	}
	params, err := GetFuncParamsFromSpec(tagged, "rec_hook")
	if err != nil || len(params) != 1 || params[0].Name != "value" || params[0].VoidSize != 16 {
		t.Fatalf("params %+v %v", params, err)
	}
	// Same tags, but without the hook tag: not generated, size ignored.
	untagged := buildSpec(t, []string{"bpf-ninja:value_size=16"})
	if IsGeneratedHook(untagged, "rec_hook") {
		t.Fatal("untagged func recognised as generated")
	}
	params, err = GetFuncParamsFromSpec(untagged, "rec_hook")
	if err != nil || params[0].VoidSize != 0 {
		t.Fatalf("size honoured without the hook tag: %+v %v", params, err)
	}
	// Two funcs share the name (static functions of two objects): the name
	// does not say which is the target, so neither counts as generated.
	dup := buildSpec(t, []string{"bpf-ninja:value_size=16"}, []string{hookabi.HookTag, "bpf-ninja:value_size=16"})
	if IsGeneratedHook(dup, "rec_hook") {
		t.Fatal("ambiguous name recognised as generated")
	}
	if params, err := GetFuncParamsFromSpec(dup, "rec_hook"); err == nil {
		t.Fatalf("ambiguous name resolved: %+v", params)
	}
}

func arrayIndexParams() []FuncParamInfo {
	u8, u16, u32 := &btf.Int{Name: "u8", Size: 1}, &btf.Int{Name: "u16", Size: 2}, &btf.Int{Name: "u32", Size: 4}
	arr := func(t btf.Type, n uint32) btf.Type { return &btf.Array{Type: t, Index: u32, Nelems: n} }
	rule := &btf.Struct{Name: "rule", Size: 12, Members: []btf.Member{{Name: "id", Type: u32}, {Name: "action", Type: u8, Offset: 88}}}
	group := &btf.Struct{Name: "group", Size: 28, Members: []btf.Member{{Name: "tag", Type: u32}, {Name: "rules", Type: arr(rule, 2), Offset: 32}}}
	value := &btf.Struct{Name: "value", Size: 96, Members: []btf.Member{
		{Name: "rules", Type: &btf.Typedef{Name: "rules_t", Type: arr(&btf.Const{Type: rule}, 3)}},
		{Name: "counts", Type: arr(u32, 4), Offset: 288},
		{Name: "grid", Type: arr(arr(u16, 3), 2), Offset: 416},
		{Name: "groups", Type: arr(group, 1), Offset: 512},
		{Name: "next", Type: &btf.Pointer{Target: u32}, Offset: 736},
		{Name: "empty", Type: arr(u8, 0), Offset: 768},
		{Name: "rulegrid", Type: arr(arr(rule, 2), 2), Offset: 768},
		{Name: "flex", Type: arr(rule, 0), Offset: 1152},
		{Name: "locks", Type: arr(&btf.Struct{Name: "bpf_spin_lock", Size: 4, Members: []btf.Member{{Name: "val", Type: u32}}}, 2), Offset: 1152},
	}}
	return []FuncParamInfo{
		{Name: "value", Index: 1, Size: 8, Kind: "ptr-struct", Type: &btf.Pointer{Target: value}},
		{Name: "vec", Index: 2, Size: 8, Kind: "ptr", Type: &btf.Pointer{Target: arr(u16, 4)}},
		{Name: "n", Index: 3, Size: 4},
		{Name: "rs", Index: 4, Size: 8, Kind: "ptr", Type: &btf.Pointer{Target: arr(rule, 3)}},
		{Name: "sc", Index: 5, Size: 8, Kind: "ptr", Type: &btf.Pointer{Target: u32}},
		{Name: "st", Index: 6, Size: 8, Kind: "ptr-struct", Type: &btf.Pointer{Target: rule}},
	}
}

func TestResolveArgArrayIndex(t *testing.T) {
	params := arrayIndexParams()
	for _, tt := range []struct {
		expr         string
		offset, size uint32
	}{
		{"value->rules[0].action", 11, 1}, {"value->rules[2].action", 35, 1}, {"value->rules[1].id", 12, 4},
		{"value->counts[0]", 36, 4}, {"value->counts[3]", 48, 4},
		{"value->grid[1][2]", 52 + 10, 2},
		{"value->groups[0].tag", 64, 4}, {"value->groups[0].rules[1].action", 64 + 4 + 12 + 11, 1},
		{"vec[0][3]", 6, 2},
		{"rs[0][2].action", 35, 1}, {"rs[0][1].id", 12, 4},
		{"st[0].action", 11, 1}, {"sc[0]", 0, 4},
		{"value->rulegrid[1][1].action", 96 + 36 + 11, 1},
	} {
		got, err := ResolveArg(tt.expr, params)
		if err != nil {
			t.Errorf("%s: %v", tt.expr, err)
			continue
		}
		if !got.Deref || got.Name != tt.expr || got.Offset != tt.offset || got.Size != tt.size {
			t.Errorf("%s: %+v, want offset %d size %d", tt.expr, got, tt.offset, tt.size)
		}
	}
	for _, tt := range []struct{ expr, want string }{
		{"value->rules[3].action", "index 3 is out of range for an array of 3 elements"},
		{"value->grid[0][3]", "index 3 is out of range"},
		{"value->empty[0]", "out of range for an array of 0 elements"},
		{"value->rules[-1].action", "[-1] must be a non-negative decimal constant"},
		{"value->rules[i].action", "[i] must be a non-negative decimal constant"},
		{"value->rules[].action", "[] must be a non-negative decimal constant"},
		{"value->rules[0x1].action", "must be a non-negative decimal constant"},
		{"value->rules[99999999999].action", "out of range"},
		{"value->rules[99999999999999999999999].action", "must be a non-negative decimal constant"},
		{"value->counts[01]", "[01] must be a non-negative decimal constant"},
		{"sc[0->x]", "invalid argument expression"}, {"vec[0][1->x]", "invalid argument expression"},
		{"sc[0->x][1]", "invalid argument expression"}, {"value->counts[1->x]", "invalid argument expression"},
		{"rs[0]", "got array (select an element with [N])"},
		{"rs[0][1]", "got struct"}, {"rs[0][3].id", "index 3 is out of range"},
		{"rs[1][0].id", "takes only [0]"},
		{"rs->id", "select an element with [N]"},
		{"st.action", `parameter "st" is a pointer; select a member with st->action`},
		{"value->rules[1.5].action", "invalid argument expression"},
		{"value->rules.action", `cannot select member "action" from array (select an element with [N])`},
		{"value->rules[0]", "got struct"},
		{"value->counts", "got array (select an element with [N])"},
		{"value->grid[1]", "got array (select an element with [N])"},
		{"value->empty", "got zero-length array"},
		{"value->counts[1][1]", "cannot apply [1] to integer"},
		{"value->rules[0].id[0]", "cannot apply [0] to integer"},
		{"value->next[0]", "cannot apply [0] to pointer"},
		{"value->rules[0]->id", "invalid argument expression"},
		{"value[1]", "takes only [0]"},
		{"vec[0]", "got array (select an element with [N])"},
		{"vec[1][0]", "takes only [0]"},
		{"vec[0][4]", "index 4 is out of range"},
		{"n[0]", "must be a pointer"},
	} {
		if _, err := ResolveArg(tt.expr, params); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error = %v, want %q", tt.expr, err, tt.want)
		}
	}
}

// The listing shows an array of structs through its first element, and every
// row must agree with the resolver.
func TestListArgMembersThroughArrays(t *testing.T) {
	params := arrayIndexParams()
	members, truncated := ListArgMembers(params[0], DefaultMembersDepth)
	if truncated != "" {
		t.Fatalf("truncated: %q", truncated)
	}
	all := checkMemberResolution(t, params, members)
	if n := all["value->rules[0].action"]; !n.Filterable || n.Offset != 11 {
		t.Errorf("array element member: %+v", n)
	}
	if n := all["value->groups[0].rules[0].action"]; !n.Filterable || n.Offset != 64+4+11 {
		t.Errorf("nested array element member: %+v", n)
	}
	if n := all["value->counts"]; n.Filterable || !strings.Contains(n.Reason, "[N]") || len(n.Members) != 1 {
		t.Errorf("array of scalars: %+v", n)
	}
	if n := all["value->counts[0]"]; !n.Filterable || n.Type != "u32" || n.Offset != 36 {
		t.Errorf("array of scalars element: %+v", n)
	}
	if n := all["value->grid[0][0]"]; !n.Filterable || n.Type != "u16" || n.Offset != 52 {
		t.Errorf("two-dimensional array of scalars: %+v", n)
	}
	if n := all["value->rulegrid[0][0].action"]; !n.Filterable || n.Offset != 96+11 {
		t.Errorf("two-dimensional array of structs: %+v", n)
	}
	if n := all["value->flex"]; n.Filterable || len(n.Members) != 0 {
		t.Errorf("zero-length array of structs: %+v", n)
	}

	// A pointer to an array lists its first element too.
	u8, u16 := &btf.Int{Name: "u8", Size: 1}, &btf.Int{Name: "u16", Size: 2}
	rule := &btf.Struct{Name: "rule", Size: 12, Members: []btf.Member{{Name: "action", Type: u8, Offset: 88}}}
	arr := func(t btf.Type, n uint32) btf.Type { return &btf.Array{Type: t, Index: u16, Nelems: n} }
	for _, tt := range []struct {
		target    btf.Type
		want, typ string
	}{
		{arr(u16, 4), "p[0][0]", "u16"}, {arr(arr(u16, 2), 2), "p[0][0][0]", "u16"},
		{arr(rule, 3), "p[0][0].action", "u8"}, {arr(arr(rule, 2), 2), "p[0][0][0].action", "u8"},
		{arr(rule, 0), "", ""},
	} {
		ps := []FuncParamInfo{{Name: "p", Index: 1, Size: 8, Kind: "ptr", Type: &btf.Pointer{Target: tt.target}}}
		rows, _ := ListArgMembers(ps[0], DefaultMembersDepth)
		got := checkMemberResolution(t, ps, rows)
		if tt.want == "" {
			if len(rows) != 0 {
				t.Errorf("zero-length array lists %+v", rows)
			}
		} else if n := got[tt.want]; !n.Filterable || n.Type != tt.typ {
			t.Errorf("%s: rows %+v", tt.want, rows)
		}
	}
}

func TestResolveArgIndexThroughBPFStruct(t *testing.T) {
	got, err := ResolveArg("value->locks[1].val", arrayIndexParams())
	if err != nil || got.Offset != 148 || !got.ThroughOpaque {
		t.Fatalf("%+v %v", got, err)
	}
}

func statusHookParams(t *testing.T, tags []string) []FuncParamInfo {
	t.Helper()
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	fn := &btf.Func{Name: "hook", Linkage: btf.GlobalFunc, Tags: tags, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{
			{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 4}}},
			{Name: "site", Type: u32}, {Name: "status", Type: u64}, {Name: "other", Type: u64},
		}}}
	builder, err := btf.NewBuilder([]btf.Type{fn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	params, err := GetFuncParamsFromSpec(spec, "hook")
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func TestResolveStatusFields(t *testing.T) {
	params := statusHookParams(t, []string{hookabi.HookTag})
	for _, tt := range []struct {
		expr   string
		offset uint32
		size   uint32
		signed bool
	}{
		{"status", 0, 8, false}, {"status.ret", 0, 4, true}, {"status.flags", 4, 4, false},
	} {
		got, err := ResolveArg(tt.expr, params)
		if err != nil {
			t.Fatalf("%s: %v", tt.expr, err)
		}
		if got.Name != tt.expr || got.Deref || got.Index != 2 || got.Offset != tt.offset || got.Size != tt.size || got.Signed != tt.signed {
			t.Errorf("%s: %+v", tt.expr, got)
		}
	}
	for _, tt := range []struct{ expr, want string }{
		{"status.bad", "fields ret and flags"}, {"other.ret", "only the status argument"},
		{"site.ret", "only the status argument"}, {"missing.ret", "not found"},
		{"status.ret.x", "invalid argument expression"}, {"status.ret[0]", "invalid argument expression"},
		{"status->ret", "use status.ret or status.flags"}, {"status[0]", "use status.ret or status.flags"},
	} {
		if _, err := ResolveArg(tt.expr, params); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error = %v, want %q", tt.expr, err, tt.want)
		}
	}
	if got := StatusFields(params[1]); len(got) != 2 || got[0].Name != "status.ret" || got[1].Name != "status.flags" {
		t.Errorf("status fields: %+v", got)
	}
	if got := StatusFields(params[2]); got != nil {
		t.Errorf("other has fields: %+v", got)
	}

	// A function inject-run did not generate may use the name for anything.
	plain := statusHookParams(t, nil)
	if _, err := ResolveArg("status.ret", plain); err == nil || !strings.Contains(err.Error(), "only the status argument") {
		t.Errorf("untagged status.ret: %v", err)
	}
	if got := StatusFields(plain[1]); got != nil {
		t.Errorf("untagged status has fields: %+v", got)
	}
}
