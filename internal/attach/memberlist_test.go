package attach

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func checkMemberResolution(t *testing.T, params []FuncParamInfo, members []ArgMemberInfo) map[string]ArgMemberInfo {
	t.Helper()
	out := make(map[string]ArgMemberInfo)
	var walk func([]ArgMemberInfo)
	walk = func(nodes []ArgMemberInfo) {
		for _, n := range nodes {
			out[n.Expression] = n
			got, err := ResolveArg(n.Expression, params)
			if n.Filterable != (err == nil) {
				t.Fatalf("%s: filterable=%v, ResolveArg error=%v", n.Expression, n.Filterable, err)
			}
			if n.Filterable {
				if n.Reason != "" || n.Size == nil || n.Signed == nil || uint64(got.Offset) != n.Offset || int(got.Size) != *n.Size || got.Signed != *n.Signed {
					t.Fatalf("%s: listing %+v disagrees with resolver %+v", n.Expression, n, got)
				}
			} else if n.Reason == "" || !strings.Contains(err.Error(), n.Reason) {
				t.Fatalf("%s: missing resolver rejection reason: %+v, %v", n.Expression, n, err)
			}
			walk(n.Members)
		}
	}
	walk(members)
	return out
}

func TestListArgMembers(t *testing.T) {
	params := memberTestParams(t) // Includes a serialized function prototype.
	members, truncated := ListArgMembers(params[0], DefaultMembersDepth)
	if truncated != "" || len(members) != 10 {
		t.Fatalf("members=%+v, truncated=%q", members, truncated)
	}
	all := checkMemberResolution(t, params, members)
	for _, expr := range []string{"q->imsi", "q->target.pdr_id", "q->seid", "q->tag", "q->small", "q->half"} {
		if !all[expr].Filterable {
			t.Errorf("%s should be filterable", expr)
		}
	}
	if n := all["q->target"]; n.Type != "target_t" || len(n.Members) != 1 || n.Offset != 8 || *n.Size != 8 {
		t.Errorf("nested typedef: %+v", n)
	}
	if n := all["q->target.pdr_id"]; n.Offset != 12 || !*n.Signed {
		t.Errorf("nested offset: %+v", n)
	}
	if n := all["q->tag"]; n.Type != "enum tag" || n.Offset != 16 || !*n.Signed {
		t.Errorf("promoted enum: %+v", n)
	}
	for expr, typ := range map[string]string{"q->bits": "i32", "q->next": "i32 *", "q->array": "i32[2]", "q->odd": "odd"} {
		if n := all[expr]; n.Filterable || n.Type != typ || len(n.Members) != 0 {
			t.Errorf("unsupported member: %+v", n)
		}
	}
	if all["q->bits"].Bitfield != 3 {
		t.Error("missing bitfield width")
	}
	union, truncated := ListArgMembers(params[2], 1)
	if truncated != "" || len(union) != 1 || union[0].Expression != "u->value" || !union[0].Filterable {
		t.Fatalf("union pointer: %+v, %q", union, truncated)
	}
	checkMemberResolution(t, params, union)
	if got, truncated := ListArgMembers(params[1], 1); len(got) != 0 || truncated != "" {
		t.Fatalf("integer parameter has members: %+v, %q", got, truncated)
	}
}

func TestListArgMembersAnonymous(t *testing.T) {
	u32 := &btf.Typedef{Name: "__u32", Type: &btf.Int{Name: "unsigned int", Size: 4}}
	child := &btf.Struct{Size: 4, Members: []btf.Member{{Name: "id", Type: u32}}}
	q := &btf.Struct{Size: 64, Members: []btf.Member{
		{Type: child, Offset: 32},
		{Type: &btf.Union{Size: 4, Members: []btf.Member{{Name: "id", Type: u32}, {Name: "unique", Type: u32}}}, Offset: 64},
		{Name: "nested", Type: &btf.Union{Size: 4, Members: []btf.Member{{Type: child}}}, Offset: 96},
		{Name: "unaligned", Type: u32, Offset: 129},
		{Name: "bad_parent", Type: child, Offset: 161},
		{Type: &btf.Struct{Size: 4, Members: []btf.Member{{Name: "promoted_bits", Type: u32}}}, Offset: 192, BitfieldSize: 3},
		{Name: "next", Type: &btf.Pointer{Target: child}, Offset: 224},
	}}
	p := FuncParamInfo{Name: "q", Index: 1, Kind: "ptr-struct", Type: &btf.Pointer{Target: q}}
	members, truncated := ListArgMembers(p, 3)
	if truncated != "" || len(members) != 8 || members[0].Expression != "q->id" || members[1].Expression != "q->id" {
		t.Fatalf("promotion: %+v, %q", members, truncated)
	}
	all := checkMemberResolution(t, []FuncParamInfo{p}, members)
	if !strings.Contains(all["q->id"].Reason, "ambiguous") {
		t.Fatalf("ambiguous name not flagged: %+v", all["q->id"])
	}
	if n := all["q->unique"]; !n.Filterable || n.Type != "__u32" || n.Offset != 8 {
		t.Errorf("promoted typedef: %+v", n)
	}
	if n := all["q->nested.id"]; !n.Filterable || n.Offset != 12 {
		t.Errorf("named union: %+v", n)
	}
	if n := all["q->unaligned"]; n.BitOffset != 1 || n.Offset != 16 || !strings.Contains(n.Reason, "byte-aligned") {
		t.Errorf("unaligned member: %+v", n)
	}
	if n := all["q->bad_parent.id"]; n.Filterable || !strings.Contains(n.Reason, "byte-aligned") {
		t.Errorf("unaligned parent: %+v", n)
	}
	if n := all["q->promoted_bits"]; n.Bitfield != 3 || !strings.Contains(n.Reason, "bitfield") {
		t.Errorf("anonymous bitfield: %+v", n)
	}
	if n := all["q->next"]; n.Filterable || len(n.Members) != 0 {
		t.Errorf("second pointer expanded: %+v", n)
	}
}

func TestListArgMembersBounds(t *testing.T) {
	params := memberTestParams(t)
	members, truncated := ListArgMembers(params[0], 1)
	all := checkMemberResolution(t, params, members)
	if n := all["q->target"]; truncated != "" || n.Truncated != "depth limit" || len(n.Members) != 0 {
		t.Fatalf("depth: %+v, %q", n, truncated)
	}
	if !all["q->seid"].Filterable {
		t.Fatal("anonymous promotion consumed a named depth level")
	}
	q := &btf.Struct{Name: "cycle", Size: 8}
	q.Members = []btf.Member{{Name: "again", Type: q}, {Type: q}, {Name: "n", Type: &btf.Int{Size: 4}}}
	p := FuncParamInfo{Name: "q", Kind: "ptr-struct", Type: &btf.Pointer{Target: q}}
	members, truncated = ListArgMembers(p, 32)
	if !strings.Contains(truncated, "cycle") || members[0].Truncated != "cycle" {
		t.Fatalf("cycle: %+v, %q", members, truncated)
	}
	checkMemberResolution(t, []FuncParamInfo{p}, members)
	q.Members = make([]btf.Member, maxMemberRows+1)
	for i := range q.Members {
		q.Members[i] = btf.Member{Name: "n", Type: &btf.Int{Size: 4}}
	}
	members, truncated = ListArgMembers(p, 1)
	if len(members) != maxMemberRows || truncated != "member limit (4096)" {
		t.Fatalf("row bound: %d, %q", len(members), truncated)
	}
}

func TestArgTypeName(t *testing.T) {
	u32 := &btf.Typedef{Name: "__u32", Type: &btf.Int{Name: "unsigned int", Size: 4}}
	for _, tc := range []struct {
		typ  btf.Type
		want string
	}{
		{u32, "__u32"},
		{&btf.TypeTag{Type: &btf.Const{Type: u32}}, "const __u32"},
		{&btf.Pointer{Target: &btf.Union{Name: "choice"}}, "union choice *"},
		{&btf.Array{Type: &btf.Array{Type: u32, Nelems: 4}, Nelems: 16}, "__u32[16][4]"},
	} {
		if got := ArgTypeName(tc.typ); got != tc.want {
			t.Errorf("type name = %q, want %q", got, tc.want)
		}
	}
	cycle := &btf.Array{Nelems: 1}
	cycle.Type = cycle
	if got := ArgTypeName(cycle); !strings.HasPrefix(got, "...") || len(got) > 110 {
		t.Fatalf("unbounded type rendering: %q", got)
	}
}
