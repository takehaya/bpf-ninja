package filter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/setmap"
)

// opaquePathParams are hook parameters whose members sit inside uapi bpf_*
// structs: key -> struct { struct bpf_lpm_trie_key lpm_key; __u8 addr[4]; },
// tuple -> struct bpf_sock_tuple, value -> struct { struct bpf_tunnel_key key; }.
func opaquePathParams() []attach.FuncParamInfo {
	u8, u16, u32 := &btf.Int{Name: "__u8", Size: 1}, &btf.Int{Name: "__be16", Size: 2}, &btf.Int{Name: "__u32", Size: 4}
	arr := func(t btf.Type, n uint32) btf.Type { return &btf.Array{Type: t, Nelems: n} }
	lpm := &btf.Struct{Name: "bpf_lpm_trie_key", Size: 4, Members: []btf.Member{{Name: "prefixlen", Type: u32}, {Name: "data", Type: arr(u8, 0), Offset: 32}}}
	key := &btf.Struct{Name: "lpm_v4_key", Size: 8, Members: []btf.Member{{Name: "lpm_key", Type: lpm}, {Name: "addr", Type: arr(u8, 4), Offset: 32}}}
	v4 := &btf.Struct{Size: 12, Members: []btf.Member{{Name: "saddr", Type: u32}, {Name: "daddr", Type: u32, Offset: 32},
		{Name: "sport", Type: u16, Offset: 64}, {Name: "dport", Type: u16, Offset: 80}}}
	v6 := &btf.Struct{Size: 36, Members: []btf.Member{{Name: "saddr", Type: arr(u32, 4)}, {Name: "daddr", Type: arr(u32, 4), Offset: 128},
		{Name: "sport", Type: u16, Offset: 256}, {Name: "dport", Type: u16, Offset: 272}}}
	tuple := &btf.Struct{Name: "bpf_sock_tuple", Size: 36, Members: []btf.Member{
		{Type: &btf.Union{Size: 36, Members: []btf.Member{{Name: "ipv4", Type: v4}, {Name: "ipv6", Type: v6}}}}}}
	tunnel := &btf.Struct{Name: "bpf_tunnel_key", Size: 24, Members: []btf.Member{{Name: "tunnel_id", Type: u32},
		{Type: &btf.Union{Size: 16, Members: []btf.Member{{Name: "remote_ipv4", Type: u32}, {Name: "remote_ipv6", Type: arr(u32, 4)}}}, Offset: 32},
		{Name: "tunnel_tos", Type: u8, Offset: 160}, {Name: "tunnel_ttl", Type: u8, Offset: 168}}}
	value := &btf.Struct{Name: "tun", Size: 24, Members: []btf.Member{{Name: "key", Type: tunnel}}}
	ptr := func(t btf.Type) btf.Type { return &btf.Pointer{Target: &btf.Const{Type: t}} }
	return []attach.FuncParamInfo{
		{Name: "key", Index: 1, Size: 8, Kind: "ptr-struct", Type: ptr(key)},
		{Name: "tuple", Index: 2, Size: 8, Kind: "ptr-struct", Type: ptr(tuple)},
		{Name: "value", Index: 3, Size: 8, Kind: "ptr-struct", Type: ptr(value)},
	}
}

var opaquePathExprs = []string{"key->lpm_key.prefixlen", "tuple->ipv4.dport", "value->key.tunnel_id"}

// opaquePathResolution renders how --arg-filter, --set, --arg-echo and
// --list-params resolve opaquePathExprs, in fields that exist on main.
func opaquePathResolution(t *testing.T) string {
	params := opaquePathParams()
	var b strings.Builder
	var exprs []string
	for _, e := range opaquePathExprs {
		exprs = append(exprs, e+"==1")
	}
	args, err := ParseAndValidateFilters(exprs, params)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range args {
		fmt.Fprintf(&b, "arg %s idx=%d size=%d signed=%v deref=%v off=%d\n", a.ParamName, a.ParamIndex, a.ParamSize, a.Signed, a.Deref, a.Offset)
	}
	set := &setmap.Set{
		SpecRef: setmap.SpecRef{Name: "s", Mapping: []setmap.MapEntry{
			{Field: "plen", Source: "arg:" + opaquePathExprs[0]}, {Field: "dport", Source: "arg:" + opaquePathExprs[1]}, {Field: "id", Source: "arg:" + opaquePathExprs[2]}}},
		Def: &setmap.Definition{KeySize: 12, Fields: []setmap.KeyField{{Name: "plen", Size: 4}, {Name: "dport", Off: 4, Size: 2}, {Name: "id", Off: 8, Size: 4}},
			ValFields: []setmap.KeyField{{Name: setmap.ValFieldTag, Size: 4}}},
	}
	sets, err := ResolveSetFilters([]*setmap.Set{set}, []string{"s"}, params)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sets[0].Fields {
		fmt.Fprintf(&b, "set %s idx=%d size=%d signed=%v deref=%v off=%d\n", f.ParamName, f.ParamIdx, f.ParamSize, f.ParamSigned, f.Deref, f.Offset)
	}
	echo, err := attach.ResolveEchoArgs(opaquePathExprs, params)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range echo {
		fmt.Fprintf(&b, "echo %s idx=%d size=%d signed=%v deref=%v off=%d\n", p.Name, p.Index, p.Size, p.Signed, p.Deref, p.Offset)
	}
	var list func([]attach.ArgMemberInfo)
	list = func(rows []attach.ArgMemberInfo) {
		for _, r := range rows {
			fmt.Fprintf(&b, "list %s off=%d filterable=%v reason=%q\n", r.Expression, r.Offset, r.Filterable, r.Reason)
			list(r.Members)
		}
	}
	for _, p := range params {
		rows, _ := attach.ListArgMembers(p, attach.MaxMembersDepth)
		list(rows)
	}
	return b.String()
}

// Member paths inside uapi bpf_* structs resolve exactly as on main
// (5d2c83d) for every command that reads them.
func TestOpaquePathsResolveAsOnMain(t *testing.T) {
	const main = `arg key->lpm_key.prefixlen idx=1 size=4 signed=false deref=true off=0
arg tuple->ipv4.dport idx=2 size=2 signed=false deref=true off=10
arg value->key.tunnel_id idx=3 size=4 signed=false deref=true off=0
set key->lpm_key.prefixlen idx=1 size=4 signed=false deref=true off=0
set tuple->ipv4.dport idx=2 size=2 signed=false deref=true off=10
set value->key.tunnel_id idx=3 size=4 signed=false deref=true off=0
echo key->lpm_key.prefixlen idx=1 size=4 signed=false deref=true off=0
echo tuple->ipv4.dport idx=2 size=2 signed=false deref=true off=10
echo value->key.tunnel_id idx=3 size=4 signed=false deref=true off=0
list key->lpm_key off=0 filterable=false reason="final member must be an integer or enum, got struct (select one of its members)"
list key->lpm_key.prefixlen off=0 filterable=true reason=""
list key->lpm_key.data off=4 filterable=false reason="final member must be an integer or enum, got array"
list key->addr off=4 filterable=false reason="final member must be an integer or enum, got array"
list tuple->ipv4 off=0 filterable=false reason="final member must be an integer or enum, got struct (select one of its members)"
list tuple->ipv4.saddr off=0 filterable=true reason=""
list tuple->ipv4.daddr off=4 filterable=true reason=""
list tuple->ipv4.sport off=8 filterable=true reason=""
list tuple->ipv4.dport off=10 filterable=true reason=""
list tuple->ipv6 off=0 filterable=false reason="final member must be an integer or enum, got struct (select one of its members)"
list tuple->ipv6.saddr off=0 filterable=false reason="final member must be an integer or enum, got array"
list tuple->ipv6.daddr off=16 filterable=false reason="final member must be an integer or enum, got array"
list tuple->ipv6.sport off=32 filterable=true reason=""
list tuple->ipv6.dport off=34 filterable=true reason=""
list value->key off=0 filterable=false reason="final member must be an integer or enum, got struct (select one of its members)"
list value->key.tunnel_id off=0 filterable=true reason=""
list value->key.remote_ipv4 off=4 filterable=true reason=""
list value->key.remote_ipv6 off=4 filterable=false reason="final member must be an integer or enum, got array"
list value->key.tunnel_tos off=20 filterable=true reason=""
list value->key.tunnel_ttl off=21 filterable=true reason=""

`
	if got := opaquePathResolution(t); strings.TrimSpace(got) != strings.TrimSpace(main) {
		t.Fatalf("resolution changed from main:\n%s\nwant:\n%s", got, main)
	}
}

// Of those paths, the ones through a bpf_* struct other than the LPM key
// structs are marked, for --arg-filter and --set alike.
func TestOpaquePathsMarked(t *testing.T) {
	params := opaquePathParams()
	want := map[string]bool{"key->lpm_key.prefixlen": false, "tuple->ipv4.dport": true, "value->key.tunnel_id": true}
	for _, e := range opaquePathExprs {
		args, err := ParseAndValidateFilters([]string{e + "==1"}, params)
		if err != nil || args[0].ThroughOpaque != want[e] {
			t.Errorf("--arg-filter %s: %+v %v", e, args, err)
		}
	}
	set := &setmap.Set{SpecRef: setmap.SpecRef{Name: "s", Mapping: []setmap.MapEntry{{Field: "f", Source: "arg:tuple->ipv4.dport"}}},
		Def: &setmap.Definition{KeySize: 2, Fields: []setmap.KeyField{{Name: "f", Size: 2}}, ValFields: []setmap.KeyField{{Name: setmap.ValFieldTag, Size: 4}}}}
	sets, err := ResolveSetFilters([]*setmap.Set{set}, []string{"s"}, params)
	if err != nil || !sets[0].Fields[0].ThroughOpaque {
		t.Errorf("--set tuple->ipv4.dport: %+v %v", sets, err)
	}
}
