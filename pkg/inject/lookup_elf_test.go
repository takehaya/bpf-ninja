package inject

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestLookupThroughELF(t *testing.T) {
	obj := testutil.CompileBPFSource(t, `
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
typedef unsigned int u32;
typedef unsigned long long u64;
struct xdp_md { u32 data, data_end; };
struct session { u64 seid; u64 imsi; };
struct {
    __uint(type, 1);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, struct session);
} sessions SEC(".maps");
static void *(*lookup)(void *, const void *) = (void *)1;
SEC("xdp") int ingress(struct xdp_md *ctx) {
    u32 key = ctx->data;
#line 100 "lookup_fixture.c"
    struct session *a = lookup(&sessions, &key);
    if (!a) return 1;
    key++;
#line 200 "lookup_fixture.c"
    struct session *b = lookup(&sessions, &key);
    return b ? 2 : 1;
}
char _license[] SEC("license") = "GPL";
`)
	elf, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(elf)
	sites, err := DiscoverLookups(elf, "ingress")
	if err != nil || len(sites) != 2 {
		t.Fatalf("discovery: %+v, %v", sites, err)
	}
	for i, site := range sites {
		if site.MapName != "sessions" || site.KeyTypeName != "u32" || site.ValueTypeName != "session" ||
			site.FuncName != "ingress" || !strings.HasSuffix(site.File, "lookup_fixture.c") ||
			site.Line != uint32(100+i*100) || site.Reason != "" || site.SitePC <= uint32(site.InstructionIndex) {
			t.Fatalf("unexpected site: %+v", site)
		}
	}
	sum := sha256.Sum256(elf)
	req := LookupRequest{ELFSHA256: strings.ToUpper(hex.EncodeToString(sum[:])), ProgramName: "ingress",
		Site: LookupSelector{MapName: "sessions"}, HookName: "observe_lookup", Stack: StackAudit{LowestOffset: -16}}
	if _, err := TransformLookup(elf, req); !errors.Is(err, ErrRefused) {
		t.Fatalf("ambiguous selector: %v", err)
	}
	req.Site.FuncName, req.Site.Line = "ingress", 200
	res, err := TransformLookup(elf, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Site != sites[1] || res.InsertedAt != 0 || res.InsertedSlots != 16 || res.AddedBytes != 128 {
		t.Fatalf("unexpected result: %+v", res)
	}
	src, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		t.Fatal(err)
	}
	want, err := checksum(src.Programs["ingress"].Instructions, src.ByteOrder)
	if err != nil || res.SourceChecksum != want || res.SourceChecksum == res.TransformedChecksum {
		t.Fatalf("source checksum=%s want=%s error=%v", res.SourceChecksum, want, err)
	}
	out := res.Spec.Programs["ingress"].Instructions
	want, err = checksum(out, res.Spec.ByteOrder)
	if err != nil || res.TransformedChecksum != want {
		t.Fatalf("output checksum: %s, %v", want, err)
	}
	// Real line_info remains on each relocated helper; the first function's
	// metadata moves to the ctx spill, and the generated hook has its own line.
	var lines []uint32
	var line uint32
	for _, ins := range out {
		if source, ok := ins.Source().(*btf.Line); ok {
			line = source.LineNumber()
		}
		if ins.IsBuiltinCall() && ins.Constant == 1 {
			lines = append(lines, line)
		}
	}
	if len(lines) != 2 || lines[0] != 100 || lines[1] != 200 {
		t.Fatalf("lost line_info: %v", lines)
	}
	if err := checkExtInfo(out); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []LookupSelector{
		{MapName: "sessions", FuncName: "ingress", AllMatches: true},
		{MapName: "sessions", SitePCs: []uint32{sites[1].SitePC, sites[0].SitePC}},
	} {
		req.Site = selector
		multi, err := TransformLookup(elf, req)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(multi.Sites, sites) || multi.Site != sites[0] || multi.InsertedSlots != 24 || multi.AddedBytes != 192 || multi.SourceChecksum != res.SourceChecksum || multi.TransformedChecksum == res.TransformedChecksum {
			t.Fatalf("unexpected multi-site result: %+v", multi)
		}
		if err := checkExtInfo(multi.Spec.Programs["ingress"].Instructions); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(elf, before) {
		t.Fatal("ELF input mutated")
	}
}

func TestLookupELFGates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*LookupRequest)
	}{
		{"missing-sha", func(r *LookupRequest) { r.ELFSHA256 = "" }},
		{"invalid-sha", func(r *LookupRequest) { r.ELFSHA256 = strings.Repeat("z", 64) }},
		{"hash-mismatch", func(r *LookupRequest) {}},
		{"missing-program", func(r *LookupRequest) { r.ProgramName = "" }},
		{"invalid-hook", func(r *LookupRequest) { r.HookName = "9invalid" }},
		{"missing-map", func(r *LookupRequest) { r.Site.MapName = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := lookupReq()
			req.ELFSHA256 = strings.Repeat("0", 64)
			tc.change(&req)
			res, err := TransformLookup([]byte("not ELF"), req)
			if res != nil || !errors.Is(err, ErrRefused) {
				t.Fatalf("want nil/refusal: %+v, %v", res, err)
			}
		})
	}
	blob := []byte("matching hash but not ELF")
	sum := sha256.Sum256(blob)
	req := lookupReq()
	req.ELFSHA256 = hex.EncodeToString(sum[:])
	if _, err := TransformLookup(blob, req); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("parse error: %v", err)
	}
	if _, err := DiscoverLookups(blob, "p"); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("discovery parse error: %v", err)
	}
}
