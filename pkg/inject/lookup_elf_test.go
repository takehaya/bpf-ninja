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
static long (*loop)(u32, void *, void *, unsigned long long) = (void *)181;
static long callback(u32 index, void *data) {
    (*(u32 *)data)++;
    return 0;
}
SEC("xdp") int ingress(struct xdp_md *ctx) {
    u32 count = 0;
    loop(3, callback, &count, 0);
    if (count != 3) return 0;
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
	assertRawLookupParity(t, src, req, res)
	want, err := checksum(src.Programs["ingress"].Instructions, src.ByteOrder)
	if err != nil || res.SourceChecksum != want || res.SourceChecksum == res.TransformedChecksum {
		t.Fatalf("source checksum=%s want=%s error=%v", res.SourceChecksum, want, err)
	}
	out := res.Spec.Programs["ingress"].Instructions
	// Exercise cilium/ebpf's actual ELF callback representation, including its
	// unresolved sentinel and the callback's function and line metadata.
	callbacks := 0
	for _, ins := range src.Programs["ingress"].Instructions {
		if !ins.IsLoadOfFunctionPointer() {
			continue
		}
		callbacks++
		if ins.Constant != -1 || ins.Reference() != "callback" {
			t.Fatalf("unexpected ELF callback reference: %v", ins)
		}
		preserved, target := false, false
		for _, transformed := range out {
			preserved = preserved || reflect.DeepEqual(ins, transformed)
			if transformed.Symbol() == ins.Reference() {
				target = btf.FuncMetadata(&transformed) != nil && transformed.Source() != nil
			}
		}
		if !preserved || !target {
			t.Fatal("callback reference or target metadata changed")
		}
	}
	if callbacks != 1 {
		t.Fatalf("callback loads=%d, want 1", callbacks)
	}
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
		assertRawLookupParity(t, src, req, multi)
		if err := checkExtInfo(multi.Spec.Programs["ingress"].Instructions); err != nil {
			t.Fatal(err)
		}
	}
	req.Site, req.Auto = LookupSelector{}, true
	auto, err := TransformLookup(elf, req)
	if err != nil {
		t.Fatal(err)
	}
	// One hook for the one map; each site also passes its SitePC.
	if !reflect.DeepEqual(auto.Sites, sites) || len(auto.Hooks) != 1 || auto.Hooks[0].Name != "observe_lookup_sessions" ||
		!reflect.DeepEqual(auto.Hooks[0].Sites, sites) || len(auto.Skipped) != 0 || auto.InsertedSlots != 26 ||
		auto.HookName != "observe_lookup_sessions" {
		t.Fatalf("unexpected auto result: %+v", auto)
	}
	assertRawLookupParity(t, src, req, auto)
	if !bytes.Equal(elf, before) {
		t.Fatal("ELF input mutated")
	}
}

func readOnlyKconfigELF(t *testing.T) []byte {
	t.Helper()
	obj := testutil.CompileBPFSource(t, `
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __kconfig __attribute__((section(".kconfig")))
typedef unsigned int u32;
struct xdp_md { u32 data, data_end; };
struct {
    __uint(type, 22);
    __uint(max_entries, 2);
    __type(value, u32);
} q SEC(".maps");
extern const volatile u32 CONFIG_HZ __kconfig;
static long (*push)(void *, const void *, unsigned long long) = (void *)87;
SEC("xdp") int p(struct xdp_md *ctx) {
    return push(&q, &CONFIG_HZ, 0) ? 1 : 2;
}
char _license[] SEC("license") = "GPL";
`)
	elf, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	return elf
}

func TestReadOnlyKconfigThroughELF(t *testing.T) {
	elf := readOnlyKconfigELF(t)
	sum := sha256.Sum256(elf)
	res, err := TransformLookup(elf, LookupRequest{ELFSHA256: hex.EncodeToString(sum[:]), ProgramName: "p", Auto: true,
		Lookups: LookupNone, Pushes: CallAny, HookName: "observe", Stack: StackAudit{LowestOffset: 0}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hooks) != 1 || !res.Hooks[0].Untrusted {
		t.Fatalf("hooks: %+v", res.Hooks)
	}
}

func TestBpfReadOnlyKconfigArg(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	elf := readOnlyKconfigELF(t)
	plainSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		t.Fatal(err)
	}
	plain := loadOrSkip(t, plainSpec)
	t.Cleanup(plain.Close)
	sum := sha256.Sum256(elf)
	res, err := TransformLookup(elf, LookupRequest{ELFSHA256: hex.EncodeToString(sum[:]), ProgramName: "p", Auto: true,
		Lookups: LookupNone, Pushes: CallAny, HookName: "observe", Stack: StackAudit{LowestOffset: 0}})
	if err != nil {
		t.Fatal(err)
	}
	injected := loadHooked(t, res.Spec, res.Hooks)
	t.Cleanup(injected.Close)
	for _, c := range []*ebpf.Collection{plain, injected} {
		if ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
			t.Fatalf("action=%d err=%v", ret, err)
		}
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

// InsertedSlots, measured through the raw API: 1 for the entry ctx spill; per
// site 8 (9 with Auto's site argument, 11 at a generic-hook site), plus 2 per
// load-store chunk and 2 for the pointer with a CopyReadOnly value copy; per
// hook 7 typed, 5 untrusted, 6 generic, 2 static; Entry 2 in the prologue and
// a 3-slot hook; TailCalls 6 per tail call (7 outside the entry function) and
// a 3-slot hook. With Dispatch: 11 per lookup site, Entry 6 in the prologue,
// 9 per tail call (10 outside the entry function), and one hook of 6 slots, 2
// when static. docs/en/lookup-site-injection.md states the same formula.
func TestLookupInsertedSlots(t *testing.T) {
	auto := func(edit func(*LookupRequest)) LookupRequest {
		req := autoReq()
		edit(&req)
		return req
	}
	tails := LookupRequest{TailCalls: true, HookName: "obs"}
	for _, tc := range []struct {
		name string
		spec func() *ebpf.CollectionSpec
		req  LookupRequest
		want int
	}{
		{"single", lookupFixture, lookupReq(), 1 + 8 + 7},
		{"entry", lookupFixture, func() LookupRequest { r := lookupReq(); r.Entry = true; return r }(), 1 + 8 + 7 + 2 + 3},
		{"auto", multiMapFixture, autoReq(), 1 + 2*9 + 2*7},
		{"untrusted", func() *ebpf.CollectionSpec { return multiMapFixtureFlags(bpfFRdonlyProg) }, autoReq(), 1 + 2*9 + 7 + 5},
		{"copy", func() *ebpf.CollectionSpec { return multiMapFixtureFlags(bpfFRdonlyProg) },
			auto(func(r *LookupRequest) { r.CopyReadOnly = true }), 1 + 2*9 + 2*2 + 2 + 2*7},
		{"static", func() *ebpf.CollectionSpec { return multiMapFixtureFlags(bpfFRdonlyProg) },
			auto(func(r *LookupRequest) { r.StaticUntrusted = true }), 1 + 2*9 + 7 + 2},
		{"generic", mapInMapFixture, autoReq(), 1 + 2*11 + 6},
		{"generic-static", mapInMapFixture, auto(func(r *LookupRequest) { r.StaticUntrusted = true }), 1 + 2*11 + 2},
		{"tail-call", tailCallerFixture, tails, 1 + 6 + 3},
		{"entry-tail-call", tailCallerFixture, LookupRequest{Entry: true, TailCalls: true, HookName: "obs"}, 1 + 2 + 3 + 6 + 3},
		{"tail-call-sub", subTailCallerFixture, tails, 1 + 7 + 3},
		{"dispatch", multiMapFixture, auto(func(r *LookupRequest) { r.Dispatch = true }), 1 + 2*11 + 6},
		{"dispatch-static", multiMapFixture, auto(func(r *LookupRequest) { r.Dispatch, r.StaticUntrusted = true, true }), 1 + 2*11 + 2},
		{"dispatch-generic", mapInMapFixture, auto(func(r *LookupRequest) { r.Dispatch = true }), 1 + 2*11 + 6},
		{"dispatch-entry-tail-call", tailCallerFixture, LookupRequest{Entry: true, TailCalls: true, Dispatch: true, HookName: "obs"}, 1 + 6 + 9 + 6},
		{"dispatch-tail-call-sub", subTailCallerFixture, LookupRequest{TailCalls: true, Dispatch: true, HookName: "obs"}, 1 + 10 + 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "p"
			if tc.spec().Programs[name] == nil {
				name = "caller"
			}
			got, err := TransformLookupRaw(rawLookupFixture(t, tc.spec(), name, true), LookupRequestRaw{Site: tc.req.Site, Auto: tc.req.Auto,
				Entry: tc.req.Entry, TailCalls: tc.req.TailCalls, CopyReadOnly: tc.req.CopyReadOnly, StaticUntrusted: tc.req.StaticUntrusted,
				Dispatch: tc.req.Dispatch, HookName: tc.req.HookName, Stack: tc.req.Stack})
			if err != nil {
				t.Fatal(err)
			}
			if got.InsertedSlots != tc.want {
				t.Fatalf("InsertedSlots %d, want %d", got.InsertedSlots, tc.want)
			}
		})
	}
}
