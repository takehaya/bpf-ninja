package attach

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

const mapUseSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16); __type(key, __u32); __type(value, __u64); } flows SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4); __type(key, __u32); __type(value, __u64); } stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 4); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, __u64); __type(value, __u32); } routes SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 2); __type(key, __u32); __type(value, __u32); } jmp SEC(".maps");

static __noinline int classify(struct xdp_md *ctx, __u32 k)
{
	__u64 *v = bpf_map_lookup_elem(&flows, &k);
	__u64 one = 1;
	if (!v)
		bpf_map_update_elem(&flows, &k, &one, BPF_NOEXIST);
	return v ? 1 : 0;
}

__noinline int global_sub(struct xdp_md *ctx)
{
	__u64 key = ctx->ingress_ifindex;
	__u32 *r = bpf_map_lookup_elem(&routes, &key);
	return r ? *r : 0;
}

static long count(__u64 i, void *data)
{
	__u32 k = i;
	bpf_map_delete_elem(&flows, &k);
	return 0;
}

SEC("xdp")
int map_use_test(struct xdp_md *ctx)
{
	__u32 k = ctx->rx_queue_index;
	__u64 *s = bpf_map_lookup_elem(&stats, &k);
	if (s)
		__sync_fetch_and_add(s, 1);
	if (classify(ctx, k))
		bpf_map_delete_elem(&flows, &k);
	global_sub(ctx);
	bpf_loop(2, count, 0, 0);
	bpf_tail_call(ctx, &jmp, 0);
	return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
`

type useKey struct{ fn, name, op string }

func mapUseKeys(funcs []FuncMaps) []useKey {
	var keys []useKey
	for _, fn := range funcs {
		for _, use := range fn.Maps {
			op := use.Op
			if use.Inlined {
				op += "/inlined"
			}
			keys = append(keys, useKey{fn.Name, use.MapName, op})
		}
	}
	return keys
}

func TestProgramMaps(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, mapUseSource))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	syms, err := LoadKernelSymbols()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProgramMaps(coll.Programs["map_use_test"], syms)
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "" {
		t.Errorf("Note = %q", got.Note)
	}
	want := []useKey{
		{"map_use_test", "stats", "lookup/inlined"},
		{"map_use_test", "flows", "delete"},
		{"map_use_test", "jmp", "tail_call"},
		{"classify", "flows", "lookup"},
		{"classify", "flows", "update"},
		{"global_sub", "routes", "lookup"},
		{"count", "flows", "delete"},
	}
	// clang decides the order of the subprograms.
	cmpKey := func(a, b useKey) int { return strings.Compare(a.fn+a.name+a.op, b.fn+b.name+b.op) }
	keys := mapUseKeys(got.Funcs)
	slices.SortStableFunc(keys, cmpKey)
	slices.SortStableFunc(want, cmpKey)
	if !slices.Equal(keys, want) {
		t.Errorf("uses = %v\nwant %v", keys, want)
	}
	// An inlined bpf_loop also calls count directly.
	entry := got.Funcs[0]
	if !slices.Contains(entry.Calls, "classify") || !slices.Contains(entry.Calls, "global_sub") || !slices.Equal(entry.Callbacks, []string{"count"}) {
		t.Errorf("entry calls = %v, callbacks = %v", entry.Calls, entry.Callbacks)
	}
	for _, fn := range got.Funcs {
		for _, use := range fn.Maps {
			if use.Line == 0 {
				t.Errorf("%s: %v has no line", fn.Name, use)
			}
		}
	}
}

// A map loaded on one line and passed to a helper on another takes the
// helper's line, which is where load-time discovery puts the call.
func TestProgramMapsCallLine(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const src = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 2); __type(key, __u32); __type(value, __u64); } h SEC(".maps");
SEC("xdp") int map_line(struct xdp_md *ctx) {
	__u64 v = 42;
	__u32 k = 0;
	void *map = &h;
	asm volatile("" : "+r"(map));
	return bpf_map_update_elem(map, &k, &v, 0) ? XDP_DROP : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
`
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, src))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	syms, err := LoadKernelSymbols()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProgramMaps(coll.Programs["map_line"], syms)
	if err != nil {
		t.Fatal(err)
	}
	if uses := got.Funcs[0].Maps; len(uses) != 1 || uses[0].Op != MapOpUpdate || uses[0].Line != 10 {
		t.Errorf("uses = %+v, want an update on line 10, the call", uses)
	}
}

// TestAnalyzeXlatedDegraded covers a dump read without BTF and without
// helper addresses: one function named after the program, every helper op
// unknown, but tail calls and inlined array lookups still recognized.
func TestAnalyzeXlatedDegraded(t *testing.T) {
	maps := map[uint32]mapIdentity{
		7: {"flows", ebpf.Hash}, 8: {"stats", ebpf.Array}, 9: {"jmp", ebpf.ProgramArray}, 10: {".bss", ebpf.Array},
	}
	mapLoad := func(dst asm.Register, id uint32, src asm.Register) asm.Instruction {
		ins := asm.LoadImm(dst, int64(id), asm.DWord)
		ins.Src = src
		return ins
	}
	insns := asm.Instructions{
		mapLoad(asm.R1, 7, asm.PseudoMapFD),
		asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: 0}, // hidden helper
		mapLoad(asm.R1, 8, asm.PseudoMapFD),
		asm.Add.Imm(asm.R1, 312),
		mapLoad(asm.R2, 9, asm.PseudoMapFD),
		asm.FnTailCall.Call(),
		mapLoad(asm.R3, 10, asm.PseudoMapValue),
		asm.Return(),
	}
	got := analyzeXlated(insns, "prog", func(id uint32) mapIdentity { return maps[id] }, func(int64) string { return "" })
	want := []useKey{{"prog", "flows", "ref"}, {"prog", "stats", "lookup/inlined"}, {"prog", "jmp", "tail_call"}, {"prog", ".bss", "value"}}
	if keys := mapUseKeys(got); !slices.Equal(keys, want) {
		t.Errorf("uses = %v\nwant %v", keys, want)
	}
}

func TestHelperOp(t *testing.T) {
	for sym, want := range map[string]string{
		"":                       "",
		"htab_map_update_elem":   MapOpUpdate,
		"__htab_map_lookup_elem": MapOpLookup,
		"trie_lookup_elem":       MapOpLookup,
		"htab_map_delete_elem":   MapOpDelete,
		"dev_map_redirect":       MapOpRedirect,
		"bpf_ringbuf_output":     "ringbuf_output",
	} {
		if got := helperOp(sym); got != want {
			t.Errorf("helperOp(%q) = %q, want %q", sym, got, want)
		}
	}
}
