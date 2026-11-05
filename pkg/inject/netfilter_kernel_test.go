package inject

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// nfFixtureSource reads a key and a tail-call index from the packet, looks
// the key up and tail-calls nf_target (NF_ACCEPT) at index 0. A miss drops;
// a failed tail call returns the session's verdict.
const nfFixtureSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct nf_hook_state;
struct sk_buff { unsigned char *data; } __attribute__((preserve_access_index));
struct bpf_nf_ctx { const struct nf_hook_state *state; struct sk_buff *skb; };
struct session { __u64 verdict; __u64 imsi; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4); __type(key, __u32); __type(value, struct session); } sessions SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 2); __type(key, __u32); __type(value, __u32); } jmp SEC(".maps");
SEC("netfilter") int nf_target(struct bpf_nf_ctx *ctx) { return 1; }
SEC("netfilter") int nf_main(struct bpf_nf_ctx *ctx) {
	__u32 pkt[2];
	if (bpf_probe_read_kernel(pkt, sizeof(pkt), ctx->skb->data))
		return 1;
	struct session *s = bpf_map_lookup_elem(&sessions, &pkt[0]);
	if (!s)
		return 0;
	bpf_tail_call(ctx, &jmp, pkt[1]);
	return s->verdict & 1;
}
char _license[] SEC("license") = "GPL";
`

// A netfilter program gets bpf_nf_ctx hooks whose ctx read is 8 bytes, the
// only width its verifier allows: the rewrite loads and its results equal the
// original's. Fentry observers on the entry, lookup and tail-call hooks read
// the packet length through ctx->skb, and the hooks' arguments. The same
// rewrite with 4-byte reads is rejected by the verifier.
func TestBpfLookupHooksNetfilter(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if err := features.HaveProgramType(ebpf.Netfilter); errors.Is(err, ebpf.ErrNotSupported) {
		t.Skip("BPF_PROG_TYPE_NETFILTER not supported by this kernel (need 6.4+)")
	}
	obj := testutil.CompileBPFSource(t, nfFixtureSource)
	fixture := func() *ebpf.CollectionSpec {
		spec, err := ebpf.LoadCollectionSpec(obj)
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	work := fixture()
	plan, err := transformLookup(work, LookupRequest{ProgramName: "nf_main", Auto: true, Entry: true, TailCalls: true,
		HookName: "obs", Stack: StackAudit{LowestOffset: -64}})
	if err != nil {
		t.Fatal(err)
	}
	names := map[HookKind]string{}
	var tailSite, lookupSite uint32
	for _, h := range plan.hooks {
		names[h.Kind] = h.Name
		switch h.Kind {
		case HookTailCall:
			tailSite = h.Sites[0].SitePC
		case HookLookup:
			lookupSite = h.Sites[0].SitePC
		}
	}
	if names[HookLookup] == "" || names[HookEntry] == "" || names[HookTailCall] == "" {
		t.Fatalf("hooks %+v", plan.hooks)
	}
	load := func(spec *ebpf.CollectionSpec) *ebpf.Collection {
		c := loadOrSkip(t, spec)
		t.Cleanup(c.Close)
		if err := c.Maps["jmp"].Put(uint32(0), c.Programs["nf_target"]); err != nil {
			t.Fatal(err)
		}
		for key, verdict := range map[uint32]uint64{1: 0, 3: 1} {
			if err := c.Maps["sessions"].Put(key, [2]uint64{verdict, 10 + uint64(key)}); err != nil { // imsi 11 or 13
				t.Fatal(err)
			}
		}
		return c
	}
	plain, injected := load(fixture()), load(work)
	entry := attachScalarObserver(t, names[HookEntry], injected.Programs["nf_main"], 0)
	tail := attachScalarObserver(t, names[HookTailCall], injected.Programs["nf_main"], 2)
	obs := loadOrSkip(t, lookupObserverArgs(t, names[HookLookup], injected.Programs["nf_main"], observerArgs{site: true}))
	t.Cleanup(obs.Close)
	l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	read := func(m *ebpf.Map) scalarRecord {
		var r scalarRecord
		if err := m.Lookup(uint32(0), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, tc := range []struct {
		key, index, verdict uint32
		tailFails           bool
	}{{1, 0, 1, false}, {1, 1, 0, true}, {3, 1, 1, true}, {2, 1, 0, false}} {
		for _, m := range []*ebpf.Map{entry, tail} {
			if err := m.Put(uint32(0), scalarRecord{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := obs.Maps["obs"].Put(uint32(0), [32]byte{}); err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, tc.key)
		binary.LittleEndian.PutUint32(packet[4:], tc.index)
		for _, c := range []*ebpf.Collection{plain, injected} {
			if ret, err := c.Programs["nf_main"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1}); err != nil || ret != tc.verdict {
				t.Fatalf("key=%d index=%d: verdict=%d err=%v", tc.key, tc.index, ret, err)
			}
		}
		var got [32]byte
		if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		// seen, packet length, key, value.imsi, site; a miss calls no lookup hook.
		want := [5]uint64{1, 64, uint64(tc.key), 10 + uint64(tc.key), uint64(lookupSite)}
		if tc.key == 2 {
			want = [5]uint64{}
		}
		le := binary.LittleEndian
		if g := [5]uint64{le.Uint64(got[:]), uint64(le.Uint32(got[8:])), uint64(le.Uint32(got[12:])), le.Uint64(got[16:]), uint64(le.Uint32(got[24:]))}; g != want {
			t.Fatalf("key=%d index=%d: lookup hook saw %v, want %v", tc.key, tc.index, g, want)
		}
		gotEntry, gotTail := read(entry), read(tail)
		if gotEntry.Seen != 1 || gotEntry.Len != 64 {
			t.Fatalf("key=%d index=%d: entry=%+v", tc.key, tc.index, gotEntry)
		}
		wantTail := scalarRecord{} // a successful tail call or a miss calls no tail-call hook
		if tc.tailFails {
			wantTail = scalarRecord{Seen: 1, Len: 64, Args: [2]uint32{tailSite, tc.index}}
		}
		if gotTail != wantTail {
			t.Fatalf("key=%d index=%d: tail=%+v, want %+v", tc.key, tc.index, gotTail, wantTail)
		}
	}
	// The hooks' first instruction is the only change between the forms.
	word := fixture()
	if _, err := transformLookup(word, LookupRequest{ProgramName: "nf_main", Auto: true, Entry: true, TailCalls: true,
		HookName: "obs", Stack: StackAudit{LowestOffset: -64}}); err != nil {
		t.Fatal(err)
	}
	hooks := map[string]bool{}
	for _, name := range names {
		hooks[name] = true
	}
	insns, changed := word.Programs["nf_main"].Instructions, 0
	for i := range insns {
		if hooks[insns[i].Symbol()] && insns[i].OpCode == asm.LoadMem(asm.R0, asm.R1, 0, asm.DWord).OpCode {
			insns[i].OpCode, changed = asm.LoadMem(asm.R0, asm.R1, 0, asm.Word).OpCode, changed+1
		}
	}
	var ve *ebpf.VerifierError
	if c, err := ebpf.NewCollection(word); changed != len(plan.hooks) || !errors.As(err, &ve) || !strings.Contains(fmt.Sprintf("%+v", ve), "invalid bpf_context access off=0 size=4") {
		if err == nil {
			c.Close()
		}
		t.Fatalf("4-byte ctx reads in %d of %d hooks: load error %v", changed, len(plan.hooks), err)
	}
}
