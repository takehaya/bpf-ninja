package program

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// A static hook the lookup transform adds to a netfilter program takes
// pointer arguments besides ctx, so the kernel discards its prototype and
// capture there must read bpf_nf_ctx and its sk_buff with
// bpf_probe_read_kernel. The record starts at L3, as at a global netfilter
// function.
func TestBpfStaticNetfilterInjectedHook(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if err := features.HaveProgramType(ebpf.Netfilter); errors.Is(err, ebpf.ErrNotSupported) {
		t.Skip("BPF_PROG_TYPE_NETFILTER not supported by this kernel (need 6.4+)")
	}
	elf, err := os.ReadFile(testutil.CompileBPFSource(t, `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct nf_hook_state;
struct sk_buff;
struct bpf_nf_ctx { const struct nf_hook_state *state; struct sk_buff *skb; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hits SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} cfg SEC(".maps");
SEC("netfilter")
int p(struct bpf_nf_ctx *ctx) {
    __u32 k = 0;
    __u64 *n = bpf_map_lookup_elem(&hits, &k);
    if (n) __sync_fetch_and_add(n, 1);
    __u32 *v = bpf_map_lookup_elem(&cfg, &k);
    return v && *v ? 0 : 1;
}
char _license[] SEC("license") = "GPL";
`))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(elf)
	res, err := inject.TransformLookup(elf, inject.LookupRequest{ELFSHA256: hex.EncodeToString(sum[:]), ProgramName: "p", Auto: true,
		Entry: true, StaticUntrusted: true, HookName: "obs", Stack: inject.StackAudit{LowestOffset: -16}})
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, h := range res.Hooks {
		if h.Static {
			name = h.Name
		}
	}
	if name == "" {
		t.Fatalf("no static hook in %+v", res.Hooks)
	}
	coll, err := ebpf.NewCollection(res.Spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	target := coll.Programs["p"]
	h, _ := hook.ByProgramType(ebpf.Netfilter)
	fallback, err := staticNeedsProbeRead(h, target, name, ebpf.AttachTraceFEntry, attach.FuncAvailability{})
	if err != nil || !fallback {
		t.Fatalf("%s must take the probe-read path: probe_read=%v err=%v", name, fallback, err)
	}
	if err := checkStaticCtxArg(target, name); err != nil {
		t.Fatal(err)
	}
	probe, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: name, Type: ebpf.Netfilter}},
		[]Stage{{Expr: "ipv4"}, {Expr: "ipv4", IsFexit: true}}, nil, true, nil, EmitBoth)
	if err != nil {
		t.Fatalf("capture at %s (probe_read=%v): %+v", name, fallback, err)
	}
	defer func() { _ = probe.Close() }()
	// BPF_PROG_TEST_RUN runs a netfilter program at NF_INET_LOCAL_OUT with
	// the input as the L3 packet and copies no packet back.
	input := ipv4TCP()
	ret, err := target.Run(&ebpf.RunOptions{Data: input})
	if err != nil || ret != 1 {
		t.Fatalf("target ret=%d err=%v", ret, err)
	}
	if err := probe.Quiesce(); err != nil {
		t.Fatal(err)
	}
	got := readCapture(t, probe)
	t.Logf("%s probe_read=%v entry=%d exit=%d", name, fallback, len(got[0]), len(got[1]))
	for mode := range got {
		if len(got[mode]) != 1 || !bytes.Equal(got[mode][0].Data, input) {
			t.Fatalf("mode %d records %+v", mode, got[mode])
		}
	}
}
