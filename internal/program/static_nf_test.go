package program

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// nfFixture is a netfilter program the lookup transform has rewritten to
// call a static hook with ctx. The program also stores ctx->skb in .bss,
// which the capture never reads, so a test can check the identity the
// capture held against the sk_buff the program saw.
type nfFixture struct {
	coll   *ebpf.Collection
	target *ebpf.Program
	hook   string
}

func loadStaticNFFixture(t *testing.T) nfFixture {
	t.Helper()
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
volatile __u64 skb_seen;
SEC("netfilter")
int p(struct bpf_nf_ctx *ctx) {
    __u32 k = 0;
    skb_seen = (__u64)ctx->skb;
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
	t.Cleanup(coll.Close)
	target := coll.Programs["p"]
	h, _ := hook.ByProgramType(ebpf.Netfilter)
	fallback, err := staticNeedsProbeRead(h, target, name, ebpf.AttachTraceFEntry, attach.FuncAvailability{})
	if err != nil || !fallback {
		t.Fatalf("%s must take the probe-read path: probe_read=%v err=%v", name, fallback, err)
	}
	if err := checkStaticCtxArg(target, name); err != nil {
		t.Fatal(err)
	}
	return nfFixture{coll: coll, target: target, hook: name}
}

// nfOutcome is what one run of the fixture under a gated capture left.
type nfOutcome struct {
	recs         [2][]capture.Packet
	hits         uint64
	cfg          uint32
	skb          uint64 // ctx->skb as the program read it
	depth, valid int    // largest per-CPU hold depth and slot-0 valid flag
	cpu          int    // CPU whose slot 0 holds a sequence number, or -1
	frame, seq   uint64 // that slot's identity and sequence number
	unpaired     uint64
}

// runNF runs the fixture once on input, quiesces probe and collects the
// records, the fixture's maps and the hold slot.
func runNF(t *testing.T, fx nfFixture, probe *Probe, input []byte) nfOutcome {
	t.Helper()
	// BPF_PROG_TEST_RUN runs a netfilter program at NF_INET_LOCAL_OUT with
	// the input as the L3 packet and copies no packet back.
	ret, err := fx.target.Run(&ebpf.RunOptions{Data: input})
	if err != nil || ret != 1 {
		t.Fatalf("target ret=%d err=%v", ret, err)
	}
	if err := probe.Quiesce(); err != nil {
		t.Fatal(err)
	}
	o := nfOutcome{recs: readCapture(t, probe), cpu: -1}
	if err := fx.coll.Maps["hits"].Lookup(uint32(0), &o.hits); err != nil {
		t.Fatal(err)
	}
	if err := fx.coll.Maps["cfg"].Lookup(uint32(0), &o.cfg); err != nil {
		t.Fatal(err)
	}
	if err := fx.coll.Maps[".bss"].Lookup(uint32(0), &o.skb); err != nil {
		t.Fatal(err)
	}
	var values [][]byte
	if err := probe.holdMap.Lookup(uint32(0), &values); err != nil {
		t.Fatal(err)
	}
	for cpu, v := range values {
		o.depth = max(o.depth, int(binary.NativeEndian.Uint32(v[holdDepth:])))
		o.valid = max(o.valid, int(binary.NativeEndian.Uint16(v[holdValid:])))
		if seq := binary.NativeEndian.Uint64(v[holdSeq:]); seq != 0 {
			if o.cpu >= 0 {
				t.Fatalf("CPUs %d and %d both hold a sequence number", o.cpu, cpu)
			}
			o.cpu, o.seq, o.frame = cpu, seq, binary.NativeEndian.Uint64(v[holdFrame:])
		}
	}
	stats, err := probe.ExportStats()
	if err != nil {
		t.Fatal(err)
	}
	o.unpaired = stats.HoldUnpaired
	t.Logf("records %d/%d hits=%d cfg=%d skb=%#x frame=%#x seq=%d cpu=%d depth=%d valid=%d unpaired=%d",
		len(o.recs[0]), len(o.recs[1]), o.hits, o.cfg, o.skb, o.frame, o.seq, o.cpu, o.depth, o.valid, o.unpaired)
	return o
}

// program checks what the fixture itself did on one run: it counted the
// packet once and left the read-only cfg at 0, and it saw an sk_buff.
func (o nfOutcome) program() error {
	if o.hits != 1 || o.cfg != 0 || o.skb == 0 {
		return fmt.Errorf("fixture maps hits=%d cfg=%d skb=%#x, want 1, 0 and a pointer", o.hits, o.cfg, o.skb)
	}
	return nil
}

// released checks that the capture gave back the depth and consumed the hold.
func (o nfOutcome) released() error {
	if o.depth != 0 || o.valid != 0 {
		return fmt.Errorf("hold depth=%d valid=%d, want both 0", o.depth, o.valid)
	}
	return nil
}

// paired checks one entry and one exit record of input from one invocation:
// L3 data, orig_len, the static hook's return (0, as every generated hook
// returns) and the packet id of the hold, which held the program's skb.
func (o nfOutcome) paired(input []byte) error {
	if err := o.program(); err != nil {
		return err
	}
	if err := o.released(); err != nil {
		return err
	}
	if o.unpaired != 0 {
		return fmt.Errorf("unpaired=%d, want 0", o.unpaired)
	}
	if o.cpu < 0 || o.seq != 1 {
		return fmt.Errorf("hold cpu=%d seq=%d, want one CPU with seq 1", o.cpu, o.seq)
	}
	if o.frame != o.skb {
		return fmt.Errorf("identity %#x is not the program's skb %#x", o.frame, o.skb)
	}
	id := uint64(o.cpu)<<packetIDCPUShift | o.seq
	for mode, recs := range o.recs {
		if len(recs) != 1 {
			return fmt.Errorf("mode %d: %d records, want 1", mode, len(recs))
		}
		r := recs[0]
		if !bytes.Equal(r.Data, input) || r.OrigLen != uint32(len(input)) || r.Action != 0 || r.PacketID != id {
			return fmt.Errorf("mode %d: data=%x orig_len=%d action=%d packet_id=%#x, want %x, %d, 0 and %#x",
				mode, r.Data, r.OrigLen, r.Action, r.PacketID, input, len(input), id)
		}
	}
	return nil
}

// dropped checks that a capture which must not pair left no record, counted
// unpaired holds and gave back the depth and hold, while the program ran.
func (o nfOutcome) dropped(unpaired uint64) error {
	if err := o.program(); err != nil {
		return err
	}
	if n := len(o.recs[0]) + len(o.recs[1]); n != 0 {
		return fmt.Errorf("%d records, want none", n)
	}
	if o.unpaired != unpaired {
		return fmt.Errorf("unpaired=%d, want %d", o.unpaired, unpaired)
	}
	return o.released()
}

// A static hook the lookup transform adds to a netfilter program takes
// pointer arguments besides ctx, so the kernel discards its prototype and
// capture there must read bpf_nf_ctx and its sk_buff with
// bpf_probe_read_kernel. The record starts at L3, as at a global netfilter
// function.
func TestBpfStaticNetfilterInjectedHook(t *testing.T) {
	fx := loadStaticNFFixture(t)
	probe, err := LoadMultiPoint([]attach.Target{{Program: fx.target, FuncName: fx.hook, Type: ebpf.Netfilter}},
		[]Stage{{Expr: "ipv4"}, {Expr: "ipv4", IsFexit: true}}, nil, true, nil, EmitBoth)
	if err != nil {
		t.Fatalf("capture at %s: %+v", fx.hook, err)
	}
	defer func() { _ = probe.Close() }()
	input := ipv4TCP()
	if err := runNF(t, fx, probe, input).paired(input); err != nil {
		t.Fatal(err)
	}
}

// loadNFGated builds the gated capture LoadMultiPoint builds for a static
// netfilter function, from the given hooks, so a test can plant a fault in
// one of them. readEntry and readExit (-1 for none) make that ctx read of
// the entry or exit fail; deferPrologue=false reads ctx before the exit
// returns the hold.
func loadNFGated(t *testing.T, fx nfFixture, entryHook, exitHook *hook.Hook, readEntry, readExit int, deferPrologue bool) *Probe {
	t.Helper()
	outE, err := compileFilter("ipv4", true, false, ebpf.Netfilter)
	if err != nil {
		t.Fatal(err)
	}
	outX, err := compileFilter("ipv4", true, true, ebpf.Netfilter)
	if err != nil {
		t.Fatal(err)
	}
	outer, inners, err := createShardedRingbuf("gated")
	if err != nil {
		t.Fatal(err)
	}
	p := &Probe{EventsMap: outer, InnerMaps: inners, IsFexit: true, maps: append([]*ebpf.Map{outer}, inners...)}
	t.Cleanup(func() { _ = p.Close() })
	if err := p.initExportStats(); err != nil {
		t.Fatal(err)
	}
	capLen := outE.Capture.MaxCapLen
	if capLen <= 0 {
		capLen = defaultCapLen
	}
	hold, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: uint32(holdHdr + capLen), MaxEntries: uint32(holdSlots)})
	if err != nil {
		t.Fatal(err)
	}
	stop, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.maps = append(p.maps, hold, stop)
	p.holdMap, p.holdStop = hold, stop
	scratchFD := 0
	if len(outE.Main) > 0 || len(outX.Main) > 0 {
		scratch, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: scratchBufSize, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		p.maps = append(p.maps, scratch)
		scratchFD = scratch.FD()
	}
	exit, err := buildGatedExitInsns(exitHook, outX, filter.TargetFilters{}, outer.FD(), hold.FD(), p.StatsMap.FD(), scratchFD, nil, nil, EmitBoth, capLen, fexitReturnViaHelper, 0, deferPrologue)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachTracingProbe(p, fx.target, "nf_exit", fx.hook, ebpf.AttachTraceFExit, failCtxRead(t, exit, readExit), false, attach.FuncAvailability{}); err != nil {
		t.Fatal(err)
	}
	entry, err := buildGatedEntryInsns(entryHook, outE, filter.TargetFilters{}, hold.FD(), stop.FD(), p.StatsMap.FD(), scratchFD, nil, nil, EmitBoth, capLen, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachTracingProbe(p, fx.target, "nf_entry", fx.hook, ebpf.AttachTraceFEntry, failCtxRead(t, entry, readEntry), false, attach.FuncAvailability{}); err != nil {
		t.Fatal(err)
	}
	return p
}

// failCtxRead makes the read-th bpf_probe_read_kernel that exits on failure
// (a ctx or identity read, not a packet copy) read from address 0.
func failCtxRead(t *testing.T, insns asm.Instructions, read int) asm.Instructions {
	t.Helper()
	if read < 0 {
		return insns
	}
	for i, in := range insns {
		if !in.IsBuiltinCall() || in.Constant != int64(asm.FnProbeReadKernel) || i+1 == len(insns) ||
			insns[i+1].OpCode.JumpOp() != asm.JNE || insns[i+1].Dst != asm.R0 || insns[i+1].Reference() != "exit" {
			continue
		}
		if read > 0 {
			read--
			continue
		}
		if in.Symbol() != "" {
			t.Fatalf("ctx read at %d carries symbol %q", i, in.Symbol())
		}
		return append(insns[:i:i], append(asm.Instructions{asm.Mov.Imm(asm.R3, 0)}, insns[i:]...)...)
	}
	t.Fatal("fewer ctx reads than planted")
	return nil
}

// withIdentity is h reading its identity at bpf_nf_ctx offset off, then
// xor-ing it with flip.
func withIdentity(h *hook.Hook, isFexit bool, off int32, flip int32) *hook.Hook {
	clone := *h
	clone.Identity = func(dst asm.Register) (asm.Instructions, error) {
		insns, err := probeReadIdentity(isFexit, off)(dst)
		if flip != 0 {
			insns = append(insns, asm.Xor.Imm(dst, flip))
		}
		return insns, err
	}
	return &clone
}

func nfCtxOffset(t *testing.T, member string) int32 {
	t.Helper()
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	var ctx *btf.Struct
	if err := spec.TypeByName("bpf_nf_ctx", &ctx); err != nil {
		t.Fatal(err)
	}
	for _, m := range ctx.Members {
		if m.Name == member {
			return int32(m.Offset.Bytes())
		}
	}
	t.Fatalf("bpf_nf_ctx has no %s", member)
	return 0
}

// The gated capture pairs an entry and an exit by ctx->skb. Each planted
// fault must fail the oracle that looks for it, and the unplanted build
// must pass both.
func TestBpfStaticNetfilterGatedIdentity(t *testing.T) {
	fx := loadStaticNFFixture(t)
	h, _ := hook.ByProgramType(ebpf.Netfilter)
	skbOff, stateOff := nfCtxOffset(t, "skb"), nfCtxOffset(t, "state")
	if skbOff == stateOff {
		t.Fatal("state and skb share an offset")
	}
	entry, exit := staticNFHook(h, fx.hook, false), staticNFHook(h, fx.hook, true)
	input := ipv4TCP()
	run := func(t *testing.T, entry, exit *hook.Hook) nfOutcome {
		hits := fx.coll.Maps["hits"]
		if err := hits.Update(uint32(0), uint64(0), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		return runNF(t, fx, loadNFGated(t, fx, entry, exit, -1, -1, true), input)
	}
	t.Run("unplanted", func(t *testing.T) {
		o := run(t, entry, exit)
		if err := o.paired(input); err != nil {
			t.Fatal(err)
		}
		if err := o.dropped(0); err == nil {
			t.Fatal("dropped accepted a paired capture")
		}
		// Each check of paired fails on the field it reads.
		for name, plant := range map[string]func(*nfOutcome){
			"hits":      func(o *nfOutcome) { o.hits++ },
			"cfg":       func(o *nfOutcome) { o.cfg = 1 },
			"skb":       func(o *nfOutcome) { o.skb = 0 },
			"depth":     func(o *nfOutcome) { o.depth = 1 },
			"valid":     func(o *nfOutcome) { o.valid = 1 },
			"unpaired":  func(o *nfOutcome) { o.unpaired = 1 },
			"seq":       func(o *nfOutcome) { o.seq = 2 },
			"identity":  func(o *nfOutcome) { o.frame ^= 8 },
			"entry":     func(o *nfOutcome) { o.recs[0] = nil },
			"exit":      func(o *nfOutcome) { o.recs[1] = append(o.recs[1], o.recs[1][0]) },
			"data":      func(o *nfOutcome) { o.recs[0][0].Data = input[1:] },
			"orig_len":  func(o *nfOutcome) { o.recs[1][0].OrigLen-- },
			"action":    func(o *nfOutcome) { o.recs[1][0].Action = 1 },
			"packet_id": func(o *nfOutcome) { o.recs[0][0].PacketID ^= 1 },
		} {
			m := o
			m.recs = [2][]capture.Packet{append([]capture.Packet(nil), o.recs[0]...), append([]capture.Packet(nil), o.recs[1]...)}
			plant(&m)
			if err := m.paired(input); err == nil {
				t.Errorf("paired accepted a planted %s", name)
			}
		}
	})
	// ctx->state is as stable within an invocation as ctx->skb, so entry and
	// exit still pair; only the comparison with the program's skb fails.
	t.Run("state at entry and exit", func(t *testing.T) {
		o := run(t, withIdentity(entry, false, stateOff, 0), withIdentity(exit, true, stateOff, 0))
		if err := o.paired(input); err == nil || o.frame == o.skb {
			t.Fatalf("paired=%v with identity %#x and skb %#x", err, o.frame, o.skb)
		}
	})
	t.Run("state at exit", func(t *testing.T) {
		o := run(t, entry, withIdentity(exit, true, stateOff, 0))
		if err := o.dropped(1); err != nil {
			t.Fatal(err)
		}
		if err := o.paired(input); err == nil {
			t.Fatal("paired accepted a dropped capture")
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		o := run(t, entry, withIdentity(exit, true, skbOff, 1))
		if err := o.dropped(1); err != nil {
			t.Fatal(err)
		}
		if err := o.paired(input); err == nil {
			t.Fatal("paired accepted a dropped capture")
		}
	})
}

// A failed ctx read, in the prologue (ctx->skb, data, len, data_len) or of
// the identity, at the entry or the exit, ends that probe with no record and
// leaves no depth or hold behind.
func TestBpfStaticNetfilterContextReadFailure(t *testing.T) {
	fx := loadStaticNFFixture(t)
	h, _ := hook.ByProgramType(ebpf.Netfilter)
	entry, exit := staticNFHook(h, fx.hook, false), staticNFHook(h, fx.hook, true)
	input := ipv4TCP()
	for _, side := range []string{"entry", "exit"} {
		for read := range 5 {
			t.Run(fmt.Sprintf("%s/read%d", side, read), func(t *testing.T) {
				if err := fx.coll.Maps["hits"].Update(uint32(0), uint64(0), ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				readEntry, readExit := read, -1
				if side == "exit" {
					readEntry, readExit = -1, read
				}
				o := runNF(t, fx, loadNFGated(t, fx, entry, exit, readEntry, readExit, true), input)
				if err := o.dropped(0); err != nil {
					t.Fatal(err)
				}
				if err := o.paired(input); err == nil {
					t.Fatal("paired accepted a failed read")
				}
			})
		}
	}
	// Reading ctx before the exit returns the hold leaks it on a failed read.
	t.Run("prologue before release", func(t *testing.T) {
		if err := fx.coll.Maps["hits"].Update(uint32(0), uint64(0), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		o := runNF(t, fx, loadNFGated(t, fx, entry, exit, -1, 0, false), input)
		if err := o.dropped(1); err == nil || !strings.Contains(err.Error(), "hold depth=1 valid=1") {
			t.Fatalf("dropped=%v, want the leaked depth and hold", err)
		}
	})
}

func TestBpfStaticNetfilterGatedContextReadFailure(t *testing.T) {
	fx := loadStaticNFFixture(t)
	h, _ := hook.ByProgramType(ebpf.Netfilter)
	entry, exit := staticNFHook(h, fx.hook, false), staticNFHook(h, fx.hook, true)
	for read := range 5 { // ctx->skb, data, len, data_len, then the identity
		t.Run(fmt.Sprint("read", read), func(t *testing.T) {
			testGatedContextReadFailure(t, fx.target, fx.hook, entry, exit, read)
		})
		// The identity is read after the hold release in either order, so
		// only the four prologue reads can leak it.
		if read < 4 {
			t.Run(fmt.Sprint("read", read, "/prologue before release"), func(t *testing.T) {
				if err := gatedContextReadLeak(t, fx.target, fx.hook, entry, exit, read, false); err == nil {
					t.Fatal("no leak found with the prologue before the hold release")
				}
			})
		}
	}
}
