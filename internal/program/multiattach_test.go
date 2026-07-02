package program

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/capture/fastrb"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// multiXDPSource builds a distinct XDP program whose entry function is
// entryName. The body must be non-trivial so clang keeps it.
func multiXDPSource(entryName string) string {
	return fmt.Sprintf(`
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int %s(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return 1;
    return 2;
}
char _license[] SEC("license") = "GPL";
`, entryName)
}

// multiNoinlineSource builds an XDP program with entryName calling a
// __noinline subfunction named capture_pt — the same subfunction name in
// several programs, like a shared DL capture point compiled into both the
// v4 and v6 handlers.
func multiNoinlineSource(entryName string) string {
	return fmt.Sprintf(`
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

__attribute__((noinline))
int capture_pt(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return 1;
    return 2;
}

SEC("xdp")
int %s(struct xdp_md *ctx) { return capture_pt(ctx); }
char _license[] SEC("license") = "GPL";
`, entryName)
}

// loadXDPByName compiles src and loads the program named entryName.
func loadXDPByName(t *testing.T, src, entryName string) *ebpf.Program {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, src))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("loading collection: %v", err)
	}
	prog := coll.Programs[entryName]
	if prog == nil {
		coll.Close()
		t.Fatalf("program %s not in collection", entryName)
	}
	// Detach the program from the collection lifetime.
	prog2 := prog
	delete(coll.Programs, entryName)
	coll.Close()
	t.Cleanup(func() { _ = prog2.Close() })
	return prog2
}

// progInfoFor wraps a loaded program as attach.ProgInfo for ResolveTargets.
func progInfoFor(t *testing.T, prog *ebpf.Program, funcName string) *attach.ProgInfo {
	t.Helper()
	info, err := prog.Info()
	if err != nil {
		t.Fatalf("prog info: %v", err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("program has no ID")
	}
	return &attach.ProgInfo{Program: prog, ProgID: uint32(id), FuncName: funcName, Type: ebpf.XDP}
}

// drainMarkers reads every shard of the probe's ringbuf and collects the
// first payload byte (the per-source marker) of each captured record.
func drainMarkers(t *testing.T, probe *Probe) map[byte]int {
	t.Helper()
	markers := map[byte]int{}
	innerSize := int(shardRingbufSize(RingbufSize, runtime.NumCPU()))
	for i, m := range probe.InnerMaps {
		rd, err := fastrb.New(m.FD(), innerSize)
		if err != nil {
			t.Fatalf("fastrb on shard %d: %v", i, err)
		}
		rd.ReadBatch(func(rec []byte) {
			if len(rec) > metadataSize { // metadata + at least 1 payload byte
				markers[rec[metadataSize]]++
			}
		})
		_ = rd.Close()
	}
	return markers
}

// runWithMarker test-runs an XDP program with a packet whose first byte is
// the given marker, firing any attached fentry probes.
func runWithMarker(t *testing.T, prog *ebpf.Program, marker byte) {
	t.Helper()
	in := make([]byte, 64)
	in[0] = marker
	if _, err := prog.Run(&ebpf.RunOptions{Data: in}); err != nil {
		t.Fatalf("test-run: %v", err)
	}
}

// TestBpfMultiAttachEntryPrograms covers case (A): one probe attached to
// the entry functions of two independent XDP programs, both emitting into
// the shared ringbuf.
func TestBpfMultiAttachEntryPrograms(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	progA := loadXDPByName(t, multiXDPSource("xdp_multi_a"), "xdp_multi_a")
	progB := loadXDPByName(t, multiXDPSource("xdp_multi_b"), "xdp_multi_b")

	infos := []*attach.ProgInfo{
		progInfoFor(t, progA, "xdp_multi_a"),
		progInfoFor(t, progB, "xdp_multi_b"),
	}
	// No --func: each program contributes its entry function.
	targets, err := attach.ResolveTargets(infos, nil)
	if err != nil {
		t.Fatalf("ResolveTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("resolved %d targets, want 2: %+v", len(targets), targets)
	}

	probe, err := LoadMultiEntry(targets, "", nil, true)
	if err != nil {
		t.Fatalf("LoadMultiEntry: %v", err)
	}
	defer func() { _ = probe.Close() }()
	if probe.AttachCount() != 2 {
		t.Fatalf("AttachCount = %d, want 2", probe.AttachCount())
	}

	runWithMarker(t, progA, 0xAA)
	runWithMarker(t, progB, 0xBB)

	markers := drainMarkers(t, probe)
	if markers[0xAA] == 0 || markers[0xBB] == 0 {
		t.Fatalf("expected events from both programs in the shared ringbuf, got markers %v", markers)
	}
}

// TestBpfMultiAttachNoinlineAcrossPrograms covers case (B): one --func
// name (a __noinline subfunction) that exists in two programs — like a
// shared DL capture point in both the v4 and the v6 handler — resolves to
// two attach pairs and both fire into the shared ringbuf.
func TestBpfMultiAttachNoinlineAcrossPrograms(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	progV4 := loadXDPByName(t, multiNoinlineSource("xdp_v4_handler"), "xdp_v4_handler")
	progV6 := loadXDPByName(t, multiNoinlineSource("xdp_v6_handler"), "xdp_v6_handler")

	infos := []*attach.ProgInfo{
		progInfoFor(t, progV4, "xdp_v4_handler"),
		progInfoFor(t, progV6, "xdp_v6_handler"),
	}
	targets, err := attach.ResolveTargets(infos, []string{"capture_pt"})
	if err != nil {
		t.Fatalf("ResolveTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("resolved %d targets, want 2 (capture_pt in both programs): %+v", len(targets), targets)
	}
	for _, tg := range targets {
		if tg.FuncName != "capture_pt" {
			t.Fatalf("target func = %q, want capture_pt", tg.FuncName)
		}
	}

	probe, err := LoadMultiEntry(targets, "", nil, true)
	if err != nil {
		t.Fatalf("LoadMultiEntry: %v", err)
	}
	defer func() { _ = probe.Close() }()
	if probe.AttachCount() != 2 {
		t.Fatalf("AttachCount = %d, want 2", probe.AttachCount())
	}

	runWithMarker(t, progV4, 0x44)
	runWithMarker(t, progV6, 0x66)

	markers := drainMarkers(t, probe)
	if markers[0x44] == 0 || markers[0x66] == 0 {
		t.Fatalf("expected events from both noinline copies in the shared ringbuf, got markers %v", markers)
	}
}

// TestResolveTargetsFuncMissingEverywhere verifies a func found in no
// target program is an error rather than a silent no-attach.
func TestResolveTargetsFuncMissingEverywhere(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	prog := loadXDPByName(t, multiXDPSource("xdp_multi_solo"), "xdp_multi_solo")
	infos := []*attach.ProgInfo{progInfoFor(t, prog, "xdp_multi_solo")}
	if _, err := attach.ResolveTargets(infos, []string{"no_such_func"}); err == nil {
		t.Fatal("expected error for func missing from every program, got nil")
	}
}
