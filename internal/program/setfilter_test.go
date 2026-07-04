package program

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/filter"
	"github.com/takehaya/xdp-ninja/internal/setmap"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// setTargetSrc derives the capture-point args from packet bytes so each
// BPF_PROG_TEST_RUN can steer (imsi, teid) — packet[0:8] is imsi and
// packet[8:12] is teid, both native-endian.
const setTargetSrc = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

__attribute__((noinline))
int set_capture_pt(struct xdp_md *ctx, unsigned long long imsi, unsigned int teid) {
    if (!ctx)
        return 0;
    return (int)(imsi + teid) & 3;
}

SEC("xdp")
int xdp_set_target(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 12 > data_end)
        return 1;
    unsigned long long imsi = *(unsigned long long *)data;
    unsigned int teid = *(unsigned int *)(data + 8);
    return set_capture_pt(ctx, imsi, teid);
}
char _license[] SEC("license") = "GPL";
`

// runWithKey test-runs the target with a packet whose leading bytes carry
// (imsi, teid). Packet byte 0 = imsi's low byte, which drainMarkers reads
// back as the per-run marker.
func runWithKey(t *testing.T, prog *ebpf.Program, imsi uint64, teid uint32) {
	t.Helper()
	in := make([]byte, 64)
	// Native-endian, matching how the target reads *(u64*)data / *(u32*).
	binary.NativeEndian.PutUint64(in[0:8], imsi)
	binary.NativeEndian.PutUint32(in[8:12], teid)
	if _, err := prog.Run(&ebpf.RunOptions{Data: in}); err != nil {
		t.Fatalf("test-run: %v", err)
	}
}

// TestBpfSetFilterLookupAndRuntimeUpdate is the end-to-end for pinned-map
// set matching: create+pin a composite-key set (with struct padding), add
// an entry, attach a probe gated on "@flows", and verify (a) only calls
// whose (imsi, teid) is in the set are captured, (b) entries added and
// deleted at runtime take effect without re-attaching.
func TestBpfSetFilterLookupAndRuntimeUpdate(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/xdpninja_settest_%d", os.Getpid())
	if err := setmap.Create(pin, "imsi:u64,teid:u32", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	def, err := setmap.Open(pin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(def.Close)
	if len(def.Fields) != 2 || def.KeySize != 16 {
		t.Fatalf("schema = %+v (key %d B), want imsi/teid in 16 B", def.Fields, def.KeySize)
	}

	const inImsi, inTeid = uint64(0x1111222233334444), uint32(0x3039)
	if err := def.Add(map[string]string{"imsi": fmt.Sprintf("%d", inImsi), "teid": fmt.Sprintf("%d", inTeid)}, 1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	prog := loadXDPByName(t, setTargetSrc, "xdp_set_target")
	params, err := attach.GetFuncParams(prog, "set_capture_pt")
	if err != nil {
		t.Fatalf("GetFuncParams: %v", err)
	}

	set := &setmap.Set{SpecRef: setmap.SpecRef{Name: "flows", Path: pin}, Def: def}
	sf, err := filter.ResolveSetFilters([]*setmap.Set{set}, []string{"flows"}, params)
	if err != nil {
		t.Fatalf("ResolveSetFilters: %v", err)
	}

	targets := []attach.Target{{Program: prog, FuncName: "set_capture_pt", Type: ebpf.XDP}}
	probe, err := LoadMultiEntry(targets, "", []filter.TargetFilters{{Sets: sf}}, true, nil)
	if err != nil {
		t.Fatalf("LoadMultiEntry with set filter: %v", err)
	}
	defer func() { _ = probe.Close() }()

	// (a) membership gates capture: 0x44 is in the set, 0x55 is not.
	runWithKey(t, prog, inImsi, inTeid)             // marker 0x44 — hit
	runWithKey(t, prog, 0x9999888877776655, inTeid) // marker 0x55 — miss (imsi)
	runWithKey(t, prog, inImsi, 0xdead)             // marker 0x44, wrong teid — miss
	markers := drainMarkers(t, probe, 1)
	if markers[0x44] != 1 {
		t.Fatalf("markers = %v, want exactly one 0x44 event (wrong-teid run must miss)", markers)
	}
	if markers[0x55] != 0 {
		t.Fatalf("markers = %v: non-member imsi was captured", markers)
	}

	// (b) runtime add: no re-attach, next call is captured.
	const newImsi = uint64(0x00000000000000aa)
	if err := def.Add(map[string]string{"imsi": fmt.Sprintf("%d", newImsi), "teid": fmt.Sprintf("%d", inTeid)}, 2); err != nil {
		t.Fatalf("runtime Add: %v", err)
	}
	runWithKey(t, prog, newImsi, inTeid)
	markers = drainMarkers(t, probe, 1)
	if markers[0xaa] != 1 {
		t.Fatalf("markers after runtime add = %v, want one 0xaa event", markers)
	}

	// (c) runtime delete: the same key stops matching.
	if err := def.Delete(map[string]string{"imsi": fmt.Sprintf("%d", newImsi), "teid": fmt.Sprintf("%d", inTeid)}); err != nil {
		t.Fatalf("runtime Delete: %v", err)
	}
	runWithKey(t, prog, newImsi, inTeid)
	markers = drainMarkers(t, probe, 0)
	if markers[0xaa] != 0 {
		t.Fatalf("markers after runtime delete = %v, want no 0xaa event", markers)
	}
}

// TestBpfSetFilterScalarKey covers the scalar (bare u64) key path,
// including the typedef-carried field name from `set create`.
func TestBpfSetFilterScalarKey(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/xdpninja_setscalar_%d", os.Getpid())
	if err := setmap.Create(pin, "imsi:u64", "", 16); err != nil {
		t.Skipf("creating pinned set map: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	def, err := setmap.Open(pin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(def.Close)
	if !def.IsScalar || def.Fields[0].Name != "imsi" {
		t.Fatalf("scalar schema = %+v (IsScalar=%v), want typedef name imsi", def.Fields, def.IsScalar)
	}

	const member = uint64(0x00000000000000bb)
	if err := def.Add(map[string]string{"imsi": fmt.Sprintf("%d", member)}, 1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	prog := loadXDPByName(t, setTargetSrc, "xdp_set_target")
	params, err := attach.GetFuncParams(prog, "set_capture_pt")
	if err != nil {
		t.Fatalf("GetFuncParams: %v", err)
	}
	set := &setmap.Set{SpecRef: setmap.SpecRef{Name: "subs", Path: pin}, Def: def}
	sf, err := filter.ResolveSetFilters([]*setmap.Set{set}, []string{"subs"}, params)
	if err != nil {
		t.Fatalf("ResolveSetFilters: %v", err)
	}

	targets := []attach.Target{{Program: prog, FuncName: "set_capture_pt", Type: ebpf.XDP}}
	probe, err := LoadMultiEntry(targets, "", []filter.TargetFilters{{Sets: sf}}, true, nil)
	if err != nil {
		t.Fatalf("LoadMultiEntry: %v", err)
	}
	defer func() { _ = probe.Close() }()

	runWithKey(t, prog, member, 1)             // hit (teid irrelevant)
	runWithKey(t, prog, 0x00000000000000cc, 1) // miss
	markers := drainMarkers(t, probe, 1)
	if markers[0xbb] != 1 || markers[0xcc] != 0 {
		t.Fatalf("markers = %v, want one 0xbb and no 0xcc", markers)
	}
}
