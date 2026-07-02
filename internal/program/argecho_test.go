package program

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/capture/fastrb"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// echoTargetSrc: an XDP program calling a global noinline subfunction that
// takes an integer arg, so --arg-echo can attach fexit/fentry to it and
// observe the arg value.
const echoTargetSrc = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

__attribute__((noinline))
int capture_pt(struct xdp_md *ctx, unsigned long long imsi) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return 0;
    if (imsi == 0)
        return 1;
    return 2;
}

SEC("xdp")
int echo_target(struct xdp_md *ctx) {
    return capture_pt(ctx, 0x1122334455667788ULL);
}
char _license[] SEC("license") = "GPL";
`

// TestBpfArgEchoEmitsArgValue loads a target with an int-arg subfunction,
// attaches an arg-echo probe to that subfunction, triggers the target via
// BPF_PROG_TEST_RUN, and asserts the echoed arg matches the value the
// target passes.
func TestBpfArgEchoEmitsArgValue(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, echoTargetSrc))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}
	var objs struct {
		Target *ebpf.Program `ebpf:"echo_target"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading target: %v", err)
	}
	defer func() { _ = objs.Target.Close() }()

	params, err := attach.GetFuncParams(objs.Target, "capture_pt")
	if err != nil {
		t.Fatalf("GetFuncParams: %v", err)
	}
	if len(params) != 1 || params[0].Name != "imsi" || params[0].Size != 8 {
		t.Fatalf("unexpected params: %+v", params)
	}

	probe, err := LoadArgEcho(objs.Target, "capture_pt", nil, params, false)
	if err != nil {
		t.Fatalf("LoadArgEcho: %v", err)
	}
	defer func() { _ = probe.Close() }()

	rd, err := fastrb.New(probe.EchoRing.FD(), EchoRingSize)
	if err != nil {
		t.Fatalf("fastrb.New: %v", err)
	}
	defer func() { _ = rd.Close() }()

	// Trigger the target (and thus the attached fentry echo) via test-run.
	in := make([]byte, 64)
	if _, err := objs.Target.Run(&ebpf.RunOptions{Data: in}); err != nil {
		t.Fatalf("test-run target: %v", err)
	}

	if n, err := rd.WaitForData(1000); err != nil {
		t.Fatalf("WaitForData: %v", err)
	} else if n == 0 {
		t.Fatal("no arg-echo record after test-run")
	}

	var got uint64
	var recs int
	rd.ReadBatch(func(rec []byte) {
		recs++
		if len(rec) >= 8 {
			got = binary.NativeEndian.Uint64(rec[:8])
		}
	})
	if recs == 0 {
		t.Fatal("ReadBatch delivered no records")
	}
	const want = uint64(0x1122334455667788)
	if got != want {
		t.Errorf("echoed imsi = 0x%x, want 0x%x", got, want)
	}
}
