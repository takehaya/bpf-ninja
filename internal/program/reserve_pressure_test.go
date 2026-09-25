package program

import (
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
)

// TestBpfReserveFailAccounting pins the export accounting: with a 4 KiB
// per-CPU ring and no reader the ring fills after a few dozen records,
// every further bpf_ringbuf_reserve returns NULL and is counted in the
// stats map, and records read + reserve failures equal the invocations.
func TestBpfReserveFailAccounting(t *testing.T) {
	old := RingbufSize
	RingbufSize = 4096
	t.Cleanup(func() { RingbufSize = old })

	prog := loadDummyXDP(t)
	targets := []attach.Target{{Program: prog, FuncName: xdpFuncName, Type: ebpf.XDP}}
	probe, err := LoadMultiPoint(targets, []Stage{{Expr: "eth"}}, nil, true, nil, EmitBoth)
	if err != nil {
		t.Fatalf("LoadMultiPoint: %v", err)
	}
	defer func() { _ = probe.Close() }()
	if probe.StatsMap == nil {
		t.Fatal("probe.StatsMap is nil")
	}

	const runs = 50
	frame := dsltest.BuildEthIPv4UDP(t, 1234, 6081, make([]byte, 32))
	for range runs {
		if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			t.Fatalf("test-run target: %v", err)
		}
	}

	var per []uint64
	if err := probe.StatsMap.Lookup(uint32(0), &per); err != nil {
		t.Fatalf("stats lookup: %v", err)
	}
	var fails uint64
	for _, v := range per {
		fails += v
	}
	if fails == 0 {
		t.Fatalf("reserve failures = 0, want > 0 with a %d-byte ring and %d runs", RingbufSize, runs)
	}

	sr, err := capture.NewShardedReader(probe.InnerMaps)
	if err != nil {
		t.Fatalf("sharded reader: %v", err)
	}
	var mu sync.Mutex
	var read int
	stop, err := sr.RunShards(func(_ int, pkts []capture.Packet) error {
		mu.Lock()
		read += len(pkts)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("RunShards: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	stop()
	mu.Lock()
	defer mu.Unlock()
	if uint64(read)+fails != runs {
		t.Fatalf("read %d + reserve_fail %d != %d runs", read, fails, runs)
	}
	t.Logf("read=%d reserve_fail=%d", read, fails)

	// Detach stops the producer: further invocations neither fill the
	// ring nor bump the counter (the ring is full again after the
	// reader stopped, so without the detach every run would count).
	if err := probe.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if n := probe.AttachCount(); n != 0 {
		t.Fatalf("AttachCount after Detach = %d, want 0", n)
	}
	for range 10 {
		if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			t.Fatalf("test-run target: %v", err)
		}
	}
	if err := probe.StatsMap.Lookup(uint32(0), &per); err != nil {
		t.Fatalf("stats lookup: %v", err)
	}
	var after uint64
	for _, v := range per {
		after += v
	}
	if after != fails {
		t.Fatalf("reserve_fail after Detach = %d, want unchanged %d", after, fails)
	}
}
