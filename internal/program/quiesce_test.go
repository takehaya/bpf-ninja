package program

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// Stall the sink, build a known backlog, stop producers, then continue running
// their target. Every pre-stop event must survive; no post-stop event may leak.
func TestBpfQuiesceDrainsAllShards(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, fast := range []bool{false, true} {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("fast=%v/raw=%v", fast, raw), func(t *testing.T) {
				spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, fexitLayoutSource))
				if err != nil {
					t.Fatal(err)
				}
				col, err := ebpf.NewCollection(spec)
				if err != nil {
					t.Fatal(err)
				}
				defer col.Close()
				target := col.Programs["layout_target"]
				var targets []attach.Target
				for _, name := range []string{"one", "two", "three"} {
					targets = append(targets, attach.Target{Program: target, FuncName: name, Type: ebpf.XDP})
				}
				probe, err := LoadMultiEntry(targets, "", nil, true, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = probe.Close() }()
				arrived, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				var written atomic.Uint64
				sink := func(n int) error { once.Do(func() { close(arrived); <-release }); written.Add(uint64(n)); return nil }
				var stop func()
				var stats *capture.SessionStats
				var readErr func() error
				if fast {
					r, e := capture.NewFastShardedReader(probe.InnerMaps)
					if e != nil {
						t.Fatal(e)
					}
					if raw {
						stop, err = r.RunRawShardsFast(func(int, []byte) error { return sink(1) })
					} else {
						stop, err = r.RunShardsFast(func(_ int, p []capture.Packet) error { return sink(len(p)) })
					}
					stats = r.Stats()
					readErr = r.Err
				} else {
					r, e := capture.NewShardedReader(probe.InnerMaps)
					if e != nil {
						t.Fatal(e)
					}
					if raw {
						stop, err = r.RunRawShards(func(int, []byte) error { return sink(1) })
					} else {
						stop, err = r.RunShards(func(_ int, p []capture.Packet) error { return sink(len(p)) })
					}
					stats = r.Stats()
					readErr = r.Err
				}
				if err != nil {
					t.Fatal(err)
				}
				run := func(n int) {
					for i := 0; i < n; i++ {
						if _, e := target.Run(&ebpf.RunOptions{Data: tcpPacket(0x99, 1234, 443)}); e != nil {
							t.Fatal(e)
						}
					}
				}
				run(1)
				select {
				case <-arrived:
				case <-time.After(5 * time.Second):
					t.Fatal("sink never started")
				}
				run(99)
				if err := probe.Quiesce(); err != nil {
					t.Fatal(err)
				}
				run(100)
				done := make(chan struct{})
				go func() { stop(); close(done) }()
				close(release)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("drain hung")
				}
				stop() // idempotent join
				if err := readErr(); err != nil {
					t.Fatal(err)
				}
				if written.Load() != 300 || stats.Consumed.Load() != 300 {
					t.Fatalf("written=%d consumed=%d, want 300", written.Load(), stats.Consumed.Load())
				}
				if err := probe.Close(); err != nil {
					t.Fatal(err)
				}
				if err := probe.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
