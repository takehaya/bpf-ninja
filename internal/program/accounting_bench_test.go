package program

import (
	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"testing"
)

// Measures a successful export with and without outcome/tombstone lookups.
// Draining every 256 calls keeps the comparison off the ring-full path.
// Wall time includes BPF_PROG_TEST_RUN and amortized mmap drain costs.
func BenchmarkExportAccounting(b *testing.B) {
	testutil.SkipIfNotRoot(b)
	for _, kind := range []string{"baseline", "counters", "counters_and_tag_gate"} {
		b.Run(kind, func(b *testing.B) {
			outer, inners, err := createShardedRingbuf("bench")
			if err != nil {
				b.Fatal(err)
			}
			probe := &Probe{EventsMap: outer, InnerMaps: inners, maps: append([]*ebpf.Map{outer}, inners...)}
			defer func() { _ = probe.Close() }()
			statsFD, gateFD := 0, 0
			if kind != "baseline" {
				if err := probe.initExportStats(); err != nil {
					b.Fatal(err)
				}
				statsFD = probe.StatsMap.FD()
			}
			if kind == "counters_and_tag_gate" {
				gateFD, err = probe.initTagBarrier()
				if err != nil {
					b.Fatal(err)
				}
			}
			var out codegen.Output
			out.Capture.MaxCapLen = 64
			p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: buildXDPNativeInsns(out, outer.FD(), nil, gateFD, statsFD)})
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = p.Close() }()
			var readers []*fastrb.Reader
			for _, m := range inners {
				r, err := fastrb.New(m.FD(), int(m.MaxEntries()))
				if err != nil {
					b.Fatal(err)
				}
				defer func() { _ = r.Close() }()
				readers = append(readers, r)
			}
			packet := make([]byte, 64)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.Run(&ebpf.RunOptions{Data: packet}); err != nil {
					b.Fatal(err)
				}
				if i%256 == 255 {
					for _, r := range readers {
						r.ReadBatch(func([]byte) {})
					}
				}
			}
			b.StopTimer()
			if statsFD > 0 {
				k, err := probe.ExportStats()
				if err != nil || k.Submitted != uint64(b.N) {
					b.Fatalf("invalid measurement: %+v %v", k, err)
				}
			}
		})
	}
}

// The same static predicate and packet isolate the read-window cost. Dynamic
// parsers require the larger window for correctness and cannot use the short
// window as a valid alternative.
func BenchmarkTracingReadWindow(b *testing.B) {
	testutil.SkipIfNotRoot(b)
	target := loadDummyXDP(b)
	oldSnap := SnaplenOverride
	SnaplenOverride = 64
	defer func() { SnaplenOverride = oldSnap }()
	for _, full := range []bool{false, true} {
		name := "14_bytes"
		if full {
			name = "512_bytes"
		}
		b.Run(name, func(b *testing.B) {
			old := ObserverPrefetch
			ObserverPrefetch = full
			defer func() { ObserverPrefetch = old }()
			probe, err := LoadEntry(target, xdpFuncName, "eth", nil, true)
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = probe.Close() }()
			var readers []*fastrb.Reader
			for _, m := range probe.InnerMaps {
				r, err := fastrb.New(m.FD(), int(m.MaxEntries()))
				if err != nil {
					b.Fatal(err)
				}
				defer func() { _ = r.Close() }()
				readers = append(readers, r)
			}
			packet := make([]byte, 1024)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := target.Run(&ebpf.RunOptions{Data: packet}); err != nil {
					b.Fatal(err)
				}
				if i%256 == 255 {
					for _, r := range readers {
						r.ReadBatch(func([]byte) {})
					}
				}
			}
			b.StopTimer()
			k, err := probe.ExportStats()
			if err != nil || k.Submitted != uint64(b.N) {
				b.Fatalf("invalid measurement: %+v %v", k, err)
			}
		})
	}
}
