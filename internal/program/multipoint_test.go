package program

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
)

// TestBpfMultiPointLoad verifies that a gated entry + exit capture
// passes the verifier for every --emit form, on XDP and tc targets, and
// attaches both probes.
func TestBpfMultiPointLoad(t *testing.T) {
	xdp := []attach.Target{{Program: loadDummyXDP(t), FuncName: xdpFuncName, Type: ebpf.XDP}}
	tc := []attach.Target{{Program: loadDummyTC(t), FuncName: tcFuncName, Type: ebpf.SchedCLS}}
	cases := []struct {
		name        string
		targets     []attach.Target
		entry, exit string
		dsl         bool
		emit        Emit
	}{
		{"empty-both", xdp, "", "", false, EmitBoth},
		{"cbpf-both", xdp, "icmp", "icmp", false, EmitBoth},
		{"dsl-both", xdp, "eth/ipv4/icmp", "eth/ipv4/icmp where action == XDP_PASS", true, EmitBoth},
		{"dsl-entry", xdp, "eth/ipv4/udp[dport==6081]", "eth where action == XDP_DROP", true, EmitEntry},
		{"dsl-exit", xdp, "eth/ipv4/udp[dport==6081]", "eth/ipv4/tcp where action == XDP_DROP", true, EmitExit},
		{"no-entry-filter", xdp, "", "eth/ipv4/icmp where action == XDP_PASS", true, EmitEntry},
		{"tc-both", tc, "eth/ipv4/tcp", "eth/ipv4/tcp where action == TC_ACT_SHOT", true, EmitBoth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stages := []Stage{{Expr: tc.entry}, {IsFexit: true, Expr: tc.exit}}
			probe, err := LoadMultiPoint(tc.targets, stages, nil, tc.dsl, nil, tc.emit)
			if err != nil {
				t.Fatalf("LoadMultiPoint: %v", err)
			}
			defer func() { _ = probe.Close() }()
			if !probe.IsFexit {
				t.Error("probe.IsFexit = false, want true (the exit stage sees the verdict)")
			}
			if n := probe.AttachCount(); n != 2 {
				t.Errorf("AttachCount = %d, want 2 (fentry + fexit)", n)
			}
		})
	}
}

// runGatedTestRun attaches a gated capture to the dummy XDP program,
// fires it once per frame (in order) through BPF_PROG_TEST_RUN and
// returns the records per shard (in order) once `want` records arrived
// or the deadline passed.
func runGatedTestRun(t *testing.T, entry, exit string, emit Emit, frames [][]byte, want int) map[int][]capture.Packet {
	t.Helper()
	prog := loadDummyXDP(t)
	targets := []attach.Target{{Program: prog, FuncName: xdpFuncName, Type: ebpf.XDP}}
	stages := []Stage{{Expr: entry}, {IsFexit: true, Expr: exit}}
	probe, err := LoadMultiPoint(targets, stages, nil, true, nil, emit)
	if err != nil {
		t.Fatalf("LoadMultiPoint: %v", err)
	}
	defer func() { _ = probe.Close() }()

	sr, err := capture.NewShardedReader(probe.InnerMaps)
	if err != nil {
		t.Fatalf("sharded reader: %v", err)
	}
	var mu sync.Mutex
	got := map[int][]capture.Packet{}
	var total int
	sink := func(shardIdx int, pkts []capture.Packet) error {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range pkts {
			p.Data = append([]byte(nil), p.Data...) // ring memory is reused after the sink returns
			got[shardIdx] = append(got[shardIdx], p)
		}
		total += len(pkts)
		return nil
	}
	stop, err := sr.RunShards(sink)
	if err != nil {
		t.Fatalf("RunShards: %v", err)
	}
	defer stop()

	for _, frame := range frames {
		if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			t.Fatalf("test-run target: %v", err)
		}
	}
	// Wait for the expected count, then a little longer to catch strays
	// (the "nothing must be emitted" cases rely on that grace period).
	deadline := time.Now().Add(2 * time.Second)
	for want > 0 && time.Now().Before(deadline) {
		mu.Lock()
		n := total
		mu.Unlock()
		if n >= want {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if total != want {
		t.Fatalf("records = %d, want %d", total, want)
	}
	return got
}

func repeatFrame(frame []byte, n int) [][]byte {
	frames := make([][]byte, n)
	for i := range frames {
		frames[i] = frame
	}
	return frames
}

// TestBpfMultiPointGatedTestRun pins the gated semantics on a real
// invocation (BPF_PROG_TEST_RUN of xdp_pass, which returns XDP_PASS and
// leaves the packet untouched):
//   - both filters match: --emit both gives an entry record followed by
//     an exit record in the same shard, same opaque packet id
//     (cpu << 48 | per-CPU sequence, increasing), both stamped with the
//     verdict, both carrying the input bytes; --emit entry / exit give
//     only that record.
//   - the exit filter fails (verdict is PASS, filter wants DROP): nothing.
//   - the entry filter fails (TCP wanted, UDP sent): nothing.
//   - the hold is consumed by every fexit: a UDP frame that matches
//     entry but not exit, followed by a TCP frame that matches exit but
//     not entry, emits nothing (a stale hold would pair them).
func TestBpfMultiPointGatedTestRun(t *testing.T) {
	const runs = 20
	udp := dsltest.BuildEthIPv4UDP(t, 1234, 6081, bytes.Repeat([]byte{0xab}, 32))
	tcp := dsltest.BuildEthIPv4TCP(t, 1234, 80)
	entry, exitPass := "eth/ipv4/udp[dport==6081]", "eth/ipv4/udp where action == XDP_PASS"

	t.Run("both", func(t *testing.T) {
		got := runGatedTestRun(t, entry, exitPass, EmitBoth, repeatFrame(udp, runs), 2*runs)
		pairs := 0
		for shard, pkts := range got {
			if len(pkts)%2 != 0 {
				t.Fatalf("shard %d: odd record count %d", shard, len(pkts))
			}
			var lastSeq uint64
			for i := 0; i < len(pkts); i += 2 {
				e, x := pkts[i], pkts[i+1]
				if e.Mode != 0 || x.Mode != 1 {
					t.Fatalf("shard %d pair %d: modes %d,%d, want entry(0) then exit(1)", shard, i/2, e.Mode, x.Mode)
				}
				if e.PacketID != x.PacketID {
					t.Errorf("shard %d pair %d: packet id entry=%#x exit=%#x, want equal", shard, i/2, e.PacketID, x.PacketID)
				}
				if cpu, seq := e.PacketID>>48, e.PacketID&(1<<48-1); cpu != uint64(shard) || seq <= lastSeq {
					t.Errorf("shard %d pair %d: packet id %#x, want cpu %d and a sequence above %d", shard, i/2, e.PacketID, shard, lastSeq)
				}
				lastSeq = e.PacketID & (1<<48 - 1)
				if e.Action != 2 || x.Action != 2 {
					t.Errorf("shard %d pair %d: actions %d,%d, want XDP_PASS(2) on both", shard, i/2, e.Action, x.Action)
				}
				if x.Timestamp.Before(e.Timestamp) {
					t.Errorf("shard %d pair %d: entry ts after exit ts", shard, i/2)
				}
				if !bytes.Equal(e.Data, udp) || !bytes.Equal(x.Data, udp) {
					t.Errorf("shard %d pair %d: entry/exit bytes differ from the input frame", shard, i/2)
				}
				pairs++
			}
		}
		if pairs != runs {
			t.Errorf("pairs = %d, want %d", pairs, runs)
		}
	})

	t.Run("entry-only", func(t *testing.T) {
		got := runGatedTestRun(t, entry, exitPass, EmitEntry, repeatFrame(udp, runs), runs)
		for shard, pkts := range got {
			for i, p := range pkts {
				if p.Mode != 0 || p.Action != 2 || p.PacketID == 0 || !bytes.Equal(p.Data, udp) {
					t.Errorf("shard %d record %d: mode=%d action=%d id=%#x len=%d, want entry image with verdict PASS", shard, i, p.Mode, p.Action, p.PacketID, len(p.Data))
				}
			}
		}
	})

	t.Run("exit-only", func(t *testing.T) {
		got := runGatedTestRun(t, entry, exitPass, EmitExit, repeatFrame(udp, runs), runs)
		for shard, pkts := range got {
			for i, p := range pkts {
				if p.Mode != 1 || p.Action != 2 || p.PacketID == 0 || !bytes.Equal(p.Data, udp) {
					t.Errorf("shard %d record %d: mode=%d action=%d id=%#x, want exit image with verdict PASS", shard, i, p.Mode, p.Action, p.PacketID)
				}
			}
		}
	})

	t.Run("exit-filter-miss", func(t *testing.T) {
		runGatedTestRun(t, entry, "eth/ipv4/udp where action == XDP_DROP", EmitBoth, repeatFrame(udp, runs), 0)
	})

	t.Run("entry-filter-miss", func(t *testing.T) {
		runGatedTestRun(t, "eth/ipv4/tcp", exitPass, EmitBoth, repeatFrame(udp, runs), 0)
	})

	t.Run("hold-consumed", func(t *testing.T) {
		var frames [][]byte
		for range runs / 2 {
			frames = append(frames, udp, tcp)
		}
		runGatedTestRun(t, entry, "eth/ipv4/tcp where action == XDP_PASS", EmitBoth, frames, 0)
	})
}
