package program

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
)

// TestBpfMultiPointLoad verifies that a gated entry + exit capture
// passes the verifier for every --emit form and attaches both probes.
func TestBpfMultiPointLoad(t *testing.T) {
	prog := loadDummyXDP(t)
	targets := []attach.Target{{Program: prog, FuncName: xdpFuncName, Type: ebpf.XDP}}
	cases := []struct {
		name, entry, exit string
		dsl               bool
		emit              Emit
	}{
		{"empty-both", "", "", false, EmitBoth},
		{"cbpf-both", "icmp", "icmp", false, EmitBoth},
		{"dsl-both", "eth/ipv4/icmp", "eth/ipv4/icmp where action == XDP_PASS", true, EmitBoth},
		{"dsl-entry", "eth/ipv4/udp[dport==6081]", "eth where action == XDP_DROP", true, EmitEntry},
		{"dsl-exit", "eth/ipv4/udp[dport==6081]", "eth/ipv4/tcp where action == XDP_DROP", true, EmitExit},
		{"no-entry-filter", "", "eth/ipv4/icmp where action == XDP_PASS", true, EmitEntry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stages := []Stage{{Expr: tc.entry}, {IsFexit: true, Expr: tc.exit}}
			probe, err := LoadMultiPoint(targets, stages, nil, tc.dsl, nil, tc.emit)
			if err != nil {
				t.Fatalf("LoadMultiPoint: %v", err)
			}
			defer func() { _ = probe.Close() }()
			if !probe.MultiPoint || !probe.IsFexit {
				t.Errorf("probe flags: MultiPoint=%v IsFexit=%v, want both true", probe.MultiPoint, probe.IsFexit)
			}
			if n := probe.AttachCount(); n != 2 {
				t.Errorf("AttachCount = %d, want 2 (fentry + fexit)", n)
			}
		})
	}
}

// icmpEchoFrame builds a minimal Ethernet/IPv4/ICMP echo request.
func icmpEchoFrame(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 1, Seq: 1}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(bytes.Repeat([]byte{0xab}, 32))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// runGatedTestRun attaches a gated capture to the dummy XDP program,
// fires it `runs` times through BPF_PROG_TEST_RUN with frame and
// returns the records per shard (in order) once `want` records arrived
// or the deadline passed.
func runGatedTestRun(t *testing.T, entry, exit string, emit Emit, frame []byte, runs, want int) map[int][]capture.Packet {
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

	for range runs {
		if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			t.Fatalf("test-run target: %v", err)
		}
	}
	// Wait for the expected count, then a little longer to catch strays
	// (the "nothing must be emitted" cases rely on that grace period).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := total
		mu.Unlock()
		if n >= want && want > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if total != want {
		t.Fatalf("records = %d, want %d", total, want)
	}
	return got
}

// TestMultiPointGatedTestRun pins the gated semantics on a real
// invocation (BPF_PROG_TEST_RUN of xdp_pass, which returns XDP_PASS and
// leaves the packet untouched):
//   - both filters match: --emit both gives an entry record followed by
//     an exit record in the same shard, same non-zero frame, both
//     stamped with the verdict, both carrying the input bytes;
//     --emit entry / exit give only that record.
//   - the exit filter fails (verdict is PASS, filter wants DROP): nothing.
//   - the entry filter fails (UDP wanted, ICMP sent): nothing.
func TestMultiPointGatedTestRun(t *testing.T) {
	const runs = 20
	frame := icmpEchoFrame(t)
	entry, exitPass := "eth/ipv4/icmp", "eth/ipv4/icmp where action == XDP_PASS"

	t.Run("both", func(t *testing.T) {
		got := runGatedTestRun(t, entry, exitPass, EmitBoth, frame, runs, 2*runs)
		pairs := 0
		for shard, pkts := range got {
			if len(pkts)%2 != 0 {
				t.Fatalf("shard %d: odd record count %d", shard, len(pkts))
			}
			for i := 0; i < len(pkts); i += 2 {
				e, x := pkts[i], pkts[i+1]
				if e.Mode != 0 || x.Mode != 1 {
					t.Fatalf("shard %d pair %d: modes %d,%d, want entry(0) then exit(1)", shard, i/2, e.Mode, x.Mode)
				}
				if e.Frame == 0 || e.Frame != x.Frame {
					t.Errorf("shard %d pair %d: frame entry=%#x exit=%#x, want equal and non-zero", shard, i/2, e.Frame, x.Frame)
				}
				if e.Action != 2 || x.Action != 2 {
					t.Errorf("shard %d pair %d: actions %d,%d, want XDP_PASS(2) on both", shard, i/2, e.Action, x.Action)
				}
				if x.Timestamp.Before(e.Timestamp) {
					t.Errorf("shard %d pair %d: entry ts after exit ts", shard, i/2)
				}
				if !bytes.Equal(e.Data, frame) || !bytes.Equal(x.Data, frame) {
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
		got := runGatedTestRun(t, entry, exitPass, EmitEntry, frame, runs, runs)
		for shard, pkts := range got {
			for i, p := range pkts {
				if p.Mode != 0 || p.Action != 2 || p.Frame == 0 || !bytes.Equal(p.Data, frame) {
					t.Errorf("shard %d record %d: mode=%d action=%d frame=%#x len=%d, want entry image with verdict PASS", shard, i, p.Mode, p.Action, p.Frame, len(p.Data))
				}
			}
		}
	})

	t.Run("exit-only", func(t *testing.T) {
		got := runGatedTestRun(t, entry, exitPass, EmitExit, frame, runs, runs)
		for shard, pkts := range got {
			for i, p := range pkts {
				if p.Mode != 1 || p.Action != 2 || p.Frame == 0 || !bytes.Equal(p.Data, frame) {
					t.Errorf("shard %d record %d: mode=%d action=%d frame=%#x, want exit image with verdict PASS", shard, i, p.Mode, p.Action, p.Frame)
				}
			}
		}
	})

	t.Run("exit-filter-miss", func(t *testing.T) {
		runGatedTestRun(t, entry, "eth/ipv4/icmp where action == XDP_DROP", EmitBoth, frame, runs, 0)
	})

	t.Run("entry-filter-miss", func(t *testing.T) {
		runGatedTestRun(t, "eth/ipv4/udp", exitPass, EmitBoth, frame, runs, 0)
	})
}
