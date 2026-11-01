package program

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
)

// TestBpfOrigLen captures a 1500-byte frame with a 128-byte snaplen on each
// capture path (fentry and fexit at XDP and tc, fentry at cgroup-skb and
// netfilter, gated entry + exit for each --emit, XDP-native) and writes the
// records to pcapng: every EPB must have captured length 128 and the
// packet's length as original length. BPF_PROG_TEST_RUN of a cgroup-skb or
// netfilter program starts the skb at L3, so their packet is 14 bytes
// shorter.
func TestBpfOrigLen(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const snap, wire = 128, 1500
	prev := SnaplenOverride
	SnaplenOverride = snap
	t.Cleanup(func() { SnaplenOverride = prev })
	frame := dsltest.BuildEthIPv4UDP(t, 1234, 6081, make([]byte, wire-42))
	if len(frame) != wire {
		t.Fatalf("frame is %d bytes, want %d", len(frame), wire)
	}

	single := func(load func(testing.TB) *ebpf.Program, name, expr string, data []byte, fexit bool) func(*testing.T) []capture.Packet {
		return func(t *testing.T) []capture.Packet {
			prog := load(t)
			probe := loadProbeOrFail(t, prog, name, expr, fexit, true)
			drain := collectShards(t, probe.InnerMaps)
			if _, err := prog.Run(&ebpf.RunOptions{Data: data}); err != nil {
				t.Fatal(err)
			}
			if err := probe.Barrier(); err != nil {
				t.Fatal(err)
			}
			return flatten(drain())
		}
	}
	gated := func(emit Emit, want int) func(*testing.T) []capture.Packet {
		return func(t *testing.T) []capture.Packet {
			return flatten(runGatedTestRun(t, "eth/ipv4/udp", "eth/ipv4/udp", emit, [][]byte{frame}, want))
		}
	}
	native := func(t *testing.T) []capture.Packet {
		out, err := compileFilter("eth/ipv4/udp", true, false, ebpf.XDP)
		if err != nil {
			t.Fatal(err)
		}
		out.Capture.MaxCapLen = snap
		outer, inners, err := createShardedRingbuf("origlen")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = outer.Close()
			for _, m := range inners {
				_ = m.Close()
			}
		})
		probe := &Probe{}
		if err := probe.initExportStats(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = probe.Close() })
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name: "bpfninja_origln", Type: ebpf.XDP, License: "GPL",
			Instructions: buildXDPNativeInsns(out, outer.FD(), nil, 0, probe.StatsMap.FD()),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = prog.Close() })
		drain := collectShards(t, inners)
		if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			t.Fatal(err)
		}
		return flatten(drain())
	}

	for _, c := range []struct {
		name string
		want int
		orig uint32
		run  func(*testing.T) []capture.Packet
	}{
		{"xdp-fentry", 1, wire, single(loadDummyXDP, xdpFuncName, "eth/ipv4/udp", frame, false)},
		{"xdp-fexit", 1, wire, single(loadDummyXDP, xdpFuncName, "eth/ipv4/udp", frame, true)},
		{"tc-fentry", 1, wire, single(loadDummyTC, tcFuncName, "eth/ipv4/udp", frame, false)},
		{"tc-fexit", 1, wire, single(loadDummyTC, tcFuncName, "eth/ipv4/udp", frame, true)},
		{"cgroup-skb-fentry", 1, wire - 14, single(loadDummyCgroupSKB, cgroupSKBFuncName, "ipv4/udp", frame, false)},
		{"netfilter-fentry", 1, wire - 14, single(loadDummyNetfilter, netfilterFuncName, "ipv4/udp", frame[14:], false)},
		{"gated-both", 2, wire, gated(EmitBoth, 2)},
		{"gated-entry", 1, wire, gated(EmitEntry, 1)},
		{"gated-exit", 1, wire, gated(EmitExit, 1)},
		{"xdp-native", 1, wire, native},
	} {
		t.Run(c.name, func(t *testing.T) {
			pkts := c.run(t)
			if len(pkts) != c.want {
				t.Fatalf("%d records, want %d", len(pkts), c.want)
			}
			for i, p := range pkts {
				if len(p.Data) != snap || p.OrigLen != c.orig {
					t.Errorf("record %d: caplen %d orig_len %d, want %d and %d", i, len(p.Data), p.OrigLen, snap, c.orig)
				}
			}
			path := filepath.Join(t.TempDir(), "out.pcapng")
			w, err := output.NewWriter(path, output.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if err := w.WriteBatch(pkts); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for ; ; n++ {
				_, ci, err := r.ReadPacketData()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if ci.CaptureLength != snap || ci.Length != int(c.orig) {
					t.Errorf("EPB %d: captured %d original %d, want %d and %d", n, ci.CaptureLength, ci.Length, snap, c.orig)
				}
			}
			if n != c.want {
				t.Errorf("%d EPBs, want %d", n, c.want)
			}
		})
	}
}

// TestBpfOrigLenXDPFrags pins a known limit: at a frags-aware XDP target,
// orig_len counts only the linear part (the shortcut in hook.xdpPacketPrologue).
func TestBpfOrigLenXDPFrags(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const wire = 9000
	prev := SnaplenOverride
	SnaplenOverride = wire
	t.Cleanup(func() { SnaplenOverride = prev })
	ctx := &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}
	fn := &btf.Func{Name: "xdp_frags_t", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: []btf.FuncParam{{Name: "ctx", Type: ctx}}}}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "xdp_frags_t", Type: ebpf.XDP, License: "GPL", Flags: unix.BPF_F_XDP_HAS_FRAGS,
		Instructions: asm.Instructions{btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 2).WithSymbol(fn.Name), fn), asm.Return()}})
	if err != nil {
		t.Skipf("frags-aware XDP target: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	probe := loadProbeOrFail(t, prog, fn.Name, "", false, true)
	drain := collectShards(t, probe.InnerMaps)
	if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, wire)}); err != nil {
		t.Skipf("test run of a %d-byte frame: %v", wire, err)
	}
	if err := probe.Barrier(); err != nil {
		t.Fatal(err)
	}
	pkts := flatten(drain())
	if len(pkts) != 1 {
		t.Fatalf("%d records, want 1", len(pkts))
	}
	if p := pkts[0]; len(p.Data) >= wire || p.OrigLen != uint32(len(p.Data)) {
		t.Fatalf("caplen %d orig_len %d: want both the linear length, below %d", len(p.Data), p.OrigLen, wire)
	}
}

func flatten(shards map[int][]capture.Packet) []capture.Packet {
	var out []capture.Packet
	for _, pkts := range shards {
		out = append(out, pkts...)
	}
	return out
}
