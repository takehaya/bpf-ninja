package program

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
)

const cbpfDeepScratchFilter = "ip[1]-(ip[2]-(ip[3]-(ip[4]-(ip[5]-(ip[6]-(ip[7]-(ip[8]-(ip[9]-(ip[10]-(ip[11]-ip[12])))))))))) > 0"

// TestBpfCBPFScratchKeepsHostSlots runs cBPF filters that use scratch memory
// M[] and checks that the set tag and the fexit action the host saved before
// the filter are still the ones recorded after it.
func TestBpfCBPFScratchKeepsHostSlots(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	requireCBPF(t)
	o := dsltest.Defaults()
	o.Payload = make([]byte, 20) // IP total length 60 (0x3c)
	frame := dsltest.Build(t, o)
	// set_capture_pt's (imsi, teid) are the frame's first 12 bytes.
	imsi := binary.NativeEndian.Uint64(frame[0:8])
	ret := uint32((imsi + uint64(binary.NativeEndian.Uint32(frame[8:12]))) & 3)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_cbpfscratch_%d", os.Getpid())
	if err := setmap.Create(pin, "imsi:u64", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })
	def, err := setmap.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(def.Close)
	if err := def.Add(map[string]string{"imsi": fmt.Sprint(imsi)}, setmap.EntryValue{Tag: 0x77}); err != nil {
		t.Fatal(err)
	}
	prog := loadXDPByName(t, setTargetSrc, "xdp_set_target")
	params, err := attach.GetFuncParams(prog, "set_capture_pt")
	if err != nil {
		t.Fatal(err)
	}
	sf, err := filter.ResolveSetFilters([]*setmap.Set{{SpecRef: setmap.SpecRef{Name: "subs", Path: pin}, Def: def}}, []string{"subs"}, params)
	if err != nil {
		t.Fatal(err)
	}

	// libpcap puts these filters' scratch in M[1] and M[2]; at StackOffset 0
	// those are fp-8 (tag) and fp-12 (fexit action).
	const tagScratch = "tcp port 80 and (ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2) != 0"
	const actionScratch = "(ip[2:2] & 0xff) - (ip[3] & 0xf) > 0"
	targets := []attach.Target{{Program: prog, FuncName: "set_capture_pt", Type: ebpf.XDP}}
	for _, c := range []struct {
		name, expr string
		exit, set  bool
		tag        uint32
	}{
		{"entry/set", tagScratch, false, true, 0x77},
		{"entry/noset", tagScratch, false, false, 0},
		{"exit/set", actionScratch, true, true, 0x77},
	} {
		t.Run(c.name, func(t *testing.T) {
			var tfs []filter.TargetFilters
			if c.set {
				tfs = []filter.TargetFilters{{Sets: sf}}
			}
			load := LoadMultiEntry
			if c.exit {
				load = LoadMultiExit
			}
			probe, err := load(targets, c.expr, tfs, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = probe.Close() }()
			drain := collectShards(t, probe.InnerMaps)
			if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
				t.Fatal(err)
			}
			p := onlyRecord(t, drain())
			if p.Tag != c.tag {
				t.Errorf("tag %#x, want %#x", p.Tag, c.tag)
			}
			if c.exit && p.Action != ret {
				t.Errorf("action %d, want set_capture_pt's return %d", p.Action, ret)
			}
			if p.OrigLen != uint32(len(frame)) {
				t.Errorf("orig_len %d, want %d", p.OrigLen, len(frame))
			}
		})
	}
	for _, emit := range []Emit{EmitBoth, EmitExit} {
		t.Run(fmt.Sprintf("gated/emit=%d", emit), func(t *testing.T) {
			prev := SnaplenOverride
			SnaplenOverride = 48
			t.Cleanup(func() { SnaplenOverride = prev })
			// Exercise both the old tag collision and M[3] at the new fp-72.
			expr := tagScratch + " and (" + cbpfDeepScratchFilter + ")"
			out, err := compileFilter(expr, false, false, ebpf.XDP)
			if err != nil {
				t.Fatal(err)
			}
			stashUsed := false
			for _, ins := range out.Main {
				stashUsed = stashUsed || ins.OpCode.Class().IsStore() && ins.Dst == asm.R10 && ins.Offset == gatedOrigLenStash
			}
			if !stashUsed {
				t.Fatal("cBPF filter does not exercise fp-72")
			}
			probe, err := LoadMultiPoint(targets, []Stage{{Expr: expr}, {Expr: expr, IsFexit: true}}, []filter.TargetFilters{{Sets: sf}}, false, nil, emit)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = probe.Close() }()
			drain := collectShards(t, probe.InnerMaps)
			if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
				t.Fatal(err)
			}
			if err := probe.Barrier(); err != nil {
				t.Fatal(err)
			}
			pkts := flatten(drain())
			want := 1
			if emit == EmitBoth {
				want = 2
			}
			if len(pkts) != want {
				t.Fatalf("%d records, want %d", len(pkts), want)
			}
			for i, p := range pkts {
				if p.Tag != 0x77 || p.OrigLen != uint32(len(frame)) || p.CapLen != 48 || p.Action != ret {
					t.Errorf("record %d: tag=%#x orig_len=%d caplen=%d action=%d, want %#x/%d/48/%d", i, p.Tag, p.OrigLen, p.CapLen, p.Action, 0x77, len(frame), ret)
				}
				if i == len(pkts)-1 && p.Mode != 1 {
					t.Errorf("last record mode=%d, want exit (1)", p.Mode)
				}
			}
		})
	}
	t.Run("xdp-native/noset", func(t *testing.T) {
		native, ring, _ := loadXDPNative(t, tagScratch, false)
		drain := collectShards(t, []*ebpf.Map{ring})
		if _, err := native.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			t.Fatal(err)
		}
		if p := onlyRecord(t, drain()); p.Tag != 0 {
			t.Errorf("tag %#x, want 0", p.Tag)
		}
	})
}

// onlyRecord returns the single record across all shards.
func onlyRecord(t *testing.T, shards map[int][]capture.Packet) capture.Packet {
	t.Helper()
	var all []capture.Packet
	for _, pkts := range shards {
		all = append(all, pkts...)
	}
	if len(all) != 1 {
		t.Fatalf("%d records, want 1", len(all))
	}
	return all[0]
}
