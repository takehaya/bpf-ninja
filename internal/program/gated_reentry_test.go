package program

import (
	"encoding/binary"
	"maps"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
)

const reentryFuncName = "tc_reentry_test"

// skbMarkOff is offsetof(struct __sk_buff, mark).
const skbMarkOff = 8

// loadReentryTC loads a SchedCLS program that re-enters itself through
// bpf_clone_redirect: an invocation that sees skb->mark == m < levels
// sets mark = m+1 and the IPv4 TOS byte to m, clones the packet to the
// egress of ifindex (where this same program is attached, so the clone
// runs it again synchronously inside dev_queue_xmit) and returns
// TC_ACT_SHOT; at m == levels it returns TC_ACT_OK unchanged. A packet
// started with mark 1 and TOS 0 therefore runs the program `levels`
// times, nested, and the invocation at depth d sees TOS d at entry.
func loadReentryTC(t *testing.T, ifindex, levels int) *ebpf.Program {
	t.Helper()
	fn := &btf.Func{
		Name: reentryFuncName,
		Type: &btf.FuncProto{
			Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
			Params: []btf.FuncParam{{Name: "skb", Type: &btf.Pointer{Target: &btf.Struct{Name: "__sk_buff"}}}},
		},
		Linkage: btf.GlobalFunc,
	}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1), fn).WithSymbol(reentryFuncName),
		asm.LoadMem(asm.R7, asm.R6, skbMarkOff, asm.Word),
		asm.JEq.Imm(asm.R7, 0, "pass"),
		asm.JGE.Imm(asm.R7, int32(levels), "pass"),
		asm.StoreMem(asm.R10, -8, asm.R7, asm.Byte), // new TOS = m
		asm.Add.Imm(asm.R7, 1),
		asm.StoreMem(asm.R6, skbMarkOff, asm.R7, asm.Word),
		// bpf_skb_store_bytes(skb, 15, &tos, 1, 0)
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 15),
		asm.Mov.Reg(asm.R3, asm.R10), asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R4, 1),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		// bpf_clone_redirect(skb, ifindex, 0): egress, synchronous
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, int32(ifindex)),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnCloneRedirect.Call(),
		asm.Mov.Imm(asm.R0, 2), // TC_ACT_SHOT
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("pass"), // TC_ACT_OK
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: reentryFuncName, Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
	if err != nil {
		t.Fatalf("load tc program: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return prog
}

// reentryNetns moves the calling test goroutine, locked to its thread,
// into a new network namespace and returns the ifindex of its loopback
// device, brought up. BPF_PROG_RUN gives the skb that namespace's
// loopback device, so the clone and the egress attach stay inside it and
// no host traffic reaches the program.
func reentryNetns(t *testing.T) int {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("current netns: %v", err)
	}
	ns, err := netns.New()
	if err != nil {
		_ = orig.Close()
		runtime.UnlockOSThread()
		t.Fatalf("new netns: %v", err)
	}
	t.Cleanup(func() {
		if err := netns.Set(orig); err != nil {
			t.Errorf("restoring netns: %v", err)
			return // leave the thread locked: it is still in the test namespace
		}
		_ = ns.Close()
		_ = orig.Close()
		runtime.UnlockOSThread()
	})
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("LinkByName(lo): %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("LinkSetUp(lo): %v", err)
	}
	return lo.Attrs().Index
}

func attachReentryEgress(t *testing.T, idx int, prog *ebpf.Program) {
	t.Helper()
	if lnk, err := link.AttachTCX(link.TCXOptions{Interface: idx, Program: prog, Attach: ebpf.AttachTCXEgress}); err == nil {
		t.Cleanup(func() { _ = lnk.Close() })
		return
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{LinkIndex: idx, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT},
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		t.Skipf("neither tcx nor clsact available (%v)", err)
	}
	f := &netlink.BpfFilter{
		FilterAttrs:  netlink.FilterAttrs{LinkIndex: idx, Parent: netlink.HANDLE_MIN_EGRESS, Handle: 1, Protocol: unix.ETH_P_ALL, Priority: 1},
		Fd:           prog.FD(),
		Name:         reentryFuncName,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(f); err != nil {
		t.Fatalf("clsact filter: %v", err)
	}
}

// reentryInvocation is the ground truth of one invocation at depth d of
// a nest of `levels` invocations (see loadReentryTC).
type reentryInvocation struct {
	entryTOS, exitTOS byte
	verdict           uint32
}

func reentryTruth(levels, d int) reentryInvocation {
	if d == levels-1 {
		return reentryInvocation{byte(d), byte(d), 0}
	}
	return reentryInvocation{byte(d), byte(d + 1), 2}
}

type reentryResult struct {
	pairs map[int]int // depth (from the entry TOS) -> pairs emitted
	stats ExportStats
}

// runGatedReentry captures `runs` nests of `levels` invocations with a
// gated EmitBoth probe and checks every emitted pair against the ground
// truth: entry and exit records joined by packet id must belong to the
// same invocation (entry TOS, exit TOS and verdict all agree).
func runGatedReentry(t *testing.T, levels, runs int, entryExpr string, prepare func(*testing.T, *Probe)) reentryResult {
	t.Helper()
	idx := reentryNetns(t)
	pinTest(t, affinityCPUs(t)[0]) // every nest on one CPU (one hold set)
	prog := loadReentryTC(t, idx, levels)
	attachReentryEgress(t, idx, prog)

	targets := []attach.Target{{Program: prog, FuncName: reentryFuncName, Type: ebpf.SchedCLS}}
	probe, err := LoadMultiPoint(targets, []Stage{{Expr: entryExpr}, {Expr: "eth", IsFexit: true}}, nil, true, nil, EmitBoth)
	if err != nil {
		t.Fatalf("load gated probe: %v", err)
	}
	defer func() { _ = probe.Close() }()
	if prepare != nil {
		prepare(t, probe)
	}

	frame := dsltest.BuildEthIPv4UDP(t, 1234, 6081, []byte{1, 2, 3, 4})
	if frame[15] != 0 {
		t.Fatalf("fixture frame TOS = %#x, want 0", frame[15])
	}
	ctx := [3]uint32{0, 0, 1} // __sk_buff len, pkt_type, mark = 1
	for range runs {
		ret, err := prog.Run(&ebpf.RunOptions{Data: frame, Context: ctx})
		if err != nil {
			t.Fatalf("prog run: %v", err)
		}
		want := reentryTruth(levels, 0).verdict
		if ret != want {
			t.Fatalf("outer verdict %d, want %d", ret, want)
		}
	}
	if err := probe.Quiesce(); err != nil {
		t.Fatal(err)
	}

	byID := map[uint64][]capture.Packet{}
	for _, m := range probe.InnerMaps {
		r, err := fastrb.New(m.FD(), int(m.MaxEntries()))
		if err != nil {
			t.Fatal(err)
		}
		r.ReadBatch(func(raw []byte) {
			p, err := capture.ParseRawSample(raw)
			if err != nil {
				t.Errorf("parse record: %v", err)
				return
			}
			p.Data = append([]byte(nil), p.Data...)
			byID[p.PacketID] = append(byID[p.PacketID], p)
		})
		_ = r.Close()
	}
	res := reentryResult{pairs: map[int]int{}}
	for id, recs := range byID {
		if len(recs) != 2 || recs[0].Mode != 0 || recs[1].Mode != 1 {
			t.Errorf("packet id %#x: records %d (modes %v), want one entry then one exit", id, len(recs), modes(recs))
			continue
		}
		entry, exit := recs[0], recs[1]
		if len(entry.Data) < 16 || len(exit.Data) < 16 {
			t.Errorf("packet id %#x: short records", id)
			continue
		}
		d := int(entry.Data[15])
		truth := reentryTruth(levels, d)
		if d >= levels || exit.Data[15] != truth.exitTOS || exit.Action != truth.verdict || entry.Action != truth.verdict {
			t.Errorf("packet id %#x: wrong pairing: entry TOS %d, exit TOS %d, verdict %d/%d; truth for depth %d is exit TOS %d verdict %d",
				id, d, exit.Data[15], entry.Action, exit.Action, d, truth.exitTOS, truth.verdict)
			continue
		}
		res.pairs[d]++
	}
	res.stats, err = probe.ExportStats()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func modes(recs []capture.Packet) []uint8 {
	var out []uint8
	for _, r := range recs {
		out = append(out, r.Mode)
	}
	return out
}

// TestBpfGatedReentry re-enters the target synchronously (nested
// invocations through bpf_clone_redirect) under a gated capture. Every
// invocation selected by both filters is either emitted as a correct
// pair or counted as lost; a missing pair is never silent.
func TestBpfGatedReentry(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const runs = 20
	all := func(levels int) map[int]int {
		m := map[int]int{}
		for d := range levels {
			m[d] = runs
		}
		return m
	}
	for _, tc := range []struct {
		name      string
		prepare   func(*testing.T, *Probe)
		slots     int
		levels    int
		entryExpr string
		pairs     map[int]int
		overflow  uint64
	}{
		// No re-entry: the baseline pairs every invocation.
		{"flat", nil, holdSlots, 1, "eth/ipv4", all(1), 0},
		// Stopped holds: nothing is held, so nothing is emitted or lost.
		{"stopped", stopHolds, holdSlots, 2, "eth/ipv4", map[int]int{}, 0},
		// Each depth has its own hold: both invocations pair.
		{"both", nil, holdSlots, 2, "eth/ipv4", all(2), 0},
		{"outer-only", nil, holdSlots, 2, "eth/ipv4[diffserv==0]", map[int]int{0: runs}, 0},
		{"inner-only", nil, holdSlots, 2, "eth/ipv4[diffserv==1]", map[int]int{1: runs}, 0},
		// The deepest nest the kernel's xmit recursion limit allows fits the
		// default slots: asking for two more levels adds none.
		{"deepest", nil, holdSlots, holdSlots + 2, "eth/ipv4", all(holdSlots), 0},
		// Past the last slot an invocation is counted, not held; the
		// shallower ones still pair.
		{"overflow", nil, 2, 4, "eth/ipv4", all(2), 2 * runs},
		{"overflow-unselected", nil, 2, 4, "eth/ipv4[diffserv==0]", map[int]int{0: runs}, 0},
		// Every depth left open by skipped fexits: the first fentry finds
		// the depth stale, restarts it, and the nests pair as usual.
		{"stale-depth", leakDepth, holdSlots, 2, "eth/ipv4", all(2), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := holdSlots
			holdSlots = tc.slots
			t.Cleanup(func() { holdSlots = prev })
			res := runGatedReentry(t, tc.levels, runs, tc.entryExpr, tc.prepare)
			s := res.stats
			resync := uint64(0)
			if tc.name == "stale-depth" {
				resync = 1 // once, on the CPU that ran the nests
			}
			if !maps.Equal(res.pairs, tc.pairs) || s.HoldOverflow != tc.overflow || s.HoldResync != resync || s.HoldOverwrite+s.HoldUnpaired != 0 {
				t.Fatalf("pairs by depth %v, stats %+v; want pairs %v, hold_depth_overflow %d, hold_depth_resync %d and no other hold loss",
					res.pairs, s, tc.pairs, tc.overflow, resync)
			}
			emitted := 0
			for _, n := range res.pairs {
				emitted += n
			}
			if s.Submitted != uint64(2*emitted) || s.ReserveFail+s.LookupMiss+s.CopyFail != 0 {
				t.Fatalf("export stats %+v for %d pairs", s, emitted)
			}
		})
	}
}

// stopHolds does what Quiesce does before detaching: no fentry writes a
// hold.
func stopHolds(t *testing.T, p *Probe) {
	if err := p.holdStop.Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

// leakDepth leaves every CPU's depth past the last slot with entry times
// long past, as fexits skipped by trampoline rewrites would.
func leakDepth(t *testing.T, p *Probe) {
	var values [][]byte
	if err := p.holdMap.Lookup(uint32(0), &values); err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		binary.NativeEndian.PutUint32(v[holdDepth:], uint32(holdSlots+3)) // past the slots too
	}
	if err := p.holdMap.Update(uint32(0), values, ebpf.UpdateExist); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // more than one jiffy at any HZ
}
