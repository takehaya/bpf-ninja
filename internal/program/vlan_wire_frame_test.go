package program

// End-to-end check of the tc host's wire-frame copy: the kernel moves the
// outer VLAN tag into skb metadata before the tc program runs, and with
// TCVlanReinsert the observer puts it back into the filter's scratch copy
// (hook.OuterVlanTag + wireFrameCopy), so a filter written against the
// frame on the wire matches at tc. The default cases check the bytes as
// the kernel holds them. A veth pair carries hand-built frames to a tc program at
// tcx (or clsact) ingress; probes on that program (fentry, fexit, gated
// entry+exit) count the captures.
//
// Root + veth + tcx required; skipped otherwise.

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// asmTCFuncName names loadAsmTC's program; the probe attaches to it.
const asmTCFuncName = "tc_wire_test"

// loadAsmTC loads a SchedCLS program that returns TC_ACT_OK, built from
// instructions with BTF func info (so fentry can attach to it) rather
// than from C, so the test needs no BPF compiler.
func loadAsmTC(t *testing.T) *ebpf.Program {
	t.Helper()
	fn := &btf.Func{
		Name: asmTCFuncName,
		Type: &btf.FuncProto{
			Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
			Params: []btf.FuncParam{{Name: "skb", Type: &btf.Pointer{Target: &btf.Struct{Name: "__sk_buff"}}}},
		},
		Linkage: btf.GlobalFunc,
	}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0), fn).WithSymbol(asmTCFuncName),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: asmTCFuncName, Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
	if err != nil {
		t.Fatalf("load tc program: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return prog
}

func TestBpfVlanWireFrameAtTC(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	tcProg := loadAsmTC(t)
	ifindex := wireTestVeth(t, tcProg)

	frames := map[string][]byte{
		"untagged": untaggedIPv4TCP(),
		"vid100":   vlanTaggedIPv4TCP(100),
		"vid200":   vlanTaggedIPv4TCP(200),
		"qinq":     qinqTaggedIPv4TCP(10, 100),
	}
	entry := func(expr string) (*Probe, error) { return LoadEntry(tcProg, asmTCFuncName, expr, nil, true) }
	exit := func(expr string) (*Probe, error) { return LoadExit(tcProg, asmTCFuncName, expr, nil, true) }
	gated := func(expr string) (*Probe, error) {
		targets := []attach.Target{{Program: tcProg, FuncName: asmTCFuncName, Type: ebpf.SchedCLS}}
		return LoadMultiPoint(targets, []Stage{{Expr: expr}, {Expr: expr, IsFexit: true}}, nil, true, nil, EmitBoth)
	}
	pcap := func(expr string) (*Probe, error) { return LoadEntry(tcProg, asmTCFuncName, expr, nil, false) }
	for _, tc := range []struct {
		name  string
		load  func(string) (*Probe, error)
		expr  string
		match []string // frames the filter matches; the others must not
	}{
		// Default: the bytes as the kernel holds them. The outer tag is not
		// there, so eth/ipv4/tcp matches a single-tagged frame too.
		{"default", entry, "eth/ipv4/tcp[dport==80]", []string{"untagged", "vid100", "vid200"}},
		{"default", entry, "eth/vlan?/ipv4/tcp[dport==80]", []string{"untagged", "vid100", "vid200", "qinq"}},
		{"default-exit", exit, "eth/ipv4/tcp where action == TC_ACT_OK", []string{"untagged", "vid100", "vid200"}},
		{"default-gated", gated, "eth/ipv4/tcp[dport==80]", []string{"untagged", "vid100", "vid200"}},
		{"entry", entry, "eth/vlan[tci==100]/ipv4/tcp[dport==80]", []string{"vid100"}},
		{"entry", entry, "eth/vlan/ipv4/tcp where vlan.tci == 200", []string{"vid200"}},
		{"entry", entry, "eth/ipv4/tcp[dport==80]", []string{"untagged"}},
		{"entry", entry, "eth/vlan?/ipv4/tcp[dport==80]", []string{"untagged", "vid100", "vid200"}},
		{"entry", entry, "eth/qinq[tci==10]/vlan[tci==100]/ipv4/tcp", []string{"qinq"}},
		{"entry", entry, "eth/qinq?/vlan?/ipv4/tcp", []string{"untagged", "vid100", "vid200", "qinq"}},
		// A chain shorter than the 16 bytes up to the end of the tag.
		{"entry", entry, "eth[ethertype==0x8100]", []string{"vid100", "vid200"}},
		{"exit", exit, "eth/vlan[tci==100]/ipv4/tcp where action == TC_ACT_OK", []string{"vid100"}},
		{"gated", gated, "eth/qinq[tci==10]/vlan[tci==100]/ipv4/tcp", []string{"qinq"}},
		// A pcap filter reads the bytes as the kernel holds them (the tag
		// is not put back), as before.
		{"pcap", pcap, "tcp dst port 80", []string{"untagged", "vid100", "vid200"}},
	} {
		t.Run(tc.name+"/"+tc.expr, func(t *testing.T) {
			// Every case but the "default" ones runs with the tag put back.
			prev := TCVlanReinsert
			TCVlanReinsert = !strings.HasPrefix(tc.name, "default")
			t.Cleanup(func() { TCVlanReinsert = prev })
			for name, frame := range frames {
				want := slices.Contains(tc.match, name)
				pkts := capturePackets(t, tc.load, tc.expr, ifindex, frame)
				if got := len(pkts) > 0; got != want {
					t.Errorf("frame %s: captured=%v, want %v", name, got, want)
				}
				// Captured bytes are the kernel's in both modes: a
				// single-tagged frame shows its inner ethertype at 12.
				for _, p := range pkts {
					if (name == "vid100" || name == "vid200") && (len(p.Data) < 14 || p.Data[12] != 0x08 || p.Data[13] != 0x00) {
						t.Errorf("frame %s: captured bytes % x; want the outer tag absent (ethertype 0x0800 at 12)", name, p.Data[:min(len(p.Data), 16)])
					}
				}
			}
		})
	}
}

// TestBpfVlanWireFrameAtTCEdges covers two corners of wireFrameCopy that
// TestBpfVlanWireFrameAtTC does not reach: a priority tag (VID 0), which
// is a tag in metadata although its TCI is zero, and a field in the last
// bytes of the frame, which the copy after the inserted tag must reach.
func TestBpfVlanWireFrameAtTCEdges(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	tcProg := loadAsmTC(t)
	ifindex := wireTestVeth(t, tcProg)
	prev := TCVlanReinsert
	TCVlanReinsert = true
	t.Cleanup(func() { TCVlanReinsert = prev })

	urg := vlanTaggedIPv4TCP(100)
	urg[len(urg)-2], urg[len(urg)-1] = 0x12, 0x34 // tcp urgent_ptr
	frames := map[string][]byte{
		"untagged": untaggedIPv4TCP(),
		"vid0":     vlanTaggedIPv4TCP(0),
		"urg":      urg,
	}
	entry := func(expr string) (*Probe, error) { return LoadEntry(tcProg, asmTCFuncName, expr, nil, true) }
	for _, tc := range []struct {
		expr  string
		match []string
	}{
		{"eth/vlan[tci==0]/ipv4/tcp[dport==80]", []string{"vid0"}},
		{"eth/vlan/ipv4/tcp[urgent_ptr==0x1234]", []string{"urg"}},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			for name, frame := range frames {
				want := slices.Contains(tc.match, name)
				if got := len(capturePackets(t, entry, tc.expr, ifindex, frame)) > 0; got != want {
					t.Errorf("frame %s: captured=%v, want %v", name, got, want)
				}
			}
		})
	}
}

// wireTestVeth creates a veth pair, attaches tcProg at ingress of the
// receiving end (tcx, or a clsact filter on kernels without tcx) and
// returns the sending end's ifindex.
func wireTestVeth(t *testing.T, tcProg *ebpf.Program) int {
	t.Helper()
	// Names carry the pid so concurrent runs on one host do not collide.
	name0, name1 := fmt.Sprintf("kxw%da", os.Getpid()%100000), fmt.Sprintf("kxw%db", os.Getpid()%100000)
	if old, err := netlink.LinkByName(name0); err == nil {
		_ = netlink.LinkDel(old) // left behind by an interrupted run
	}
	la := netlink.NewLinkAttrs()
	la.Name = name0
	veth := &netlink.Veth{LinkAttrs: la, PeerName: name1}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("veth unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	v0, err := netlink.LinkByName(name0)
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	v1, err := netlink.LinkByName(name1)
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	for _, l := range []netlink.Link{v0, v1} {
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("LinkSetUp: %v", err)
		}
	}
	idx := v1.Attrs().Index
	if lnk, err := link.AttachTCX(link.TCXOptions{Interface: idx, Program: tcProg, Attach: ebpf.AttachTCXIngress}); err == nil {
		t.Cleanup(func() { _ = lnk.Close() })
		return v0.Attrs().Index
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{LinkIndex: idx, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT},
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		t.Skipf("neither tcx nor clsact available (%v)", err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  netlink.FilterAttrs{LinkIndex: idx, Parent: netlink.HANDLE_MIN_INGRESS, Handle: 1, Protocol: unix.ETH_P_ALL, Priority: 1},
		Fd:           tcProg.FD(),
		Name:         asmTCFuncName,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		t.Fatalf("clsact filter: %v", err)
	}
	return v0.Attrs().Index
}

// capturePackets loads a probe with load(expr), sends the frame out
// ifindex, and returns the captures.
func capturePackets(t *testing.T, load func(string) (*Probe, error), expr string, ifindex int, frame []byte) []capture.Packet {
	t.Helper()
	probe, err := load(expr)
	if err != nil {
		t.Fatalf("load probe %q: %v", expr, err)
	}
	defer func() { _ = probe.Close() }()
	sr, err := capture.NewShardedReader(probe.InnerMaps)
	if err != nil {
		t.Fatalf("sharded reader: %v", err)
	}
	var mu sync.Mutex
	var got []capture.Packet
	stop, err := sr.RunShards(func(_ int, pkts []capture.Packet) error {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range pkts {
			p.Data = append([]byte(nil), p.Data...)
			got = append(got, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RunShards: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	sendFrame(t, ifindex, frame)
	time.Sleep(300 * time.Millisecond)
	stop()
	mu.Lock()
	defer mu.Unlock()
	return got
}

// qinqTaggedIPv4TCP builds eth(0x88a8)/qinq(svid)/vlan(cvid)/ipv4/tcp:80.
func qinqTaggedIPv4TCP(svid, cvid uint16) []byte {
	f := []byte{
		0x02, 0, 0, 0, 0, 0x01,
		0x02, 0, 0, 0, 0, 0x02,
		0x88, 0xa8, byte(svid >> 8), byte(svid),
		0x81, 0x00, byte(cvid >> 8), byte(cvid),
		0x08, 0x00,
	}
	return append(f, ipv4TCP()...)
}
