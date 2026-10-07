package program

// End-to-end check of the tc host's wire-frame copy: the kernel moves the
// outer VLAN tag into skb metadata before the tc program runs, and the
// observer puts it back into the filter's scratch copy (hook.OuterVlanTag
// + wireFrameCopy), so a filter written against the frame on the wire
// matches at tc. A veth pair carries hand-built frames to a tc program at
// tcx (or clsact) ingress; probes on that program (fentry, fexit, gated
// entry+exit) count the captures.
//
// Root + veth + tcx required; skipped otherwise.

import (
	"slices"
	"sync/atomic"
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
			for name, frame := range frames {
				want := slices.Contains(tc.match, name)
				got := captureCount(t, tc.load, tc.expr, ifindex, frame) > 0
				if got != want {
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
	if old, err := netlink.LinkByName("kxwire0"); err == nil {
		_ = netlink.LinkDel(old) // left behind by an interrupted run
	}
	la := netlink.NewLinkAttrs()
	la.Name = "kxwire0"
	veth := &netlink.Veth{LinkAttrs: la, PeerName: "kxwire1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("veth unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	v0, err := netlink.LinkByName("kxwire0")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	v1, err := netlink.LinkByName("kxwire1")
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

// captureCount loads a probe with load(expr), sends the frame out
// ifindex, and counts the captures.
func captureCount(t *testing.T, load func(string) (*Probe, error), expr string, ifindex int, frame []byte) int {
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
	var count atomic.Int64
	stop, err := sr.RunShards(func(_ int, pkts []capture.Packet) error {
		count.Add(int64(len(pkts)))
		return nil
	})
	if err != nil {
		t.Fatalf("RunShards: %v", err)
	}
	defer stop()
	time.Sleep(100 * time.Millisecond)
	sendFrame(t, ifindex, frame)
	time.Sleep(300 * time.Millisecond)
	return int(count.Load())
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
