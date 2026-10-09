package program

// The egress side of TestBpfVlanWireFrameAtTC. At tc egress the outer tag
// is in skb metadata when the frame comes from a VLAN device (the vlan
// driver puts it there; the real device inserts it into the bytes only
// after the tc hook), but a tagged frame written to a packet socket keeps
// its tag in the bytes. The filter must see the frame as on the wire in
// both cases once TCVlanReinsert is set: wireFrameCopy inserts the tag
// from metadata when there is one and copies the bytes unchanged
// otherwise.
//
// Root + veth + vlan + tcx (or clsact) required; skipped otherwise.

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfVlanWireFrameAtTCEgress(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	tcProg := loadAsmTC(t)
	direct, vlanDev := wireTestVethEgress(t, tcProg)

	// Each frame is sent out the interface named with it. "vlandev" goes
	// through the VLAN device (tag in metadata at the hook), "socket" is
	// written already tagged (tag in the bytes at the hook).
	type sent struct {
		ifindex int
		frame   []byte
	}
	frames := map[string]sent{
		"untagged": {direct, untaggedIPv4TCP()},
		"vlandev":  {vlanDev, untaggedIPv4TCP()},
		"socket":   {direct, vlanTaggedIPv4TCP(100)},
	}
	entry := func(expr string) (*Probe, error) { return LoadEntry(tcProg, asmTCFuncName, expr, nil, true) }
	exit := func(expr string) (*Probe, error) { return LoadExit(tcProg, asmTCFuncName, expr, nil, true) }
	for _, tc := range []struct {
		name  string
		load  func(string) (*Probe, error)
		expr  string
		match []string
	}{
		// Default: the bytes as the kernel holds them.
		{"default", entry, "eth/ipv4/tcp[dport==80]", []string{"untagged", "vlandev"}},
		{"default", entry, "eth/vlan?/ipv4/tcp[dport==80]", []string{"untagged", "vlandev", "socket"}},
		// With the tag put back, both tagged paths look the same.
		{"entry", entry, "eth/vlan[tci==100]/ipv4/tcp[dport==80]", []string{"vlandev", "socket"}},
		{"entry", entry, "eth/ipv4/tcp[dport==80]", []string{"untagged"}},
		{"exit", exit, "eth/vlan[tci==100]/ipv4/tcp where action == TC_ACT_OK", []string{"vlandev", "socket"}},
	} {
		t.Run(tc.name+"/"+tc.expr, func(t *testing.T) {
			prev := TCVlanReinsert
			TCVlanReinsert = !strings.HasPrefix(tc.name, "default")
			t.Cleanup(func() { TCVlanReinsert = prev })
			for name, s := range frames {
				want := slices.Contains(tc.match, name)
				pkts := capturePackets(t, tc.load, tc.expr, s.ifindex, s.frame)
				if got := len(pkts) > 0; got != want {
					t.Errorf("frame %s: captured=%v, want %v", name, got, want)
				}
				// Captured bytes are the kernel's: no tag from the VLAN
				// device (it is in metadata), the tag from the socket.
				for _, p := range pkts {
					if len(p.Data) < 14 {
						t.Fatalf("frame %s: short capture % x", name, p.Data)
					}
					et := uint16(p.Data[12])<<8 | uint16(p.Data[13])
					if wantET := map[string]uint16{"untagged": 0x0800, "vlandev": 0x0800, "socket": 0x8100}[name]; et != wantET {
						t.Errorf("frame %s: captured ethertype %#04x at 12, want %#04x", name, et, wantET)
					}
				}
			}
		})
	}
}

// wireTestVethEgress creates a veth pair with a VLAN device (vid 100) on
// its first end, attaches tcProg at egress of that end (tcx, or a clsact
// filter on kernels without tcx), and returns the ifindexes of the veth
// end and of the VLAN device.
func wireTestVethEgress(t *testing.T, tcProg *ebpf.Program) (direct, vlanDev int) {
	t.Helper()
	// Names carry the pid so concurrent runs on one host do not collide.
	name0, name1 := fmt.Sprintf("kxe%da", os.Getpid()%100000), fmt.Sprintf("kxe%db", os.Getpid()%100000)
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
	vla := netlink.NewLinkAttrs()
	vla.Name = name0 + ".100"
	vla.ParentIndex = v0.Attrs().Index
	if err := netlink.LinkAdd(&netlink.Vlan{LinkAttrs: vla, VlanId: 100}); err != nil {
		t.Skipf("vlan device unavailable (%v)", err)
	}
	vd, err := netlink.LinkByName(name0 + ".100")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	for _, l := range []netlink.Link{v0, v1, vd} {
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("LinkSetUp: %v", err)
		}
	}
	idx := v0.Attrs().Index
	if lnk, err := link.AttachTCX(link.TCXOptions{Interface: idx, Program: tcProg, Attach: ebpf.AttachTCXEgress}); err == nil {
		t.Cleanup(func() { _ = lnk.Close() })
		return idx, vd.Attrs().Index
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{LinkIndex: idx, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT},
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		t.Skipf("neither tcx nor clsact available (%v)", err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  netlink.FilterAttrs{LinkIndex: idx, Parent: netlink.HANDLE_MIN_EGRESS, Handle: 1, Protocol: unix.ETH_P_ALL, Priority: 1},
		Fd:           tcProg.FD(),
		Name:         asmTCFuncName,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		t.Fatalf("clsact filter: %v", err)
	}
	return idx, vd.Attrs().Index
}
