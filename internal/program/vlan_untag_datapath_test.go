package program

// Real-datapath confirmation of the premise the whole tc-VLAN design
// rests on: by the time a tc/clsact ingress program runs, the kernel
// has already stripped the outer 802.1Q tag out of the packet bytes
// (skb_vlan_untag runs in __netif_receive_skb_core, before
// sch_handle_ingress / tcx) and moved it into skb metadata
// (vlan_present / vlan_tci).
//
// A veth pair carries a hand-built VLAN-tagged IPv4/TCP frame; a
// minimal SchedCLS program attached at tcx ingress on the receiving
// end records the ethertype it sees at L2 offset 12 plus
// skb->vlan_present / skb->vlan_tci. If the premise holds, the program
// sees ethertype 0x0800 (the INNER protocol — the tag bytes are gone)
// with vlan_present=1 and vlan_tci carrying VID 100.
//
// Combined with the dsltest packet checks (kunai's `eth/vlan?/ipv4/tcp`
// matches exactly this de-tagged byte layout), this closes the loop:
// an optional VLAN chain matches a tagged frame correctly at tc.
//
// Root + veth + tcx required; skipped otherwise. Run via make test-bpf
// or: sudo -E go test ./internal/program -run TestVlanUntag -v

import (
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// __sk_buff UAPI offsets (stable; verifier rewrites these loads).
const (
	skbProtocol    = 16
	skbVlanPresent = 20
	skbVlanTCI     = 24
	skbData        = 76
	skbDataEnd     = 80
)

func TestVlanUntagAtTCIngress(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	// --- record map: [0]=ethertype@12, [1]=vlan_present, [2]=vlan_tci ---
	rec, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "vlan_rec", Type: ebpf.Array, KeySize: 4, ValueSize: 12, MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create map: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// --- minimal SchedCLS classifier (hand asm, no C) ---
	// Reads ethertype at L2 offset 12 and the VLAN skb metadata, stores
	// all three into rec[0]. Returns TC_ACT_OK (0).
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "vlan_probe",
		Type:    ebpf.SchedCLS,
		License: "GPL",
		Instructions: asm.Instructions{
			// R6=ctx, R7=data, R8=data_end (R6-R9 are callee-saved, so
			// they survive the bpf_map_lookup_elem call below; R1-R5 do
			// not, which is why the lookup comes before the field loads).
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.LoadMem(asm.R7, asm.R6, skbData, asm.Word),
			asm.LoadMem(asm.R8, asm.R6, skbDataEnd, asm.Word),
			// rec[0] lookup -> R0.
			asm.StoreImm(asm.R10, -4, 0, asm.Word),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -4),
			asm.LoadMapPtr(asm.R1, rec.FD()),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "out"),
			// Re-establish the packet range after the call, then read.
			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Add.Imm(asm.R1, 14),
			asm.JGT.Reg(asm.R1, asm.R8, "out"), // need 14 bytes of L2
			// ethertype (wire order) = data[12]<<8 | data[13]
			asm.LoadMem(asm.R3, asm.R7, 12, asm.Byte),
			asm.LSh.Imm(asm.R3, 8),
			asm.LoadMem(asm.R9, asm.R7, 13, asm.Byte),
			asm.Or.Reg(asm.R3, asm.R9),
			asm.StoreMem(asm.R0, 0, asm.R3, asm.Word),
			asm.LoadMem(asm.R4, asm.R6, skbVlanPresent, asm.Word),
			asm.StoreMem(asm.R0, 4, asm.R4, asm.Word),
			asm.LoadMem(asm.R5, asm.R6, skbVlanTCI, asm.Word),
			asm.StoreMem(asm.R0, 8, asm.R5, asm.Word),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("out"), // TC_ACT_OK
			asm.Return(),
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier:\n%+v", ve)
		}
		t.Fatalf("load SchedCLS probe: %v", err)
	}
	defer func() { _ = prog.Close() }()

	// --- veth pair in the current netns ---
	la := netlink.NewLinkAttrs()
	la.Name = "kxvlan0"
	veth := &netlink.Veth{LinkAttrs: la, PeerName: "kxvlan1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("veth unavailable (%v); skipping datapath test", err)
	}
	defer func() { _ = netlink.LinkDel(veth) }()

	v0, err := netlink.LinkByName("kxvlan0")
	if err != nil {
		t.Fatalf("LinkByName kxvlan0: %v", err)
	}
	v1, err := netlink.LinkByName("kxvlan1")
	if err != nil {
		t.Fatalf("LinkByName kxvlan1: %v", err)
	}
	if err := netlink.LinkSetUp(v0); err != nil {
		t.Fatalf("set up v0: %v", err)
	}
	if err := netlink.LinkSetUp(v1); err != nil {
		t.Fatalf("set up v1: %v", err)
	}

	// --- attach the probe at tcx ingress on the receiving end (v1) ---
	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: v1.Attrs().Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		t.Skipf("AttachTCX unavailable (%v); skipping datapath test", err)
	}
	defer func() { _ = lnk.Close() }()

	// --- raw send a VLAN-tagged IPv4/TCP frame out v0 -> v1 receives ---
	sendFrame(t, v0.Attrs().Index, vlanTaggedIPv4TCP(100))

	eth, present, tci := pollRecord(t, rec)
	t.Logf("tagged frame: tc saw ethertype=0x%04x vlan_present=%d vlan_tci=%d (vid=%d)",
		eth, present, tci, tci&0x0fff)

	if eth != 0x0800 {
		t.Fatalf("ethertype at L2 offset 12 = 0x%04x; want 0x0800 (inner). The outer tag was NOT stripped from packet bytes — premise broken", eth)
	}
	if present != 1 {
		t.Fatalf("vlan_present=%d; want 1 (tag should be in skb metadata)", present)
	}
	if tci&0x0fff != 100 {
		t.Fatalf("vlan_tci vid = %d; want 100", tci&0x0fff)
	}

	// --- control: an untagged frame leaves no tag in metadata ---
	if err := rec.Update(uint32(0), make([]byte, 12), ebpf.UpdateAny); err != nil {
		t.Fatalf("reset map: %v", err)
	}
	sendFrame(t, v0.Attrs().Index, untaggedIPv4TCP())
	eth2, present2, _ := pollRecord(t, rec)
	t.Logf("untagged frame: tc saw ethertype=0x%04x vlan_present=%d", eth2, present2)
	if eth2 != 0x0800 {
		t.Fatalf("untagged ethertype = 0x%04x; want 0x0800", eth2)
	}
	if present2 != 0 {
		t.Fatalf("untagged vlan_present=%d; want 0", present2)
	}
}

// pollRecord reads rec[0] until ethertype is non-zero (the probe ran)
// or the deadline elapses.
func pollRecord(t *testing.T, rec *ebpf.Map) (eth, present, tci uint32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var v [12]byte
		if err := rec.Lookup(uint32(0), &v); err != nil {
			t.Fatalf("map lookup: %v", err)
		}
		eth = uint32(v[0]) | uint32(v[1])<<8 | uint32(v[2])<<16 | uint32(v[3])<<24
		present = uint32(v[4]) | uint32(v[5])<<8 | uint32(v[6])<<16 | uint32(v[7])<<24
		tci = uint32(v[8]) | uint32(v[9])<<8 | uint32(v[10])<<16 | uint32(v[11])<<24
		if eth != 0 {
			return eth, present, tci
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("probe did not run within deadline (no frame reached tcx ingress)")
	return 0, 0, 0
}

// sendFrame transmits raw bytes out the given ifindex via AF_PACKET.
func sendFrame(t *testing.T, ifindex int, frame []byte) {
	t.Helper()
	const ethPAll = 0x0003
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		t.Fatalf("AF_PACKET socket: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	addr := &unix.SockaddrLinklayer{Ifindex: ifindex, Halen: 6}
	copy(addr.Addr[:], frame[0:6])
	// send a few times — the probe records the last one it sees.
	for range 5 {
		if err := unix.Sendto(fd, frame, 0, addr); err != nil {
			t.Fatalf("sendto: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// vlanTaggedIPv4TCP builds eth(0x8100)/vlan(vid)/ipv4/tcp:80 bytes.
func vlanTaggedIPv4TCP(vid uint16) []byte {
	f := []byte{
		0x02, 0, 0, 0, 0, 0x01, // dst mac
		0x02, 0, 0, 0, 0, 0x02, // src mac
		0x81, 0x00, // VLAN ethertype
		byte(vid >> 8), byte(vid), // TCI (pcp/dei 0, vid)
		0x08, 0x00, // inner ethertype = IPv4
	}
	return append(f, ipv4TCP()...)
}

// untaggedIPv4TCP builds eth(0x0800)/ipv4/tcp:80 bytes.
func untaggedIPv4TCP() []byte {
	f := []byte{
		0x02, 0, 0, 0, 0, 0x01,
		0x02, 0, 0, 0, 0, 0x02,
		0x08, 0x00, // ethertype = IPv4
	}
	return append(f, ipv4TCP()...)
}

// ipv4TCP returns a minimal 20-byte IPv4 header (proto=TCP) + 20-byte
// TCP header (dport 80). Checksums are zero; tc ingress does not verify
// them.
func ipv4TCP() []byte {
	ip := []byte{
		0x45, 0x00, 0x00, 0x28, // ver/ihl, tos, total_len=40
		0x00, 0x00, 0x00, 0x00, // id, flags/frag
		0x40, 0x06, 0x00, 0x00, // ttl=64, proto=6 (TCP), csum=0
		10, 0, 0, 1, // src
		10, 0, 0, 2, // dst
	}
	tcp := []byte{
		0x30, 0x39, 0x00, 0x50, // sport=12345, dport=80
		0x00, 0x00, 0x00, 0x00, // seq
		0x00, 0x00, 0x00, 0x00, // ack
		0x50, 0x02, 0x20, 0x00, // data_off=5, flags=SYN, window
		0x00, 0x00, 0x00, 0x00, // csum, urg
	}
	return append(ip, tcp...)
}
