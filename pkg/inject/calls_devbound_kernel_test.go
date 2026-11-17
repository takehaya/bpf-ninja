package inject

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Kernel tests of the XDP receive-metadata kfuncs. A program may call them
// only when it is bound to a device at load time (prog_ifindex with
// BPF_F_XDP_DEV_BOUND_ONLY), and BPF_PROG_TEST_RUN refuses a device-bound
// program, so the fixtures run on real frames sent over a veth pair to a
// program attached in driver mode at the receiving end.

// metadataSentinel fills the kfunc's value buffer before the call, so that
// a value equal to it shows the callee did not write.
const metadataSentinel = 0x1122334455667788

// metadataEtherType marks the test frames (IEEE local experimental).
const metadataEtherType = 0x88b5

// xdpMetadataFixture (XDP) fills fp-8 with metadataSentinel and fp-16 with
// 0, calls kfunc(ctx, fp-8), or kfunc(ctx, fp-8, fp-16) with third, stores
// the 8 bytes at fp-8 in out slot 0, the int status in slot 1 and the 8
// bytes at fp-16 in slot 2, and returns XDP_PASS when the status is 0, else
// XDP_DROP.
func xdpMetadataFixture(call asm.Instruction, third bool) *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadImm(asm.R1, metadataSentinel, asm.DWord),
		asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, 0), asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
	}
	if third {
		insns = append(insns, asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16))
	}
	insns = append(insns, call, asm.Mov.Reg(asm.R7, asm.R0), asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord))
	insns = append(insns, outStore(0, asm.R8)...)
	insns = append(insns, outStore(1, asm.R7)...)
	insns = append(insns, asm.LoadMem(asm.R8, asm.RFP, -16, asm.DWord))
	insns = append(insns, outStore(2, asm.R8)...)
	insns = append(insns, asm.Mov.Imm(asm.R0, 2), asm.JEq.Imm(asm.R7, 0, "ret"), asm.Mov.Imm(asm.R0, 1), asm.Return().WithSymbol("ret"))
	return callFixtureSpec(ebpf.XDP, insns)
}

// bindTo binds program p of spec to the device ifindex (device-bound when
// devBound, else a request to offload).
func bindTo(spec *ebpf.CollectionSpec, ifindex int, devBound bool) *ebpf.CollectionSpec {
	spec.Programs["p"].Ifindex = uint32(ifindex)
	if devBound {
		spec.Programs["p"].Flags |= unix.BPF_F_XDP_DEV_BOUND_ONLY
	}
	return spec
}

// metadataVeth is a veth pair: frames sent from tx arrive at rx, with VLAN
// tag 100 out of band when it was made with vlan.
type metadataVeth struct {
	rx, tx         netlink.Link
	rxSock, txSock int
}

// newMetadataVeth creates a veth pair without IPv6, so that no frame but
// the test's crosses it, and opens a sending socket on one end and a
// receiving socket on the other. It skips when veth (or with vlan, tcx) is
// unavailable.
func newMetadataVeth(t *testing.T, vlan bool) *metadataVeth {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	name0, name1 := fmt.Sprintf("kxm%da", os.Getpid()%100000), fmt.Sprintf("kxm%db", os.Getpid()%100000)
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
	v := &metadataVeth{}
	for i, name := range []string{name0, name1} {
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte("1"), 0o644)
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			v.rx = l
		} else {
			v.tx = l
		}
	}
	open := func(link netlink.Link, proto uint16) int {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(proto)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(proto), Ifindex: link.Attrs().Index}); err != nil {
			t.Fatal(err)
		}
		return fd
	}
	if vlan {
		// No VLAN device is needed: bpf_skb_vlan_push at tx egress puts
		// tag 100 out of band, where the veth hands it on.
		push, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R2, int32(htons(unix.ETH_P_8021Q))), asm.Mov.Imm(asm.R3, 100),
			asm.FnSkbVlanPush.Call(),
			asm.Mov.Imm(asm.R0, 0), // TCX_PASS
			asm.Return(),
		}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = push.Close() })
		l, err := link.AttachTCX(link.TCXOptions{Interface: v.tx.Attrs().Index, Program: push, Attach: ebpf.AttachTCXEgress})
		if err != nil {
			t.Skipf("tcx unavailable to tag the frames (%v)", err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	// The receiving socket takes every protocol: a frame whose tag no VLAN
	// device on rx takes reaches only such taps.
	v.rxSock, v.txSock = open(v.rx, unix.ETH_P_ALL), open(v.tx, 0)
	tv := unix.Timeval{Usec: 200_000}
	if err := unix.SetsockoptTimeval(v.rxSock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	return v
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// send sends one test frame from tx and reports whether the stack at rx
// received it (the program passed it).
func (v *metadataVeth) send(t *testing.T, seq byte) bool {
	t.Helper()
	frame := make([]byte, 64)
	copy(frame[0:6], v.rx.Attrs().HardwareAddr)
	copy(frame[6:12], v.tx.Attrs().HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], metadataEtherType)
	frame[14] = seq
	if err := unix.Sendto(v.txSock, frame, 0, &unix.SockaddrLinklayer{Ifindex: v.tx.Attrs().Index, Halen: 6}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(v.rxSock, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if n >= 15 && binary.BigEndian.Uint16(buf[12:14]) == metadataEtherType && buf[14] == seq {
			return true
		}
	}
	return false
}

// attach attaches prog in driver mode at rx until the returned function runs.
func (v *metadataVeth) attach(t *testing.T, prog *ebpf.Program) func() {
	t.Helper()
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: v.rx.Attrs().Index, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatalf("attaching in driver mode: %v", err)
	}
	return func() { _ = l.Close() }
}

// metadataKfunc skips unless the kernel has the kfunc name and returns its call.
func metadataKfunc(t *testing.T, name string) (asm.Instruction, *btf.Spec) {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	kernel := kernelBTF(t)
	var fn *btf.Func
	if err := kernel.TypeByName(name, &fn); err != nil {
		t.Skipf("kernel lacks kfunc %s: %v", name, err)
	}
	return kernelKfunc(t, name), kernel
}

// TestBpfDevBoundTrialLoad is the supervisor's trial on a device-bound
// program: a load with BPF_LOG_STATS reports the stack depth, and the
// program then loads again bound to the same device while nothing else
// holds the trial. Without BPF_F_XDP_DEV_BOUND_ONLY the load asks for
// offload, which a veth refuses.
func TestBpfDevBoundTrialLoad(t *testing.T) {
	call, _ := metadataKfunc(t, "bpf_xdp_metadata_rx_timestamp")
	v := newMetadataVeth(t, false)
	ifindex := v.rx.Attrs().Index
	if _, err := ebpf.NewCollection(xdpMetadataFixture(call, false)); err == nil {
		t.Fatal("an unbound program calling bpf_xdp_metadata_rx_timestamp loaded")
	} else {
		t.Logf("unbound: %v", firstLine(err))
	}
	trial, depth := loadWithDepth(t, bindTo(xdpMetadataFixture(call, false), ifindex, true))
	info, err := trial.Programs["p"].Info()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := info.BTFID(); !ok || depth < 16 {
		t.Fatalf("trial: btf id present %v, stack depth %d", ok, depth)
	}
	t.Logf("trial: stack depth %d", depth)
	trial.Close()
	again, err := ebpf.NewCollection(bindTo(xdpMetadataFixture(call, false), ifindex, true))
	if err != nil {
		t.Fatalf("load after the trial: %v", err)
	}
	again.Close()
	_, err = ebpf.NewCollection(bindTo(xdpMetadataFixture(call, false), ifindex, false))
	if err == nil {
		t.Fatal("an offload request loaded on a veth")
	}
	t.Logf("offload request: %v", firstLine(err))
}

func firstLine(err error) string { s, _, _ := strings.Cut(err.Error(), "\n"); return s }

// testCallHookRowMetadata runs the fixture of kfunc name on frames over a
// veth pair, first unmodified and then with its call hooked, and checks
// that the hook takes the value buffer as a typed argument of size bytes,
// sees for each frame the value and status the program stores, and that
// every frame gets the same action. With vlan the frames carry VLAN tag 100.
// It returns the last value and the 8 bytes at fp-16.
func testCallHookRowMetadata(t *testing.T, name string, third, vlan bool, size uint32) (uint64, uint64) {
	call, kernel := metadataKfunc(t, name)
	v := newMetadataVeth(t, vlan)
	ifindex := v.rx.Attrs().Index
	const frames = 3
	plain, err := ebpf.NewCollection(bindTo(xdpMetadataFixture(call, third), ifindex, true))
	if err != nil {
		t.Fatalf("unmodified program: %v", err)
	}
	defer plain.Close()
	detach := v.attach(t, plain.Programs["p"])
	var plainPassed []bool
	for seq := range frames {
		plainPassed = append(plainPassed, v.send(t, byte(seq+1)))
	}
	detach()
	var plainOut [4]uint64
	if err := plain.Maps["out"].Lookup(uint32(0), &plainOut); err != nil {
		t.Fatal(err)
	}

	work := bindTo(xdpMetadataFixture(call, third), ifindex, true)
	in := slices.Clone(work.Programs["p"].Instructions)
	injectcheck.Label(work.Programs["p"].Instructions)
	req := callReq(name)
	req.Kernel = kernel
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || len(plan.skipped) != 0 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	if h := plan.hooks[0]; h.ArgReg != 2 || h.ArgSize != size || h.Untrusted || h.Static || h.ArgReason != "" || h.RetSize != 4 {
		t.Fatalf("hook %+v", h)
	}
	out := work.Programs["p"].Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
	if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != len(plan.sites) {
		t.Fatalf("checker: counts %+v sites %d err %v", counts, len(plan.sites), err)
	}
	hooked := loadHooked(t, work, plan.hooks)
	defer hooked.Close()
	obs := attachArgObserver(t, plan.hooks[0].Name, hooked.Programs["p"], false, true, false)
	defer v.attach(t, hooked.Programs["p"])()
	mask := uint64(1)<<(8*size) - 1
	var got [4]uint64
	for seq := range frames {
		if passed := v.send(t, byte(seq+1)); passed != plainPassed[seq] {
			t.Fatalf("frame %d: passed %v, unmodified %v", seq+1, passed, plainPassed[seq])
		}
		if err := hooked.Maps["out"].Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		saw := lastCall(t, obs, seq+1)
		if saw[0] != uint64(plan.hooks[0].Sites[0].SitePC) || saw[1]&mask != got[0]&mask || uint32(saw[2]) != uint32(got[1]) {
			t.Fatalf("frame %d: hook site %d value %#x status %#x, program stored value %#x status %#x",
				seq+1, saw[0], saw[1], saw[2], got[0], got[1])
		}
	}
	if int32(uint32(got[1])) != int32(uint32(plainOut[1])) {
		t.Fatalf("status %d, unmodified %d", int32(uint32(got[1])), int32(uint32(plainOut[1])))
	}
	if int32(uint32(got[1])) == 0 && got[0]&mask == metadataSentinel&mask {
		t.Fatalf("status 0 but the buffer still holds the sentinel %#x", got[0])
	}
	t.Logf("status %d value %#x passed %v (unmodified: status %d value %#x)", int32(uint32(got[1])), got[0]&mask, plainPassed,
		int32(uint32(plainOut[1])), plainOut[0]&mask)
	return got[0] & mask, got[2]
}

func TestBpfCallHookRowXdpRxTimestamp(t *testing.T) {
	testCallHookRowMetadata(t, "bpf_xdp_metadata_rx_timestamp", false, false, 8)
}

func TestBpfCallHookRowXdpRxHash(t *testing.T) {
	testCallHookRowMetadata(t, "bpf_xdp_metadata_rx_hash", true, false, 4)
}

// The VLAN protocol is in network byte order: 802.1Q (0x8100) is the bytes
// 81 00, which the hook's u16 reads as 0x0081 on a little-endian host.
func TestBpfCallHookRowXdpRxVlanTag(t *testing.T) {
	proto, tci := testCallHookRowMetadata(t, "bpf_xdp_metadata_rx_vlan_tag", true, true, 2)
	if proto != 0x0081 || uint16(tci)&0xfff != 100 {
		t.Fatalf("vlan_proto %#x tci %#x, want 802.1Q and VLAN 100", proto, uint16(tci))
	}
}
