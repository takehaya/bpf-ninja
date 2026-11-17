//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The XDP receive-metadata kfuncs need a device-bound program, and
// BPF_PROG_TEST_RUN refuses one, so these tests send real frames over a veth
// pair to the program attached in driver mode at the receiving end.

const (
	devBoundSentinel  = 0x1122334455667788 // fills the value buffers before the calls
	devBoundEtherType = 0x88b5             // IEEE local experimental
)

// devBoundSpec is an XDP program name, bound to ifindex with
// BPF_F_XDP_DEV_BOUND_ONLY when devBound (else an offload request), that
// fills fp-8 and fp-16 with devBoundSentinel, calls
// bpf_xdp_metadata_rx_timestamp(ctx, fp-8) and
// bpf_xdp_metadata_rx_hash(ctx, fp-16, fp-24), stores the 8 bytes at fp-8,
// those at fp-16 and the two int statuses in out[0], and returns XDP_PASS
// when both statuses are 0, else XDP_DROP.
func devBoundSpec(t *testing.T, name string, ifindex int, devBound bool) *ebpf.CollectionSpec {
	t.Helper()
	fn := &btf.Func{Name: name + "_entry", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadImm(asm.R1, devBoundSentinel, asm.DWord),
		asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, 0), asm.StoreMem(asm.RFP, -24, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		retryKfunc(t, "bpf_xdp_metadata_rx_timestamp"),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -24),
		retryKfunc(t, "bpf_xdp_metadata_rx_hash"),
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.LoadMapValue(asm.R1, 0, 0).WithReference("out"),
		asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord), asm.StoreMem(asm.R1, 0, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord), asm.StoreMem(asm.R1, 8, asm.R2, asm.DWord),
		asm.StoreMem(asm.R1, 16, asm.R7, asm.DWord), asm.StoreMem(asm.R1, 24, asm.R8, asm.DWord),
		asm.Mov.Imm(asm.R0, 1),
		asm.JNE.Imm32(asm.R7, 0, "ret"),
		asm.JNE.Imm32(asm.R8, 0, "ret"),
		asm.Mov.Imm(asm.R0, 2),
		asm.Return().WithSymbol("ret"),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(fn.Name).WithSource(asm.Comment("device-bound loader")), fn)
	flags := uint32(0)
	if devBound {
		flags = unix.BPF_F_XDP_DEV_BOUND_ONLY
	}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"out": {Name: "out", Type: ebpf.Array, KeySize: 4, ValueSize: 32, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{name: {Name: name, Type: ebpf.XDP, License: "GPL", Instructions: insns,
			Ifindex: uint32(ifindex), Flags: flags}},
	}
}

// devBoundObserver records, at each of the first eight calls of the hook fn
// of target, the 8 bytes its arg (the hook's third argument) points to in
// seen[8*n+8], and counts the calls in seen[0].
func devBoundObserver(t *testing.T, fn string, target *ebpf.Program) (*ebpf.Collection, link.Link) {
	t.Helper()
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMapValue(asm.R7, 0, 0).WithReference("seen"),
		asm.LoadMem(asm.R8, asm.R7, 0, asm.DWord), asm.Mov.Reg(asm.R2, asm.R8), asm.Add.Imm(asm.R2, 1), asm.StoreMem(asm.R7, 0, asm.R2, asm.DWord),
		asm.JGT.Imm(asm.R8, 7, "done"),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8),
		asm.FnGetFuncArg.Call(),
		asm.JNE.Imm(asm.R0, 0, "done"),
		asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
		asm.LSh.Imm(asm.R8, 3), asm.Add.Reg(asm.R7, asm.R8), asm.Add.Imm(asm.R7, 8),
		asm.Mov.Reg(asm.R1, asm.R7), asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadKernel.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("done"),
		asm.Return(),
	}
	coll, err := ebpf.NewCollection(&ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"seen": {Name: "seen", Type: ebpf.Array, KeySize: 4, ValueSize: 72, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"observe": {Name: "observe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: fn, AttachTarget: target, License: "GPL", Instructions: insns}},
	})
	if err != nil {
		t.Errorf("observer of %s: %v", fn, err)
		return nil, nil
	}
	l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		coll.Close()
		t.Errorf("attaching the observer of %s: %v", fn, err)
		return nil, nil
	}
	return coll, l
}

// devBoundSeen returns what obs recorded: the values of the first calls.
func devBoundSeen(t *testing.T, obs *ebpf.Collection) []uint64 {
	t.Helper()
	var seen [9]uint64
	if err := obs.Maps["seen"].Lookup(uint32(0), &seen); err != nil {
		t.Fatal(err)
	}
	return seen[1 : 1+min(seen[0], 8)]
}

// devBoundVeth creates a veth pair without IPv6, so that no frame but the
// test's crosses it, and returns its names; it skips when veth is missing.
func devBoundVeth(t *testing.T) (rx, tx string) {
	t.Helper()
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	isolated, err := netns.New()
	if err != nil {
		_ = original.Close()
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := netns.Set(original); err != nil {
			t.Errorf("restoring netns: %v", err)
			return
		}
		_ = isolated.Close()
		_ = original.Close()
		runtime.UnlockOSThread()
	})
	rx, tx = fmt.Sprintf("kxd%da", os.Getpid()%100000), fmt.Sprintf("kxd%db", os.Getpid()%100000)
	if old, err := netlink.LinkByName(rx); err == nil {
		_ = netlink.LinkDel(old) // left behind by an interrupted run
	}
	la := netlink.NewLinkAttrs()
	la.Name = rx
	veth := &netlink.Veth{LinkAttrs: la, PeerName: tx}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("veth unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	for _, name := range []string{rx, tx} {
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte("1"), 0o644)
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
	}
	return rx, tx
}

// devBoundSend sends frame seq from tx and reports whether a packet socket
// on rx received it, that is, whether the program attached at rx passed it.
func devBoundSend(t *testing.T, rx, tx netlink.Link, seq byte) bool {
	t.Helper()
	proto := int(devBoundEtherType>>8 | devBoundEtherType<<8&0xff00)
	rs, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rs) }()
	if err := unix.Bind(rs, &unix.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: rx.Attrs().Index}); err != nil {
		t.Fatal(err)
	}
	tv := unix.Timeval{Usec: 200_000}
	if err := unix.SetsockoptTimeval(rs, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	ts, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(ts) }()
	frame := make([]byte, 64)
	copy(frame[0:6], rx.Attrs().HardwareAddr)
	copy(frame[6:12], tx.Attrs().HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], devBoundEtherType)
	frame[14] = seq
	if err := unix.Sendto(ts, frame, 0, &unix.SockaddrLinklayer{Ifindex: tx.Attrs().Index, Halen: 6}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		n, _, err := unix.Recvfrom(rs, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if n >= 15 && buf[14] == seq {
			return true
		}
	}
	return false
}

// devBoundRun sends three frames to name of coll attached at rx and returns
// whether each passed and the program's out[0].
func devBoundRun(t *testing.T, coll *ebpf.Collection, name string, rx, tx netlink.Link, each func(seq int, out [4]uint64)) ([]bool, [4]uint64) {
	t.Helper()
	l, err := link.AttachXDP(link.XDPOptions{Program: coll.Programs[name], Interface: rx.Attrs().Index, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatalf("attaching %s in driver mode: %v", name, err)
	}
	defer func() { _ = l.Close() }()
	var passed []bool
	var out [4]uint64
	for seq := 1; seq <= 3; seq++ {
		passed = append(passed, devBoundSend(t, rx, tx, byte(seq)))
		if err := coll.Maps["out"].Lookup(uint32(0), &out); err != nil {
			t.Fatal(err)
		}
		if each != nil {
			each(seq, out)
		}
	}
	return passed, out
}

// devBoundLoader is the loader: it loads the unmodified program q (no rule
// names it) and the hooked program p, both bound to the receiving veth, and
// checks that every one of three frames gets the same action from p as
// from q. It prints the values p stores for each frame, which the test
// compares with what its observers of p's hooks saw. In mode
// "offload" it loads p as an offload request instead and prints the refusal.
func devBoundLoader(t *testing.T, mode string) {
	rxLink, err := netlink.LinkByName(os.Getenv("SYSCALLHOOK_DEVBOUND_RX"))
	if err != nil {
		t.Fatal(err)
	}
	txLink, err := netlink.LinkByName(os.Getenv("SYSCALLHOOK_DEVBOUND_TX"))
	if err != nil {
		t.Fatal(err)
	}
	ifindex := rxLink.Attrs().Index
	if mode == "offload" {
		coll, err := ebpf.NewCollection(devBoundSpec(t, "p", ifindex, false))
		if err == nil {
			coll.Close()
			t.Fatal("an offload request loaded on a veth")
		}
		fmt.Printf("offload load refused: %v\n", errors.Unwrap(err))
		return
	}
	plain, err := ebpf.NewCollection(devBoundSpec(t, "q", ifindex, true))
	if err != nil {
		t.Fatalf("unmodified program: %+v", err)
	}
	defer plain.Close()
	plainPassed, plainOut := devBoundRun(t, plain, "q", rxLink, txLink, nil)
	hooked, err := ebpf.NewCollection(devBoundSpec(t, "p", ifindex, true))
	if err != nil {
		t.Fatalf("hooked program: %+v", err)
	}
	defer hooked.Close()
	passed, out := devBoundRun(t, hooked, "p", rxLink, txLink, func(seq int, out [4]uint64) {
		fmt.Printf("frame %d timestamp=%#x hash=%#x\n", seq, out[0], uint32(out[1]))
	})
	for i := range passed {
		if passed[i] != plainPassed[i] {
			t.Fatalf("frame %d: passed %v, unmodified %v", i+1, passed[i], plainPassed[i])
		}
	}
	if int32(uint32(out[2])) != int32(uint32(plainOut[2])) || int32(uint32(out[3])) != int32(uint32(plainOut[3])) || out[1] == devBoundSentinel {
		t.Fatalf("hooked out %#x, unmodified %#x", out, plainOut)
	}
	fmt.Printf("devbound timestamp=%#x hash=%#x status=%d,%d passed=%v unmodified passed=%v\n",
		out[0], uint32(out[1]), int32(uint32(out[2])), int32(uint32(out[3])), passed, plainPassed)
}

// A device-bound XDP program gets its hooks: the supervisor's trial load
// keeps the program bound to the same veth, the timestamp and hash hooks
// take the values the kfuncs wrote, and real frames get the same action as
// without the tool. A load with prog_ifindex and without
// BPF_F_XDP_DEV_BOUND_ONLY asks for offload: it gets no hook, the
// supervisor says why, and the kernel refuses it on a veth as before.
func TestIntegrationDevBound(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	if mode := os.Getenv("SYSCALLHOOK_DEVBOUND_CHILD"); mode != "" {
		devBoundLoader(t, mode)
		return
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("kernel BTF: %v", err)
	}
	for _, name := range []string{"bpf_xdp_metadata_rx_timestamp", "bpf_xdp_metadata_rx_hash"} {
		var fn *btf.Func
		if err := kernel.TypeByName(name, &fn); err != nil {
			t.Skipf("kernel lacks kfunc %s: %v", name, err)
		}
	}
	observers := map[string]*ebpf.Collection{}
	run := func(t *testing.T, mode string) ([]Injection, string, string) {
		rx, tx := devBoundVeth(t)
		t.Setenv("SYSCALLHOOK_DEVBOUND_RX", rx)
		t.Setenv("SYSCALLHOOK_DEVBOUND_TX", tx)
		t.Setenv("SYSCALLHOOK_DEVBOUND_CHILD", mode)
		out, err := os.CreateTemp(t.TempDir(), "loader.out")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = out.Close() }()
		rule := Rule{Program: "p", Hook: "h", Calls: []string{"bpf_xdp_metadata_rx_timestamp", "bpf_xdp_metadata_rx_hash"}}
		var logs bytes.Buffer
		var injected []Injection
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		// The observers attach while the loader waits in its load.
		onInject := func(inj Injection) {
			injected = append(injected, inj)
			target, err := ebpf.NewProgramFromID(ebpf.ProgramID(inj.ProgID))
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = target.Close() }()
			for _, h := range inj.Hooks {
				if obs, l := devBoundObserver(t, h.Name, target); obs != nil {
					observers[h.Call] = obs
					t.Cleanup(func() { _ = l.Close(); obs.Close() })
				}
			}
		}
		code, err := Run(ctx, []string{os.Args[0], "-test.run=^TestIntegrationDevBound$"}, Options{Rules: []Rule{rule}, Stdout: out, Stderr: out, Log: &logs,
			OnInject: onInject})
		data, _ := os.ReadFile(out.Name())
		t.Logf("supervisor:\n%sloader:\n%s", &logs, data)
		if err != nil || code != 0 {
			t.Fatalf("code=%d err=%v", code, err)
		}
		return injected, logs.String(), string(data)
	}
	t.Run("device-bound", func(t *testing.T) {
		injected, logs, out := run(t, "hook")
		if len(injected) != 1 || len(injected[0].Hooks) != 2 || len(injected[0].Skipped) != 0 {
			t.Fatalf("injections %+v", injected)
		}
		for _, h := range injected[0].Hooks {
			if h.ArgReg != 2 || h.Untrusted || h.Static || h.ArgReason != "" {
				t.Fatalf("hook %+v", h)
			}
		}
		if !strings.Contains(logs, "checker accepted") || strings.Contains(logs, "stack depth unavailable") || !strings.Contains(out, "devbound timestamp=") {
			t.Fatal("the device-bound program was not hooked as checked")
		}
		// The receive-metadata functions have no review record: the driver's function runs.
		if nr := injected[0].NotReviewed; len(nr) != 2 || !slices.Contains(nr, "bpf_xdp_metadata_rx_timestamp") || !slices.Contains(nr, "bpf_xdp_metadata_rx_hash") ||
			!strings.Contains(logs, "kernel functions without a review record: calls bpf_xdp_metadata_rx_") {
			t.Fatalf("not reviewed %v", nr)
		}
		if observers["bpf_xdp_metadata_rx_timestamp"] == nil || observers["bpf_xdp_metadata_rx_hash"] == nil {
			t.Fatal("observers missing")
		}
		ts := devBoundSeen(t, observers["bpf_xdp_metadata_rx_timestamp"])
		hash := devBoundSeen(t, observers["bpf_xdp_metadata_rx_hash"])
		if len(ts) != 3 || len(hash) != 3 {
			t.Fatalf("hook calls %d and %d, want 3 each", len(ts), len(hash))
		}
		for i := range 3 {
			want := fmt.Sprintf("frame %d timestamp=%#x hash=%#x\n", i+1, ts[i], uint32(hash[i]))
			if !strings.Contains(out, want) {
				t.Fatalf("hooks saw %q; the loader printed\n%s", want, out)
			}
		}
	})
	t.Run("offload", func(t *testing.T) {
		injected, logs, out := run(t, "offload")
		if len(injected) != 0 || !strings.Contains(logs, "offloaded programs do not expose local verifier stack accounting") ||
			!strings.Contains(out, "offload load refused") {
			t.Fatalf("injections %+v", injected)
		}
	})
}
