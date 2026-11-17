//go:build linux && amd64

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// devBoundHook is the hook a ready rule gives the device-bound loader's call.
const devBoundHook = "ninja_bpf_xdp_metadata_rx_hash"

// devBoundNetNS moves the calling goroutine's thread into a new network
// namespace until the test ends, with lo up.
func devBoundNetNS(t *testing.T) {
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
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
}

// devBoundFrame is an Ethernet IPv4 UDP frame from tx to rx with source
// port sport, so that each frame has its own flow hash.
func devBoundFrame(rx, tx netlink.Link, sport uint16) []byte {
	f := make([]byte, 14+20+8+18)
	copy(f[0:6], rx.Attrs().HardwareAddr)
	copy(f[6:12], tx.Attrs().HardwareAddr)
	binary.BigEndian.PutUint16(f[12:], unix.ETH_P_IP)
	ip := f[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(ip[2:], uint16(len(f)-14))
	copy(ip[12:16], []byte{10, 78, 0, 1})
	copy(ip[16:20], []byte{10, 78, 0, 2})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum+sum>>16))
	binary.BigEndian.PutUint16(f[34:], sport)
	binary.BigEndian.PutUint16(f[36:], 9)
	binary.BigEndian.PutUint16(f[38:], uint16(len(f)-34))
	return f
}

// devBoundChild is the loader: in a network namespace of its own it makes
// a veth pair and loads, bound to one end, an XDP program that calls
// bpf_xdp_metadata_rx_hash with the hash at fp-8 and stores the hash, the
// status and a frame count in out. With list it stops there; else it
// attaches the program, captures at the hook with --arg-filter 'ret==0'
// --arg-echo 'arg[0]' while frames cross the veth, and compares the echoed
// hashes with the ones the program stored.
func devBoundChild(t *testing.T, list bool) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("kernel BTF: %v", err)
	}
	var fn *btf.Func
	if err := kernel.TypeByName("bpf_xdp_metadata_rx_hash", &fn); err != nil {
		t.Skipf("kernel lacks kfunc bpf_xdp_metadata_rx_hash: %v", err)
	}
	id, err := kernel.TypeID(fn)
	if err != nil {
		t.Fatal(err)
	}
	devBoundNetNS(t)
	name0, name1 := fmt.Sprintf("kxc%da", os.Getpid()%100000), fmt.Sprintf("kxc%db", os.Getpid()%100000)
	la := netlink.NewLinkAttrs()
	la.Name = name0
	veth := &netlink.Veth{LinkAttrs: la, PeerName: name1}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("veth unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	var links []netlink.Link
	for _, name := range []string{name0, name1} {
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte("1"), 0o644)
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
		links = append(links, l)
	}
	rx, tx := links[0], links[1]
	out, err := ebpf.NewMap(&ebpf.MapSpec{Name: "out", Type: ebpf.Array, KeySize: 4, ValueSize: 24, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	spec := retProgram("devhash", asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R1, 0), asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
		{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: int64(id)},
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LoadMem(asm.R8, asm.RFP, -8, asm.Word),
		asm.LoadMapValue(asm.R1, out.FD(), 0),
		asm.StoreMem(asm.R1, 0, asm.R8, asm.DWord),
		asm.StoreMem(asm.R1, 8, asm.R7, asm.DWord),
		asm.LoadMem(asm.R2, asm.R1, 16, asm.DWord), asm.Add.Imm(asm.R2, 1), asm.StoreMem(asm.R1, 16, asm.R2, asm.DWord),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	})
	spec.Ifindex, spec.Flags = uint32(rx.Attrs().Index), unix.BPF_F_XDP_DEV_BOUND_ONLY
	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		t.Fatalf("device-bound program: %v", err)
	}
	defer func() { _ = prog.Close() }()
	if list {
		return
	}
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	progID, _ := info.ID()
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: rx.Attrs().Index, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatalf("attaching in driver mode: %v", err)
	}
	defer func() { _ = l.Close() }()
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(sock) }()
	const frames = 3
	c := startCapture(t, "-p", fmt.Sprint(progID), "--func", devBoundHook, "--arg-filter", "ret==0", "--arg-echo",
		"-c", fmt.Sprint(frames), "arg[0]")
	c.waitFor("arg-echo on")
	var hashes []uint32
	for i := range frames {
		var before, got [3]uint64
		if err := out.Lookup(uint32(0), &before); err != nil {
			t.Fatal(err)
		}
		if err := unix.Sendto(sock, devBoundFrame(rx, tx, uint16(40000+i)), 0, &unix.SockaddrLinklayer{Ifindex: tx.Attrs().Index, Halen: 6}); err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if err := out.Lookup(uint32(0), &got); err != nil {
				t.Fatal(err)
			}
			if got[2] != before[2] || time.Now().After(deadline) {
				break
			}
		}
		if got[2] != before[2]+1 || int32(got[1]) != 0 {
			t.Fatalf("frame %d: count %d after %d, status %d", i, got[2], before[2], int32(got[1]))
		}
		hashes = append(hashes, uint32(got[0]))
	}
	stderr := c.finish()
	t.Logf("stored hashes %v; capture:\n%s", hashes, stderr)
	echoed := regexp.MustCompile(`arg\[0\]=(\d+)\b`).FindAllStringSubmatch(stderr, -1)
	var seen []string
	for _, m := range echoed {
		seen = append(seen, m[1])
	}
	for _, h := range hashes {
		if !slices.Contains(seen, fmt.Sprint(h)) {
			t.Errorf("hash %d the program stored was not echoed (echoed %v)", h, seen)
		}
	}
	if len(seen) != frames {
		t.Errorf("%d values echoed, want %d", len(seen), frames)
	}
}

// TestBpfDevBoundCapture: a device-bound XDP program that calls
// bpf_xdp_metadata_rx_hash is loaded under inject-run with the ready rule
// of its listing, and bpf-ninja captures at the hook with --arg-filter
// 'ret==0' --arg-echo 'arg[0]' while frames cross a veth: each echoed hash
// is the one the program stored.
func TestBpfDevBoundCapture(t *testing.T) {
	if out := os.Getenv("BPF_NINJA_DEVBOUND_CHILD"); out != "" {
		res := retMemberResult{}
		defer func() {
			res.Done = !t.Failed() && !t.Skipped()
			if t.Skipped() {
				res.Error = "skipped"
			}
			data, _ := json.Marshal(res)
			_ = os.WriteFile(out, data, 0o600)
		}()
		devBoundChild(t, os.Getenv("BPF_NINJA_DEVBOUND_LIST") != "")
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("kernel BTF: %v", err)
	}
	var fn *btf.Func
	if err := kernel.TypeByName("bpf_xdp_metadata_rx_hash", &fn); err != nil {
		t.Skipf("kernel lacks kfunc bpf_xdp_metadata_rx_hash: %v", err)
	}
	dir := t.TempDir()
	run := func(name string, flags ...string) {
		t.Helper()
		out := filepath.Join(dir, name+".out")
		t.Setenv("BPF_NINJA_DEVBOUND_CHILD", out)
		argv := append(append([]string{"bpf-ninja", "inject-run"}, flags...), "--", os.Args[0], "-test.run=^TestBpfDevBoundCapture$", "-test.v")
		if err := newRootCommand().Run(context.Background(), argv); err != nil {
			t.Fatalf("%s: inject-run: %v", name, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("%s: the loader did not finish: %v", name, err)
		}
		var res retMemberResult
		if err := json.Unmarshal(data, &res); err == nil && res.Error == "skipped" {
			t.Skip("the loader skipped")
		}
		if err != nil || !res.Done {
			t.Fatalf("%s: loader: %s", name, data)
		}
	}
	sites := filepath.Join(dir, "sites.json")
	t.Setenv("BPF_NINJA_DEVBOUND_LIST", "1")
	run("list", "--lookups-json", sites)
	data, err := os.ReadFile(sites)
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Programs []struct {
			Rule json.RawMessage `json:"rule"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(data, &listing); err != nil || len(listing.Programs) != 1 || listing.Programs[0].Rule == nil {
		t.Fatalf("listing (%v):\n%s", err, data)
	}
	config, hooks := filepath.Join(dir, "rules.json"), filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(config, []byte("["+string(listing.Programs[0].Rule)+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BPF_NINJA_DEVBOUND_LIST", "")
	run("capture", "--config", config, "--hooks-json", hooks)
	data, err = os.ReadFile(hooks)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rule %s; hooks:\n%s", listing.Programs[0].Rule, data)
	var file hooksFileJSON
	if err := json.Unmarshal(data, &file); err != nil || len(file.Programs) != 1 {
		t.Fatalf("hooks file (%v):\n%s", err, data)
	}
	p := file.Programs[0]
	i := slices.IndexFunc(p.Hooks, func(h hookJSON) bool { return h.Name == devBoundHook })
	if i < 0 || p.Hooks[i].RetSize != 4 || !p.Hooks[i].RetSigned || p.Hooks[i].ArgReg != 2 || !strings.Contains(p.NotReviewed, "bpf_xdp_metadata_rx_hash") {
		t.Fatalf("hook %s or not_reviewed missing:\n%s", devBoundHook, data)
	}
}
