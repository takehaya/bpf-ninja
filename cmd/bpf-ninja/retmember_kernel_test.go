//go:build linux && amd64

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

// retMemberResult is what the loader of TestBpfRetMember saw.
type retMemberResult struct {
	Error string `json:"error,omitempty"`
	Done  bool   `json:"done"`
}

// Conntrack flows of the fixture: 10.77.0.1:4321 to 10.77.0.2:port. Flow A
// is seeded with IPS_SEEN_REPLY|IPS_ASSURED, flow B with neither, and
// there is no entry for the miss port. The ports differ from the
// pkg/inject conntrack tests so that entries left behind never collide.
const (
	retFlowA    = 8141
	retFlowB    = 8142
	retFlowMiss = 8143
	retSeeded   = 2 | 4 // IPS_SEEN_REPLY | IPS_ASSURED
)

// retKfunc is the call of the vmlinux kernel function name.
func retKfunc(t *testing.T, kernel *btf.Spec, name string) asm.Instruction {
	t.Helper()
	var fn *btf.Func
	if err := kernel.TypeByName(name, &fn); err != nil {
		t.Skipf("kfunc %s: %v", name, err)
	}
	id, err := kernel.TypeID(fn)
	if err != nil {
		t.Fatal(err)
	}
	return asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: int64(id)}
}

// retIP is an IPv4 address as the immediate of a 4-byte store.
func retIP(a [4]byte) int64 { return int64(int32(binary.LittleEndian.Uint32(a[:]))) }

// retPort is a port in network order as the immediate of a 2-byte store.
func retPort(p uint16) int64 { return int64(p>>8 | p<<8) }

// retPacket is a test packet whose first two bytes are port in network order.
func retPacket(port uint16) []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint16(b, port)
	return b
}

// retPortFromPacket loads the packet's first two bytes into R9 (network
// order, as the tuple holds it) with the context in R6; a shorter packet
// jumps to drop.
func retPortFromPacket() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R2), asm.Add.Imm(asm.R4, 2),
		asm.JGT.Reg(asm.R4, asm.R3, "drop"),
		asm.LoadMem(asm.R9, asm.R2, 0, asm.Half),
	}
}

// retCtTuple writes the tuple 10.77.0.1:4321 to 10.77.0.2:R9 at fp-16 and
// struct bpf_ct_opts {netns_id -1, l4proto TCP} at fp-32, and sets R1-R5
// for a lookup or alloc kfunc.
func retCtTuple() asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.RFP, -16, retIP([4]byte{10, 77, 0, 1}), asm.Word),
		asm.StoreImm(asm.RFP, -12, retIP([4]byte{10, 77, 0, 2}), asm.Word),
		asm.StoreImm(asm.RFP, -8, retPort(4321), asm.Half),
		asm.StoreMem(asm.RFP, -6, asm.R9, asm.Half),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.StoreImm(asm.RFP, -32, -1, asm.Word),
		asm.StoreImm(asm.RFP, -28, 0, asm.Word),
		asm.StoreImm(asm.RFP, -24, unix.IPPROTO_TCP, asm.Word),
		asm.StoreImm(asm.RFP, -20, 0, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16), asm.Mov.Imm(asm.R3, 12),
		asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -32), asm.Mov.Imm(asm.R5, 12),
	}
}

// retProgram is an XDP program name with BTF whose instructions are insns.
func retProgram(name string, insns asm.Instructions) *ebpf.ProgramSpec {
	fn := &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(name).WithSource(asm.Comment(name)), fn)
	return &ebpf.ProgramSpec{Name: name, Type: ebpf.XDP, License: "GPL", Instructions: insns}
}

// retSeed inserts the entry of flow port with status bits status (none: 0)
// and a 30 s timeout; the program is not named by the rule.
func retSeed(t *testing.T, kernel *btf.Spec, port uint16, status int32) {
	t.Helper()
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Imm(asm.R9, int32(retPort(port)))}
	insns = append(insns, retCtTuple()...)
	insns = append(insns, retKfunc(t, kernel, "bpf_xdp_ct_alloc"),
		asm.JNE.Imm(asm.R0, 0, "allocated"),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
		asm.Mov.Reg(asm.R7, asm.R0).WithSymbol("allocated"),
		asm.Mov.Reg(asm.R1, asm.R7), asm.Mov.Imm(asm.R2, 30000),
		retKfunc(t, kernel, "bpf_ct_set_timeout"))
	if status != 0 {
		// A refused status shows as unseeded bits in the hit's status.
		insns = append(insns, asm.Mov.Reg(asm.R1, asm.R7), asm.Mov.Imm(asm.R2, status),
			retKfunc(t, kernel, "bpf_ct_set_status"))
	}
	insns = append(insns, asm.Mov.Reg(asm.R1, asm.R7))
	insns = append(insns, retKfunc(t, kernel, "bpf_ct_insert_entry"),
		asm.JNE.Imm(asm.R0, 0, "inserted"),
		asm.Mov.Imm(asm.R0, 3), asm.Return(),
		asm.Mov.Reg(asm.R1, asm.R0).WithSymbol("inserted"),
		retKfunc(t, kernel, "bpf_ct_release"),
		asm.Mov.Imm(asm.R0, 1), asm.Return())
	p, err := ebpf.NewProgram(retProgram("ctseed", insns))
	if err != nil {
		t.Fatalf("seed program: %v", err)
	}
	defer func() { _ = p.Close() }()
	if ret, _, err := p.Test(make([]byte, 64)); err != nil || ret != 1 {
		t.Fatalf("seeding port %d: %d, %v; want 1", port, ret, err)
	}
}

// retStatusOffset is the byte offset of status in the kernel's struct nf_conn.
func retStatusOffset(t *testing.T, kernel *btf.Spec) int16 {
	t.Helper()
	var conn *btf.Struct
	if err := kernel.TypeByName("nf_conn", &conn); err != nil {
		t.Skipf("nf_conn: %v", err)
	}
	for _, m := range conn.Members {
		if m.Name == "status" {
			return int16(m.Offset.Bytes())
		}
	}
	t.Fatal("nf_conn lacks status")
	return 0
}

// ctLookupProgram (ctprog) looks up the flow of the packet's port with
// bpf_xdp_ct_lookup. A hit stores ct->status in out and passes, a miss drops.
func ctLookupProgram(t *testing.T, kernel *btf.Spec, out *ebpf.Map) *ebpf.ProgramSpec {
	insns := append(retPortFromPacket(), retCtTuple()...)
	insns = append(insns, retKfunc(t, kernel, "bpf_xdp_ct_lookup"),
		asm.JNE.Imm(asm.R0, 0, "hit"),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("drop"), asm.Return(),
		asm.Mov.Reg(asm.R7, asm.R0).WithSymbol("hit"),
		asm.LoadMem(asm.R2, asm.R7, retStatusOffset(t, kernel), asm.DWord),
		asm.LoadMapValue(asm.R1, out.FD(), 0),
		asm.StoreMem(asm.R1, 0, asm.R2, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R7), retKfunc(t, kernel, "bpf_ct_release"),
		asm.Mov.Imm(asm.R0, 2), asm.Return())
	return retProgram("ctprog", insns)
}

// skLookupProgram (skprog) looks up the TCP socket for 127.0.0.1:4321 to
// 127.0.0.1:port with bpf_skc_lookup_tcp; a hit releases it and passes, a
// miss drops.
func skLookupProgram() *ebpf.ProgramSpec {
	lo := [4]byte{127, 0, 0, 1}
	insns := append(retPortFromPacket(),
		asm.StoreImm(asm.RFP, -16, retIP(lo), asm.Word),
		asm.StoreImm(asm.RFP, -12, retIP(lo), asm.Word),
		asm.StoreImm(asm.RFP, -8, retPort(4321), asm.Half),
		asm.StoreMem(asm.RFP, -6, asm.R9, asm.Half),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16), asm.Mov.Imm(asm.R3, 12),
		asm.Mov.Imm(asm.R4, -1), // BPF_F_CURRENT_NETNS
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkcLookupTcp.Call(),
		asm.JNE.Imm(asm.R0, 0, "hit"),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("drop"), asm.Return(),
		asm.Mov.Reg(asm.R1, asm.R0).WithSymbol("hit"),
		asm.FnSkRelease.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return())
	return retProgram("skprog", insns)
}

// epbPackets returns the data and the comments of every packet block in a
// little-endian pcapng file.
func epbPackets(t *testing.T, path string) (data [][]byte, comments []string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off+12 <= len(b); {
		n := int(binary.LittleEndian.Uint32(b[off+4:]))
		if n < 12 || off+n > len(b) {
			t.Fatalf("pcapng block at %d has length %d", off, n)
		}
		if binary.LittleEndian.Uint32(b[off:]) == 6 {
			body := b[off+8 : off+n-4]
			capLen := int(binary.LittleEndian.Uint32(body[12:]))
			data = append(data, body[20:20+capLen])
			comment := ""
			for opt := 20 + (capLen+3)&^3; opt+4 <= len(body); {
				code, l := binary.LittleEndian.Uint16(body[opt:]), int(binary.LittleEndian.Uint16(body[opt+2:]))
				if code == 0 {
					break
				}
				if code == 1 {
					comment = string(body[opt+4 : opt+4+l])
				}
				opt += 4 + (l+3)&^3
			}
			comments = append(comments, comment)
		}
		off += n
	}
	return data, comments
}

// runCLI runs bpf-ninja with argv in this process and returns its stderr.
func runCLI(t *testing.T, argv ...string) string {
	t.Helper()
	c := startCapture(t, argv...)
	return c.finish()
}

// retMemberChild is the loader TestBpfRetMember runs under inject-run.
func retMemberChild(t *testing.T, dir string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("kernel BTF: %v", err)
	}
	out, err := ebpf.NewMap(&ebpf.MapSpec{Name: "out", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	retSeed(t, kernel, retFlowA, retSeeded)
	retSeed(t, kernel, retFlowB, 0)
	ct, err := ebpf.NewProgram(ctLookupProgram(t, kernel, out))
	if err != nil {
		t.Fatalf("ctprog: %v", err)
	}
	defer func() { _ = ct.Close() }()
	run := func(prog *ebpf.Program, port uint16) uint32 {
		t.Helper()
		ret, _, err := prog.Test(retPacket(port))
		if err != nil {
			t.Fatal(err)
		}
		return ret
	}
	status := func(port uint16) uint64 {
		t.Helper()
		if ret := run(ct, port); ret != 2 {
			t.Fatalf("flow %d: action %d, want a hit (2)", port, ret)
		}
		var v uint64
		if err := out.Lookup(uint32(0), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	statusA, statusB := status(retFlowA), status(retFlowB)
	if statusA&retSeeded != retSeeded || statusB&retSeeded != 0 {
		t.Fatalf("seeded status: A %#x, B %#x", statusA, statusB)
	}
	if ret := run(ct, retFlowMiss); ret != 1 {
		t.Fatalf("miss: action %d, want 1", ret)
	}
	info, err := ct.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	hook := "ninja_bpf_xdp_ct_lookup"

	// The listing shows the members behind ret.
	listing := runCLI(t, "-p", fmt.Sprint(id), "--func", hook, "--list-params", "--members")
	t.Logf("flow A status %#x, flow B status %#x; listing (head):\n%.600s", statusA, statusB, listing)
	if !strings.Contains(listing, "ret: struct nf_conn *") || !strings.Contains(listing, "ret->status") {
		t.Errorf("listing lacks ret's members:\n%s", listing)
	}

	// A condition on ret->status selects only flow A's packets, and records
	// the value; flow B and the miss (null ret) are not selected.
	pcap := filepath.Join(dir, "ct.pcapng")
	cond := fmt.Sprintf("ret->status==%d", statusA)
	c := startCapture(t, "-p", fmt.Sprint(id), "--func", hook, "--arg-filter", cond, "--record", "filter",
		"-w", pcap, "-c", "2", "--no-cpu-affinity", "-v")
	c.waitFor("capturing (")
	for _, port := range []uint16{retFlowB, retFlowMiss, retFlowA, retFlowB, retFlowMiss, retFlowA} {
		run(ct, port)
	}
	stderr := c.finish()
	data, comments := epbPackets(t, pcap)
	t.Logf("conntrack capture with %s: %d packets, comments %q", cond, len(data), comments)
	if len(data) != 2 {
		t.Fatalf("%d packets, want 2\n%s", len(data), stderr)
	}
	for i := range data {
		if got := binary.BigEndian.Uint16(data[i]); got != retFlowA {
			t.Errorf("packet %d is flow %d, want %d", i, got, retFlowA)
		}
		if want := fmt.Sprintf("ret->status=%d", statusA); !strings.Contains(comments[i], want) {
			t.Errorf("packet %d comment %q, want %q", i, comments[i], want)
		}
	}

	// Echo prints the field; a null ret (the miss) prints nothing.
	c = startCapture(t, "-p", fmt.Sprint(id), "--func", hook, "--arg-echo", "-c", "1", "ret->status")
	c.waitFor("arg-echo on")
	run(ct, retFlowMiss)
	run(ct, retFlowB)
	stderr = c.finish()
	t.Logf("echo:\n%s", stderr)
	if want := fmt.Sprintf("ret->status=%d ", statusB); !strings.Contains(stderr, want) {
		t.Errorf("echo lacks %q:\n%s", want, stderr)
	}

	// A socket lookup: the family in the common part selects the hit.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	sk, err := ebpf.NewProgram(skLookupProgram())
	if err != nil {
		t.Fatalf("skprog: %v", err)
	}
	defer func() { _ = sk.Close() }()
	info, err = sk.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ = info.ID()
	pcap = filepath.Join(dir, "sk.pcapng")
	c = startCapture(t, "-p", fmt.Sprint(id), "--func", "ninja_bpf_skc_lookup_tcp", "--arg-filter", "ret->skc_family==2", "--record", "filter",
		"-w", pcap, "-c", "1", "--no-cpu-affinity", "-v")
	c.waitFor("capturing (")
	if a, b := run(sk, port+1), run(sk, port); a != 1 || b != 2 {
		t.Fatalf("socket lookups: miss %d hit %d, want 1 and 2", a, b)
	}
	stderr = c.finish()
	data, comments = epbPackets(t, pcap)
	t.Logf("socket capture: %d packets, comments %q", len(data), comments)
	if len(data) != 1 || binary.BigEndian.Uint16(data[0]) != port || !strings.Contains(comments[0], "ret->skc_family=2") {
		t.Fatalf("socket capture: %d packets %q\n%s", len(data), comments, stderr)
	}
}

// TestBpfRetMember: inject-run hooks a conntrack lookup and a socket lookup
// with ret typed through the ret_type tag; a capture whose condition names
// a field behind ret selects by that field, records it, and leaves a null
// ret unselected.
func TestBpfRetMember(t *testing.T) {
	if out := os.Getenv("BPF_NINJA_RET_CHILD"); out != "" {
		res := retMemberResult{}
		defer func() {
			res.Done = !t.Failed() && !t.Skipped()
			if t.Skipped() {
				res.Error = "skipped"
			}
			data, _ := json.Marshal(res)
			_ = os.WriteFile(out, data, 0o600)
		}()
		retMemberChild(t, filepath.Dir(out))
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root and BPF privileges")
	}
	t.Setenv("BPF_NINJA_INJECT_CONFIG", "")
	dir := t.TempDir()
	rules := []syscallhook.Rule{
		{Program: "ctprog", HookPrefix: "ninja", Calls: []string{"bpf_xdp_ct_lookup"}},
		{Program: "skprog", HookPrefix: "ninja", Calls: []string{"bpf_skc_lookup_tcp"}},
	}
	encoded, _ := json.Marshal(rules)
	config, hooks, out := filepath.Join(dir, "rules.json"), filepath.Join(dir, "hooks.json"), filepath.Join(dir, "child.out")
	if err := os.WriteFile(config, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BPF_NINJA_RET_CHILD", out)
	err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--config", config, "--hooks-json", hooks,
		"--", os.Args[0], "-test.run=^TestBpfRetMember$", "-test.v"})
	data, _ := os.ReadFile(hooks)
	t.Logf("hooks:\n%s", data)
	if err != nil {
		t.Fatalf("inject-run: %v", err)
	}
	var file hooksFileJSON
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, p := range file.Programs {
		for _, h := range p.Hooks {
			types[h.Call] = h.RetType
		}
	}
	if types["bpf_xdp_ct_lookup"] != "nf_conn" || types["bpf_skc_lookup_tcp"] != "sock_common" {
		t.Errorf("hook types %v", types)
	}
	result, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the loader did not finish: %v", err)
	}
	var res retMemberResult
	if err := json.Unmarshal(result, &res); err == nil && res.Error == "skipped" {
		t.Skip("the loader skipped")
	}
	if err != nil || !res.Done {
		t.Fatalf("loader: %s", result)
	}
}
