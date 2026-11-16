package inject

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Call fixtures are plain programs that call helpers and kfuncs reading
// state outside the program (clock, CPU, routes, sockets, conntrack). They
// write what they saw into "out", one array entry of four u64 slots read by
// direct value access, so they contain no map helper call. Call positions
// below are raw instruction offsets (SitePC); TestCallFixtureShape checks them.

// callFixtureSpec gives insns the entry symbol p and XDP or tc BTF, after
// resolving its labelled jumps.
func callFixtureSpec(typ ebpf.ProgramType, insns asm.Instructions) *ebpf.CollectionSpec {
	insns = equivResolveBranches(insns)
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("call fixture")), xdpFunc("p"))
	spec := &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps:     map[string]*ebpf.MapSpec{"out": {Name: "out", Type: ebpf.Array, KeySize: 4, ValueSize: 32, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
	if typ != ebpf.XDP {
		return asTC(spec)
	}
	return spec
}

// outStore stores src (not R1) in out slot n, leaving the value's address in R1.
func outStore(n int16, src asm.Register) asm.Instructions {
	return asm.Instructions{asm.LoadMapValue(asm.R1, 0, 0).WithReference("out"), asm.StoreMem(asm.R1, 8*n, src, asm.DWord)}
}

// callVerdicts are a forwarder's actions: forward, pass to the stack, drop.
func callVerdicts(typ ebpf.ProgramType) (fwd, pass, drop int32) {
	if typ == ebpf.XDP {
		return 3, 2, 1 // XDP_TX, XDP_PASS, XDP_DROP
	}
	return 7, 0, 2 // TC_ACT_REDIRECT, TC_ACT_OK, TC_ACT_SHOT
}

// kfuncCall calls the vmlinux kfunc with BTF id id. cilium/ebpf resolves
// kfunc names only for instructions read from an ELF.
func kfuncCall(id int64) asm.Instruction {
	return asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: id}
}

// ipImm is an IPv4 address as the immediate of a 4-byte store.
func ipImm(a [4]byte) int64 { return int64(int32(binary.LittleEndian.Uint32(a[:]))) }

// portImm is a port in network order as the immediate of a 2-byte store.
func portImm(p uint16) int64 { return int64(p>>8 | p<<8) }

// scalarFixture (XDP) calls bpf_ktime_get_ns at 0, bpf_get_smp_processor_id
// at 4, bpf_get_prandom_u32 at 8 and bpf_jiffies64 at 12, stores the results
// in out slots 0 to 3 and returns XDP_PASS.
func scalarFixture() *ebpf.CollectionSpec {
	var insns asm.Instructions
	for i, fn := range []asm.BuiltinFunc{asm.FnKtimeGetNs, asm.FnGetSmpProcessorId, asm.FnGetPrandomU32, asm.FnJiffies64} {
		insns = append(append(insns, fn.Call()), outStore(int16(i), asm.R0)...)
	}
	return callFixtureSpec(ebpf.XDP, append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return()))
}

// adjacentFixture (XDP) calls bpf_ktime_get_ns at 0 and bpf_jiffies64 at 1,
// stores the second result in out slot 0 and returns XDP_PASS.
func adjacentFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{asm.FnKtimeGetNs.Call(), asm.FnJiffies64.Call()}
	insns = append(insns, outStore(0, asm.R0)...)
	return callFixtureSpec(ebpf.XDP, append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return()))
}

// loopFixture (XDP) runs bpf_loop (at 5) four times over the callback cb,
// which calls bpf_ktime_get_ns (at 11), stores it in out slot 0 and counts
// itself in slot 1. The entry stores bpf_loop's result in slot 2 and returns
// XDP_PASS.
func loopFixture() *ebpf.CollectionSpec {
	cb := &btf.Func{Name: "cb", Linkage: btf.StaticFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "index", Type: &btf.Int{Name: "u32", Size: 4}}, {Name: "data", Type: &btf.Pointer{Target: &btf.Void{}}}},
	}}
	insns := asm.Instructions{asm.Mov.Imm(asm.R1, 4), callbackLoad(asm.R2, -1, "cb"), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()}
	insns = append(insns, outStore(2, asm.R0)...)
	insns = append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return(),
		btf.WithFuncMetadata(asm.FnKtimeGetNs.Call().WithSymbol("cb").WithSource(asm.Comment("loop callback")), cb))
	insns = append(insns, outStore(0, asm.R0)...)
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R1, 8, asm.DWord), asm.Add.Imm(asm.R2, 1), asm.StoreMem(asm.R1, 8, asm.R2, asm.DWord),
		asm.Mov.Imm(asm.R0, 0), asm.Return())
	return callFixtureSpec(ebpf.XDP, insns)
}

// The fib fixtures look up fibDst from fibSrc; tests route it through fibGw.
var fibSrc, fibGw, fibDst = [4]byte{10, 201, 0, 1}, [4]byte{10, 201, 0, 2}, [4]byte{10, 201, 9, 9}

// fibCall fills a zeroed struct bpf_fib_lookup at fp-64 (AF_INET, fibSrc to
// fibDst, ifindex from the ctx in R6), calls bpf_fib_lookup(ctx, params, 64,
// 0) 19 instructions in, and stores the code, the output ifindex and the 8
// bytes ending with dmac in out slots 0 to 2. The code stays in R7.
func fibCall(typ ebpf.ProgramType) asm.Instructions {
	ifindex := int16(12) // xdp_md.ingress_ifindex
	if typ != ebpf.XDP {
		ifindex = 40 // __sk_buff.ifindex
	}
	insns := asm.Instructions{asm.Mov.Imm(asm.R1, 0)}
	for off := int16(-64); off < 0; off += 8 {
		insns = append(insns, asm.StoreMem(asm.RFP, off, asm.R1, asm.DWord))
	}
	insns = append(insns,
		asm.StoreImm(asm.RFP, -64, unix.AF_INET, asm.Byte),
		asm.LoadMem(asm.R1, asm.R6, ifindex, asm.Word),
		asm.StoreMem(asm.RFP, -64+8, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, -64+16, ipImm(fibSrc), asm.Word),
		asm.StoreImm(asm.RFP, -64+32, ipImm(fibDst), asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -64),
		asm.Mov.Imm(asm.R3, 64), asm.Mov.Imm(asm.R4, 0),
		asm.FnFibLookup.Call(),
		asm.Mov.Reg(asm.R7, asm.R0))
	insns = append(insns, outStore(0, asm.R7)...)
	return append(insns,
		asm.LoadMem(asm.R2, asm.RFP, -64+8, asm.Word), asm.StoreMem(asm.R1, 8, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord), asm.StoreMem(asm.R1, 16, asm.R2, asm.DWord))
}

// fibVerdict returns by the code in R7 as a forwarder does: forward on
// success, drop on blackhole, unreachable or prohibit (1 to 3), else pass the
// packet to the stack (not forwarded, forwarding disabled, no neighbour, ...).
func fibVerdict(typ ebpf.ProgramType) asm.Instructions {
	fwd, pass, drop := callVerdicts(typ)
	return asm.Instructions{
		asm.JEq.Imm(asm.R7, 0, "fib_fwd"),
		asm.JGT.Imm(asm.R7, 3, "fib_pass"),
		asm.Mov.Imm(asm.R0, drop), asm.Return(),
		asm.Mov.Imm(asm.R0, pass).WithSymbol("fib_pass"), asm.Return(),
		asm.Mov.Imm(asm.R0, fwd).WithSymbol("fib_fwd"), asm.Return(),
	}
}

// fibFixture calls bpf_fib_lookup at 20 in the entry.
func fibFixture(typ ebpf.ProgramType) *ebpf.CollectionSpec {
	insns := append(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, fibCall(typ)...)
	return callFixtureSpec(typ, append(insns, fibVerdict(typ)...))
}

// fibSubprogFixture is fibFixture with the lookup in the static subprogram
// fib_sub (at 10), which gets ctx as its first argument and returns the code;
// bpf_fib_lookup is at 30.
func fibSubprogFixture(typ ebpf.ProgramType) *ebpf.CollectionSpec {
	insns := append(asm.Instructions{asm.Call.Label("fib_sub"), asm.Mov.Reg(asm.R7, asm.R0)}, fibVerdict(typ)...)
	insns = append(insns, btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("fib_sub").WithSource(asm.Comment("fib subprogram")), staticFunc("fib_sub")))
	insns = append(insns, fibCall(typ)...)
	return callFixtureSpec(typ, append(insns, asm.Mov.Reg(asm.R0, asm.R7), asm.Return()))
}

// loadBytesAt and loadBytesLen are the packet range loadBytesFixture copies.
const loadBytesAt, loadBytesLen = 56, 8

// loadBytesFixture copies packet bytes 56 to 63 into a zeroed fp-8 with
// bpf_xdp_load_bytes (tc: bpf_skb_load_bytes) at 8, stores the code and the
// buffer in out slots 0 and 1 and passes on success, else drops.
func loadBytesFixture(typ ebpf.ProgramType) *ebpf.CollectionSpec {
	_, pass, drop := callVerdicts(typ)
	fn := asm.FnXdpLoadBytes
	if typ != ebpf.XDP {
		fn = asm.FnSkbLoadBytes
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Imm(asm.R1, 0), asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, loadBytesAt),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8), asm.Mov.Imm(asm.R4, loadBytesLen),
		fn.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
	}
	insns = append(insns, outStore(0, asm.R7)...)
	return callFixtureSpec(typ, append(insns,
		asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord), asm.StoreMem(asm.R1, 8, asm.R2, asm.DWord),
		asm.JEq.Imm(asm.R7, 0, "lb_pass"),
		asm.Mov.Imm(asm.R0, drop), asm.Return(),
		asm.Mov.Imm(asm.R0, pass).WithSymbol("lb_pass"), asm.Return()))
}

// skLookupFixture looks up the TCP socket for 127.0.0.1:4321 to
// 127.0.0.1:dport in the current netns with bpf_sk_lookup_tcp at 11, and
// on a hit releases it with bpf_sk_release at 16 and passes; a miss drops.
func skLookupFixture(typ ebpf.ProgramType, dport uint16) *ebpf.CollectionSpec {
	_, pass, drop := callVerdicts(typ)
	lo := [4]byte{127, 0, 0, 1}
	return callFixtureSpec(typ, asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -16, ipImm(lo), asm.Word),
		asm.StoreImm(asm.RFP, -12, ipImm(lo), asm.Word),
		asm.StoreImm(asm.RFP, -8, portImm(4321), asm.Half),
		asm.StoreImm(asm.RFP, -6, portImm(dport), asm.Half),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16), asm.Mov.Imm(asm.R3, 12),
		asm.Mov.Imm(asm.R4, -1), // BPF_F_CURRENT_NETNS
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkLookupTcp.Call(),
		asm.JNE.Imm(asm.R0, 0, "sk_hit"),
		asm.Mov.Imm(asm.R0, drop), asm.Return(),
		asm.Mov.Reg(asm.R1, asm.R0).WithSymbol("sk_hit"),
		asm.FnSkRelease.Call(),
		asm.Mov.Imm(asm.R0, pass), asm.Return(),
	})
}

// ctPrefix returns "bpf_xdp_ct_" or, for tc, "bpf_skb_ct_".
func ctPrefix(typ ebpf.ProgramType) string {
	if typ == ebpf.XDP {
		return "bpf_xdp_ct_"
	}
	return "bpf_skb_ct_"
}

// ctCall writes the tuple 10.77.0.1:4321 to 10.77.0.2:dport at fp-16 and a
// struct bpf_ct_opts {netns_id -1, l4proto TCP} at fp-32, then calls the
// lookup or alloc kfunc fn on them (at 17), ctx in R6.
func ctCall(fn asm.Instruction, dport uint16) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -16, ipImm([4]byte{10, 77, 0, 1}), asm.Word),
		asm.StoreImm(asm.RFP, -12, ipImm([4]byte{10, 77, 0, 2}), asm.Word),
		asm.StoreImm(asm.RFP, -8, portImm(4321), asm.Half),
		asm.StoreImm(asm.RFP, -6, portImm(dport), asm.Half),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.StoreImm(asm.RFP, -32, -1, asm.Word),
		asm.StoreImm(asm.RFP, -28, 0, asm.Word),
		asm.StoreImm(asm.RFP, -24, unix.IPPROTO_TCP, asm.Word),
		asm.StoreImm(asm.RFP, -20, 0, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16), asm.Mov.Imm(asm.R3, 12),
		asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -32), asm.Mov.Imm(asm.R5, 12),
		fn,
	}
}

// ctFixture calls bpf_xdp_ct_lookup (tc: bpf_skb_ct_lookup) at 17. A miss
// stores opts.error in out slot 1 and drops. A hit stores ct->status (at
// statusOff in struct nf_conn) in slot 0, calls bpf_ct_release and passes:
// at 31 in ctFixture, at 37 with unchecked. unchecked first keeps the result
// in R7, calls bpf_ktime_get_ns (at 19) and stores it in slot 2, and only
// then tests the result for NULL. kfunc gives the call of a named kfunc.
func ctFixture(typ ebpf.ProgramType, kfunc func(string) asm.Instruction, statusOff int16, dport uint16, unchecked bool) *ebpf.CollectionSpec {
	_, pass, drop := callVerdicts(typ)
	insns := ctCall(kfunc(ctPrefix(typ)+"lookup"), dport)
	if unchecked {
		insns = append(insns, asm.Mov.Reg(asm.R7, asm.R0), asm.FnKtimeGetNs.Call())
		insns = append(insns, outStore(2, asm.R0)...)
		insns = append(insns, asm.Mov.Reg(asm.R0, asm.R7))
	}
	insns = append(insns, asm.JNE.Imm(asm.R0, 0, "ct_hit"), asm.LoadMem(asm.R2, asm.RFP, -28, asm.Word))
	insns = append(insns, outStore(1, asm.R2)...)
	insns = append(insns, asm.Mov.Imm(asm.R0, drop), asm.Return(),
		asm.Mov.Reg(asm.R7, asm.R0).WithSymbol("ct_hit"), asm.LoadMem(asm.R2, asm.R7, statusOff, asm.DWord))
	insns = append(insns, outStore(0, asm.R2)...)
	return callFixtureSpec(typ, append(insns,
		asm.Mov.Reg(asm.R1, asm.R7), kfunc("bpf_ct_release"),
		asm.Mov.Imm(asm.R0, pass), asm.Return()))
}

// ctInsertProgram is test setup, not a fixture: it allocates the entry
// ctFixture looks up, inserts it with a 30 s timeout and returns 1.
func ctInsertProgram(typ ebpf.ProgramType, kfunc func(string) asm.Instruction, dport uint16) *ebpf.CollectionSpec {
	insns := append(ctCall(kfunc(ctPrefix(typ)+"alloc"), dport),
		asm.JNE.Imm(asm.R0, 0, "ct_allocated"),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
		asm.Mov.Reg(asm.R7, asm.R0).WithSymbol("ct_allocated"),
		asm.Mov.Reg(asm.R1, asm.R7), asm.Mov.Imm(asm.R2, 30000),
		kfunc("bpf_ct_set_timeout"),
		asm.Mov.Reg(asm.R1, asm.R7),
		kfunc("bpf_ct_insert_entry"),
		asm.JNE.Imm(asm.R0, 0, "ct_inserted"),
		asm.Mov.Imm(asm.R0, 3), asm.Return(),
		asm.Mov.Reg(asm.R1, asm.R0).WithSymbol("ct_inserted"),
		kfunc("bpf_ct_release"),
		asm.Mov.Imm(asm.R0, 1), asm.Return())
	return callFixtureSpec(typ, insns)
}

// callNames lists the helper and kfunc calls in insns as "offset:name",
// naming a kfunc by kfuncs[id].
func callNames(insns asm.Instructions, kfuncs map[int64]string) []string {
	var calls []string
	it := insns.Iterate()
	for it.Next() {
		switch {
		case it.Ins.IsBuiltinCall():
			calls = append(calls, fmt.Sprintf("%d:%v", it.Offset, asm.BuiltinFunc(it.Ins.Constant)))
		case it.Ins.IsKfuncCall():
			calls = append(calls, fmt.Sprintf("%d:%s", it.Offset, kfuncs[it.Ins.Constant]))
		}
	}
	return calls
}

// TestCallFixtureShape checks that every call fixture assembles, that its
// calls sit where its comment says, and that map-call discovery finds no
// site in it: the out map is read by direct value access.
func TestCallFixtureShape(t *testing.T) {
	kfuncs := map[int64]string{}
	kfunc := func(name string) asm.Instruction {
		id := int64(1000 + len(kfuncs))
		kfuncs[id] = name
		return kfuncCall(id)
	}
	fib := []string{"20:FnFibLookup"}
	sub := []string{"30:FnFibLookup"}
	sk := []string{"11:FnSkLookupTcp", "16:FnSkRelease"}
	for _, tc := range []struct {
		name string
		spec *ebpf.CollectionSpec
		want []string
	}{
		{"scalar", scalarFixture(), []string{"0:FnKtimeGetNs", "4:FnGetSmpProcessorId", "8:FnGetPrandomU32", "12:FnJiffies64"}},
		{"adjacent", adjacentFixture(), []string{"0:FnKtimeGetNs", "1:FnJiffies64"}},
		{"loop", loopFixture(), []string{"5:FnLoop", "11:FnKtimeGetNs"}},
		{"fib xdp", fibFixture(ebpf.XDP), fib},
		{"fib tc", fibFixture(ebpf.SchedCLS), fib},
		{"fib subprogram xdp", fibSubprogFixture(ebpf.XDP), sub},
		{"fib subprogram tc", fibSubprogFixture(ebpf.SchedCLS), sub},
		{"load bytes xdp", loadBytesFixture(ebpf.XDP), []string{"8:FnXdpLoadBytes"}},
		{"load bytes tc", loadBytesFixture(ebpf.SchedCLS), []string{"8:FnSkbLoadBytes"}},
		{"sk lookup xdp", skLookupFixture(ebpf.XDP, 80), sk},
		{"sk lookup tc", skLookupFixture(ebpf.SchedCLS, 80), sk},
		{"ct xdp", ctFixture(ebpf.XDP, kfunc, 8, 80, false), []string{"17:bpf_xdp_ct_lookup", "31:bpf_ct_release"}},
		{"ct tc", ctFixture(ebpf.SchedCLS, kfunc, 8, 80, false), []string{"17:bpf_skb_ct_lookup", "31:bpf_ct_release"}},
		{"ct unchecked xdp", ctFixture(ebpf.XDP, kfunc, 8, 80, true), []string{"17:bpf_xdp_ct_lookup", "19:FnKtimeGetNs", "37:bpf_ct_release"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prog := tc.spec.Programs["p"]
			if err := slices.Clone(prog.Instructions).Marshal(io.Discard, binary.LittleEndian); err != nil {
				t.Fatalf("assemble: %v", err)
			}
			if got := callNames(prog.Instructions, kfuncs); !slices.Equal(got, tc.want) {
				t.Fatalf("calls %v, want %v", got, tc.want)
			}
			sites, err := discoverMapCalls(prog.Instructions, prog.Type, elfLookupMaps(tc.spec))
			if err != nil || len(sites) != 0 {
				t.Fatalf("map calls %+v, %v; want none", sites, err)
			}
			if sites, err := discoverLookupProgram(prog.Instructions, prog.Type, elfLookupMaps(tc.spec)); err != nil || len(sites) != 0 {
				t.Fatalf("lookups %+v, %v; want none", sites, err)
			}
		})
	}
}

// kernelKfunc is the call of the vmlinux kfunc name.
func kernelKfunc(t *testing.T, name string) asm.Instruction {
	t.Helper()
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatalf("kernel BTF: %v", err)
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		t.Fatalf("kfunc %s: %v", name, err)
	}
	id, err := spec.TypeID(fn)
	if err != nil {
		t.Fatalf("kfunc %s: %v", name, err)
	}
	return kfuncCall(int64(id))
}

// nfConnStatusOffset is the byte offset of status in the kernel's struct nf_conn.
func nfConnStatusOffset(t *testing.T) int16 {
	t.Helper()
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatalf("kernel BTF: %v", err)
	}
	var conn *btf.Struct
	if err := spec.TypeByName("nf_conn", &conn); err != nil {
		t.Fatalf("nf_conn: %v", err)
	}
	for _, m := range conn.Members {
		if m.Name == "status" {
			return int16(m.Offset.Bytes())
		}
	}
	t.Fatal("kernel nf_conn lacks status")
	return 0
}

// loadCallFixture loads spec and closes it at cleanup.
func loadCallFixture(t *testing.T, spec *ebpf.CollectionSpec) *ebpf.Collection {
	t.Helper()
	coll := loadOrSkip(t, spec)
	t.Cleanup(coll.Close)
	return coll
}

// runCallFixture runs coll's program once on data with ctx (nil for none)
// and returns its action and out value.
func runCallFixture(t *testing.T, coll *ebpf.Collection, data []byte, ctx any) (uint32, [4]uint64) {
	t.Helper()
	ret, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: data, Context: ctx, Repeat: 1})
	if err != nil {
		t.Fatalf("test run: %v", err)
	}
	var out [4]uint64
	if err := coll.Maps["out"].Lookup(uint32(0), &out); err != nil {
		t.Fatal(err)
	}
	return ret, out
}

func TestBpfCallFixtureScalars(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	coll := loadCallFixture(t, scalarFixture())
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	ret, first := runCallFixture(t, coll, make([]byte, 64), nil)
	_, second := runCallFixture(t, coll, make([]byte, 64), nil)
	t.Logf("ktime, cpu, prandom, jiffies: %v then %v", first, second)
	switch {
	case ret != 2:
		t.Fatalf("action %d, want XDP_PASS", ret)
	case first[0] == 0 || second[0] <= first[0]:
		t.Fatal("bpf_ktime_get_ns is zero or did not increase")
	case first[1] >= uint64(cpus) || second[1] >= uint64(cpus):
		t.Fatalf("bpf_get_smp_processor_id not below the %d possible CPUs", cpus)
	case first[2] == second[2]:
		t.Fatal("bpf_get_prandom_u32 returned the same value twice")
	case first[3] == 0 || second[3] < first[3]:
		t.Fatal("bpf_jiffies64 is zero or went back")
	}
}

func TestBpfCallFixtureAdjacent(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if ret, out := runCallFixture(t, loadCallFixture(t, adjacentFixture()), make([]byte, 64), nil); ret != 2 || out[0] == 0 {
		t.Fatalf("action %d, jiffies %d; want XDP_PASS and non-zero", ret, out[0])
	}
}

func TestBpfCallFixtureLoop(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if ret, out := runCallFixture(t, loadCallFixture(t, loopFixture()), make([]byte, 64), nil); ret != 2 || out[0] == 0 || out[1] != 4 || out[2] != 4 {
		t.Fatalf("action %d, out %v; want XDP_PASS, non-zero ktime, 4 callback runs, bpf_loop 4", ret, out)
	}
}

// fibDevice creates the up device name, a vxlan device or, where that kind
// is unavailable, netkit, with fibSrc/24 and IPv4 forwarding on. It is
// removed at cleanup.
func fibDevice(t *testing.T, name string) netlink.Link {
	t.Helper()
	nk := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{Name: name}, Mode: netlink.NETKIT_MODE_L3,
		Policy: netlink.NETKIT_POLICY_FORWARD, PeerPolicy: netlink.NETKIT_POLICY_FORWARD}
	nk.SetPeerAttrs(&netlink.LinkAttrs{Name: name + "p"})
	var errs []error
	for _, link := range []netlink.Link{
		&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: name}, VxlanId: 4201, Port: 4789, SrcAddr: net.IPv4(127, 0, 0, 1)},
		nk,
	} {
		if err := netlink.LinkAdd(link); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", link.Type(), err))
			continue
		}
		t.Cleanup(func() { _ = netlink.LinkDel(link) })
		if peer, err := netlink.LinkByName(name + "p"); err == nil {
			if err := netlink.LinkSetUp(peer); err != nil {
				t.Fatal(err)
			}
		}
		dev, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(fibSrc[:]), Mask: net.CIDRMask(24, 32)}}
		if err := errors.Join(netlink.LinkSetUp(dev), netlink.AddrAdd(dev, addr),
			os.WriteFile("/proc/sys/net/ipv4/conf/"+name+"/forwarding", []byte("1"), 0o644)); err != nil {
			t.Fatalf("setting up %s: %v", link.Type(), err)
		}
		t.Logf("%s device %s, ifindex %d", link.Type(), name, dev.Attrs().Index)
		return dev
	}
	t.Skipf("skipping: neither a vxlan nor a netkit device can be created: %v", errors.Join(errs...))
	return nil
}

// testCallFixtureFib runs fibFixture and fibSubprogFixture with ifindex in
// ctx: with no route the lookup is not forwarded (4, pass), through an
// unreachable route it is unreachable (2, drop), through a gateway without a
// neighbour it has no neighbour (7, pass), and with the neighbour it succeeds
// (0, forward) with the device's ifindex and the neighbour's MAC.
func testCallFixtureFib(t *testing.T, typ ebpf.ProgramType, name string) {
	testutil.SkipIfNotRoot(t)
	colls := []*ebpf.Collection{loadCallFixture(t, fibFixture(typ)), loadCallFixture(t, fibSubprogFixture(typ))}
	dev := fibDevice(t, name)
	index := dev.Attrs().Index
	packet := make([]byte, 64)
	ctx := fibCtx(typ, index, len(packet))
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 0x42}
	fwd, pass, drop := callVerdicts(typ)
	actions := map[uint64]int32{4: pass, 2: drop, 7: pass, 0: fwd}
	fibSteps(t, index, func(step string, code uint64) {
		t.Helper()
		action := actions[code]
		for i, coll := range colls {
			ret, out := runCallFixture(t, coll, packet, ctx)
			if ret != uint32(action) || out[0] != code {
				t.Fatalf("%s, fixture %d: action %d code %d, want %d and %d", step, i, ret, out[0], action, code)
			}
			if code != 0 {
				continue
			}
			got := binary.LittleEndian.AppendUint64(nil, out[2])[2:]
			if out[1] != uint64(index) || !slices.Equal(got, mac) {
				t.Fatalf("%s, fixture %d: ifindex %d dmac %x, want %d and %s", step, i, out[1], got, index, mac)
			}
		}
	})
}

// fibCtx is the context of a fib fixture run on the device index.
func fibCtx(typ ebpf.ProgramType, index, size int) any {
	if typ != ebpf.XDP {
		var skb [48]uint32 // struct __sk_buff
		skb[10] = uint32(index)
		return skb
	}
	return [6]uint32{0, uint32(size), 0, uint32(index)} // struct xdp_md
}

// fibSteps sets up the routes of testCallFixtureFib on the device index one
// by one and calls check after each with the lookup's expected code: no
// route, an unreachable route, a gateway without and with its neighbour
// (MAC 02:00:00:00:00:42).
func fibSteps(t *testing.T, index int, check func(step string, code uint64)) {
	t.Helper()
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 0x42}
	dst := &net.IPNet{IP: net.IP{fibDst[0], fibDst[1], fibDst[2], 0}, Mask: net.CIDRMask(24, 32)}
	unreachable := &netlink.Route{Dst: dst, Type: unix.RTN_UNREACHABLE}
	check("no route", 4) // BPF_FIB_LKUP_RET_NOT_FWDED
	if err := netlink.RouteAdd(unreachable); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(unreachable) }) // when a check fails before the next step
	check("unreachable route", 2) // BPF_FIB_LKUP_RET_UNREACHABLE
	if err := errors.Join(netlink.RouteDel(unreachable),
		netlink.RouteAdd(&netlink.Route{LinkIndex: index, Dst: dst, Gw: net.IP(fibGw[:])})); err != nil {
		t.Fatal(err)
	}
	check("route without neighbour", 7) // BPF_FIB_LKUP_RET_NO_NEIGH
	if err := netlink.NeighSet(&netlink.Neigh{LinkIndex: index, State: netlink.NUD_PERMANENT, IP: net.IP(fibGw[:]), HardwareAddr: mac}); err != nil {
		t.Fatal(err)
	}
	check("route and neighbour", 0)
}

func TestBpfCallFixtureFibXDP(t *testing.T) { testCallFixtureFib(t, ebpf.XDP, "cfxfibx") }
func TestBpfCallFixtureFibTC(t *testing.T)  { testCallFixtureFib(t, ebpf.SchedCLS, "cfxfibt") }

// testCallFixtureLoadBytes copies the bytes from a 64-byte packet, and fails
// on a 32-byte one with the buffer left zero.
func testCallFixtureLoadBytes(t *testing.T, typ ebpf.ProgramType, short unix.Errno) {
	testutil.SkipIfNotRoot(t)
	coll := loadCallFixture(t, loadBytesFixture(typ))
	_, pass, drop := callVerdicts(typ)
	packet := make([]byte, 64)
	copy(packet[loadBytesAt:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if ret, out := runCallFixture(t, coll, packet, nil); ret != uint32(pass) || out[0] != 0 || out[1] != binary.LittleEndian.Uint64(packet[loadBytesAt:]) {
		t.Fatalf("64-byte packet: action %d, out %#x", ret, out)
	}
	if ret, out := runCallFixture(t, coll, packet[:32], nil); ret != uint32(drop) || int64(out[0]) != -int64(short) || out[1] != 0 {
		t.Fatalf("32-byte packet: action %d, code %d, buffer %#x; want %d, -%d (%v), 0", ret, int64(out[0]), out[1], drop, short, short)
	}
}

func TestBpfCallFixtureLoadBytesXDP(t *testing.T) {
	testCallFixtureLoadBytes(t, ebpf.XDP, unix.EINVAL)
}
func TestBpfCallFixtureLoadBytesTC(t *testing.T) {
	testCallFixtureLoadBytes(t, ebpf.SchedCLS, unix.EFAULT)
}

// testCallFixtureSkLookup finds a listener on 127.0.0.1 and misses once it is
// closed.
func testCallFixtureSkLookup(t *testing.T, typ ebpf.ProgramType) {
	testutil.SkipIfNotRoot(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	coll := loadCallFixture(t, skLookupFixture(typ, uint16(l.Addr().(*net.TCPAddr).Port)))
	_, pass, drop := callVerdicts(typ)
	if ret, _ := runCallFixture(t, coll, make([]byte, 64), nil); ret != uint32(pass) {
		t.Fatalf("listening: action %d, want %d", ret, pass)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if ret, _ := runCallFixture(t, coll, make([]byte, 64), nil); ret != uint32(drop) {
		t.Fatalf("closed: action %d, want %d", ret, drop)
	}
}

func TestBpfCallFixtureSkLookupXDP(t *testing.T) { testCallFixtureSkLookup(t, ebpf.XDP) }
func TestBpfCallFixtureSkLookupTC(t *testing.T)  { testCallFixtureSkLookup(t, ebpf.SchedCLS) }

// testCallFixtureCt runs ctFixture, checked and unchecked, before and after
// ctInsertProgram adds the entry: a miss with -ENOENT, then a hit whose
// status has IPS_CONFIRMED.
func testCallFixtureCt(t *testing.T, typ ebpf.ProgramType, dport uint16) {
	testutil.SkipIfNotRoot(t)
	kfunc := func(name string) asm.Instruction { return kernelKfunc(t, name) }
	status := nfConnStatusOffset(t)
	colls := []*ebpf.Collection{
		loadCallFixture(t, ctFixture(typ, kfunc, status, dport, false)),
		loadCallFixture(t, ctFixture(typ, kfunc, status, dport, true)),
	}
	_, pass, drop := callVerdicts(typ)
	for i, coll := range colls {
		if ret, out := runCallFixture(t, coll, make([]byte, 64), nil); ret != uint32(drop) || int32(out[1]) != -int32(unix.ENOENT) {
			t.Fatalf("fixture %d before insert: action %d, error %d; want %d, -ENOENT", i, ret, int32(out[1]), drop)
		}
	}
	insert := loadCallFixture(t, ctInsertProgram(typ, kfunc, dport))
	if ret, err := insert.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 1 {
		t.Fatalf("insert: %d, %v; want 1", ret, err)
	}
	const confirmed = 1 << 3 // IPS_CONFIRMED
	for i, coll := range colls {
		if ret, out := runCallFixture(t, coll, make([]byte, 64), nil); ret != uint32(pass) || out[0]&confirmed == 0 || (i == 1 && out[2] == 0) {
			t.Fatalf("fixture %d after insert: action %d, out %#x; want %d, IPS_CONFIRMED", i, ret, out, pass)
		}
	}
}

func TestBpfCallFixtureCtXDP(t *testing.T) { testCallFixtureCt(t, ebpf.XDP, 8101) }
func TestBpfCallFixtureCtTC(t *testing.T)  { testCallFixtureCt(t, ebpf.SchedCLS, 8102) }

// fastcallFixture (XDP) wraps bpf_get_smp_processor_id at 2 in the fastcall
// spill and fill of R1 at fp-8, stores the result in out slot 0 and the
// filled R1 (7) in slot 1, and returns XDP_PASS.
func fastcallFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R1, 7),
		asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		asm.FnGetSmpProcessorId.Call(),
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.DWord),
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	insns = append(append(insns, outStore(0, asm.R0)...), outStore(1, asm.R6)...)
	return callFixtureSpec(ebpf.XDP, append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return()))
}
