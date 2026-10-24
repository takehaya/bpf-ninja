package inject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

func lookupFixture() *ebpf.CollectionSpec {
	u32 := &btf.Int{Name: "u32", Size: 4}
	u64 := &btf.Int{Name: "u64", Size: 8}
	ctx := &btf.Struct{Name: "xdp_md", Size: 24, Members: []btf.Member{
		{Name: "data", Type: u32}, {Name: "data_end", Type: u32, Offset: 32},
	}}
	fn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: ctx}}},
	}}
	short := asm.JGT.Reg(asm.R3, asm.R4, "")
	short.Offset = 10 // slot 4 -> 15
	missing := asm.JEq.Imm(asm.R0, 0, "")
	missing.Offset = 2 // slot 12 -> 15
	insns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),            // 0: data
		asm.LoadMem(asm.R4, asm.R1, 4, asm.Word),            // 1: data_end
		asm.Mov.Reg(asm.R3, asm.R2),                         // 2
		asm.Add.Imm(asm.R3, 4),                              // 3
		short,                                               // 4
		asm.LoadMem(asm.R2, asm.R2, 0, asm.Word),            // 5: packet key
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),         // 6
		asm.Mov.Reg(asm.R2, asm.RFP),                        // 7
		asm.Add.Imm(asm.R2, -4),                             // 8
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), // 9-10
		asm.FnMapLookupElem.Call(),                          // 11
		missing,                                             // 12
		asm.LoadMem(asm.R0, asm.R0, 0, asm.DWord),           // 13: use restored result (seid = action)
		asm.Return(),                                        // 14
		asm.Mov.Imm(asm.R0, 1),                              // 15: miss -> XDP_DROP
		asm.Return(),                                        // 16
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("lookup fixture")), fn)
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"sessions": {
			Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 16, MaxEntries: 4,
			Key: u32, Value: &btf.Struct{Name: "session", Size: 16, Members: []btf.Member{
				{Name: "seid", Type: u64}, {Name: "imsi", Type: u64, Offset: 64},
			}},
		}},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

func lookupReq() LookupRequest {
	return LookupRequest{ProgramName: "p", Site: LookupSelector{MapName: "sessions"},
		HookName: "lookup_hook", Stack: StackAudit{LowestOffset: -8}}
}

func lookupObserver(t *testing.T, hook string, target *ebpf.Program) *ebpf.CollectionSpec {
	t.Helper()
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	var xdp *btf.Struct
	if err := kernel.TypeByName("xdp_buff", &xdp); err != nil {
		t.Fatal(err)
	}
	offsets := map[string]int16{}
	for _, member := range xdp.Members {
		if member.Name == "data" || member.Name == "data_end" {
			offsets[member.Name] = int16(member.Offset.Bytes())
		}
	}
	if len(offsets) != 2 {
		t.Fatal("kernel xdp_buff lacks data/data_end")
	}
	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord), // xdp ctx
		asm.Mov.Reg(asm.R9, asm.R1),
		asm.Mov.Imm(asm.R2, 1), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
		asm.FnGetFuncArg.Call(),
		asm.JNE.Imm(asm.R0, 0, "done"),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.Mov.Imm(asm.R2, 2), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -24),
		asm.FnGetFuncArg.Call(),
		asm.JNE.Imm(asm.R0, 0, "done"),
		asm.LoadMem(asm.R7, asm.RFP, -16, asm.DWord), // raw key pointer
		asm.LoadMem(asm.R8, asm.RFP, -24, asm.DWord), // raw value pointer
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -28),
		asm.Mov.Imm(asm.R2, 4), asm.Mov.Reg(asm.R3, asm.R7), asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, "done"),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -40),
		asm.Mov.Imm(asm.R2, 8), asm.Mov.Reg(asm.R3, asm.R8), asm.Add.Imm(asm.R3, 8),
		asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, "done"),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("obs"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord), asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		// The tracing verifier translates xdp_md to the kernel's xdp_buff.
		asm.LoadMem(asm.R1, asm.R6, offsets["data"], asm.DWord),
		asm.LoadMem(asm.R2, asm.R6, offsets["data_end"], asm.DWord),
		asm.Sub.Reg(asm.R2, asm.R1),
		asm.StoreMem(asm.R0, 8, asm.R2, asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, -28, asm.Word),
		asm.StoreMem(asm.R0, 12, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, -40, asm.DWord),
		asm.StoreMem(asm.R0, 16, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return(),
	}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"obs": {Type: ebpf.Array, KeySize: 4, ValueSize: 24, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"observe": {
			Name: "lookup_observe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: hook, AttachTarget: target, License: "GPL", Instructions: insns,
		}},
	}
}

func TestBpfLookupInjectionObservesContextKeyValue(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain := loadOrSkip(t, lookupFixture())
	t.Cleanup(plain.Close)
	work := lookupFixture()
	if _, err := transformLookup(work, lookupReq()); err != nil {
		t.Fatal(err)
	}
	injected := loadOrSkip(t, work)
	t.Cleanup(injected.Close)
	for _, c := range []*ebpf.Collection{plain, injected} {
		for i, key := range []uint32{7, 0xffffffff} {
			if err := c.Maps["sessions"].Put(key, [2]uint64{2, uint64(100000000000001 + i)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	obs := loadOrSkip(t, lookupObserver(t, lookupReq().HookName, injected.Programs["p"]))
	t.Cleanup(obs.Close)
	run := func(t *testing.T, key uint32, length int) {
		t.Helper()
		packet := make([]byte, length)
		binary.LittleEndian.PutUint32(packet, key)
		want := uint32(2)
		if key == 99 {
			want = 1
		}
		for _, c := range []*ebpf.Collection{plain, injected} {
			out := make([]byte, len(packet))
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Repeat: 1})
			if err != nil || ret != want || !bytes.Equal(packet, out) {
				t.Fatalf("run key=%d: action=%d want=%d err=%v output equal=%v", key, ret, want, err, bytes.Equal(packet, out))
			}
		}
	}
	read := func(t *testing.T) [24]byte {
		t.Helper()
		var record [24]byte
		if err := obs.Maps["obs"].Lookup(uint32(0), &record); err != nil {
			t.Fatal(err)
		}
		return record
	}
	run(t, 7, 64)
	if got := read(t); got != [24]byte{} {
		t.Fatal("observation before attach")
	}
	attached, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("fentry unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { attached.Close() })
	for i, tc := range []struct {
		name   string
		key    uint32
		length int
	}{{"first_key", 7, 64}, {"second_key", 0xffffffff, 96}, {"missing_key", 99, 80}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := obs.Maps["obs"].Put(uint32(0), [24]byte{}); err != nil {
				t.Fatal(err)
			}
			run(t, tc.key, tc.length)
			got := read(t)
			if tc.key == 99 {
				if got != [24]byte{} {
					t.Fatalf("miss generated observation: %x", got)
				}
				return
			}
			seen, length, key, imsi := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[8:]),
				binary.LittleEndian.Uint32(got[12:]), binary.LittleEndian.Uint64(got[16:])
			if seen != 1 || length != uint32(tc.length) || key != tc.key || imsi != uint64(100000000000001+i) {
				t.Fatalf("got seen=%d length=%d key=%d imsi=%d", seen, length, key, imsi)
			}
		})
	}
	if err := attached.Close(); err != nil {
		t.Fatal(err)
	}
	run(t, 7, 64)
	if got := read(t); got != [24]byte{} {
		t.Fatal("observation after detach")
	}
}
