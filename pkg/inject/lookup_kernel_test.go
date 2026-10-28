package inject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
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

// The packet key selects one of two paths, each with its own lookup helper.
func multiLookupFixture() *ebpf.CollectionSpec {
	spec := lookupFixture()
	original := spec.Programs["p"].Instructions
	branch, join := asm.JEq.Imm(asm.R2, 7, ""), asm.Ja.Label("")
	branch.Offset, join.Offset = 6, 5
	insns := append(asm.Instructions(nil), original[:7]...)
	insns[4].Offset = 17 // short packet -> shared drop
	insns = append(insns, branch)
	insns = append(insns, original[7:11]...)
	insns = append(insns, join)
	insns = append(insns, original[7:11]...)
	insns = append(insns, original[11:]...)
	spec.Programs["p"].Instructions = insns
	return spec
}

func lookupReq() LookupRequest {
	return LookupRequest{ProgramName: "p", Site: LookupSelector{MapName: "sessions"},
		HookName: "lookup_hook", Stack: StackAudit{LowestOffset: -8}}
}

// multiMapFixture is multiLookupFixture with the second lookup reading a
// different map whose value has its own BTF type: key 7 takes that path.
func multiMapFixture() *ebpf.CollectionSpec {
	spec := multiLookupFixture()
	insns := spec.Programs["p"].Instructions
	for i, seen := 0, 0; i < len(insns); i++ {
		if insns[i].IsLoadFromMap() {
			if seen++; seen == 2 {
				insns[i] = insns[i].WithReference("flows")
			}
		}
	}
	sessions := spec.Maps["sessions"]
	spec.Maps["flows"] = &ebpf.MapSpec{Name: "flows", Type: ebpf.Hash, KeySize: 4, ValueSize: 16, MaxEntries: 4,
		Key: sessions.Key, Value: &btf.Struct{Name: "flow", Size: 16, Members: []btf.Member{
			{Name: "seid", Type: &btf.Int{Name: "u64", Size: 8}},
			{Name: "imsi", Type: &btf.Int{Name: "u64", Size: 8}, Offset: 64},
		}}}
	return spec
}

func lookupObserver(t *testing.T, hook string, target *ebpf.Program) *ebpf.CollectionSpec {
	return lookupObserverArgs(t, hook, target, observerArgs{})
}

// observerArgs selects what lookupObserverArgs reads. site records the hook's
// u32 site argument at offset 24. mapID, which needs site, also records the id
// of the generic hook's map argument at 28. rawCtx reads the packet bounds
// through bpf_probe_read_kernel, for a static hook whose ctx argument the
// kernel passes as a u64.
type observerArgs struct{ site, mapID, rawCtx bool }

// bpfMapIDOffset is the byte offset of struct bpf_map's id in kernel.
func bpfMapIDOffset(t *testing.T, kernel *btf.Spec) int32 {
	t.Helper()
	var bpfMap *btf.Struct
	if err := kernel.TypeByName("bpf_map", &bpfMap); err != nil {
		t.Fatal(err)
	}
	for _, member := range bpfMap.Members {
		if member.Name == "id" {
			return int32(member.Offset.Bytes())
		}
	}
	t.Fatal("kernel bpf_map lacks id")
	return -1
}

// lookupObserverArgs records seen, packet length, key, value.imsi and what
// args selects.
func lookupObserverArgs(t *testing.T, hook string, target *ebpf.Program, args observerArgs) *ebpf.CollectionSpec {
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
	keyArg, recordSize := int32(1), uint32(24)
	if args.site {
		keyArg, recordSize = 2, 32
	}
	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord), // xdp ctx
		asm.Mov.Reg(asm.R9, asm.R1),
		asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.RFP, -48, asm.R0, asm.DWord),
	}
	// The tracing verifier translates xdp_md to the kernel's xdp_buff.
	bounds := asm.Instructions{
		asm.LoadMem(asm.R1, asm.R6, offsets["data"], asm.DWord),
		asm.LoadMem(asm.R2, asm.R6, offsets["data_end"], asm.DWord),
	}
	if args.rawCtx {
		for i, field := range []string{"data", "data_end"} {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, int32(-72-8*i)),
				asm.Mov.Imm(asm.R2, 8), asm.Mov.Reg(asm.R3, asm.R6), asm.Add.Imm(asm.R3, int32(offsets[field])),
				asm.FnProbeReadKernel.Call(),
				asm.JNE.Imm(asm.R0, 0, "done"))
		}
		bounds = asm.Instructions{asm.LoadMem(asm.R1, asm.RFP, -72, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -80, asm.DWord)}
	}
	insns = append(insns,
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.Mov.Imm(asm.R2, keyArg), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
		asm.FnGetFuncArg.Call(),
		asm.JNE.Imm(asm.R0, 0, "done"),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.Mov.Imm(asm.R2, keyArg+1), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -24),
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
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord))
	insns = append(insns, bounds...)
	insns = append(insns,
		asm.Sub.Reg(asm.R2, asm.R1),
		asm.StoreMem(asm.R0, 8, asm.R2, asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, -28, asm.Word),
		asm.StoreMem(asm.R0, 12, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, -40, asm.DWord),
		asm.StoreMem(asm.R0, 16, asm.R1, asm.DWord))
	if args.site {
		insns = append(insns,
			asm.Mov.Reg(asm.R7, asm.R0),
			asm.Mov.Reg(asm.R1, asm.R9),
			asm.Mov.Imm(asm.R2, 1), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -48),
			asm.FnGetFuncArg.Call(),
			asm.LoadMem(asm.R1, asm.RFP, -48, asm.Word),
			asm.StoreMem(asm.R7, 24, asm.R1, asm.Word))
	}
	if args.mapID {
		idOffset := bpfMapIDOffset(t, kernel)
		insns = append(insns,
			asm.Mov.Reg(asm.R1, asm.R9),
			asm.Mov.Imm(asm.R2, 4), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -56),
			asm.FnGetFuncArg.Call(),
			asm.JNE.Imm(asm.R0, 0, "done"),
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -60),
			asm.Mov.Imm(asm.R2, 4), asm.LoadMem(asm.R3, asm.RFP, -56, asm.DWord), asm.Add.Imm(asm.R3, idOffset),
			asm.FnProbeReadKernel.Call(),
			asm.JNE.Imm(asm.R0, 0, "done"),
			asm.LoadMem(asm.R1, asm.RFP, -60, asm.Word),
			asm.StoreMem(asm.R7, 28, asm.R1, asm.Word))
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return())
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"obs": {Type: ebpf.Array, KeySize: 4, ValueSize: recordSize, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"observe": {
			Name: "lookup_observe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: hook, AttachTarget: target, License: "GPL", Instructions: insns,
		}},
	}
}

func TestBpfLookupInjectionObservesContextKeyValue(t *testing.T) {
	testLookupObservation(t, lookupFixture, lookupReq())
}

func TestBpfLookupInjectionMultipleSites(t *testing.T) {
	req := lookupReq()
	req.Site.AllMatches = true
	testLookupObservation(t, multiLookupFixture, req)
}

func testLookupObservation(t *testing.T, fixture func() *ebpf.CollectionSpec, req LookupRequest) {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	plain := loadOrSkip(t, fixture())
	t.Cleanup(plain.Close)
	work := fixture()
	if _, err := transformLookup(work, req); err != nil {
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
	obs := loadOrSkip(t, lookupObserver(t, req.HookName, injected.Programs["p"]))
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
	t.Cleanup(func() { _ = attached.Close() })
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

// The callback increments a counter in the entry stack three times. The
// program returns XDP_ABORTED unless all three increments survive injection.
// The counter starts from a value the verifier cannot know: 6.1 verifies a
// bpf_loop callback once, so a constant start lets it prove the count is 1 and
// remove the success branch. An unreached subprogram precedes the callback so
// kernel dead-code elimination compacts func_info without compacting
// func_info_aux.
func callbackLookupFixture(symbolic bool) *ebpf.CollectionSpec {
	spec := lookupFixture()
	original := spec.Programs["p"].Instructions
	skip := asm.JEq.Imm(asm.R0, 0, "")
	skip.Offset = 1
	done := asm.JEq.Imm(asm.R0, 3, "")
	done.Offset = 2
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord),
		asm.Mov.Imm(asm.R0, 0), skip, asm.Call.Label("unused"),
		asm.Mov.Imm(asm.R1, 3),
		callbackLoad(asm.R2, -1, "callback"),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -16, asm.DWord), asm.LoadMem(asm.R1, asm.RFP, -24, asm.DWord),
		asm.Sub.Reg(asm.R0, asm.R1), done,
		asm.Mov.Imm(asm.R0, 0), asm.Return(),
		asm.Mov.Reg(asm.R1, asm.R6),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(original[0].Source()), btf.FuncMetadata(&original[0]))
	original[0] = btf.WithFuncMetadata(original[0].WithSymbol(""), nil)
	insns = append(insns, original...)
	unused := btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("unused").WithSource(asm.Comment("unused subprogram")),
		&btf.Func{Name: "unused", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
			Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		}})
	insns = append(insns, unused, asm.Return())
	if !symbolic {
		insns[8] = callbackLoad(asm.R2, int64(insns.Size()/8)-8-1, "")
	}
	insns = append(insns, callbackHead("callback"),
		asm.Add.Imm(asm.R0, 1), asm.StoreMem(asm.R2, 0, asm.R0, asm.DWord),
		asm.Mov.Imm(asm.R0, 0), asm.Return())
	spec.Programs["p"].Instructions = insns
	return spec
}

func TestBpfLookupInjectionCallback(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, symbolic := range []bool{false, true} {
		name := "numeric"
		if symbolic {
			name = "symbolic"
		}
		t.Run(name, func(t *testing.T) {
			req := lookupReq()
			req.Stack.LowestOffset = -24
			testLookupObservation(t, func() *ebpf.CollectionSpec { return callbackLookupFixture(symbolic) }, req)
		})
	}
}

// Auto instruments both maps with separate typed hooks. Each observer sees
// only its own map's lookups, and the site argument is the reported SitePC.
func TestBpfLookupInjectionAutoMultiMap(t *testing.T) {
	testAutoMultiMap(t, multiMapFixture, LookupRequest{})
}

// The flows map is read-only for programs, so its hook takes untrusted
// pointers; the observer reads the same key and value through them.
func TestBpfLookupInjectionReadOnlyMap(t *testing.T) {
	testAutoMultiMap(t, func() *ebpf.CollectionSpec { return multiMapFixtureFlags(bpfFRdonlyProg) }, LookupRequest{})
}

// With CopyReadOnly the observer reads the read-only map's value from a stack
// copy through a typed hook, which needs no arg:untrusted.
func TestBpfLookupInjectionReadOnlyMapCopy(t *testing.T) {
	testAutoMultiMap(t, func() *ebpf.CollectionSpec { return multiMapFixtureFlags(bpfFRdonlyProg) }, LookupRequest{CopyReadOnly: true})
}

// With StaticUntrusted the read-only map's hook is static, which needs no
// arg:untrusted either. The fixture reads the value, so it cannot use a
// write-only map.
func TestBpfLookupInjectionReadOnlyMapStatic(t *testing.T) {
	testAutoMultiMap(t, func() *ebpf.CollectionSpec { return multiMapFixtureFlags(bpfFRdonlyProg) }, LookupRequest{StaticUntrusted: true})
}

// testAutoMultiMap takes CopyReadOnly and StaticUntrusted from opts.
func testAutoMultiMap(t *testing.T, fixture func() *ebpf.CollectionSpec, opts LookupRequest) {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	plain := loadOrSkip(t, fixture())
	t.Cleanup(plain.Close)
	work := fixture()
	plan, err := transformLookup(work, LookupRequest{ProgramName: "p", Auto: true, CopyReadOnly: opts.CopyReadOnly,
		StaticUntrusted: opts.StaticUntrusted, HookName: "obs", Stack: StackAudit{LowestOffset: -8}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || len(plan.skipped) != 0 {
		t.Fatalf("hooks=%+v skipped=%+v", plan.hooks, plan.skipped)
	}
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	imsi := map[string]uint64{"sessions": 100000000000001, "flows": 200000000000001}
	for _, c := range []*ebpf.Collection{plain, injected} {
		for name, base := range imsi {
			for i, key := range []uint32{7, 0xffffffff} {
				if err := c.Maps[name].Put(key, [2]uint64{2, base + uint64(i)}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	observers := map[string]*ebpf.Collection{}
	site := map[string]uint32{}
	for _, hook := range plan.hooks {
		if len(hook.Sites) != 1 || hook.Static != (opts.StaticUntrusted && hook.MapName == "flows") {
			t.Fatalf("hook %s sites=%+v static=%v", hook.Name, hook.Sites, hook.Static)
		}
		obs := loadOrSkip(t, lookupObserverArgs(t, hook.Name, injected.Programs["p"], observerArgs{site: true, rawCtx: hook.Static}))
		t.Cleanup(obs.Close)
		l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
		if err != nil {
			if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
				t.Skipf("fentry unavailable: %v", err)
			}
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		observers[hook.MapName], site[hook.MapName] = obs, hook.Sites[0].SitePC
	}
	for i, tc := range []struct {
		key  uint32
		hits string // map whose hook must fire; the other stays silent
	}{{7, "flows"}, {0xffffffff, "sessions"}} {
		for _, obs := range observers {
			if err := obs.Maps["obs"].Put(uint32(0), [32]byte{}); err != nil {
				t.Fatal(err)
			}
		}
		packet := make([]byte, 64+16*i)
		binary.LittleEndian.PutUint32(packet, tc.key)
		for _, c := range []*ebpf.Collection{plain, injected} {
			out := make([]byte, len(packet))
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Repeat: 1})
			if err != nil || ret != 2 || !bytes.Equal(packet, out) {
				t.Fatalf("key=%d: action=%d err=%v", tc.key, ret, err)
			}
		}
		for name, obs := range observers {
			var got [32]byte
			if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
				t.Fatal(err)
			}
			if name != tc.hits {
				if got != [32]byte{} {
					t.Fatalf("key=%d: %s hook fired: %x", tc.key, name, got)
				}
				continue
			}
			seen, length, key := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[8:]), binary.LittleEndian.Uint32(got[12:])
			value, gotSite := binary.LittleEndian.Uint64(got[16:]), binary.LittleEndian.Uint32(got[24:])
			if seen != 1 || length != uint32(len(packet)) || key != tc.key || value != imsi[name]+uint64(i) || gotSite != site[name] {
				t.Fatalf("key=%d %s: seen=%d length=%d key=%d imsi=%d site=%d want site %d", tc.key, name, seen, length, key, value, gotSite, site[name])
			}
		}
	}
}

// The map declares key and value only by size, so the hook takes opaque bytes.
func TestBpfLookupInjectionOpaqueTypes(t *testing.T) {
	testLookupObservation(t, func() *ebpf.CollectionSpec {
		spec := lookupFixture()
		spec.Maps["sessions"].Key, spec.Maps["sessions"].Value = nil, nil
		return spec
	}, lookupReq())
}

// lpmFixture is lookupFixture over an LPM trie: the key is a /32 prefix
// length at fp-8 followed by the packet's first word.
func lpmFixture() *ebpf.CollectionSpec {
	spec := lookupFixture()
	original := spec.Programs["p"].Instructions
	insns := append(asm.Instructions(nil), original[:7]...)
	insns = append(insns, asm.StoreImm(asm.RFP, -8, 32, asm.Word))
	insns = append(insns, original[7:]...)
	insns[4].Offset++      // short packet still lands on XDP_DROP
	insns[9].Constant = -8 // key starts at the prefix length
	spec.Programs["p"].Instructions = insns
	u32 := &btf.Int{Name: "u32", Size: 4}
	m := spec.Maps["sessions"]
	m.Type, m.KeySize, m.Flags = ebpf.LPMTrie, 8, unix.BPF_F_NO_PREALLOC
	m.Key = &btf.Struct{Name: "lpm_key", Size: 8, Members: []btf.Member{
		{Name: "prefixlen", Type: u32}, {Name: "addr", Type: u32, Offset: 32},
	}}
	return spec
}

func TestBpfLookupInjectionLPMTrie(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain := loadOrSkip(t, lpmFixture())
	t.Cleanup(plain.Close)
	work := lpmFixture()
	if _, err := transformLookup(work, lookupReq()); err != nil {
		t.Fatal(err)
	}
	injected := loadOrSkip(t, work)
	t.Cleanup(injected.Close)
	for _, c := range []*ebpf.Collection{plain, injected} {
		if err := c.Maps["sessions"].Put([2]uint32{32, 7}, [2]uint64{2, 100000000000001}); err != nil {
			t.Fatal(err)
		}
	}
	obs := loadOrSkip(t, lookupObserver(t, "lookup_hook", injected.Programs["p"]))
	t.Cleanup(obs.Close)
	l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("fentry unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for _, tc := range []struct {
		key  uint32
		want uint32
	}{{7, 2}, {99, 1}} {
		if err := obs.Maps["obs"].Put(uint32(0), [24]byte{}); err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, tc.key)
		for _, c := range []*ebpf.Collection{plain, injected} {
			out := make([]byte, len(packet))
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Repeat: 1})
			if err != nil || ret != tc.want || !bytes.Equal(packet, out) {
				t.Fatalf("key=%d: action=%d err=%v", tc.key, ret, err)
			}
		}
		var got [24]byte
		if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		if tc.want == 1 {
			if got != [24]byte{} {
				t.Fatalf("miss generated observation: %x", got)
			}
			continue
		}
		// The observer reads the key's first word, the prefix length.
		seen, prefix, imsi := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[12:]), binary.LittleEndian.Uint64(got[16:])
		if seen != 1 || prefix != 32 || imsi != 100000000000001 {
			t.Fatalf("seen=%d prefix=%d imsi=%d", seen, prefix, imsi)
		}
	}
}

// kindFixture looks up key 0 in a map of the given kind by a direct R1
// reference, returning XDP_TX on a hit and XDP_PASS on a miss.
func kindFixture(mapType ebpf.MapType, valueSize uint32) *ebpf.CollectionSpec {
	miss := asm.JEq.Imm(asm.R0, 0, "")
	miss.Offset = 2 // slot 6 -> slot 9
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),       // 0: key 0
		asm.Mov.Reg(asm.R2, asm.RFP),                 // 1
		asm.Add.Imm(asm.R2, -4),                      // 2
		asm.LoadMapPtr(asm.R1, 0).WithReference("m"), // 3-4
		asm.FnMapLookupElem.Call(),                   // 5
		miss,                                         // 6
		asm.Mov.Imm(asm.R0, 3),                       // 7: hit -> XDP_TX
		asm.Return(),                                 // 8
		asm.Mov.Imm(asm.R0, 2),                       // 9: miss -> XDP_PASS
		asm.Return(),                                 // 10
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("generic-kind fixture")), xdpFunc("p"))
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps:     map[string]*ebpf.MapSpec{"m": {Name: "m", Type: mapType, KeySize: 4, ValueSize: valueSize, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

// Auto routes a direct lookup on a map kind a typed hook refuses to the generic
// hook; the verifier accepts the generic ABI receiving the special result.
func TestBpfLookupInjectionGenericKinds(t *testing.T)       { testGenericKinds(t, false) }
func TestBpfLookupInjectionGenericKindsStatic(t *testing.T) { testGenericKinds(t, true) }

func testGenericKinds(t *testing.T, static bool) {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		typ  ebpf.MapType
		size uint32
		fill any // nil leaves the runtime hit unexercised
	}{
		{"xskmap", ebpf.XSKMap, 4, nil},
		{"devmap", ebpf.DevMap, 4, uint32(lo.Index)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain := loadOrSkip(t, kindFixture(tc.typ, tc.size))
			t.Cleanup(plain.Close)
			work := kindFixture(tc.typ, tc.size)
			plan, err := transformLookup(work, LookupRequest{ProgramName: "p", Auto: true, StaticUntrusted: static, HookName: "obs", Stack: StackAudit{LowestOffset: -8}})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 1 || !plan.hooks[0].Generic || plan.hooks[0].Static != static || len(plan.skipped) != 0 {
				t.Fatalf("plan: %+v", plan)
			}
			injected := loadHooked(t, work, plan.hooks)
			t.Cleanup(injected.Close)
			obs := loadOrSkip(t, lookupObserverArgs(t, "obs_any", injected.Programs["p"], observerArgs{site: true, mapID: true, rawCtx: static}))
			t.Cleanup(obs.Close)
			l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
			if err != nil {
				if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
					t.Skipf("fentry unavailable: %v", err)
				}
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			if err := obs.Maps["obs"].Put(uint32(0), [32]byte{}); err != nil {
				t.Fatal(err)
			}
			// A miss: the empty map returns NULL, so the hook never fires.
			if ret, _ := runXDP(t, injected.Programs["p"]); ret != 2 {
				t.Fatalf("miss action %d", ret)
			}
			var got [32]byte
			if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
				t.Fatal(err)
			}
			if got != [32]byte{} {
				t.Fatalf("miss fired the hook: %x", got)
			}
			if tc.fill == nil {
				return
			}
			if err := injected.Maps["m"].Put(uint32(0), tc.fill); err != nil {
				t.Skipf("populate %s: %v", tc.name, err)
			}
			if ret, _ := runXDP(t, injected.Programs["p"]); ret != 3 {
				t.Fatalf("hit action %d", ret)
			}
			info, err := injected.Maps["m"].Info()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := info.ID()
			if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
				t.Fatal(err)
			}
			if seen := binary.LittleEndian.Uint64(got[:]); seen != 1 || ebpf.MapID(binary.LittleEndian.Uint32(got[28:])) != id {
				t.Fatalf("hit: seen=%d mapID=%d want %d", seen, binary.LittleEndian.Uint32(got[28:]), id)
			}
		})
	}
}

// mapInMapFixture looks up the packet's first word in the inner map that
// outer[0] holds. The inner lookup's R1 is the outer lookup's result.
func mapInMapFixture() *ebpf.CollectionSpec {
	spec := lookupFixture()
	sessions := spec.Maps["sessions"]
	short, outerMiss, innerMiss := asm.JGT.Reg(asm.R3, asm.R4, ""), asm.JEq.Imm(asm.R0, 0, ""), asm.JEq.Imm(asm.R0, 0, "")
	short.Offset, outerMiss.Offset, innerMiss.Offset = 16, 7, 2 // slots 4, 13, 18 -> 21
	insns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),         // 0: data
		asm.LoadMem(asm.R4, asm.R1, 4, asm.Word),         // 1: data_end
		asm.Mov.Reg(asm.R3, asm.R2),                      // 2
		asm.Add.Imm(asm.R3, 4),                           // 3
		short,                                            // 4
		asm.LoadMem(asm.R2, asm.R2, 0, asm.Word),         // 5: packet key
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),      // 6: inner key
		asm.StoreImm(asm.RFP, -8, 0, asm.Word),           // 7: outer key
		asm.Mov.Reg(asm.R2, asm.RFP),                     // 8
		asm.Add.Imm(asm.R2, -8),                          // 9
		asm.LoadMapPtr(asm.R1, 0).WithReference("outer"), // 10-11
		asm.FnMapLookupElem.Call(),                       // 12: outer lookup
		outerMiss,                                        // 13
		asm.Mov.Reg(asm.R1, asm.R0),                      // 14: inner map
		asm.Mov.Reg(asm.R2, asm.RFP),                     // 15
		asm.Add.Imm(asm.R2, -4),                          // 16
		asm.FnMapLookupElem.Call(),                       // 17: inner lookup
		innerMiss,                                        // 18
		asm.LoadMem(asm.R0, asm.R0, 0, asm.DWord),        // 19: seid = action
		asm.Return(),                                     // 20
		asm.Mov.Imm(asm.R0, 1),                           // 21: miss -> XDP_DROP
		asm.Return(),                                     // 22
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("map-in-map fixture")),
		btf.FuncMetadata(&spec.Programs["p"].Instructions[0]))
	spec.Programs["p"].Instructions = insns
	delete(spec.Maps, "sessions")
	spec.Maps["outer"] = &ebpf.MapSpec{Name: "outer", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1,
		InnerMap: sessions}
	return spec
}

// Auto passes both lookups to the generic hook. The observer sees the inner
// lookup last: its key, value and the inner map's id.
func TestBpfLookupInjectionMapInMap(t *testing.T) {
	testMapInMap(t, false)
}

// The static generic hook reports the same maps without arg:untrusted.
func TestBpfLookupInjectionMapInMapStatic(t *testing.T) {
	testMapInMap(t, true)
}

func testMapInMap(t *testing.T, static bool) {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	plain := loadOrSkip(t, mapInMapFixture())
	t.Cleanup(plain.Close)
	work := mapInMapFixture()
	plan, err := transformLookup(work, LookupRequest{ProgramName: "p", Auto: true, StaticUntrusted: static,
		HookName: "obs", Stack: StackAudit{LowestOffset: -8}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || !plan.hooks[0].Generic || plan.hooks[0].Static != static || len(plan.hooks[0].Sites) != 2 || len(plan.skipped) != 0 {
		t.Fatalf("plan: %+v", plan)
	}
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	var innerID ebpf.MapID
	for _, c := range []*ebpf.Collection{plain, injected} {
		inner, err := ebpf.NewMap(work.Maps["outer"].InnerMap)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		if err := inner.Put(uint32(7), [2]uint64{2, 100000000000001}); err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["outer"].Put(uint32(0), inner); err != nil {
			t.Fatal(err)
		}
		info, err := inner.Info()
		if err != nil {
			t.Fatal(err)
		}
		innerID, _ = info.ID()
	}
	obs := loadOrSkip(t, lookupObserverArgs(t, "obs_any", injected.Programs["p"], observerArgs{site: true, mapID: true, rawCtx: static}))
	t.Cleanup(obs.Close)
	l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("fentry unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for _, tc := range []struct {
		key  uint32
		want uint32
		seen uint64
	}{{7, 2, 2}, {99, 1, 1}} {
		if err := obs.Maps["obs"].Put(uint32(0), [32]byte{}); err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, tc.key)
		for _, c := range []*ebpf.Collection{plain, injected} {
			out := make([]byte, len(packet))
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Repeat: 1})
			if err != nil || ret != tc.want || !bytes.Equal(packet, out) {
				t.Fatalf("key=%d: action=%d err=%v", tc.key, ret, err)
			}
		}
		var got [32]byte
		if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		seen, key, imsi := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[12:]), binary.LittleEndian.Uint64(got[16:])
		site, id := binary.LittleEndian.Uint32(got[24:]), binary.LittleEndian.Uint32(got[28:])
		// A miss in the inner map leaves the outer lookup's observation: key 0
		// and the outer map's id.
		if tc.seen == 2 && (seen != 2 || key != 7 || imsi != 100000000000001 || site != plan.hooks[0].Sites[1].SitePC || ebpf.MapID(id) != innerID) {
			t.Fatalf("hit: seen=%d key=%d imsi=%d site=%d id=%d want id %d", seen, key, imsi, site, id, innerID)
		}
		if tc.seen == 1 {
			outerInfo, err := injected.Maps["outer"].Info()
			if err != nil {
				t.Fatal(err)
			}
			outerID, _ := outerInfo.ID()
			if seen != 1 || key != 0 || site != plan.hooks[0].Sites[0].SitePC || ebpf.MapID(id) != outerID {
				t.Fatalf("miss: seen=%d key=%d site=%d id=%d want id %d", seen, key, site, id, outerID)
			}
		}
	}
}
