package inject

import (
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

func xdpFunc(name string) *btf.Func {
	u32 := &btf.Int{Name: "u32", Size: 4}
	ctx := &btf.Struct{Name: "xdp_md", Size: 24, Members: []btf.Member{
		{Name: "data", Type: u32}, {Name: "data_end", Type: u32, Offset: 32},
	}}
	return &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: ctx}}},
	}}
}

// tailCallerFixture tail-calls jmp[first packet byte] and returns XDP_PASS
// when the tail call fails.
func tailCallerFixture() *ebpf.CollectionSpec {
	short := asm.JGT.Reg(asm.R4, asm.R3, "")
	short.Offset = 5 // slot 5 -> 11
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),                    // 0
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),       // 1: data
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),       // 2: data_end
		asm.Mov.Reg(asm.R4, asm.R2),                    // 3
		asm.Add.Imm(asm.R4, 1),                         // 4
		short,                                          // 5
		asm.LoadMem(asm.R3, asm.R2, 0, asm.Byte),       // 6: index
		asm.Mov.Reg(asm.R1, asm.R6),                    // 7
		asm.LoadMapPtr(asm.R2, 0).WithReference("jmp"), // 8-9
		asm.FnTailCall.Call(),                          // 10
		asm.Mov.Imm(asm.R0, 2),                         // 11: XDP_PASS
		asm.Return(),                                   // 12
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("caller").WithSource(asm.Comment("tail caller")), xdpFunc("caller"))
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps:     map[string]*ebpf.MapSpec{"jmp": {Name: "jmp", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 2}},
		Programs: map[string]*ebpf.ProgramSpec{"caller": {Name: "caller", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

// tailTargetFixture returns XDP_TX.
func tailTargetFixture() *ebpf.CollectionSpec {
	insns := asm.Instructions{asm.Mov.Imm(asm.R0, 3), asm.Return()}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("target").WithSource(asm.Comment("tail target")), xdpFunc("target"))
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Programs: map[string]*ebpf.ProgramSpec{"target": {Name: "target", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

// scalarObserver counts calls of fn and records the packet length and the
// u32 arguments after ctx: {u64 seen; u32 len; u32 args[2]}.
func scalarObserver(t *testing.T, fn string, target *ebpf.Program, args int) *ebpf.CollectionSpec {
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
	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord), // xdp ctx
		asm.Mov.Reg(asm.R9, asm.R1),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("obs"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LoadMem(asm.R1, asm.R7, 0, asm.DWord), asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R7, 0, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R6, offsets["data"], asm.DWord),
		asm.LoadMem(asm.R2, asm.R6, offsets["data_end"], asm.DWord),
		asm.Sub.Reg(asm.R2, asm.R1),
		asm.StoreMem(asm.R7, 8, asm.R2, asm.Word),
	}
	for i := 1; i <= args; i++ {
		insns = append(insns,
			asm.Mov.Reg(asm.R1, asm.R9),
			asm.Mov.Imm(asm.R2, int32(i)), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
			asm.FnGetFuncArg.Call(),
			asm.JNE.Imm(asm.R0, 0, "done"),
			asm.LoadMem(asm.R1, asm.RFP, -16, asm.Word),
			asm.StoreMem(asm.R7, int16(8+4*i), asm.R1, asm.Word))
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return())
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"obs": {Type: ebpf.Array, KeySize: 4, ValueSize: 24, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"observe": {
			Name: "scalar_observe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: fn, AttachTarget: target, License: "GPL", Instructions: insns,
		}},
	}
}

type scalarRecord struct {
	Seen uint64
	Len  uint32
	Args [2]uint32
	_    uint32
}

func attachScalarObserver(t *testing.T, fn string, target *ebpf.Program, args int) *ebpf.Map {
	t.Helper()
	obs := loadOrSkip(t, scalarObserver(t, fn, target, args))
	t.Cleanup(obs.Close)
	l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("fentry unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return obs.Maps["obs"]
}

// The entry hook fires when the target is entered through a tail call, where
// an fentry on the target itself does not. The tail-call hook fires only when
// bpf_tail_call returns, with the site and the index.
func TestBpfTailCallHooks(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	stack := StackAudit{LowestOffset: 0}
	caller, target := tailCallerFixture(), tailTargetFixture()
	callerPlan, err := transformLookup(caller, LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: stack})
	if err != nil {
		t.Fatal(err)
	}
	if len(callerPlan.hooks) != 1 || callerPlan.hooks[0].Name != "obs_tail_call" || len(callerPlan.hooks[0].Sites) != 1 {
		t.Fatalf("caller hooks: %+v", callerPlan.hooks)
	}
	site := callerPlan.hooks[0].Sites[0].SitePC
	targetPlan, err := transformLookup(target, LookupRequest{ProgramName: "target", Entry: true, HookName: "obs", Stack: stack})
	if err != nil {
		t.Fatal(err)
	}
	if len(targetPlan.hooks) != 1 || targetPlan.hooks[0].Name != "obs_entry" {
		t.Fatalf("target hooks: %+v", targetPlan.hooks)
	}
	load := func(c, tg *ebpf.CollectionSpec) (*ebpf.Collection, *ebpf.Collection) {
		cc, tc := loadOrSkip(t, c), loadOrSkip(t, tg)
		t.Cleanup(cc.Close)
		t.Cleanup(tc.Close)
		if err := cc.Maps["jmp"].Put(uint32(0), tc.Programs["target"]); err != nil {
			t.Fatal(err)
		}
		return cc, tc
	}
	plainCaller, _ := load(tailCallerFixture(), tailTargetFixture())
	injCaller, injTarget := load(caller, target)
	tail := attachScalarObserver(t, "obs_tail_call", injCaller.Programs["caller"], 2)
	entry := attachScalarObserver(t, "obs_entry", injTarget.Programs["target"], 0)
	main := attachScalarObserver(t, "target", injTarget.Programs["target"], 0)
	read := func(m *ebpf.Map) scalarRecord {
		var r scalarRecord
		if err := m.Lookup(uint32(0), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, tc := range []struct {
		index  byte
		action uint32
	}{{0, 3}, {1, 2}} {
		for _, m := range []*ebpf.Map{tail, entry, main} {
			if err := m.Put(uint32(0), scalarRecord{}); err != nil {
				t.Fatal(err)
			}
		}
		packet := make([]byte, 64+int(tc.index)*16)
		packet[0] = tc.index
		for _, c := range []*ebpf.Collection{plainCaller, injCaller} {
			ret, err := c.Programs["caller"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
			if err != nil || ret != tc.action {
				t.Fatalf("index=%d: action=%d err=%v", tc.index, ret, err)
			}
		}
		gotTail, gotEntry, gotMain := read(tail), read(entry), read(main)
		if gotMain.Seen != 0 {
			t.Fatalf("index=%d: fentry on the tail-call target fired %d times", tc.index, gotMain.Seen)
		}
		if tc.index == 0 {
			if gotTail.Seen != 0 || gotEntry.Seen != 1 || gotEntry.Len != uint32(len(packet)) {
				t.Fatalf("tail call: tail=%+v entry=%+v", gotTail, gotEntry)
			}
		} else if gotEntry.Seen != 0 || gotTail.Seen != 1 || gotTail.Len != uint32(len(packet)) ||
			gotTail.Args != [2]uint32{site, uint32(tc.index)} {
			t.Fatalf("failed tail call: tail=%+v entry=%+v, want site %d", gotTail, gotEntry, site)
		}
	}
	// A direct run enters the target through its trampoline: both fire.
	for _, m := range []*ebpf.Map{entry, main} {
		if err := m.Put(uint32(0), scalarRecord{}); err != nil {
			t.Fatal(err)
		}
	}
	if ret, err := injTarget.Programs["target"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 3 {
		t.Fatalf("direct target: action=%d err=%v", ret, err)
	}
	if read(entry).Seen != 1 || read(main).Seen != 1 {
		t.Fatalf("direct target: entry=%+v main=%+v", read(entry), read(main))
	}
}

// Entry composes with lookup hooks in one program and keeps its results.
func TestBpfEntryHookWithLookup(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain := loadOrSkip(t, lookupFixture())
	t.Cleanup(plain.Close)
	work := lookupFixture()
	req := lookupReq()
	req.Entry = true
	if _, err := transformLookup(work, req); err != nil {
		t.Fatal(err)
	}
	injected := loadOrSkip(t, work)
	t.Cleanup(injected.Close)
	for _, c := range []*ebpf.Collection{plain, injected} {
		if err := c.Maps["sessions"].Put(uint32(7), [2]uint64{3, 9}); err != nil {
			t.Fatal(err)
		}
	}
	entry := attachScalarObserver(t, "lookup_hook_entry", injected.Programs["p"], 0)
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
	for i, key := range []uint32{7, 8} {
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, key)
		var want uint32
		for j, c := range []*ebpf.Collection{plain, injected} {
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
			if err != nil || (j == 1 && ret != want) {
				t.Fatalf("key=%d: action=%d want %d err=%v", key, ret, want, err)
			}
			want = ret
		}
		var r scalarRecord
		if err := entry.Lookup(uint32(0), &r); err != nil || r.Seen != uint64(i+1) || r.Len != 64 {
			t.Fatalf("key=%d: entry=%+v err=%v", key, r, err)
		}
		// The lookup hook fired once, for the hit (key 7, imsi 9), after the
		// entry hook left the ctx spill intact; the key-8 miss adds nothing.
		var got [24]byte
		if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		seen, length, gotKey, imsi := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[8:]),
			binary.LittleEndian.Uint32(got[12:]), binary.LittleEndian.Uint64(got[16:])
		if seen != 1 || length != 64 || gotKey != 7 || imsi != 9 {
			t.Fatalf("key=%d: lookup seen=%d len=%d key=%d imsi=%d", key, seen, length, gotKey, imsi)
		}
	}
}

// subTailCallerFixture is tailCallerFixture with the tail call in a static
// subprogram that the entry function calls with ctx.
func subTailCallerFixture() *ebpf.CollectionSpec {
	spec := tailCallerFixture()
	body := spec.Programs["caller"].Instructions
	sub := xdpFunc("sub")
	sub.Linkage = btf.StaticFunc
	body[0] = btf.WithFuncMetadata(body[0].WithSymbol("sub").WithSource(asm.Comment("tail-calling subprogram")), sub)
	entry := btf.WithFuncMetadata(asm.Call.Label("sub").WithSymbol("caller").WithSource(asm.Comment("entry")), xdpFunc("caller"))
	spec.Programs["caller"].Instructions = append(asm.Instructions{entry, asm.Return()}, body...)
	return spec
}

// paddedSubTailCaller is subTailCallerFixture whose entry frame references
// R10+bound, so the transform's entry ctx spill lands one slot below it.
func paddedSubTailCaller(bound int16) *ebpf.CollectionSpec {
	spec := subTailCallerFixture()
	insns := spec.Programs["caller"].Instructions
	entry := insns[0] // Call sub, carrying the caller func metadata
	pad := btf.WithFuncMetadata(asm.StoreImm(asm.RFP, bound, 0, asm.Word).
		WithSymbol(entry.Symbol()).WithSource(entry.Source()), btf.FuncMetadata(&entry))
	entry = btf.WithFuncMetadata(entry.WithSymbol("").WithSource(nil), nil)
	spec.Programs["caller"].Instructions = append(asm.Instructions{pad, entry}, insns[1:]...)
	return spec
}

// At an audited bound where the transform's entry ctx spill crosses the
// kernel's 256-byte caller-depth limit the transform refuses; one slot less
// transforms and the kernel loads it. The original at the deeper bound still
// loads, so it is the transform, not the program, that crosses.
func TestBpfTailCallStackLimit(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	req := func(bound int16) LookupRequest {
		return LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: StackAudit{LowestOffset: bound}}
	}
	if _, err := transformLookup(paddedSubTailCaller(-224), req(-224)); !errors.Is(err, ErrRefused) {
		t.Fatalf("-224: want refusal, got %v", err)
	}
	plain := loadOrSkip(t, paddedSubTailCaller(-224))
	t.Cleanup(plain.Close)
	work := paddedSubTailCaller(-216)
	if _, err := transformLookup(work, req(-216)); err != nil {
		t.Fatal(err)
	}
	injected := loadOrSkip(t, work)
	t.Cleanup(injected.Close)
}

// The tail-call hook also fires for a failed tail call in a subprogram, with
// the ctx that subprogram passed to the helper.
func TestBpfTailCallInSubprogram(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	work := subTailCallerFixture()
	plan, err := transformLookup(work, LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: StackAudit{LowestOffset: 0}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || len(plan.hooks[0].Sites) != 1 || plan.hooks[0].Sites[0].FuncName != "sub" {
		t.Fatalf("plan: %+v", plan)
	}
	site := plan.hooks[0].Sites[0].SitePC
	load := func(spec *ebpf.CollectionSpec) *ebpf.Collection {
		c, target := loadOrSkip(t, spec), loadOrSkip(t, tailTargetFixture())
		t.Cleanup(c.Close)
		t.Cleanup(target.Close)
		if err := c.Maps["jmp"].Put(uint32(0), target.Programs["target"]); err != nil {
			t.Fatal(err)
		}
		return c
	}
	plain, injected := load(subTailCallerFixture()), load(work)
	tail := attachScalarObserver(t, "obs_tail_call", injected.Programs["caller"], 2)
	for _, tc := range []struct {
		index  byte
		action uint32
	}{{0, 3}, {1, 2}} {
		if err := tail.Put(uint32(0), scalarRecord{}); err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 64+int(tc.index)*16)
		packet[0] = tc.index
		for _, c := range []*ebpf.Collection{plain, injected} {
			ret, err := c.Programs["caller"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
			if err != nil || ret != tc.action {
				t.Fatalf("index=%d: action=%d err=%v", tc.index, ret, err)
			}
		}
		var got scalarRecord
		if err := tail.Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		if tc.index == 0 && got.Seen != 0 {
			t.Fatalf("successful tail call fired the hook: %+v", got)
		}
		if tc.index == 1 && (got.Seen != 1 || got.Len != uint32(len(packet)) || got.Args != [2]uint32{site, 1}) {
			t.Fatalf("failed tail call: %+v, want site %d", got, site)
		}
	}
}
