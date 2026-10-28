package inject

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
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
	_, length := packetLength(t, kernel, target, false)
	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord), // hook ctx
		asm.Mov.Reg(asm.R9, asm.R1),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("obs"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LoadMem(asm.R1, asm.R7, 0, asm.DWord), asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R7, 0, asm.R1, asm.DWord),
	}
	insns = append(insns, length...)
	insns = append(insns, asm.StoreMem(asm.R7, 8, asm.R2, asm.Word))
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

// The per-map hooks of a tc program take struct __sk_buff *. Auto with Entry
// and TailCalls instruments dispatchFixture as a SchedCLS program with a typed
// lookup hook, an entry hook and a tail-call hook; an fentry on each reads the
// packet length through the ctx (sk_buff len) and the hook's own arguments,
// and the program's results do not change.
func TestBpfLookupHooksTC(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	fixture := func() *ebpf.CollectionSpec { return asTC(dispatchFixture()) }
	work := fixture()
	plan, err := transformLookup(work, LookupRequest{ProgramName: "p", Auto: true, Entry: true, TailCalls: true,
		HookName: "obs", Stack: StackAudit{LowestOffset: -8}})
	if err != nil {
		t.Fatal(err)
	}
	names := map[HookKind]string{}
	var lookupPC, tailPC uint32
	for _, hook := range plan.hooks {
		if hook.Dispatch || hook.Static || hook.Untrusted {
			t.Fatalf("hook: %+v", hook)
		}
		names[hook.Kind] = hook.Name
		switch hook.Kind {
		case HookLookup:
			if hook.MapName != "sessions" || len(hook.Sites) != 1 {
				t.Fatalf("lookup hook: %+v", hook)
			}
			lookupPC = hook.Sites[0].SitePC
		case HookTailCall:
			tailPC = hook.Sites[0].SitePC
		}
	}
	if len(plan.hooks) != 3 || len(names) != 3 || lookupPC != 13 || tailPC != 20 {
		t.Fatalf("hooks %+v", plan.hooks)
	}
	load := func(spec *ebpf.CollectionSpec) *ebpf.Collection {
		c, tgt := loadOrSkip(t, spec), loadOrSkip(t, asTC(tailTargetFixture()))
		t.Cleanup(c.Close)
		t.Cleanup(tgt.Close)
		if err := c.Maps["jmp"].Put(uint32(0), tgt.Programs["target"]); err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["sessions"].Put(uint32(7), [2]uint64{3, 9}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	plain, injected := load(fixture()), load(work)
	prog := injected.Programs["p"]
	entry := attachScalarObserver(t, names[HookEntry], prog, 0)
	tail := attachScalarObserver(t, names[HookTailCall], prog, 2)
	obs := loadOrSkip(t, lookupObserverArgs(t, names[HookLookup], prog, observerArgs{site: true}))
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
		key, index uint32
		length     int
		action     uint32
		hit        bool // the lookup hits and the tail call fails
	}{{7, 1, 64, 2, true}, {8, 0, 80, 3, false}} {
		for _, m := range []*ebpf.Map{entry, tail} {
			if err := m.Put(uint32(0), scalarRecord{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := obs.Maps["obs"].Put(uint32(0), [32]byte{}); err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, tc.length)
		binary.LittleEndian.PutUint32(packet, tc.key)
		binary.LittleEndian.PutUint32(packet[4:], tc.index)
		for _, c := range []*ebpf.Collection{plain, injected} {
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
			if err != nil || ret != tc.action {
				t.Fatalf("key=%d index=%d: action=%d want %d err=%v", tc.key, tc.index, ret, tc.action, err)
			}
		}
		read := func(m *ebpf.Map) scalarRecord {
			var r scalarRecord
			if err := m.Lookup(uint32(0), &r); err != nil {
				t.Fatal(err)
			}
			return r
		}
		var got [32]byte
		if err := obs.Maps["obs"].Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		seen, length, key := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[8:]), binary.LittleEndian.Uint32(got[12:])
		imsi, site := binary.LittleEndian.Uint64(got[16:]), binary.LittleEndian.Uint32(got[24:])
		gotEntry, gotTail := read(entry), read(tail)
		if gotEntry.Seen != 1 || gotEntry.Len != uint32(tc.length) {
			t.Fatalf("key=%d: entry=%+v", tc.key, gotEntry)
		}
		if !tc.hit {
			if got != [32]byte{} || gotTail != (scalarRecord{}) {
				t.Fatalf("key=%d: lookup %x tail=%+v", tc.key, got, gotTail)
			}
			continue
		}
		if seen != 1 || length != uint32(tc.length) || key != tc.key || imsi != 9 || site != lookupPC {
			t.Fatalf("key=%d: lookup seen=%d len=%d key=%d imsi=%d site=%d, want site %d", tc.key, seen, length, key, imsi, site, lookupPC)
		}
		if gotTail.Seen != 1 || gotTail.Len != uint32(tc.length) || gotTail.Args != [2]uint32{tailPC, tc.index} {
			t.Fatalf("key=%d: tail=%+v, want site %d", tc.key, gotTail, tailPC)
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

// lookupSubTailCaller is a lookup fixture whose entry first references
// R10+bound and calls sub, a static subprogram that tail-calls, with ctx: the
// entry frame, with the transform's slots, is sub's caller depth.
func lookupSubTailCaller(spec *ebpf.CollectionSpec, bound int16) *ebpf.CollectionSpec {
	insns := spec.Programs["p"].Instructions
	entry := insns[0]
	head := asm.Instructions{
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, bound, 0, asm.Word).WithSymbol(entry.Symbol()).WithSource(entry.Source()), btf.FuncMetadata(&entry)),
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Call.Label("sub"),
		asm.Mov.Reg(asm.R1, asm.R6),
	}
	insns[0] = btf.WithFuncMetadata(entry.WithSymbol("").WithSource(nil), nil)
	spec.Programs["p"].Instructions = append(append(head, insns...), subBody(btf.StaticFunc)...)
	spec.Maps["jmp"] = tailCallerFixture().Maps["jmp"]
	return spec
}

// chainTailCaller is entry -> middle -> sub, where only middle uses stack
// (depth bytes) and only sub tail-calls, so the kernel's caller-depth check
// for sub sums the entry and middle frames.
func chainTailCaller(depth int16) *ebpf.CollectionSpec {
	spec := tailCallerFixture()
	body := spec.Programs["caller"].Instructions
	sub := xdpFunc("sub")
	sub.Linkage = btf.StaticFunc
	body[0] = btf.WithFuncMetadata(body[0].WithSymbol("sub").WithSource(asm.Comment("tail-calling subprogram")), sub)
	middle := xdpFunc("middle")
	middle.Linkage = btf.StaticFunc
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Call.Label("middle").WithSymbol("caller").WithSource(asm.Comment("entry")), xdpFunc("caller")),
		asm.Return(),
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, -depth, 0, asm.Word).WithSymbol("middle").WithSource(asm.Comment("middle")), middle),
		asm.Call.Label("sub"),
		asm.Return(),
	}
	spec.Programs["caller"].Instructions = append(insns, body...)
	return spec
}

// nestedTailCaller tail-calls in the entry, whose frame reaches R10+bound,
// and on failure calls sub, which tail-calls again: the entry's own tail-call
// spill counts toward sub's caller depth.
func nestedTailCaller(bound int16) *ebpf.CollectionSpec {
	spec := tailCallerFixture()
	body := spec.Programs["caller"].Instructions
	sub := xdpFunc("sub")
	sub.Linkage = btf.StaticFunc
	body[0] = btf.WithFuncMetadata(body[0].WithSymbol("sub").WithSource(asm.Comment("tail-calling subprogram")), sub)
	short := asm.JGT.Reg(asm.R4, asm.R3, "")
	short.Offset = 8 // slot 6 -> 15
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, bound, 0, asm.Word).WithSymbol("caller").WithSource(asm.Comment("entry")), xdpFunc("caller")), // 0
		asm.Mov.Reg(asm.R6, asm.R1),                    // 1
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),       // 2: data
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),       // 3: data_end
		asm.Mov.Reg(asm.R4, asm.R2),                    // 4
		asm.Add.Imm(asm.R4, 1),                         // 5
		short,                                          // 6
		asm.LoadMem(asm.R3, asm.R2, 0, asm.Byte),       // 7: index
		asm.Mov.Reg(asm.R1, asm.R6),                    // 8
		asm.LoadMapPtr(asm.R2, 0).WithReference("jmp"), // 9-10
		asm.FnTailCall.Call(),                          // 11
		asm.Mov.Reg(asm.R1, asm.R6),                    // 12: failed; try sub
		asm.Call.Label("sub"),                          // 13
		asm.Return(),                                   // 14
		asm.Mov.Imm(asm.R0, 2),                         // 15: XDP_PASS
		asm.Return(),                                   // 16
	}
	spec.Programs["caller"].Instructions = append(insns, body...)
	return spec
}

// staticFunc is a static subprogram taking an XDP ctx, which the verifier
// does not check against its BTF.
func staticFunc(name string) *btf.Func {
	fn := xdpFunc(name)
	fn.Linkage = btf.StaticFunc
	return fn
}

// subBody is tailCallerFixture's body as the subprogram sub with linkage.
func subBody(linkage btf.FuncLinkage) asm.Instructions {
	body := tailCallerFixture().Programs["caller"].Instructions
	sub := xdpFunc("sub")
	sub.Linkage = linkage
	body[0] = btf.WithFuncMetadata(body[0].WithSymbol("sub").WithSource(asm.Comment("tail-calling subprogram")), sub)
	return body
}

// loopTailCaller spills ctx at R10+bound in the entry and runs the bpf_loop
// callback cb once, which reloads ctx and calls sub, which tail-calls. The
// kernel walks the callback reference like a call, so the entry and cb frames
// are sub's callers.
func loopTailCaller(bound int16, linkage btf.FuncLinkage) *ebpf.CollectionSpec {
	spec := tailCallerFixture()
	cb := &btf.Func{Name: "cb", Linkage: btf.StaticFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "index", Type: &btf.Int{Name: "u32", Size: 4}}, {Name: "data", Type: &btf.Pointer{Target: &btf.Void{}}}},
	}}
	callback := asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R2, Src: asm.PseudoFunc, Constant: -1}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.StoreMem(asm.RFP, bound, asm.R1, asm.DWord).WithSymbol("caller").WithSource(asm.Comment("entry")), xdpFunc("caller")),
		asm.Mov.Imm(asm.R1, 1),
		callback.WithReference("cb"),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, int32(bound)),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnLoop.Call(),
		asm.Mov.Imm(asm.R0, 2),
		asm.Return(),
		btf.WithFuncMetadata(asm.LoadMem(asm.R1, asm.R2, 0, asm.DWord).WithSymbol("cb").WithSource(asm.Comment("callback")), cb),
		asm.Call.Label("sub"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
	spec.Programs["caller"].Instructions = append(insns, subBody(linkage)...)
	return spec
}

// wideCaller references R10-depth in the entry, tail-calls, and on failure
// calls wide, which references R10-depth too and does not tail-call: the two
// frames total 512 bytes at depth 248 or 256.
func wideCaller(depth int16) *ebpf.CollectionSpec {
	spec := nestedTailCaller(-depth)
	insns := spec.Programs["caller"].Instructions[:16] // the entry, up to sub
	insns[12] = asm.Call.Label("wide")
	spec.Programs["caller"].Instructions = append(insns,
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, -depth, 0, asm.Word).WithSymbol("wide").WithSource(asm.Comment("wide")), staticFunc("wide")),
		asm.Mov.Imm(asm.R0, 2),
		asm.Return())
	return spec
}

// aliasCallee is a stackless entry that calls sub, which reaches R10-depth
// only through a copy of R10, so its depth has no direct R10 reference.
func aliasCallee(depth int16) *ebpf.CollectionSpec {
	spec := tailCallerFixture()
	spec.Programs["caller"].Instructions = asm.Instructions{
		btf.WithFuncMetadata(asm.Call.Label("sub").WithSymbol("caller").WithSource(asm.Comment("entry")), xdpFunc("caller")),
		asm.Mov.Imm(asm.R0, 2),
		asm.Return(),
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R2, asm.RFP).WithSymbol("sub").WithSource(asm.Comment("aliased stack")), staticFunc("sub")),
		asm.Add.Imm(asm.R2, -int32(depth)),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
	return spec
}

// timerCallee is an entry that references R10+entry, looks up a bpf_timer
// and hands the callback cb to a helper; cb references R10+cb (below zero)
// and calls sub, which references R10+sub. register is how the callback
// pointer travels: "timer" loads it into R2 straight before
// bpf_timer_set_callback; "dead" does the same behind a branch the verifier
// proves taken (R0 = 0; if R0 == 0), so only the entry's reference stays
// live and the kernel never analyzes the registration; "moved" loads it into
// R3 and copies it; "jump" branches between the load and the helper; "loop"
// hands it to bpf_loop; "direct" also calls cb from the entry.
func timerCallee(entry, cb, sub int16, register string) *ebpf.CollectionSpec {
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	timer := &btf.Struct{Name: "bpf_timer", Size: 16, Members: []btf.Member{
		{Name: "__opaque", Type: &btf.Array{Index: u32, Type: u64, Nelems: 2}},
	}}
	callback := &btf.Func{Name: "cb", Linkage: btf.StaticFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{
			{Name: "map", Type: &btf.Pointer{Target: &btf.Void{}}},
			{Name: "key", Type: &btf.Pointer{Target: u32}},
			{Name: "value", Type: &btf.Pointer{Target: timer}},
		},
	}}
	load := func(dst asm.Register) asm.Instruction {
		return asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: dst, Src: asm.PseudoFunc, Constant: -1}.WithReference("cb")
	}
	next := asm.JEq.Imm(asm.R0, 0, "") // to the call right after
	var hand asm.Instructions
	switch register {
	case "timer", "dead":
		hand = asm.Instructions{load(asm.R2), asm.FnTimerSetCallback.Call()}
	case "moved":
		hand = asm.Instructions{load(asm.R3), asm.Mov.Reg(asm.R2, asm.R3), asm.FnTimerSetCallback.Call()}
	case "jump":
		hand = asm.Instructions{load(asm.R2), next, asm.FnTimerSetCallback.Call()}
	case "loop":
		hand = asm.Instructions{asm.Mov.Imm(asm.R1, 1), load(asm.R2), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call()}
	case "direct":
		hand = asm.Instructions{load(asm.R2), asm.FnTimerSetCallback.Call(), asm.Call.Label("cb")}
	default:
		panic(register)
	}
	// The miss branch at raw offset 7 skips to "out", right after hand, which
	// starts at raw offset 15.
	miss := asm.JEq.Imm(asm.R0, 0, "")
	miss.Offset = int16(7 + hand.Size()/asm.InstructionSize)
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, entry, 0, asm.Word).WithSymbol("caller").WithSource(asm.Comment("entry")), xdpFunc("caller")), // 0
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),                // 1
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), // 2-3
		asm.LoadMapPtr(asm.R1, 0).WithReference("timers"),                                                      // 4-5
		asm.FnMapLookupElem.Call(),                                                                             // 6
		miss,                                                                                                   // 7
		asm.Mov.Reg(asm.R6, asm.R0),                                                                            // 8
		asm.Mov.Reg(asm.R1, asm.R6), asm.LoadMapPtr(asm.R2, 0).WithReference("timers"), asm.Mov.Imm(asm.R3, 1), // 9-12: CLOCK_MONOTONIC
		asm.FnTimerInit.Call(),      // 13
		asm.Mov.Reg(asm.R1, asm.R6), // 14
	}
	insns = append(insns, hand...)
	if register == "dead" {
		// R0 is 0, so the verifier walks only the branch to "out" and never
		// sees the lookup, the timer calls or the callback reference.
		skip := asm.JEq.Imm(asm.R0, 0, "")
		skip.Offset = int16(insns[1:].Size() / asm.InstructionSize)
		insns = append(asm.Instructions{insns[0], asm.Mov.Imm(asm.R0, 0), skip}, insns[1:]...)
	}
	insns = append(insns,
		asm.Mov.Imm(asm.R0, 2), // out
		asm.Return(),
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, cb, 0, asm.Word).WithSymbol("cb").WithSource(asm.Comment("timer callback")), callback),
		asm.Call.Label("sub"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, sub, 0, asm.Word).WithSymbol("sub").WithSource(asm.Comment("sub")), staticFunc("sub")),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return())
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"timers": {
			Name: "timers", Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 1,
			Key: u32, Value: &btf.Struct{Name: "timer_value", Size: 16, Members: []btf.Member{{Name: "t", Type: timer}}},
		}},
		Programs: map[string]*ebpf.ProgramSpec{"caller": {Name: "caller", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

// deadStoreCallee is an entry 288 bytes deep calling sub, which is 224 bytes
// deep but also stores at R10-256 behind a branch the verifier never takes:
// the kernel counts 288+224 = 512 bytes, the instructions say 544.
func deadStoreCallee() *ebpf.CollectionSpec {
	spec := tailCallerFixture()
	taken := asm.JEq.Imm(asm.R0, 0, "")
	taken.Offset = 1 // always: R0 is 0
	spec.Programs["caller"].Instructions = asm.Instructions{
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, -288, 0, asm.Word).WithSymbol("caller").WithSource(asm.Comment("entry")), xdpFunc("caller")),
		asm.Call.Label("sub"),
		asm.Mov.Imm(asm.R0, 2),
		asm.Return(),
		btf.WithFuncMetadata(asm.StoreImm(asm.RFP, -224, 0, asm.Word).WithSymbol("sub").WithSource(asm.Comment("sub")), staticFunc("sub")),
		asm.Mov.Imm(asm.R0, 0),
		taken,
		asm.StoreImm(asm.RFP, -256, 0, asm.Word), // never runs
		asm.Return(),
	}
	return spec
}

// paddedTailCaller is tailCallerFixture whose entry frame references
// R10+bound.
func paddedTailCaller(bound int16) *ebpf.CollectionSpec {
	spec := tailCallerFixture()
	insns := spec.Programs["caller"].Instructions
	entry := insns[0]
	pad := btf.WithFuncMetadata(asm.StoreImm(asm.RFP, bound, 0, asm.Word).
		WithSymbol(entry.Symbol()).WithSource(entry.Source()), btf.FuncMetadata(&entry))
	insns[0] = btf.WithFuncMetadata(entry.WithSymbol("").WithSource(nil), nil)
	spec.Programs["caller"].Instructions = append(asm.Instructions{pad}, insns...)
	return spec
}

// frameChain is a stackless call chain of frames functions, the entry
// first and the tail-calling sub last.
func frameChain(frames int) *ebpf.CollectionSpec {
	name := func(i int) string {
		switch i {
		case 0:
			return "caller"
		case frames - 1:
			return "sub"
		}
		return fmt.Sprintf("f%d", i)
	}
	var insns asm.Instructions
	for i := range frames - 1 {
		fn := staticFunc(name(i))
		if i == 0 {
			fn = xdpFunc("caller")
		}
		insns = append(insns,
			btf.WithFuncMetadata(asm.Call.Label(name(i+1)).WithSymbol(name(i)).WithSource(asm.Comment(name(i))), fn),
			asm.Return())
	}
	spec := tailCallerFixture()
	spec.Programs["caller"].Instructions = append(insns, subBody(btf.StaticFunc)...)
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

// The kernel sums every frame above a tail-calling subprogram. At the refusing
// bound the original still loads, so it is the transform's deepening that
// crosses; one slot shallower transforms and loads.
func TestBpfTailCallDepthSumsCallers(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, tc := range []struct {
		name           string
		deep, shallow  func() *ebpf.CollectionSpec
		deepReq, shReq LookupRequest
	}{
		{"chain", func() *ebpf.CollectionSpec { return chainTailCaller(192) }, func() *ebpf.CollectionSpec { return chainTailCaller(96) },
			LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Stack: StackAudit{LowestOffset: -192}},
			LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Stack: StackAudit{LowestOffset: -96}}},
		{"nested", func() *ebpf.CollectionSpec { return nestedTailCaller(-216) }, func() *ebpf.CollectionSpec { return nestedTailCaller(-208) },
			LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: StackAudit{LowestOffset: -216}},
			LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: StackAudit{LowestOffset: -208}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain := loadOrSkip(t, tc.deep())
			t.Cleanup(plain.Close)
			if _, err := transformLookup(tc.deep(), tc.deepReq); !errors.Is(err, ErrRefused) {
				t.Fatalf("deep: want refusal, got %v", err)
			}
			work := tc.shallow()
			if _, err := transformLookup(work, tc.shReq); err != nil {
				t.Fatal(err)
			}
			injected := loadOrSkip(t, work)
			t.Cleanup(injected.Close)
		})
	}
}

// The transform's deeper frames and hook frames reach the kernel's other call
// chain limits too: the caller-depth limit through a bpf_loop callback, the
// 512-byte combined stack (also a lookup site's frame plus its hook's), and
// the 8-frame call depth. At the refusing bound the original loads; one step
// shallower transforms and loads.
func TestBpfStackLimitsAcrossCalls(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, tc := range stackLimitCases() {
		if tc.refuse == nil {
			continue // the shallow case loads below, next to its deep twin
		}
		t.Run(tc.name, func(t *testing.T) {
			plain, err := ebpf.NewCollection(tc.spec())
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) && strings.Contains(fmt.Sprintf("%+v", ve), "cannot tail call within callback") {
				t.Skipf("kernel forbids tail calls in callbacks: %v", err)
			}
			if err != nil {
				plain = loadOrSkip(t, tc.spec())
			}
			t.Cleanup(plain.Close)
			if _, err := transformLookup(tc.spec(), tc.req); !errors.Is(err, ErrRefused) {
				t.Fatalf("deep: want refusal, got %v", err)
			}
			shallow := findStackLimitCase(tc.name + "-shallow")
			work := shallow.spec()
			if _, err := transformLookup(work, shallow.req); err != nil {
				t.Fatal(err)
			}
			injected := loadOrSkip(t, work)
			t.Cleanup(injected.Close)
		})
	}
}

// A depth taken from instructions can overstate the kernel's: deadStoreCallee
// loads, though its instructions add up past 512 bytes. The entry's ctx
// spill really does push the chain past the limit, so the transform refuses
// instead of treating the overestimated original as already past it.
func TestBpfStackLimitsOverestimatedOriginal(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	plain := loadOrSkip(t, deadStoreCallee())
	t.Cleanup(plain.Close)
	if _, err := transformLookup(deadStoreCallee(), overestimatedReq); !errors.Is(err, ErrRefused) {
		t.Fatalf("want refusal, got %v", err)
	}
}

// A timer callback stays in the chain that registers it, because the kernel
// only marks it async when it analyzes the registration: with the
// registration behind a branch the verifier proves dead, the original (a
// live 448-byte entry, cb and sub at their unverified depth of 0, 32 each
// once rounded) loads at 512 bytes, and the entry's ctx spill makes it 544,
// which the transform refuses and the kernel, where it rounds to 32 (6.1 and
// 6.6; 6.12 on JITs and rounds to 16, where dead frames count 0), rejects.
// The live registration is refused too, although the kernel walks that
// callback as a root of its own: the shape alone cannot tell the two apart.
func TestBpfStackLimitsTimerCallback(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	req := func(bound int16) LookupRequest {
		return LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Stack: StackAudit{LowestOffset: bound}}
	}
	for _, tc := range []struct {
		name     string
		spec     func() *ebpf.CollectionSpec
		bound    int16
		original string // what the kernel does with the original: "loads" or "" for either
	}{
		{"live", func() *ebpf.CollectionSpec { return timerCallee(-256, -16, -256, "timer") }, -256, "loads"},
		{"dead", func() *ebpf.CollectionSpec { return timerCallee(-448, -16, -16, "dead") }, -448, "loads"},
		// The entry's spill: what the transform would emit for "dead".
		// CheckLookupStack already refuses a bound this deep, so only the
		// kernel's verdict is checked.
		{"dead-544", func() *ebpf.CollectionSpec { return timerCallee(-480, -16, -16, "dead") }, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.bound != 0 {
				if _, err := transformLookup(tc.spec(), req(tc.bound)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "caller -> cb -> sub") {
					t.Fatalf("want refusal naming caller -> cb -> sub, got %v", err)
				}
			}
			if tc.original == "loads" {
				plain := loadOrSkip(t, tc.spec())
				t.Cleanup(plain.Close)
				return
			}
			plain, err := ebpf.NewCollection(tc.spec())
			if err == nil {
				t.Cleanup(plain.Close)
				t.Log("kernel loads the 544-byte chain: it rounds frames to 16 bytes and counts the dead callback's at 0")
				return
			}
			var ve *ebpf.VerifierError
			if !errors.As(err, &ve) || !strings.Contains(fmt.Sprintf("%+v", ve), "combined stack size") {
				t.Fatalf("want the kernel's combined-stack refusal or a load, got %v", err)
			}
			t.Log("kernel refuses the 544-byte chain through the dead registration")
		})
	}
}

// Entry and TailCalls without lookups reserve only the slots they use: an
// entry-only request at -472 (ctx at -480) and a tail-call request at -464
// (ctx and index down to -480) leave the 32 bytes their hook frame counts on
// kernels that round to 32, and transform and load.
func TestBpfStackLimitsReserve(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, tc := range reserveCases() {
		if !tc.ok {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			work := paddedTailCaller(tc.req.Stack.LowestOffset)
			if _, err := transformLookup(work, tc.req); err != nil {
				t.Fatal(err)
			}
			injected := loadOrSkip(t, work)
			t.Cleanup(injected.Close)
		})
	}
}

// When the lookup slots alone break a call-chain limit, Auto retries with fewer
// lookups instead of refusing the rule, and the kernel loads what it keeps:
// the tail-call hook alone at -208 (also as a static dispatch hook), the
// typed sessions hook without the read-only flows copy at -200.
func TestBpfStackLimitsAutoRetry(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	// The other cases keep every lookup, refuse, or (map-in-map) lack the
	// inner map a load needs.
	retried := map[string]bool{"tails-208": true, "dispatch-tails-208": true, "copy-200": true}
	for _, tc := range autoRetryCases() {
		if !retried[tc.name] {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			plain := loadOrSkip(t, tc.spec())
			t.Cleanup(plain.Close)
			work := tc.spec()
			plan, err := transformLookup(work, tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.skipped) == 0 {
				t.Fatalf("nothing skipped: %+v", plan)
			}
			injected := loadHooked(t, work, plan.hooks)
			t.Cleanup(injected.Close)
		})
	}
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
