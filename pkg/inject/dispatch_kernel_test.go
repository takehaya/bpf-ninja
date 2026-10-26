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

// dispatchFixture looks up sessions[packet u32 at 0], then tail-calls
// jmp[packet u32 at 4] and returns XDP_PASS when the tail call fails.
func dispatchFixture() *ebpf.CollectionSpec {
	spec := lookupFixture()
	short := asm.JGT.Reg(asm.R4, asm.R3, "")
	short.Offset = 17 // slot 5 -> 23
	missing := asm.JEq.Imm(asm.R0, 0, "")
	missing.Offset = 1 // slot 14 -> 16
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),                         // 0
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),            // 1: data
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),            // 2: data_end
		asm.Mov.Reg(asm.R4, asm.R2),                         // 3
		asm.Add.Imm(asm.R4, 8),                              // 4
		short,                                               // 5
		asm.LoadMem(asm.R7, asm.R2, 4, asm.Word),            // 6: tail-call index
		asm.LoadMem(asm.R2, asm.R2, 0, asm.Word),            // 7: key
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),         // 8
		asm.Mov.Reg(asm.R2, asm.RFP),                        // 9
		asm.Add.Imm(asm.R2, -4),                             // 10
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), // 11-12
		asm.FnMapLookupElem.Call(),                          // 13
		missing,                                             // 14
		asm.LoadMem(asm.R8, asm.R0, 0, asm.DWord),           // 15: use the result
		asm.Mov.Reg(asm.R1, asm.R6),                         // 16
		asm.Mov.Reg(asm.R3, asm.R7),                         // 17
		asm.LoadMapPtr(asm.R2, 0).WithReference("jmp"),      // 18-19
		asm.FnTailCall.Call(),                               // 20
		asm.Mov.Imm(asm.R0, 2),                              // 21: XDP_PASS
		asm.Return(),                                        // 22
		asm.Mov.Imm(asm.R0, 1),                              // 23: short packet -> XDP_DROP
		asm.Return(),                                        // 24
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("dispatch fixture")),
		btf.FuncMetadata(&spec.Programs["p"].Instructions[0]))
	spec.Programs["p"].Instructions = insns
	spec.Maps["jmp"] = &ebpf.MapSpec{Name: "jmp", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 2}
	return spec
}

// dispatchRecord is one observed dispatch call: the site, the first 8 bytes
// behind key (zero for NULL), and the value and map pointers.
type dispatchRecord struct {
	Site  uint32
	Seen  uint32
	Key   uint64
	Value uint64
	Map   uint64
}

// dispatchObserver appends each call of fn to obs[0..7] in order; cnt[0]
// counts the calls.
func dispatchObserver(fn string, target *ebpf.Program) *ebpf.CollectionSpec {
	arg := func(n int32) asm.Instructions {
		return asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.R9), asm.Mov.Imm(asm.R2, n),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
			asm.FnGetFuncArg.Call(),
			asm.JNE.Imm(asm.R0, 0, "done"),
			asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord),
		}
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R9, asm.R1),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("cnt"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.LoadMem(asm.R7, asm.R0, 0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R7), asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.JGT.Imm(asm.R7, 7, "done"),
		asm.StoreMem(asm.RFP, -8, asm.R7, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		asm.LoadMapPtr(asm.R1, 0).WithReference("obs"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.StoreImm(asm.R6, 4, 1, asm.Word),
	}
	insns = append(insns, arg(1)...)
	insns = append(insns, asm.StoreMem(asm.R6, 0, asm.R1, asm.Word))
	insns = append(insns, arg(2)...)
	insns = append(insns, asm.Mov.Reg(asm.R3, asm.R1), asm.Mov.Reg(asm.R1, asm.R6), asm.Add.Imm(asm.R1, 8),
		asm.Mov.Imm(asm.R2, 8), asm.FnProbeReadKernel.Call())
	insns = append(insns, arg(3)...)
	insns = append(insns, asm.StoreMem(asm.R6, 16, asm.R1, asm.DWord))
	insns = append(insns, arg(4)...)
	insns = append(insns, asm.StoreMem(asm.R6, 24, asm.R1, asm.DWord))
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return())
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{
			"cnt": {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
			"obs": {Type: ebpf.Array, KeySize: 4, ValueSize: 32, MaxEntries: 8},
		},
		Programs: map[string]*ebpf.ProgramSpec{"observe": {
			Name: "dispatch_obs", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: fn, AttachTarget: target, License: "GPL", Instructions: insns,
		}},
	}
}

func TestBpfDispatch(t *testing.T)       { testDispatch(t, false) }
func TestBpfDispatchStatic(t *testing.T) { testDispatch(t, true) }

// One fentry on the dispatch hook sees the entry, each lookup hit and each
// failed tail call of the program, in order, and the program's results do
// not change.
func testDispatch(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	work := dispatchFixture()
	plan, err := transformLookup(work, LookupRequest{ProgramName: "p", Auto: true, Entry: true, TailCalls: true,
		Dispatch: true, StaticUntrusted: static, HookName: "d", Stack: StackAudit{LowestOffset: -8}})
	if err != nil {
		t.Fatal(err)
	}
	var lookupPC, tailPC uint32
	var kinds []HookKind
	for _, hook := range plan.hooks {
		if hook.Name != "d" || !hook.Dispatch || hook.Static != static || hook.Untrusted == static {
			t.Fatalf("hook: %+v", hook)
		}
		kinds = append(kinds, hook.Kind)
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
	if len(kinds) != 3 || lookupPC != 13 || tailPC != 20 {
		t.Fatalf("hooks %v, lookup %d, tail call %d", kinds, lookupPC, tailPC)
	}
	load := func(spec *ebpf.CollectionSpec) *ebpf.Collection {
		c, target := loadOrSkip(t, spec), loadOrSkip(t, tailTargetFixture())
		t.Cleanup(c.Close)
		t.Cleanup(target.Close)
		if err := c.Maps["jmp"].Put(uint32(0), target.Programs["target"]); err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["sessions"].Put(uint32(7), [2]uint64{3, 9}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	plain, injected := load(dispatchFixture()), load(work)
	obs := loadOrSkip(t, dispatchObserver("d", injected.Programs["p"]))
	t.Cleanup(obs.Close)
	l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("fentry unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	type want struct {
		site        uint32
		key         uint32
		value, map_ bool
	}
	for _, tc := range []struct {
		key, index uint32
		action     uint32
		calls      []want
	}{
		// Hit, failed tail call.
		{7, 1, 2, []want{{DispatchEntrySite, 0, false, false}, {lookupPC, 7, true, true}, {tailPC, 1, false, true}}},
		// Miss, successful tail call: only the entry.
		{8, 0, 3, []want{{DispatchEntrySite, 0, false, false}}},
	} {
		if err := obs.Maps["cnt"].Put(uint32(0), uint64(0)); err != nil {
			t.Fatal(err)
		}
		for i := range uint32(8) {
			if err := obs.Maps["obs"].Put(i, dispatchRecord{}); err != nil {
				t.Fatal(err)
			}
		}
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, tc.key)
		binary.LittleEndian.PutUint32(packet[4:], tc.index)
		for _, c := range []*ebpf.Collection{plain, injected} {
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
			if err != nil || ret != tc.action {
				t.Fatalf("key=%d index=%d: action=%d want %d err=%v", tc.key, tc.index, ret, tc.action, err)
			}
		}
		var n uint64
		if err := obs.Maps["cnt"].Lookup(uint32(0), &n); err != nil || n != uint64(len(tc.calls)) {
			t.Fatalf("key=%d index=%d: %d calls, want %d (err %v)", tc.key, tc.index, n, len(tc.calls), err)
		}
		for i, w := range tc.calls {
			var r dispatchRecord
			if err := obs.Maps["obs"].Lookup(uint32(i), &r); err != nil {
				t.Fatal(err)
			}
			if r.Seen != 1 || r.Site != w.site || uint32(r.Key) != w.key || (r.Value != 0) != w.value || (r.Map != 0) != w.map_ {
				t.Fatalf("key=%d index=%d call %d: %+v, want %+v", tc.key, tc.index, i, r, w)
			}
		}
	}
}

// With Dispatch a tail call in the entry function spills the prog array into
// the map slot, so that frame reaches one slot deeper than with the scalar
// tail-call hook. The transform refuses at the bound where that crosses the
// caller-depth limit and loads one slot under it; the original at the refused
// bound still loads. The hook is static so every kernel loads it.
func TestBpfDispatchStackLimit(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	req := func(bound int16) LookupRequest {
		return LookupRequest{ProgramName: "caller", TailCalls: true, Dispatch: true, StaticUntrusted: true, HookName: "d", Stack: StackAudit{LowestOffset: bound}}
	}
	if _, err := transformLookup(nestedTailCaller(-200), req(-200)); !errors.Is(err, ErrRefused) {
		t.Fatalf("-200: want refusal, got %v", err)
	}
	plain := loadOrSkip(t, nestedTailCaller(-200))
	t.Cleanup(plain.Close)
	work := nestedTailCaller(-192)
	plan, err := transformLookup(work, req(-192))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Kind != HookTailCall || len(plan.hooks[0].Sites) != 2 {
		t.Fatalf("plan: %+v", plan)
	}
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
}
