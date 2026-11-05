package inject

import (
	"encoding/binary"
	"errors"
	"slices"
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
// behind key and value (zero for NULL) and the id of the bpf_map behind map.
type dispatchRecord struct {
	Site  uint32
	Seen  uint32
	Key   uint64
	Value uint64
	MapID uint32
	_     uint32
}

// dispatchObserver appends each call of fn to obs[0..7] in order; cnt[0]
// counts the calls. The pointer arguments are read with
// bpf_probe_read_kernel, which zeroes the destination for a NULL pointer.
func dispatchObserver(t *testing.T, fn string, target *ebpf.Program) *ebpf.CollectionSpec {
	t.Helper()
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	idOffset := bpfMapIDOffset(t, kernel)
	arg := func(n int32) asm.Instructions {
		return asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.R9), asm.Mov.Imm(asm.R2, n),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
			asm.FnGetFuncArg.Call(),
			asm.JNE.Imm(asm.R0, 0, "done"),
			asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord),
		}
	}
	// read copies size bytes from R1+off into the record at dst.
	read := func(dst, size, off int32) asm.Instructions {
		return asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R1), asm.Add.Imm(asm.R3, off),
			asm.Mov.Reg(asm.R1, asm.R6), asm.Add.Imm(asm.R1, dst),
			asm.Mov.Imm(asm.R2, size), asm.FnProbeReadKernel.Call(),
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
	insns = append(insns, read(8, 8, 0)...)
	insns = append(insns, arg(3)...)
	insns = append(insns, read(16, 8, 0)...)
	insns = append(insns, arg(4)...)
	insns = append(insns, read(24, 4, idOffset)...)
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

// asTC turns an XDP fixture whose context reads are data at 0 and data_end
// at 4 into a tc program: struct __sk_buff context, data at 76, data_end at 80.
func asTC(spec *ebpf.CollectionSpec) *ebpf.CollectionSpec {
	u32 := &btf.Int{Name: "u32", Size: 4}
	skb := &btf.Struct{Name: "__sk_buff", Size: 192, Members: []btf.Member{
		{Name: "len", Type: u32}, {Name: "data", Type: u32, Offset: 76 * 8}, {Name: "data_end", Type: u32, Offset: 80 * 8},
	}}
	for _, p := range spec.Programs {
		p.Type = ebpf.SchedCLS
		fn := *btf.FuncMetadata(&p.Instructions[0])
		proto := *fn.Type.(*btf.FuncProto)
		proto.Params = []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: skb}}}
		fn.Type = &proto
		p.Instructions[0] = btf.WithFuncMetadata(p.Instructions[0], &fn)
		for i, ins := range p.Instructions {
			if ins.OpCode.Class() == asm.LdXClass && ins.Src == asm.R6 && ins.Dst != asm.R6 && (ins.Offset == 0 || ins.Offset == 4) {
				p.Instructions[i].Offset += 76
			}
		}
	}
	return spec
}

// asCGroupSKB is asTC as a cgroup_skb egress program, whose verifier allows
// the fixtures' return values 0 to 3.
func asCGroupSKB(spec *ebpf.CollectionSpec) *ebpf.CollectionSpec {
	for _, p := range asTC(spec).Programs {
		p.Type, p.AttachType = ebpf.CGroupSKB, ebpf.AttachCGroupInetEgress
	}
	return spec
}

// l3Offset is where a program of type typ sees BPF_PROG_TEST_RUN's input
// start: cgroup_skb gets the skb after the Ethernet header is pulled.
func l3Offset(typ ebpf.ProgramType) int {
	if typ == ebpf.CGroupSKB {
		return 14
	}
	return 0
}

// skipNoPacketPointers skips a cgroup_skb test where BPF_PROG_TEST_RUN does
// not set the skb's data_end for cgroup_skb (6.12 does not): the fixtures
// then take their short-packet path, return 1, for every packet. A zero
// packet misses and tail-calls the target, which returns 3.
func skipNoPacketPointers(t *testing.T, prog *ebpf.Program) {
	t.Helper()
	if prog.Type() != ebpf.CGroupSKB {
		return
	}
	if ret, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err == nil && ret == 1 {
		t.Skip("BPF_PROG_TEST_RUN sets no cgroup_skb packet pointers on this kernel")
	}
}

func TestBpfDispatch(t *testing.T)         { testDispatch(t, false, false, "") }
func TestBpfDispatchStatic(t *testing.T)   { testDispatch(t, true, false, "") }
func TestBpfDispatchTC(t *testing.T)       { testDispatch(t, false, true, "") }
func TestBpfDispatchTCStatic(t *testing.T) { testDispatch(t, true, true, "") }

// With Lookups the lookup reports misses too, with a NULL value, or only them.
func TestBpfDispatchMiss(t *testing.T)         { testDispatch(t, false, false, LookupMiss) }
func TestBpfDispatchAny(t *testing.T)          { testDispatch(t, false, false, LookupAny) }
func TestBpfDispatchAnyStatic(t *testing.T)    { testDispatch(t, true, false, LookupAny) }
func TestBpfDispatchAnyTC(t *testing.T)        { testDispatch(t, false, true, LookupAny) }
func TestBpfDispatchMissTCStatic(t *testing.T) { testDispatch(t, true, true, LookupMiss) }

func TestBpfDispatchCGroupSKB(t *testing.T)       { testDispatchAs(t, false, asCGroupSKB, LookupAny) }
func TestBpfDispatchCGroupSKBStatic(t *testing.T) { testDispatchAs(t, true, asCGroupSKB, LookupAny) }

// One fentry on the dispatch hook sees the entry, each lookup hit and each
// failed tail call of the program, in order, and the program's results do
// not change. With tc, the same program runs as a tc classifier.
func testDispatch(t *testing.T, static, tc bool, lookups LookupWhen) {
	conv := func(spec *ebpf.CollectionSpec) *ebpf.CollectionSpec { return spec }
	if tc {
		conv = asTC
	}
	testDispatchAs(t, static, conv, lookups)
}

// testDispatchAs is testDispatch with the fixtures converted by conv.
func testDispatchAs(t *testing.T, static bool, conv func(*ebpf.CollectionSpec) *ebpf.CollectionSpec, lookups LookupWhen) {
	testutil.SkipIfNotRoot(t)
	fixture := func() *ebpf.CollectionSpec { return conv(dispatchFixture()) }
	target := func() *ebpf.CollectionSpec { return conv(tailTargetFixture()) }
	work := fixture()
	plan, err := transformLookup(work, LookupRequest{ProgramName: "p", Auto: true, Entry: true, TailCalls: true,
		Dispatch: true, StaticUntrusted: static, Lookups: lookups, HookName: "d", Stack: StackAudit{LowestOffset: -8}})
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
	// hooks is nil for the plain program: only the transformed load may skip
	// on a kernel without arg:untrusted.
	load := func(spec *ebpf.CollectionSpec, hooks []LookupHook) *ebpf.Collection {
		c, tgt := loadHooked(t, spec, hooks), loadOrSkip(t, target())
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
	plain, injected := load(fixture(), nil), load(work, plan.hooks)
	skipNoPacketPointers(t, plain.Programs["p"])
	mapID := func(m *ebpf.Map) uint32 {
		info, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := info.ID()
		return uint32(id)
	}
	sessions, jmp := mapID(injected.Maps["sessions"]), mapID(injected.Maps["jmp"])
	obs := loadOrSkip(t, dispatchObserver(t, "d", injected.Programs["p"]))
	t.Cleanup(obs.Close)
	l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("fentry unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	entry := dispatchRecord{Site: DispatchEntrySite, Seen: 1}
	hit := []dispatchRecord{{Site: lookupPC, Seen: 1, Key: 7, Value: 3, MapID: sessions}}
	miss := []dispatchRecord{{Site: lookupPC, Seen: 1, Key: 8, MapID: sessions}}
	if !lookups.hit() {
		hit = nil
	}
	if !lookups.miss() {
		miss = nil
	}
	for _, tc := range []struct {
		key, index uint32
		action     uint32
		calls      []dispatchRecord
	}{
		// Hit, failed tail call: the lookup passes sessions and its value
		// {3, 9}; the tail call passes the index and the prog array.
		{7, 1, 2, slices.Concat([]dispatchRecord{entry}, hit, []dispatchRecord{{Site: tailPC, Seen: 1, Key: 1, MapID: jmp}})},
		// Miss, successful tail call: the entry, and the lookup with a NULL
		// value when misses are observed.
		{8, 0, 3, slices.Concat([]dispatchRecord{entry}, miss)},
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
		off := l3Offset(work.Programs["p"].Type)
		binary.LittleEndian.PutUint32(packet[off:], tc.key)
		binary.LittleEndian.PutUint32(packet[off+4:], tc.index)
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
			r.Key = uint64(uint32(r.Key)) // the key slot holds a u32; its upper half is stack
			if r != w {
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
