package inject

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

const (
	queuePushPC = 18
	queuePopPC  = 23
	queuePeekPC = 28
	selPop      = 2
	selPeek     = 3
	bpfExist    = 2
)

// queueFixture reads a u32 value and a u32 selector from the packet and
// stores the value as a u64 at fp-8. Selector 0 pushes it, 1 pushes it with
// BPF_EXIST, 2 pops into fp-8 and 3 peeks into it. The program returns
// XDP_PASS when the helper succeeded and XDP_DROP when it failed, testing W0
// as the guard does. Each helper has its own map reference, since a branch
// ends the basic block discovery tracks R1 in. With peekOnly the pop is a
// peek too, for a bloom filter, which has no pop. The pop and peek branches
// read the value first: 7.1 and newer kernels without the verifier fix reject
// a bloom filter peek behind a branch when nothing else on its path reads the
// value ("slot poisoned by dead code elimination"), which 7.0 loads. See
// TestBpfBloomPeekPoisoned.
func queueFixture(typ ebpf.MapType, peekOnly bool) *ebpf.CollectionSpec {
	u64 := &btf.Int{Name: "u64", Size: 8}
	jump := func(ins asm.Instruction, off int16) asm.Instruction { ins.Offset = off; return ins }
	m := func() asm.Instruction { return asm.LoadMapPtr(asm.R1, 0).WithReference("q") }
	second := asm.FnMapPopElem
	if peekOnly {
		second = asm.FnMapPeekElem
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),                  // 0
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),     // 1: data
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),     // 2: data_end
		asm.Mov.Reg(asm.R4, asm.R2),                  // 3
		asm.Add.Imm(asm.R4, 8),                       // 4
		jump(asm.JGT.Reg(asm.R4, asm.R3, ""), 28),    // 5 -> 34
		asm.LoadMem(asm.R8, asm.R2, 0, asm.Word),     // 6: value
		asm.LoadMem(asm.R9, asm.R2, 4, asm.Word),     // 7: selector
		asm.StoreMem(asm.RFP, -8, asm.R8, asm.DWord), // 8
		asm.Mov.Reg(asm.R2, asm.RFP),                 // 9
		asm.Add.Imm(asm.R2, -8),                      // 10
		jump(asm.JEq.Imm(asm.R9, selPop, ""), 8),     // 11 -> 20
		jump(asm.JEq.Imm(asm.R9, selPeek, ""), 12),   // 12 -> 25
		asm.Mov.Imm(asm.R3, 0),                       // 13
		jump(asm.JEq.Imm(asm.R9, 0, ""), 1),          // 14 -> 16
		asm.Mov.Imm(asm.R3, bpfExist),                // 15
		m(),                                          // 16-17
		asm.FnMapPushElem.Call(),                     // 18
		jump(asm.Ja.Label(""), 9),                    // 19 -> 29
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.DWord),  // 20: read the value
		m(),                       // 21-22
		second.Call(),             // 23
		jump(asm.Ja.Label(""), 4), // 24 -> 29
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.DWord), // 25: read the value
		m(),                                    // 26-27
		asm.FnMapPeekElem.Call(),               // 28
		asm.Mov.Imm(asm.R1, 2),                 // 29: XDP_PASS
		jump(asm.JSGE.Imm32(asm.R0, 0, ""), 1), // 30 -> 32
		asm.Mov.Imm(asm.R1, 1),                 // 31: XDP_DROP
		asm.Mov.Reg(asm.R0, asm.R1),            // 32
		asm.Return(),                           // 33
		asm.Mov.Imm(asm.R0, 1),                 // 34: short packet
		asm.Return(),                           // 35
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("queue fixture")), xdpFunc("p"))
	spec := &ebpf.MapSpec{Name: "q", Type: typ, ValueSize: 8, MaxEntries: 2, Value: u64}
	if typ == ebpf.BloomFilter {
		spec.MaxEntries = 16
	}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps:     map[string]*ebpf.MapSpec{"q": spec},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

// queueStep is one run of queueFixture: the packet's value and selector, the
// helper's result and the value the hook sees.
type queueStep struct {
	value, sel uint32
	ret        int64
	seen       uint64
}

// queueSteps fill a two-entry queue (E2BIG when full, BPF_EXIST replacing the
// oldest), then drain it until a pop and a peek fail with ENOENT and zeroes.
var queueSteps = []queueStep{
	{10, 0, 0, 10}, {11, 0, 0, 11}, {12, 0, -int64(unix.E2BIG), 12}, {13, 1, 0, 13},
	{99, selPop, 0, 11}, {99, selPeek, 0, 13}, {99, selPop, 0, 13},
	{99, selPop, -int64(unix.ENOENT), 0}, {99, selPeek, -int64(unix.ENOENT), 0},
}

// bloomSteps miss a value, push it, find it, and miss another.
var bloomSteps = []queueStep{
	{5, selPeek, -int64(unix.ENOENT), 5}, {5, 0, 0, 5}, {5, selPeek, 0, 5}, {6, selPop, -int64(unix.ENOENT), 6},
}

func (s queueStep) op() (HookKind, uint64) {
	switch s.sel {
	case selPop:
		return HookPop, queuePopPC
	case selPeek:
		return HookPeek, queuePeekPC
	}
	return HookPush, queuePushPC
}

// runQueue runs steps through plain and injected, which must return XDP_PASS
// exactly when the helper succeeded.
func runQueue(t *testing.T, plain, injected *ebpf.Collection, steps []queueStep) {
	t.Helper()
	for _, step := range steps {
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, step.value)
		binary.LittleEndian.PutUint32(packet[4:], step.sel)
		want := uint32(2)
		if step.ret < 0 {
			want = 1
		}
		for i, c := range []*ebpf.Collection{plain, injected} {
			ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
			if err != nil || ret != want {
				t.Fatalf("%s %+v: action=%d want %d err=%v", []string{"plain", "injected"}[i], step, ret, want, err)
			}
		}
	}
}

func TestBpfQueueOps(t *testing.T)   { testQueueOps(t, ebpf.Queue, false) }
func TestBpfStackOps(t *testing.T)   { testQueueOps(t, ebpf.Stack, false) }
func TestBpfQueueOpsTC(t *testing.T) { testQueueOps(t, ebpf.Queue, true) }

// The typed push, pop and peek hooks see the site, the value pushed or
// written and status = (u32)ret | flags << 32 of every call, and the
// program's results do not change. A stack pops the newest value instead.
func testQueueOps(t *testing.T, typ ebpf.MapType, tc bool) {
	testutil.SkipIfNotRoot(t)
	fixture := func() *ebpf.CollectionSpec { return queueFixture(typ, false) }
	if tc {
		fixture = func() *ebpf.CollectionSpec { return asTC(queueFixture(typ, false)) }
	}
	steps := queueSteps
	if typ == ebpf.Stack {
		// BPF_EXIST drops the oldest value of a stack too: [11, 13] after
		// the pushes, popped and peeked newest first.
		steps = slices.Clone(queueSteps)
		steps[4].seen, steps[5].seen, steps[6].seen = 13, 11, 11
	}
	work := fixture()
	req := autoReq()
	req.Lookups, req.Pushes, req.Pops, req.Peeks, req.Stack.LowestOffset = LookupNone, CallAny, CallAny, CallAny, -8
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"lookup_hook_q_push", "lookup_hook_q_pop", "lookup_hook_q_peek"}
	if len(plan.hooks) != 3 || slices.ContainsFunc(plan.hooks, func(h LookupHook) bool {
		return !slices.Contains(names, h.Name) || h.Untrusted || h.Static || h.When != string(CallAny)
	}) {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, fixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	obs := map[HookKind]*ebpf.Collection{}
	for i, op := range []HookKind{HookPush, HookPop, HookPeek} {
		obs[op] = attachArgObserver(t, names[i], injected.Programs["p"], false, true, false)
	}
	runQueue(t, plain, injected, steps)
	want := map[HookKind][][4]uint64{}
	for _, step := range steps {
		op, pc := step.op()
		status := uint64(uint32(step.ret))
		if step.sel == 1 {
			status |= bpfExist << 32
		}
		want[op] = append(want[op], [4]uint64{pc, step.seen, status})
	}
	for op, o := range obs {
		if got := observed(t, o); !slices.Equal(got, want[op]) {
			t.Errorf("%s hook: %x\nwant %x", op, got, want[op])
		}
	}
}

// A bloom filter peek tests the value the program passes, and misses with
// ENOENT until the value was pushed. The push hook sees the push, and the
// error-only peek hook each miss.
func TestBpfBloomFilterOps(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	fixture := func() *ebpf.CollectionSpec { return queueFixture(ebpf.BloomFilter, true) }
	work := fixture()
	req := autoReq()
	req.Lookups, req.Pushes, req.Peeks, req.Stack.LowestOffset = LookupNone, CallAny, CallError, -8
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || plan.hooks[1].Name != "lookup_hook_q_peek" || len(plan.hooks[1].Sites) != 2 {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, fixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	push := attachArgObserver(t, plan.hooks[0].Name, injected.Programs["p"], false, true, false)
	peek := attachArgObserver(t, plan.hooks[1].Name, injected.Programs["p"], false, true, false)
	runQueue(t, plain, injected, bloomSteps)
	ret := -int64(unix.ENOENT)
	enoent := uint64(uint32(ret))
	if got, want := observed(t, push), [][4]uint64{{queuePushPC, 5, 0}}; !slices.Equal(got, want) {
		t.Errorf("push hook: %x\nwant %x", got, want)
	}
	want := [][4]uint64{{queuePeekPC, 5, enoent}, {queuePopPC, 6, enoent}} // the second peek sits at the pop's site
	if got := observed(t, peek); !slices.Equal(got, want) {
		t.Errorf("peek hook: %x\nwant %x", got, want)
	}
}

func TestBpfQueueOpsDispatch(t *testing.T)       { testQueueOpsDispatch(t, false) }
func TestBpfQueueOpsDispatchStatic(t *testing.T) { testQueueOpsDispatch(t, true) }

// One dispatch hook sees every push and every failed pop and peek with info =
// site | op << 32 | (flags & 0xff) << 36 | (u16)ret << 48, a NULL key and the
// value.
func testQueueOpsDispatch(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	work := queueFixture(ebpf.Queue, false)
	req := autoReq()
	req.Lookups, req.Pushes, req.Pops, req.Peeks = LookupNone, CallAny, CallError, CallError
	req.Dispatch, req.StaticUntrusted, req.HookName, req.Stack.LowestOffset = true, static, "d", -8
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 3 || plan.hooks[0].Static != static {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, queueFixture(ebpf.Queue, false))
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	obs := attachArgObserver(t, "d", injected.Programs["p"], false, true, true)
	// The observer keeps eight calls: the four pushes and four of the pops
	// and peeks, two of them failures.
	steps := queueSteps[:8]
	runQueue(t, plain, injected, steps)
	var want [][4]uint64
	for _, step := range steps {
		op, pc := step.op()
		if op != HookPush && step.ret >= 0 {
			continue
		}
		info := pc | map[HookKind]uint64{HookPush: 3, HookPop: 4, HookPeek: 5}[op]<<32 | uint64(uint16(step.ret))<<48
		if step.sel == 1 {
			info |= bpfExist << 36
		}
		want = append(want, [4]uint64{info, 0, step.seen})
	}
	if got := observed(t, obs); !slices.Equal(got, want) {
		t.Errorf("dispatch hook: %x\nwant %x", got, want)
	}
}

const (
	innerPushPC = 22
	innerPopPC  = 24
)

// innerQueueFixture pushes the packet's value to the queue an array of maps
// holds at index 0, with BPF_EXIST when the selector is 1, or pops it when
// the selector is selPop. R1 is the inner map the outer lookup returned, so
// the push and pop go to the generic hooks.
func innerQueueFixture() *ebpf.CollectionSpec {
	u64 := &btf.Int{Name: "u64", Size: 8}
	jump := func(ins asm.Instruction, off int16) asm.Instruction { ins.Offset = off; return ins }
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),                      // 0
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),         // 1: data
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),         // 2: data_end
		asm.Mov.Reg(asm.R4, asm.R2),                      // 3
		asm.Add.Imm(asm.R4, 8),                           // 4
		jump(asm.JGT.Reg(asm.R4, asm.R3, ""), 24),        // 5 -> 30
		asm.LoadMem(asm.R8, asm.R2, 0, asm.Word),         // 6: value
		asm.LoadMem(asm.R9, asm.R2, 4, asm.Word),         // 7: selector
		asm.StoreMem(asm.RFP, -16, asm.R8, asm.DWord),    // 8
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),           // 9: outer key
		asm.Mov.Reg(asm.R2, asm.RFP),                     // 10
		asm.Add.Imm(asm.R2, -4),                          // 11
		asm.LoadMapPtr(asm.R1, 0).WithReference("outer"), // 12-13
		asm.FnMapLookupElem.Call(),                       // 14
		jump(asm.JEq.Imm(asm.R0, 0, ""), 14),             // 15 -> 30
		asm.Mov.Reg(asm.R1, asm.R0),                      // 16: inner map
		asm.Mov.Reg(asm.R2, asm.RFP),                     // 17
		asm.Add.Imm(asm.R2, -16),                         // 18
		jump(asm.JEq.Imm(asm.R9, selPop, ""), 4),         // 19 -> 24
		asm.Mov.Reg(asm.R3, asm.R9),                      // 20
		asm.LSh.Imm(asm.R3, 1),                           // 21: 1 -> BPF_EXIST
		asm.FnMapPushElem.Call(),                         // 22
		jump(asm.Ja.Label(""), 1),                        // 23 -> 25
		asm.FnMapPopElem.Call(),                          // 24
		asm.Mov.Imm(asm.R1, 2),                           // 25: XDP_PASS
		jump(asm.JSGE.Imm32(asm.R0, 0, ""), 1),           // 26 -> 28
		asm.Mov.Imm(asm.R1, 1),                           // 27: XDP_DROP
		asm.Mov.Reg(asm.R0, asm.R1),                      // 28
		asm.Return(),                                     // 29
		asm.Mov.Imm(asm.R0, 1),                           // 30: short packet or no inner map
		asm.Return(),                                     // 31
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("inner queue fixture")), xdpFunc("p"))
	inner := &ebpf.MapSpec{Name: "q", Type: ebpf.Queue, ValueSize: 8, MaxEntries: 2, Value: u64}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps:     map[string]*ebpf.MapSpec{"outer": {Name: "outer", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: inner}},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

func TestBpfQueueOpsInner(t *testing.T)       { testQueueOpsInner(t, false) }
func TestBpfQueueOpsInnerStatic(t *testing.T) { testQueueOpsInner(t, true) }

// Auto sends a push and pop on an inner queue to PREFIX_any_push and
// PREFIX_any_pop, which see the info word, a NULL key and the value.
func testQueueOpsInner(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	work := innerQueueFixture()
	req := autoReq()
	req.Lookups, req.Pushes, req.Pops, req.StaticUntrusted, req.HookName, req.Stack.LowestOffset = LookupNone, CallAny, CallAny, static, "obs", -16
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || plan.hooks[0].Name != "obs_any_push" || plan.hooks[1].Name != "obs_any_pop" ||
		slices.ContainsFunc(plan.hooks, func(h LookupHook) bool { return !h.Generic || h.Static != static }) {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, innerQueueFixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	for _, c := range []*ebpf.Collection{plain, injected} {
		inner, err := ebpf.NewMap(work.Maps["outer"].InnerMap)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		if err := c.Maps["outer"].Put(uint32(0), inner); err != nil {
			t.Fatal(err)
		}
	}
	push := attachArgObserver(t, "obs_any_push", injected.Programs["p"], false, true, true)
	pop := attachArgObserver(t, "obs_any_pop", injected.Programs["p"], false, true, true)
	// queueSteps without the peeks: [11, 13] after the pushes.
	steps := []queueStep{queueSteps[0], queueSteps[1], queueSteps[2], queueSteps[3], queueSteps[4], queueSteps[6], queueSteps[7]}
	runQueue(t, plain, injected, steps)
	want := map[HookKind][][4]uint64{}
	for _, step := range steps {
		op, pc := HookPush, uint64(innerPushPC)
		if step.sel == selPop {
			op, pc = HookPop, innerPopPC
		}
		info := pc | map[HookKind]uint64{HookPush: 3, HookPop: 4}[op]<<32 | uint64(uint16(step.ret))<<48
		if step.sel == 1 {
			info |= bpfExist << 36
		}
		want[op] = append(want[op], [4]uint64{info, 0, step.seen})
	}
	for op, o := range map[HookKind]*ebpf.Collection{HookPush: push, HookPop: pop} {
		if got := observed(t, o); !slices.Equal(got, want[op]) {
			t.Errorf("%s hook: %x\nwant %x", op, got, want[op])
		}
	}
}

// popUninitFixture pops q into fp-8, which nothing wrote before, and returns
// XDP_PASS when the pop succeeded and XDP_DROP when it failed.
func popUninitFixture() *ebpf.CollectionSpec {
	spec := queueFixture(ebpf.Queue, false)
	jump := func(ins asm.Instruction, off int16) asm.Instruction { ins.Offset = off; return ins }
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.RFP),                 // 0
		asm.Add.Imm(asm.R2, -8),                      // 1
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), // 2-3
		asm.FnMapPopElem.Call(),                      // 4
		asm.Mov.Imm(asm.R1, 2),                       // 5
		jump(asm.JSGE.Imm32(asm.R0, 0, ""), 1),       // 6 -> 8
		asm.Mov.Imm(asm.R1, 1),                       // 7
		asm.Mov.Reg(asm.R0, asm.R1),                  // 8
		asm.Return(),                                 // 9
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("uninitialized pop fixture")), xdpFunc("p"))
	spec.Programs["p"].Instructions = insns
	return spec
}

func TestBpfQueuePopUninit(t *testing.T)         { testQueuePopUninit(t, false) }
func TestBpfQueuePopUninitDispatch(t *testing.T) { testQueuePopUninit(t, true) }

// A pop into stack nothing wrote loads with its hook, typed or (static)
// dispatch, which sees the element popped and then the zeroes the kernel
// writes when the queue is empty.
func testQueuePopUninit(t *testing.T, dispatch bool) {
	testutil.SkipIfNotRoot(t)
	work := popUninitFixture()
	req := autoReq()
	req.Lookups, req.Pops, req.Stack.LowestOffset = LookupNone, CallAny, -8
	name := "lookup_hook_q_pop"
	if dispatch {
		req.Dispatch, req.StaticUntrusted, req.HookName, name = true, true, "d", "d"
	}
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Name != name {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, popUninitFixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	for _, c := range []*ebpf.Collection{plain, injected} {
		if err := c.Maps["q"].Put(nil, uint64(7)); err != nil {
			t.Fatal(err)
		}
	}
	// A typed hook's third argument is the status, the dispatch hook's the
	// value.
	obs := attachArgObserver(t, name, injected.Programs["p"], false, true, dispatch)
	for _, want := range []uint32{2, 1} {
		for _, c := range []*ebpf.Collection{plain, injected} {
			if ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != want {
				t.Fatalf("action=%d want %d err=%v", ret, want, err)
			}
		}
	}
	ret := -int64(unix.ENOENT)
	want := [][4]uint64{{4, 7, 0}, {4, 0, uint64(uint32(ret))}}
	if dispatch {
		want = [][4]uint64{{4 | 4<<32, 0, 7}, {4 | 4<<32 | uint64(uint16(ret))<<48, 0, 0}}
	}
	if got := observed(t, obs); !slices.Equal(got, want) {
		t.Errorf("pop hook: %x\nwant %x", got, want)
	}
}

// percpuFixture looks up the packet's u32 key in the per-CPU array m on the
// CPU the packet names, and returns the value's action word on a hit,
// XDP_DROP on a miss.
func percpuFixture() *ebpf.CollectionSpec {
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	jump := func(ins asm.Instruction, off int16) asm.Instruction { ins.Offset = off; return ins }
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),                  // 0
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),     // 1: data
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),     // 2: data_end
		asm.Mov.Reg(asm.R4, asm.R2),                  // 3
		asm.Add.Imm(asm.R4, 8),                       // 4
		jump(asm.JGT.Reg(asm.R4, asm.R3, ""), 11),    // 5 -> 17
		asm.LoadMem(asm.R8, asm.R2, 0, asm.Word),     // 6: key
		asm.LoadMem(asm.R3, asm.R2, 4, asm.Word),     // 7: cpu
		asm.StoreMem(asm.RFP, -4, asm.R8, asm.Word),  // 8
		asm.Mov.Reg(asm.R2, asm.RFP),                 // 9
		asm.Add.Imm(asm.R2, -4),                      // 10
		asm.LoadMapPtr(asm.R1, 0).WithReference("m"), // 11-12
		asm.FnMapLookupPercpuElem.Call(),             // 13
		jump(asm.JEq.Imm(asm.R0, 0, ""), 2),          // 14 -> 17
		asm.LoadMem(asm.R0, asm.R0, 8, asm.DWord),    // 15: action
		asm.Return(),           // 16
		asm.Mov.Imm(asm.R0, 1), // 17: miss
		asm.Return(),           // 18
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("percpu fixture")), xdpFunc("p"))
	value := &btf.Struct{Name: "slot", Size: 16, Members: []btf.Member{{Name: "tag", Type: u64}, {Name: "action", Type: u64, Offset: 64}}}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"m": {Name: "m", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 16, MaxEntries: 2,
			Key: u32, Value: value}},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

// bpf_map_lookup_percpu_elem is instrumented as a lookup: the typed hook sees
// the key and the named CPU's value, and the miss hook a CPU past the last.
// Every CPU but the first holds another action, so a CPU argument the
// rewrite loses changes what the program returns.
func TestBpfLookupPercpu(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	work := percpuFixture()
	req := autoReq()
	req.Lookups, req.Stack.LowestOffset = LookupAny, -8
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || plan.hooks[0].Name != "lookup_hook_m" || plan.hooks[1].Name != "lookup_hook_m_miss" {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, percpuFixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	if cpus < 2 {
		t.Skip("needs two possible CPUs to tell them apart")
	}
	for _, c := range []*ebpf.Collection{plain, injected} {
		values := make([][2]uint64, cpus)
		for cpu := range values {
			values[cpu] = [2]uint64{uint64(100 + cpu), 3} // XDP_TX
		}
		values[0][1] = 2 // XDP_PASS
		if err := c.Maps["m"].Put(uint32(1), values); err != nil {
			t.Fatal(err)
		}
	}
	hit := attachArgObserver(t, "lookup_hook_m", injected.Programs["p"], false, true, true)
	miss := attachArgObserver(t, "lookup_hook_m_miss", injected.Programs["p"], false, true)
	last := uint32(cpus - 1)
	for _, tc := range []struct {
		key, cpu, want uint32
	}{{1, 0, 2}, {1, last, 3}, {1, uint32(cpus), 1}} {
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, tc.key)
		binary.LittleEndian.PutUint32(packet[4:], tc.cpu)
		for _, c := range []*ebpf.Collection{plain, injected} {
			if ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1}); err != nil || ret != tc.want {
				t.Fatalf("cpu %d: action=%d err=%v", tc.cpu, ret, err)
			}
		}
	}
	key := func(got [][4]uint64) [][4]uint64 {
		for i := range got {
			got[i][1] = uint64(uint32(got[i][1]))
		}
		return got
	}
	if got, want := key(observed(t, hit)), [][4]uint64{{13, 1, 100}, {13, 1, uint64(100 + last)}}; !slices.Equal(got, want) {
		t.Errorf("hit hook: %x\nwant %x", got, want)
	}
	if got, want := key(observed(t, miss)), [][4]uint64{{13, 1}}; !slices.Equal(got, want) {
		t.Errorf("miss hook: %x\nwant %x", got, want)
	}
}

// readOnlyArgFixture pushes a constant from the read-only map ro, as a
// program pushes a .rodata value, and updates h with it as key and value.
func readOnlyArgFixture() *ebpf.CollectionSpec {
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	ro := func(r asm.Register) asm.Instruction { return asm.LoadMapValue(r, 0, 0).WithReference("ro") }
	insns := asm.Instructions{
		ro(asm.R2), // 0-1
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), // 2-3
		asm.Mov.Imm(asm.R3, 0),                       // 4
		asm.FnMapPushElem.Call(),                     // 5
		ro(asm.R2),                                   // 6-7
		ro(asm.R3),                                   // 8-9
		asm.LoadMapPtr(asm.R1, 0).WithReference("h"), // 10-11
		asm.Mov.Imm(asm.R4, 0),                       // 12
		asm.FnMapUpdateElem.Call(),                   // 13
		asm.Mov.Imm(asm.R0, 2),                       // 14
		asm.Return(),                                 // 15
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("read-only arg fixture")), xdpFunc("p"))
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{
			"ro": {Name: "ro", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1, Flags: bpfFRdonlyProg, Key: u32, Value: u64,
				Contents: []ebpf.MapKV{{Key: uint32(0), Value: uint64(42)}}},
			"q": {Name: "q", Type: ebpf.Queue, ValueSize: 8, MaxEntries: 2, Value: u64},
			"h": {Name: "h", Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 2, Key: u64, Value: u64},
		},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}},
	}
}

func TestBpfReadOnlyArg(t *testing.T)       { testReadOnlyArg(t, false) }
func TestBpfReadOnlyArgStatic(t *testing.T) { testReadOnlyArg(t, true) }

// A key or value pointer into a read-only map's value fails a typed hook's
// memory check, so the push and update hooks take untrusted pointers, or are
// static under StaticUntrusted, and still see the constant.
func testReadOnlyArg(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	work := readOnlyArgFixture()
	req := autoReq()
	req.Lookups, req.Pushes, req.Updates, req.StaticUntrusted, req.Stack.LowestOffset = LookupNone, CallAny, CallAny, static, -8
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || slices.ContainsFunc(plan.hooks, func(h LookupHook) bool { return h.Untrusted == static || h.Static != static }) {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, readOnlyArgFixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	push := attachArgObserver(t, "lookup_hook_q_push", injected.Programs["p"], false, true, false)
	update := attachArgObserver(t, "lookup_hook_h_update", injected.Programs["p"], false, true, true, false)
	for _, c := range []*ebpf.Collection{plain, injected} {
		if ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
			t.Fatalf("action=%d err=%v", ret, err)
		}
	}
	if got, want := observed(t, push), [][4]uint64{{5, 42, 0}}; !slices.Equal(got, want) {
		t.Errorf("push hook: %x\nwant %x", got, want)
	}
	if got, want := observed(t, update), [][4]uint64{{13, 42, 42, 0}}; !slices.Equal(got, want) {
		t.Errorf("update hook: %x\nwant %x", got, want)
	}
}

func TestBpfReadOnlyArgShapes(t *testing.T)       { testReadOnlyArgShapes(t, false) }
func TestBpfReadOnlyArgShapesStatic(t *testing.T) { testReadOnlyArgShapes(t, true) }

// readOnlyArgCallFixture returns a read-only map value through a static
// subprogram. The map pointer is either passed directly or spilled first.
func readOnlyArgCallFixture(spillMap bool) *ebpf.CollectionSpec {
	spec := readOnlyArgFixture()
	done := asm.JEq.Imm(asm.R0, 0, "")
	done.Offset = 5
	call := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference("ro"),
	}
	if spillMap {
		call = append(call, asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord), asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord))
	}
	call = append(call,
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.Call.Label("sub"),
		done, asm.Mov.Reg(asm.R2, asm.R0),
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
		btf.WithFuncMetadata(asm.FnMapLookupElem.Call().WithSymbol("sub").WithSource(asm.Comment("read-only lookup subprogram")), staticFunc("sub")),
		asm.Return(),
	)
	call[0] = btf.WithFuncMetadata(call[0].WithSymbol("p").WithSource(asm.Comment("read-only call fixture")), xdpFunc("p"))
	spec.Programs["p"].Instructions = call
	return spec
}

// readOnlyArgMapSpillFixture spills a read-only map pointer before looking up
// the value passed to the queue helper.
func readOnlyArgMapSpillFixture() *ebpf.CollectionSpec {
	spec := readOnlyArgFixture()
	done := asm.JEq.Imm(asm.R0, 0, "")
	done.Offset = 5
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference("ro"),
		asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord), asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
		done, asm.Mov.Reg(asm.R2, asm.R0),
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("read-only map spill fixture")), xdpFunc("p"))
	spec.Programs["p"].Instructions = insns
	return spec
}

// readOnlyArgStackPointerSpillFixture reloads a spilled stack pointer before
// using it to reload a spilled read-only value.
func readOnlyArgStackPointerSpillFixture() *ebpf.CollectionSpec {
	spec := readOnlyArgFixture()
	insns := asm.Instructions{
		asm.LoadMapValue(asm.R6, 0, 0).WithReference("ro"), asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord),
		asm.Mov.Reg(asm.R7, asm.RFP), asm.StoreMem(asm.RFP, -16, asm.R7, asm.DWord),
		asm.LoadMem(asm.R7, asm.RFP, -16, asm.DWord), asm.LoadMem(asm.R2, asm.R7, -8, asm.DWord),
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("read-only stack pointer spill fixture")), xdpFunc("p"))
	spec.Programs["p"].Instructions = insns
	return spec
}

// readOnlyArgOffsetFixture adds a known register to a map-value relocation
// with a nonzero offset.
func readOnlyArgOffsetFixture() *ebpf.CollectionSpec {
	spec := readOnlyArgFixture()
	u64 := &btf.Int{Name: "u64", Size: 8}
	spec.Maps["ro"].ValueSize = 16
	spec.Maps["ro"].Value = &btf.Array{Index: &btf.Int{Name: "u32", Size: 4}, Type: u64, Nelems: 2}
	spec.Maps["ro"].Contents = []ebpf.MapKV{{Key: uint32(0), Value: [2]uint64{41, 42}}}
	insns := asm.Instructions{
		asm.LoadMapValue(asm.R2, 0, 8).WithReference("ro"), asm.Mov.Imm(asm.R6, 0), asm.Add.Reg(asm.R2, asm.R6),
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("read-only offset fixture")), xdpFunc("p"))
	spec.Programs["p"].Instructions = insns
	return spec
}

// readOnlyArgStoreFixture passes a read-only value and a caller stack pointer
// to a static subprogram, which stores the value for the caller to reload.
func readOnlyArgStoreFixture() *ebpf.CollectionSpec {
	spec := readOnlyArgFixture()
	call := asm.Instructions{
		asm.LoadMapValue(asm.R2, 0, 0).WithReference("ro"),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Call.Label("sub"),
		asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord),
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
		btf.WithFuncMetadata(asm.StoreMem(asm.R1, 0, asm.R2, asm.DWord).WithSymbol("sub").WithSource(asm.Comment("read-only store subprogram")), staticFunc("sub")),
		asm.Mov.Imm(asm.R0, 0), asm.Return(),
	}
	call[0] = btf.WithFuncMetadata(call[0].WithSymbol("p").WithSource(asm.Comment("read-only store fixture")), xdpFunc("p"))
	spec.Programs["p"].Instructions = call
	return spec
}

// readOnlyArgCallbackFixture spills a writable value pointer, and the
// bpf_loop callback replaces it with the read-only one through its data
// argument before the entry pushes the reloaded pointer.
func readOnlyArgCallbackFixture() *ebpf.CollectionSpec {
	spec := readOnlyArgFixture()
	spec.Maps["rw"] = spec.Maps["ro"].Copy()
	spec.Maps["rw"].Name, spec.Maps["rw"].Flags = "rw", 0
	cb := callbackHead("cb")
	insns := asm.Instructions{
		asm.LoadMapValue(asm.R0, 0, 0).WithReference("rw"), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.Mov.Imm(asm.R1, 1), callbackLoad(asm.R2, -1, "cb"), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call(),
		asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord),
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
		btf.WithFuncMetadata(asm.LoadMapValue(asm.R0, 0, 0).WithReference("ro").WithSymbol("cb").WithSource(asm.Comment("read-only callback")), btf.FuncMetadata(&cb)),
		asm.StoreMem(asm.R2, 0, asm.R0, asm.DWord), asm.Mov.Imm(asm.R0, 0), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("read-only callback fixture")), xdpFunc("p"))
	spec.Programs["p"].Instructions = insns
	return spec
}

// readOnlyArgSubprogLoadFixture has no read-only map reference in the entry;
// the static subprogram loads and returns the value itself.
func readOnlyArgSubprogLoadFixture() *ebpf.CollectionSpec {
	spec := readOnlyArgFixture()
	done := asm.JEq.Imm(asm.R0, 0, "")
	done.Offset = 5
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Call.Label("sub").WithSymbol("p").WithSource(asm.Comment("read-only subprogram load fixture")), xdpFunc("p")),
		done, asm.Mov.Reg(asm.R2, asm.R0),
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
		btf.WithFuncMetadata(asm.LoadMapValue(asm.R0, 0, 0).WithReference("ro").WithSymbol("sub").WithSource(asm.Comment("read-only value subprogram")), staticFunc("sub")),
		asm.Return(),
	}
	spec.Programs["p"].Instructions = insns
	return spec
}

// readOnlyArgInnerMapFixture passes a value from a read-only inner map to the
// queue helper. The program itself only contains a relocation for the outer
// map, whose lookup returns the inner map pointer.
func readOnlyArgInnerMapFixture() *ebpf.CollectionSpec {
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	jump := func(ins asm.Instruction, off int16) asm.Instruction { ins.Offset = off; return ins }
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("outer"), asm.FnMapLookupElem.Call(),
		jump(asm.JEq.Imm(asm.R0, 0, ""), 10), asm.Mov.Reg(asm.R1, asm.R0),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
		jump(asm.JEq.Imm(asm.R0, 0, ""), 5), asm.Mov.Reg(asm.R2, asm.R0),
		asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("read-only inner map fixture")), xdpFunc("p"))
	inner := &ebpf.MapSpec{Name: "ro", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1, Flags: bpfFRdonlyProg, Key: u32, Value: u64}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{
			"outer": {Name: "outer", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: inner},
			"q":     {Name: "q", Type: ebpf.Queue, ValueSize: 8, MaxEntries: 2, Value: u64},
		},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns}}}
}

func TestBpfReadOnlyArgCalls(t *testing.T)       { testReadOnlyArgCalls(t, false) }
func TestBpfReadOnlyArgCallsStatic(t *testing.T) { testReadOnlyArgCalls(t, true) }

// Read-only values reached through spilled map and stack pointers, a called
// subprogram, or a map-in-map take an untrusted or static push hook.
func testReadOnlyArgCalls(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	for _, tc := range []struct {
		name    string
		fixture func() *ebpf.CollectionSpec
	}{
		{"read-only inner map", readOnlyArgInnerMapFixture},
		{"nonzero offset", readOnlyArgOffsetFixture},
		{"stack pointer spill", readOnlyArgStackPointerSpillFixture},
		{"map spill", readOnlyArgMapSpillFixture},
		{"map argument", func() *ebpf.CollectionSpec { return readOnlyArgCallFixture(false) }},
		{"spilled map argument", func() *ebpf.CollectionSpec { return readOnlyArgCallFixture(true) }},
		{"callee stack store", readOnlyArgStoreFixture},
		{"callee map load", readOnlyArgSubprogLoadFixture},
		{"callback stack store", readOnlyArgCallbackFixture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plainSpec := tc.fixture()
			plain := loadOrSkip(t, plainSpec)
			t.Cleanup(plain.Close)
			work := tc.fixture()
			req := autoReq()
			req.Lookups, req.Pushes, req.StaticUntrusted, req.Stack.LowestOffset = LookupNone, CallAny, static, -16
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 1 || plan.hooks[0].Untrusted == static || plan.hooks[0].Static != static {
				t.Fatalf("hooks: %+v", plan.hooks)
			}
			injected := loadHooked(t, work, plan.hooks)
			t.Cleanup(injected.Close)
			for _, c := range []*ebpf.Collection{plain, injected} {
				if outer := c.Maps["outer"]; outer != nil {
					inner, err := ebpf.NewMap(plainSpec.Maps["outer"].InnerMap)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = inner.Close() })
					if err := inner.Put(uint32(0), uint64(42)); err != nil {
						t.Fatal(err)
					}
					if err := outer.Put(uint32(0), inner); err != nil {
						t.Fatal(err)
					}
				}
			}
			obs := attachArgObserver(t, "lookup_hook_q_push", injected.Programs["p"], false, true, false)
			for _, c := range []*ebpf.Collection{plain, injected} {
				if ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
					t.Fatalf("action=%d err=%v", ret, err)
				}
			}
			want := [][4]uint64{{uint64(plan.hooks[0].Sites[0].SitePC), 42, 0}}
			if got := observed(t, obs); !slices.Equal(got, want) {
				t.Errorf("push hook: %x\nwant %x", got, want)
			}
		})
	}
}

// A pointer into a read-only map's value that reaches the push other than by
// a direct load still gets an untrusted or static hook, which loads and sees
// the constant.
func testReadOnlyArgShapes(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	ro := func(r asm.Register) asm.Instruction { return asm.LoadMapValue(r, 0, 0).WithReference("ro") }
	jump := func(ins asm.Instruction, off int16) asm.Instruction { ins.Offset = off; return ins }
	for _, tc := range []struct {
		name string
		key  asm.Instructions
	}{
		{"register copy", asm.Instructions{ro(asm.R6), asm.Mov.Reg(asm.R2, asm.R6)}},
		{"subtract zero", asm.Instructions{ro(asm.R2), asm.Sub.Imm(asm.R2, 0)}},
		{"scalar plus pointer", asm.Instructions{ro(asm.R6), asm.Mov.Imm(asm.R2, 0), asm.Add.Reg(asm.R2, asm.R6)}},
		// A plain atomic add keeps R0.
		{"atomic", asm.Instructions{ro(asm.R0), asm.Mov.Imm(asm.R6, 1), asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord),
			{OpCode: asm.StoreXAddOp(asm.DWord), Dst: asm.RFP, Src: asm.R6, Offset: -8}, asm.Mov.Reg(asm.R2, asm.R0)}},
		// An exchange returns the spilled pointer.
		{"atomic exchange", asm.Instructions{ro(asm.R6), asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord), asm.Mov.Imm(asm.R2, 0), atomicMem(asm.Xchg, asm.RFP, asm.R2, -8)}},
		{"atomic compare exchange", asm.Instructions{ro(asm.R6), asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord), asm.Mov.Imm(asm.R0, 0), asm.Mov.Imm(asm.R3, 0),
			atomicMem(asm.CmpXchg, asm.RFP, asm.R3, -8), asm.Mov.Reg(asm.R2, asm.R0)}},
		{"stack reload", asm.Instructions{ro(asm.R2), asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord)}},
		{"branch", asm.Instructions{ro(asm.R2), asm.LoadMem(asm.R0, asm.R1, 16, asm.Word), jump(asm.JEq.Imm(asm.R0, 0, ""), 1), asm.Add.Imm(asm.R2, 0)}},
		// The stack on one path, the constant on the other.
		{"join", asm.Instructions{asm.Mov.Imm(asm.R3, 42), asm.StoreMem(asm.RFP, -8, asm.R3, asm.DWord), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
			asm.LoadMem(asm.R0, asm.R1, 16, asm.Word), jump(asm.JNE.Imm(asm.R0, 0, ""), 2), ro(asm.R2)}},
		{"lookup result", asm.Instructions{asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
			asm.LoadMapPtr(asm.R1, 0).WithReference("ro"), asm.FnMapLookupElem.Call(), jump(asm.JEq.Imm(asm.R0, 0, ""), 5), asm.Mov.Reg(asm.R2, asm.R0)}},
		{"loop", asm.Instructions{ro(asm.R2), asm.Mov.Imm(asm.R6, 2), asm.Sub.Imm(asm.R6, 1), jump(asm.JNE.Imm(asm.R6, 0, ""), -2)}},
		{"stack offset join", asm.Instructions{ro(asm.R6), asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord), asm.Mov.Imm(asm.R9, 42), asm.StoreMem(asm.RFP, -24, asm.R9, asm.DWord),
			asm.Mov.Reg(asm.R8, asm.RFP), asm.Add.Imm(asm.R8, -24), asm.StoreMem(asm.RFP, -16, asm.R8, asm.DWord), asm.Mov.Reg(asm.R7, asm.RFP),
			asm.LoadMem(asm.R0, asm.R1, 16, asm.Word), jump(asm.JEq.Imm(asm.R0, 0, ""), 2), asm.Add.Imm(asm.R7, -8), jump(asm.Ja.Label(""), 1),
			asm.Add.Imm(asm.R7, -16), asm.LoadMem(asm.R2, asm.R7, 0, asm.DWord)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := func() *ebpf.CollectionSpec {
				spec := readOnlyArgFixture()
				insns := append(append(asm.Instructions{}, tc.key...), asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0),
					asm.FnMapPushElem.Call(), asm.Mov.Imm(asm.R0, 2), asm.Return())
				insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("read-only shape")), xdpFunc("p"))
				spec.Programs["p"].Instructions = insns
				return spec
			}
			work := fixture()
			req := autoReq()
			req.Lookups, req.Pushes, req.StaticUntrusted, req.Stack.LowestOffset = LookupNone, CallAny, static, -24
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 1 || plan.hooks[0].Untrusted == static || plan.hooks[0].Static != static {
				t.Fatalf("hooks: %+v", plan.hooks)
			}
			plain := loadOrSkip(t, fixture())
			t.Cleanup(plain.Close)
			injected := loadHooked(t, work, plan.hooks)
			t.Cleanup(injected.Close)
			push := attachArgObserver(t, "lookup_hook_q_push", injected.Programs["p"], false, true, false)
			for _, c := range []*ebpf.Collection{plain, injected} {
				if ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
					t.Fatalf("action=%d err=%v", ret, err)
				}
			}
			if got, want := observed(t, push), [][4]uint64{{uint64(plan.hooks[0].Sites[0].SitePC), 42, 0}}; !slices.Equal(got, want) {
				t.Errorf("push hook: %x\nwant %x", got, want)
			}
		})
	}
}

// A lookup keyed by a read-only constant has a static hook under
// StaticUntrusted, which copies nothing, so a value too large to copy
// below the audited stack does not refuse it with CopyReadOnly.
func TestBpfCopyReadOnlyKey(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	fixture := func() *ebpf.CollectionSpec {
		spec := readOnlyArgFixture()
		u8, u32 := &btf.Int{Name: "u8", Size: 1}, &btf.Int{Name: "u32", Size: 4}
		value := &btf.Struct{Name: "big", Size: 512, Members: []btf.Member{{Name: "data", Type: &btf.Array{Index: u32, Type: u8, Nelems: 512}}}}
		spec.Maps["big"] = &ebpf.MapSpec{Name: "big", Type: ebpf.Array, KeySize: 4, ValueSize: 512, MaxEntries: 64, Flags: bpfFRdonlyProg, Key: u32, Value: value}
		insns := asm.Instructions{
			asm.LoadMapValue(asm.R2, 0, 0).WithReference("ro"),
			asm.LoadMapPtr(asm.R1, 0).WithReference("big"),
			asm.FnMapLookupElem.Call(),
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		}
		insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("copy with read-only key")), xdpFunc("p"))
		spec.Programs["p"].Instructions = insns
		return spec
	}
	work := fixture()
	req := autoReq()
	req.CopyReadOnly, req.StaticUntrusted, req.Stack.LowestOffset = true, true, 0
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatalf("%v; skipped %+v", err, plan.skipped)
	}
	if len(plan.hooks) != 1 || !plan.hooks[0].Static || plan.hooks[0].Copied {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, fixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	for _, c := range []*ebpf.Collection{plain, injected} {
		if ret, err := c.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
			t.Fatalf("action=%d err=%v", ret, err)
		}
	}
}

// TestBpfBloomPeekPoisoned pins why queueFixture reads the value before a
// pop or peek.
//
// A bloom filter peek only reads its value: it hashes the value and tests
// the bits. Queue and stack peeks write it. The helper prototype they share
// marks the value as written, and the argument checks correct this for a
// bloom filter, but the static stack liveness analysis added in 7.1 reads the
// prototype as is. It then takes the value stored at fp-8 as dead before the
// peek, a checkpoint poisons the slot, and checking the peek reads the
// poisoned slot: the verifier rejects the plain program, before any rewrite,
// with "slot poisoned by dead code elimination". Reading fp-8 on the path to
// the peek keeps the slot live, so the fixture loads.
//
// Mainline fixed this in 830e4372de5c ("bpf: Describe helper stack accesses
// with arg_access_info"), which 7.1 to 7.3 lack. The test drops the reads and
// requires 7.0 and older to load the program. On 7.1 and newer it accepts
// either outcome, since a release or a backport may carry the fix: a
// rejection must be this one, and a load is logged, as the reads are not
// needed on that kernel.
func TestBpfBloomPeekPoisoned(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	spec := queueFixture(ebpf.BloomFilter, true)
	insns := spec.Programs["p"].Instructions
	read := asm.LoadMem(asm.R1, asm.RFP, -8, asm.DWord)
	reads := 0
	for i, ins := range insns {
		if ins.OpCode == read.OpCode && ins.Dst == asm.R1 && ins.Src == asm.RFP && ins.Offset == -8 {
			insns[i] = asm.Mov.Imm(asm.R1, 0)
			reads++
		}
	}
	if reads != 2 {
		t.Fatalf("replaced %d reads, want 2", reads)
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(u.Release[:])
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		t.Fatalf("release %q: %v", release, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err == nil {
		coll.Close()
	}
	const msg = "slot poisoned by dead code elimination"
	switch {
	case major < 7 || major == 7 && minor < 1:
		if err != nil {
			t.Errorf("%s: %+v", release, err)
		}
	case err == nil:
		t.Logf("%s loads the bloom filter peek without the reads: the kernel has the verifier fix", release)
	case !strings.Contains(fmt.Sprintf("%+v", err), msg):
		t.Errorf("%s: err = %v, want %q or a load", release, err, msg)
	}
}

// atomicMem is op.Mem for an 8-byte access with the immediate set:
// cilium/ebpf v0.22 marshals the immediate before deriving it from the
// opcode, so op.Mem would load as an atomic add.
func atomicMem(op asm.AtomicOp, dst, src asm.Register, off int16) asm.Instruction {
	ins := op.Mem(dst, src, asm.DWord, off)
	ins.Constant = int64(op >> 8)
	return ins
}
