package inject

import (
	"encoding/binary"
	"slices"
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
// read the value first: 7.1 and newer reject a bloom filter peek behind a
// branch when nothing else on its path reads the value ("slot poisoned by
// dead code elimination"), which 7.0 loads.
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
// ENOENT until the value was pushed; the peek hook sees each test.
func TestBpfBloomFilterOps(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	fixture := func() *ebpf.CollectionSpec { return queueFixture(ebpf.BloomFilter, true) }
	work := fixture()
	req := autoReq()
	req.Lookups, req.Pushes, req.Peeks, req.Stack.LowestOffset = LookupNone, CallError, CallError, -8
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
	if got := observed(t, push); len(got) != 0 {
		t.Errorf("push hook saw a successful push: %x", got)
	}
	want := [][4]uint64{{queuePeekPC, 5, enoent}, {queuePopPC, 6, enoent}} // the second peek sits at the pop's site
	if got := observed(t, peek); !slices.Equal(got, want) {
		t.Errorf("peek hook: %x\nwant %x", got, want)
	}
}

func TestBpfQueueOpsDispatch(t *testing.T)       { testQueueOpsDispatch(t, false) }
func TestBpfQueueOpsDispatchStatic(t *testing.T) { testQueueOpsDispatch(t, true) }

// One dispatch hook sees every failed push, pop and peek with info = site |
// op << 32 | (flags & 0xff) << 36 | (u16)ret << 48, a NULL key and the value.
func testQueueOpsDispatch(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	work := queueFixture(ebpf.Queue, false)
	req := autoReq()
	req.Lookups, req.Pushes, req.Pops, req.Peeks = LookupNone, CallError, CallError, CallError
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
	steps := slices.Clone(queueSteps)
	steps[3].ret = -int64(unix.E2BIG) // BPF_EXIST on a full queue succeeds; make the step a failure
	steps[3].sel, steps[3].seen = 0, 13
	steps = steps[:4]
	steps = append(steps, queueStep{99, selPop, 0, 10}, queueStep{99, selPop, 0, 11},
		queueStep{99, selPop, -int64(unix.ENOENT), 0}, queueStep{99, selPeek, -int64(unix.ENOENT), 0})
	runQueue(t, plain, injected, steps)
	var want [][4]uint64
	for _, step := range steps {
		if step.ret >= 0 {
			continue
		}
		op, pc := step.op()
		info := pc | map[HookKind]uint64{HookPush: 3, HookPop: 4, HookPeek: 5}[op]<<32 | uint64(uint16(step.ret))<<48
		want = append(want, [4]uint64{info, 0, step.seen})
	}
	if got := observed(t, obs); !slices.Equal(got, want) {
		t.Errorf("dispatch hook: %x\nwant %x", got, want)
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
	for _, c := range []*ebpf.Collection{plain, injected} {
		values := make([][2]uint64, cpus)
		for cpu := range values {
			values[cpu] = [2]uint64{uint64(100 + cpu), 2}
		}
		if err := c.Maps["m"].Put(uint32(1), values); err != nil {
			t.Fatal(err)
		}
	}
	hit := attachArgObserver(t, "lookup_hook_m", injected.Programs["p"], false, true, true)
	miss := attachArgObserver(t, "lookup_hook_m_miss", injected.Programs["p"], false, true)
	last := uint32(cpus - 1)
	for _, tc := range []struct {
		key, cpu, want uint32
	}{{1, 0, 2}, {1, last, 2}, {1, uint32(cpus), 1}} {
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
