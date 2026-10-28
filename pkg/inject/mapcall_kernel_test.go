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

// mapCallFixture reads a u32 key and a u32 selector from the packet. Selector
// 3 deletes the key from sessions; any other selector updates it with that
// selector as flags and the value {0x1111, selector}. The program returns
// XDP_PASS when the helper succeeded and XDP_DROP when it failed, so the
// restored R0 is checked by the return code. It tests W0 as the guard does:
// on 6.1 a failed update leaves the upper half of R0 zero.
func mapCallFixture() *ebpf.CollectionSpec {
	spec := lookupFixture()
	short, del, done, ok := asm.JGT.Reg(asm.R4, asm.R3, ""), asm.JEq.Imm(asm.R9, 3, ""), asm.Ja.Label(""), asm.JSGE.Imm32(asm.R0, 0, "")
	short.Offset, del.Offset, done.Offset, ok.Offset = 24, 10, 3, 1 // slots 5 -> 30, 11 -> 22, 21 -> 25, 26 -> 28
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),                         // 0
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),            // 1: data
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),            // 2: data_end
		asm.Mov.Reg(asm.R4, asm.R2),                         // 3
		asm.Add.Imm(asm.R4, 8),                              // 4
		short,                                               // 5
		asm.LoadMem(asm.R8, asm.R2, 0, asm.Word),            // 6: key
		asm.LoadMem(asm.R9, asm.R2, 4, asm.Word),            // 7: selector
		asm.StoreMem(asm.RFP, -4, asm.R8, asm.Word),         // 8
		asm.Mov.Reg(asm.R2, asm.RFP),                        // 9
		asm.Add.Imm(asm.R2, -4),                             // 10
		del,                                                 // 11
		asm.Mov.Imm(asm.R5, 0x1111),                         // 12
		asm.StoreMem(asm.RFP, -24, asm.R5, asm.DWord),       // 13: value.seid
		asm.StoreMem(asm.RFP, -16, asm.R9, asm.DWord),       // 14: value.imsi
		asm.Mov.Reg(asm.R3, asm.RFP),                        // 15
		asm.Add.Imm(asm.R3, -24),                            // 16
		asm.Mov.Reg(asm.R4, asm.R9),                         // 17: flags
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), // 18-19
		asm.FnMapUpdateElem.Call(),                          // 20
		done,                                                // 21
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), // 22-23
		asm.FnMapDeleteElem.Call(),                          // 24
		asm.Mov.Imm(asm.R1, 2),                              // 25: XDP_PASS
		ok,                                                  // 26
		asm.Mov.Imm(asm.R1, 1),                              // 27: XDP_DROP
		asm.Mov.Reg(asm.R0, asm.R1),                         // 28
		asm.Return(),                                        // 29
		asm.Mov.Imm(asm.R0, 1),                              // 30: short packet
		asm.Return(),                                        // 31
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("map call fixture")),
		btf.FuncMetadata(&spec.Programs["p"].Instructions[0]))
	spec.Programs["p"].Instructions = insns
	spec.Maps["sessions"].MaxEntries = 2
	return spec
}

const (
	mapCallUpdatePC = 20
	mapCallDeletePC = 24
	selectDelete    = 3
)

// argObserver records the first nargs arguments after ctx of each call of
// fn, up to eight calls: obs[n][i] is argument i+1, read as 8 bytes through
// it when pointer[i] is set (zero for NULL), else its raw value. cnt[0]
// counts the calls.
func argObserver(fn string, target *ebpf.Program, pointer ...bool) *ebpf.CollectionSpec {
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
	}
	for i, ptr := range pointer {
		insns = append(insns,
			asm.Mov.Reg(asm.R1, asm.R9), asm.Mov.Imm(asm.R2, int32(i+1)),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
			asm.FnGetFuncArg.Call(),
			asm.JNE.Imm(asm.R0, 0, "done"),
			asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord))
		if ptr {
			insns = append(insns,
				asm.Mov.Reg(asm.R3, asm.R1),
				asm.Mov.Reg(asm.R1, asm.R6), asm.Add.Imm(asm.R1, int32(8*i)),
				asm.Mov.Imm(asm.R2, 8), asm.FnProbeReadKernel.Call())
		} else {
			insns = append(insns, asm.StoreMem(asm.R6, int16(8*i), asm.R1, asm.DWord))
		}
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return())
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{
			"cnt": {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
			"obs": {Type: ebpf.Array, KeySize: 4, ValueSize: 32, MaxEntries: 8},
		},
		Programs: map[string]*ebpf.ProgramSpec{"observe": {
			Name: "arg_obs", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: fn, AttachTarget: target, License: "GPL", Instructions: insns,
		}},
	}
}

// attachArgObserver loads argObserver on fn and attaches it.
func attachArgObserver(t *testing.T, fn string, target *ebpf.Program, pointer ...bool) *ebpf.Collection {
	t.Helper()
	obs := loadOrSkip(t, argObserver(fn, target, pointer...))
	t.Cleanup(obs.Close)
	l, err := link.AttachTracing(link.TracingOptions{Program: obs.Programs["observe"], AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("fentry unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return obs
}

// observed returns the calls obs recorded.
func observed(t *testing.T, obs *ebpf.Collection) [][4]uint64 {
	t.Helper()
	var n uint64
	if err := obs.Maps["cnt"].Lookup(uint32(0), &n); err != nil {
		t.Fatal(err)
	}
	var calls [][4]uint64
	for i := range min(n, 8) {
		var r [4]uint64
		if err := obs.Maps["obs"].Lookup(uint32(i), &r); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, r)
	}
	return calls
}

// mapCallStep is one run of mapCallFixture and the helper's result.
type mapCallStep struct {
	key, sel uint32
	ret      int64
}

func (s mapCallStep) pc() uint32 {
	if s.sel == selectDelete {
		return mapCallDeletePC
	}
	return mapCallUpdatePC
}

// hashSteps fill a two-entry hash: EEXIST for BPF_NOEXIST on a present key,
// ENOENT for BPF_EXIST on an absent one, E2BIG when full, and ENOENT for
// deleting an absent key, between successful calls.
var hashSteps = []mapCallStep{
	{7, 1, 0}, {7, 1, -int64(unix.EEXIST)}, {8, 2, -int64(unix.ENOENT)}, {8, 0, 0}, {9, 0, -int64(unix.E2BIG)},
	{99, selectDelete, -int64(unix.ENOENT)}, {7, selectDelete, 0},
}

// runMapCalls runs steps through plain and injected, which must return
// XDP_PASS exactly when the helper succeeded.
func runMapCalls(t *testing.T, plain, injected *ebpf.Collection, steps []mapCallStep) {
	t.Helper()
	for _, step := range steps {
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, step.key)
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

// observes reports whether a hook on when sees a call with result ret.
func observes(when CallWhen, ret int64) bool { return when == CallAny || ret < 0 }

func TestBpfMapCallsTyped(t *testing.T)    { testMapCallsTyped(t, CallError, false) }
func TestBpfMapCallsTypedAny(t *testing.T) { testMapCallsTyped(t, CallAny, false) }
func TestBpfMapCallsTypedTC(t *testing.T)  { testMapCallsTyped(t, CallError, true) }

// The typed update and delete hooks see the site, the key, the value and
// status = (u32)ret | flags << 32 of each call whose result they observe, and
// the program's results do not change.
func testMapCallsTyped(t *testing.T, when CallWhen, tc bool) {
	testutil.SkipIfNotRoot(t)
	fixture := mapCallFixture
	if tc {
		fixture = func() *ebpf.CollectionSpec { return asTC(mapCallFixture()) }
	}
	work := fixture()
	req := autoReq()
	req.Lookups, req.Updates, req.Deletes, req.Stack.LowestOffset = LookupNone, when, when, -24
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"lookup_hook_sessions_update", "lookup_hook_sessions_delete"}
	if len(plan.hooks) != 2 || plan.hooks[0].Name != names[0] || plan.hooks[1].Name != names[1] ||
		plan.hooks[0].When != string(when) || plan.hooks[0].Untrusted || plan.hooks[0].Static {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, fixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	update := attachArgObserver(t, names[0], injected.Programs["p"], false, true, true, false)
	del := attachArgObserver(t, names[1], injected.Programs["p"], false, true, false)
	runMapCalls(t, plain, injected, hashSteps)
	var wantUpdate, wantDelete [][4]uint64
	for _, step := range hashSteps {
		if !observes(when, step.ret) {
			continue
		}
		status := uint64(uint32(step.ret))
		if step.sel == selectDelete {
			wantDelete = append(wantDelete, [4]uint64{uint64(step.pc()), uint64(step.key), status})
			continue
		}
		wantUpdate = append(wantUpdate, [4]uint64{uint64(step.pc()), uint64(step.key), 0x1111, status | uint64(step.sel)<<32})
	}
	for _, check := range []struct {
		name string
		obs  *ebpf.Collection
		want [][4]uint64
	}{{"update", update, wantUpdate}, {"delete", del, wantDelete}} {
		got := observed(t, check.obs)
		for i := range got {
			got[i][1] = uint64(uint32(got[i][1])) // the key is a u32 on the stack
		}
		if !slices.Equal(got, check.want) {
			t.Errorf("%s hook: %x\nwant %x", check.name, got, check.want)
		}
	}
}

func TestBpfMapCallsDispatch(t *testing.T)         { testMapCallsDispatch(t, false, false) }
func TestBpfMapCallsDispatchStatic(t *testing.T)   { testMapCallsDispatch(t, true, false) }
func TestBpfMapCallsDispatchTCStatic(t *testing.T) { testMapCallsDispatch(t, true, true) }

// One dispatch hook sees every failed update and delete in order, with info =
// site | op << 32 | (flags & 0xff) << 36 | (u16)ret << 48, the key, the value
// (NULL for a delete) and the map. The audited stack is as low as an update
// under Dispatch allows: the fifth slot ends at -480.
func testMapCallsDispatch(t *testing.T, static, tc bool) {
	testutil.SkipIfNotRoot(t)
	fixture := mapCallFixture
	if tc {
		fixture = func() *ebpf.CollectionSpec { return asTC(mapCallFixture()) }
	}
	work := fixture()
	req := autoReq()
	req.Lookups, req.Updates, req.Deletes = LookupNone, CallError, CallError
	req.Dispatch, req.StaticUntrusted, req.HookName, req.Stack.LowestOffset = true, static, "d", -440
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || plan.hooks[0].Kind != HookUpdate || plan.hooks[1].Kind != HookDelete || plan.hooks[0].Static != static {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, fixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	obs := attachArgObserver(t, "d", injected.Programs["p"], false, true, true)
	runMapCalls(t, plain, injected, hashSteps)
	var want [][4]uint64
	for _, step := range hashSteps {
		if step.ret >= 0 {
			continue
		}
		op, flags, value := uint64(InfoOpUpdate), uint64(step.sel), uint64(0x1111)
		if step.sel == selectDelete {
			op, flags, value = InfoOpDelete, 0, 0
		}
		info := uint64(step.pc()) | op<<32 | flags<<36 | uint64(uint16(step.ret))<<48
		want = append(want, [4]uint64{info, uint64(step.key), value})
	}
	got := observed(t, obs)
	for i := range got {
		got[i][1] = uint64(uint32(got[i][1]))
	}
	if !slices.Equal(got, want) {
		t.Errorf("dispatch hook: %x\nwant %x", got, want)
	}
}

// An array's update fails only for an index past max_entries (E2BIG) or
// BPF_NOEXIST (EEXIST, every element exists), and its delete always (EINVAL).
// A write-only map takes the typed hook: the key and value are the
// program's. Each failure is observed.
func TestBpfMapCallsArrayWriteOnly(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	fixture := func() *ebpf.CollectionSpec {
		spec := mapCallFixture()
		m := spec.Maps["sessions"]
		m.Type, m.MaxEntries, m.Flags = ebpf.Array, 4, bpfFWronlyProg
		return spec
	}
	steps := []mapCallStep{
		{1, 0, 0}, {4, 0, -int64(unix.E2BIG)}, {1, 1, -int64(unix.EEXIST)}, {2, 2, 0}, {1, selectDelete, -int64(unix.EINVAL)},
	}
	work := fixture()
	req := autoReq()
	req.Lookups, req.Updates, req.Deletes, req.Stack.LowestOffset = LookupNone, CallError, CallError, -24
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || plan.hooks[0].Untrusted || plan.hooks[1].Untrusted {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, fixture())
	t.Cleanup(plain.Close)
	injected := loadHooked(t, work, plan.hooks)
	t.Cleanup(injected.Close)
	update := attachArgObserver(t, plan.hooks[0].Name, injected.Programs["p"], false, true, true, false)
	del := attachArgObserver(t, plan.hooks[1].Name, injected.Programs["p"], false, true, false)
	runMapCalls(t, plain, injected, steps)
	status := func(ret int64) uint64 { return uint64(uint32(ret)) }
	want := []uint64{status(-int64(unix.E2BIG)), status(-int64(unix.EEXIST)) | 1<<32, status(-int64(unix.EINVAL))}
	if got := observedStatuses(t, update, del); !slices.Equal(got, want) {
		t.Errorf("statuses %x, want %x", got, want)
	}
}

// observedStatuses lists the status of each update call, then each delete.
func observedStatuses(t *testing.T, update, del *ebpf.Collection) []uint64 {
	t.Helper()
	var out []uint64
	for _, call := range observed(t, update) {
		out = append(out, call[3])
	}
	for _, call := range observed(t, del) {
		out = append(out, call[2])
	}
	return out
}

// innerUpdateFixture updates the hash an array of maps holds at index 0, with
// the packet's key and selector as in mapCallFixture. R1 is the inner map the
// outer lookup returned, so the update goes to the generic hook.
func innerUpdateFixture() *ebpf.CollectionSpec {
	spec := mapCallFixture()
	sessions := spec.Maps["sessions"]
	short, outerMiss, ok := asm.JGT.Reg(asm.R4, asm.R3, ""), asm.JEq.Imm(asm.R0, 0, ""), asm.JSGE.Imm32(asm.R0, 0, "")
	short.Offset, outerMiss.Offset, ok.Offset = 25, 12, 1 // slots 5 -> 31, 18 -> 31, 27 -> 29
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),                      // 0
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),         // 1
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),         // 2
		asm.Mov.Reg(asm.R4, asm.R2),                      // 3
		asm.Add.Imm(asm.R4, 8),                           // 4
		short,                                            // 5
		asm.LoadMem(asm.R8, asm.R2, 0, asm.Word),         // 6
		asm.LoadMem(asm.R9, asm.R2, 4, asm.Word),         // 7
		asm.StoreMem(asm.RFP, -4, asm.R8, asm.Word),      // 8: inner key
		asm.StoreImm(asm.RFP, -8, 0, asm.Word),           // 9: outer key
		asm.Mov.Imm(asm.R5, 0x1111),                      // 10
		asm.StoreMem(asm.RFP, -24, asm.R5, asm.DWord),    // 11
		asm.StoreMem(asm.RFP, -16, asm.R9, asm.DWord),    // 12
		asm.Mov.Reg(asm.R2, asm.RFP),                     // 13
		asm.Add.Imm(asm.R2, -8),                          // 14
		asm.LoadMapPtr(asm.R1, 0).WithReference("outer"), // 15-16
		asm.FnMapLookupElem.Call(),                       // 17
		outerMiss,                                        // 18
		asm.Mov.Reg(asm.R1, asm.R0),                      // 19: inner map
		asm.Mov.Reg(asm.R2, asm.RFP),                     // 20
		asm.Add.Imm(asm.R2, -4),                          // 21
		asm.Mov.Reg(asm.R3, asm.RFP),                     // 22
		asm.Add.Imm(asm.R3, -24),                         // 23
		asm.Mov.Reg(asm.R4, asm.R9),                      // 24
		asm.FnMapUpdateElem.Call(),                       // 25
		asm.Mov.Imm(asm.R1, 2),                           // 26
		ok,                                               // 27
		asm.Mov.Imm(asm.R1, 1),                           // 28
		asm.Mov.Reg(asm.R0, asm.R1),                      // 29
		asm.Return(),                                     // 30
		asm.Mov.Imm(asm.R0, 1),                           // 31
		asm.Return(),                                     // 32
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("inner update fixture")),
		btf.FuncMetadata(&spec.Programs["p"].Instructions[0]))
	spec.Programs["p"].Instructions = insns
	delete(spec.Maps, "sessions")
	spec.Maps["outer"] = &ebpf.MapSpec{Name: "outer", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: sessions}
	return spec
}

func TestBpfMapCallsInnerUpdate(t *testing.T)       { testInnerUpdate(t, false) }
func TestBpfMapCallsInnerUpdateStatic(t *testing.T) { testInnerUpdate(t, true) }

// Auto sends the inner map's update to PREFIX_any_update, which sees the
// update's info word, key and value.
func testInnerUpdate(t *testing.T, static bool) {
	testutil.SkipIfNotRoot(t)
	work := innerUpdateFixture()
	req := autoReq()
	req.Lookups, req.Updates, req.StaticUntrusted, req.HookName, req.Stack.LowestOffset = LookupNone, CallAny, static, "obs", -24
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Name != "obs_any_update" || !plan.hooks[0].Generic || plan.hooks[0].Kind != HookUpdate {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
	plain := loadOrSkip(t, innerUpdateFixture())
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
	obs := attachArgObserver(t, "obs_any_update", injected.Programs["p"], false, true, true)
	steps := []mapCallStep{{7, 1, 0}, {7, 1, -int64(unix.EEXIST)}}
	runMapCalls(t, plain, injected, steps)
	var want [][4]uint64
	for _, step := range steps {
		info := uint64(25) | InfoOpUpdate<<32 | uint64(step.sel)<<36 | uint64(uint16(step.ret))<<48
		want = append(want, [4]uint64{info, uint64(step.key), 0x1111})
	}
	got := observed(t, obs)
	for i := range got {
		got[i][1] = uint64(uint32(got[i][1]))
	}
	if !slices.Equal(got, want) {
		t.Errorf("generic hook: %x\nwant %x", got, want)
	}
}
