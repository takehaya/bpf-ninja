package inject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/ctxflow"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

func TestBpfSubprogSiteLoads(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, source := range []string{"register", "slot"} {
		t.Run(source, func(t *testing.T) {
			work := subprogramLookupFixture(source)
			req := autoReq()
			req.Stack.LowestOffset = -16
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.sites) != 1 || plan.sites[0].CtxSource == "entry" {
				t.Fatalf("plan = %+v", plan)
			}
			coll := loadHooked(t, work, plan.hooks)
			t.Cleanup(coll.Close)
			if err := coll.Maps["sessions"].Put(uint32(0), [2]uint64{2, 1234}); err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 64)
			out := make([]byte, len(packet))
			ret, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Repeat: 1})
			if err != nil || ret != 2 || !bytes.Equal(packet, out) {
				t.Fatalf("action=%d err=%v output_equal=%v", ret, err, bytes.Equal(packet, out))
			}
		})
	}
	t.Run("caller-frame-key", func(t *testing.T) {
		coll := loadOrSkip(t, subprogCtxTarget(btf.GlobalFunc, false))
		t.Cleanup(coll.Close)
		if ret, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
			t.Fatalf("action=%d err=%v", ret, err)
		}
	})
}

func TestBpfPerFrameFloorLoads(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	work := subprogramLookupFixture("register")
	insns := work.Programs["p"].Instructions
	for i, ins := range insns {
		if fn := btf.FuncMetadata(&ins); fn != nil && fn.Name == "sub" {
			insns = append(insns[:i+1], append(asm.Instructions{asm.StoreImm(asm.RFP, -168, 0, asm.Word)}, insns[i+1:]...)...)
			break
		}
	}
	work.Programs["p"].Instructions = insns
	req := autoReq()
	req.Stack = StackAudit{Frames: map[string]int16{"p": -8, "sub": -168}, Source: "verifier", FrameRounding: 16}
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.sites) != 1 || plan.sites[0].FuncName != "sub" {
		t.Fatalf("plan = %+v", plan)
	}
	coll := loadHooked(t, work, plan.hooks)
	t.Cleanup(coll.Close)
	if ret, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
		t.Fatalf("action=%d err=%v", ret, err)
	}
}

func TestBpfFastcallSpillKept(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	work := fastcallLookupFixture()
	trial, err := ebpf.NewCollectionWithOptions(work, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats, LogSizeStart: 64 << 10},
	})
	if err != nil {
		loadOrSkip(t, work).Close()
		t.Fatalf("loading trial with verifier statistics: %v", err)
	}
	log := trial.Programs["p"].VerifierLog
	trial.Close()
	depths, err := ParseStackDepths(log)
	if err != nil {
		t.Fatalf("parsing verifier statistics: %v\n%s", err, log)
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		t.Fatalf("release %q: %v", release, err)
	}
	report, err := FrameFloors(depths, []string{"p"}, work.Programs["p"].Instructions, KernelInfo{Major: major, Minor: minor})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Functions) != 1 || report.Functions[0].TextDepth < 16 || report.Functions[0].Floor > -16 {
		t.Fatalf("fastcall floor = %+v", report.Functions)
	}
	t.Logf("fastcall verifier depth=%d text depth=%d source=%s", report.Functions[0].VerifiedDepth,
		report.Functions[0].TextDepth, report.Functions[0].Source)
	if major > 6 || major == 6 && minor >= 12 {
		f := report.Functions[0]
		if f.VerifiedDepth >= f.TextDepth || f.Source != "text" {
			t.Fatalf("kernel %s did not exercise fastcall shrink: %+v", release, f)
		}
	}
	req := autoReq()
	req.Stack = StackAudit{Frames: report.Frames(), Source: "verifier", FrameRounding: 32}
	if slots := lookupSlots(req.Stack.floor("p")); slots.ctx >= -16 {
		t.Fatalf("ctx slot %d overlaps fastcall spill", slots.ctx)
	}
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.sites) != 1 {
		t.Fatalf("plan = %+v", plan.sites)
	}
	coll := loadHooked(t, work, plan.hooks)
	t.Cleanup(coll.Close)
	if err := coll.Maps["sessions"].Put(uint32(0), uint32(2)); err != nil {
		t.Fatal(err)
	}
	if ret, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
		t.Fatalf("action=%d err=%v", ret, err)
	}
}

func fastcallLookupFixture() *ebpf.CollectionSpec {
	u32 := &btf.Int{Name: "u32", Size: 4}
	ctx := &btf.Struct{Name: "xdp_md", Size: 24}
	fn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: ctx}}},
	}}
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R2, 123),
		asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord),
		asm.FnGetSmpProcessorId.Call(),
		asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord),
		asm.Mov.Reg(asm.R6, asm.R2),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "bad"),
		asm.JNE.Imm(asm.R6, 123, "bad"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word), asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("bad"), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p").WithSource(asm.Comment("fastcall entry")), fn)
	return &ebpf.CollectionSpec{
		ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"sessions": {
			Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1, Key: u32, Value: u32,
		}},
		Programs: map[string]*ebpf.ProgramSpec{"p": {
			Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: insns,
		}},
	}
}

func TestBpfSubprogSiteWrongCtxRejected(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	_, err := ebpf.NewCollection(subprogCtxTarget(btf.GlobalFunc, true))
	if err == nil {
		t.Fatal("global typed hook accepted a non-context R1")
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("BPF unsupported or insufficient privileges: %v", err)
	}
	var verifier *ebpf.VerifierError
	if !errors.As(err, &verifier) {
		t.Fatalf("loading wrong-context fixture: %v", err)
	}
	log := fmt.Sprintf("%+v", verifier)
	// Kernels say "expects pointer to ctx" or "expected pointer to ctx".
	if !strings.Contains(log, "pointer to ctx") || !strings.Contains(log, "Caller passes invalid args") {
		t.Fatalf("unexpected verifier rejection: %s", log)
	}
}

func TestBpfSubprogStaticHookWrongCtxLoads(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	target := loadOrSkip(t, subprogCtxTarget(btf.StaticFunc, true))
	t.Cleanup(target.Close)
	observer := loadOrSkip(t, subprogRawArgObserver(target.Programs["p"]))
	t.Cleanup(observer.Close)
	attached := attachTracingOrSkip(t, observer.Programs["observe"])
	t.Cleanup(func() { _ = attached.Close() })
	if ret, err := target.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
		t.Fatalf("action=%d err=%v", ret, err)
	}
	var got uint64
	if err := observer.Maps["seen"].Lookup(uint32(0), &got); err != nil || got == 0 {
		t.Fatalf("raw first argument=%#x err=%v", got, err)
	}
}

func TestBpfSubprogStaticHookAttach(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	work := subprogramLookupFixture("register")
	req := autoReq()
	req.Stack.LowestOffset, req.Dispatch, req.StaticUntrusted = -16, true, true
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || !plan.hooks[0].Static || len(plan.hooks[0].Sites) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	target := loadHooked(t, work, plan.hooks)
	t.Cleanup(target.Close)
	info, err := target.Programs["p"].Info()
	if err != nil {
		t.Fatal(err)
	}
	translated, err := info.Instructions()
	if err != nil {
		t.Fatal(err)
	}
	if reason := ctxflow.CallsRefusal(translated, plan.hooks[0].Name); reason != "" {
		var calls strings.Builder
		for it := translated.Iterate(); it.Next(); {
			if fn := btf.FuncMetadata(it.Ins); fn != nil {
				fmt.Fprintf(&calls, "func pc=%d name=%s linkage=%v symbol=%q\n", it.Offset, fn.Name, fn.Linkage, it.Ins.Symbol())
			}
			if it.Ins.OpCode.JumpOp() == asm.Call {
				fmt.Fprintf(&calls, "call pc=%d opcode=%v src=%v off=%d imm=%d ref=%q function=%v builtin=%v\n",
					it.Offset, it.Ins.OpCode, it.Ins.Src, it.Ins.Offset, it.Ins.Constant,
					it.Ins.Reference(), it.Ins.IsFunctionCall(), it.Ins.IsBuiltinCall())
			}
		}
		t.Fatalf("translated context proof: %s\n%s", reason, calls.String())
	}
	if err := target.Maps["sessions"].Put(uint32(0), [2]uint64{2, 987654321}); err != nil {
		t.Fatal(err)
	}
	observer := loadOrSkip(t, lookupObserverArgs(t, plan.hooks[0].Name, target.Programs["p"], observerArgs{site: true, mapID: true, rawCtx: true}))
	t.Cleanup(observer.Close)
	attached := attachTracingOrSkip(t, observer.Programs["observe"])
	t.Cleanup(func() { _ = attached.Close() })
	packet := make([]byte, 80)
	out := make([]byte, len(packet))
	ret, err := target.Programs["p"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Repeat: 1})
	if err != nil || ret != 2 || !bytes.Equal(packet, out) {
		t.Fatalf("action=%d err=%v output_equal=%v", ret, err, bytes.Equal(packet, out))
	}
	var got [32]byte
	if err := observer.Maps["obs"].Lookup(uint32(0), &got); err != nil {
		t.Fatal(err)
	}
	seen, length := binary.LittleEndian.Uint64(got[:]), binary.LittleEndian.Uint32(got[8:])
	key, value, site := binary.LittleEndian.Uint32(got[12:]), binary.LittleEndian.Uint64(got[16:]), binary.LittleEndian.Uint32(got[24:])
	if seen != 1 || length != uint32(len(packet)) || key != 0 || value != 987654321 || site != plan.hooks[0].Sites[0].SitePC {
		t.Fatalf("record seen=%d length=%d key=%d value=%d site=%d", seen, length, key, value, site)
	}
}

func attachTracingOrSkip(t *testing.T, program *ebpf.Program) link.Link {
	t.Helper()
	attached, err := link.AttachTracing(link.TracingOptions{Program: program, AttachType: ebpf.AttachTraceFEntry})
	if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("fentry unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return attached
}

// subprogCtxTarget is entry(ctx) -> static sub(ctx, pointer into the entry
// frame) -> hook. It isolates the kernel's global/static argument checking.
func subprogCtxTarget(linkage btf.FuncLinkage, wrong bool) *ebpf.CollectionSpec {
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	u32 := &btf.Int{Name: "__u32", Size: 4}
	ctx := &btf.Struct{Name: "xdp_md", Size: 24, Members: []btf.Member{{Name: "data", Type: u32}, {Name: "data_end", Type: u32, Offset: 32}}}
	params := []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: ctx}}, {Name: "key", Type: &btf.Pointer{Target: u32}}}
	fn := func(name string, fnLinkage btf.FuncLinkage, ps []btf.FuncParam, head asm.Instruction) asm.Instruction {
		meta := &btf.Func{Name: name, Linkage: fnLinkage, Type: &btf.FuncProto{Return: i32, Params: ps}}
		return btf.WithFuncMetadata(head.WithSymbol(name).WithSource(asm.Comment(name)), meta)
	}
	entry := asm.Instructions{
		fn("p", btf.GlobalFunc, params[:1], asm.StoreImm(asm.RFP, -8, 7, asm.Word)),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.Call.Label("sub"), asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	sub := asm.Instructions{
		fn("sub", btf.StaticFunc, params, asm.Mov.Reg(asm.R6, asm.R1)), asm.Mov.Reg(asm.R7, asm.R2),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Reg(asm.R2, asm.R7),
	}
	if wrong {
		sub = append(sub, asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8))
	}
	sub = append(sub, asm.Call.Label("hook"), asm.Mov.Imm(asm.R0, 0), asm.Return())
	hook := asm.Instructions{fn("hook", linkage, params, asm.Mov.Imm(asm.R0, 0)), asm.Return()}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian, Programs: map[string]*ebpf.ProgramSpec{
		"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: append(append(entry, sub...), hook...)},
	}}
}

func subprogRawArgObserver(target *ebpf.Program) *ebpf.CollectionSpec {
	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("seen"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"), asm.StoreMem(asm.R0, 0, asm.R6, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return(),
	}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"seen": {Name: "seen", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"observe": {
			Name: "observe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: "hook", AttachTarget: target, License: "GPL", Instructions: insns,
		}},
	}
}
