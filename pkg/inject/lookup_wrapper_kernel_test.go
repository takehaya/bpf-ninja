package inject

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// wrapperObserver records what an argument pointer points to: fentry reads the
// site in ctx[1], 4 key bytes through ctx[2] and, when value, the first 8 value
// bytes through ctx[3] into seen[0]. A miss hook has no value.
func wrapperObserver(target *ebpf.Program, hook string, value bool) *ebpf.CollectionSpec {
	// bpf_get_func_arg, because the verifier refuses a direct ctx load of a
	// pointer to a struct it cannot type in the target's BTF.
	read := func(arg int32, size int32, to int16) asm.Instructions {
		return asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, arg), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -32),
			asm.FnGetFuncArg.Call(),
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, int32(to)), asm.Mov.Imm(asm.R2, size),
			asm.LoadMem(asm.R3, asm.RFP, -32, asm.DWord), asm.FnProbeReadKernel.Call(),
		}
	}
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.StoreImm(asm.RFP, -8, 0, asm.Word), asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.StoreImm(asm.RFP, -16, 0, asm.Word), asm.StoreImm(asm.RFP, -12, 0, asm.Word)}
	insns = append(insns, read(2, 4, -8)...)
	if value {
		insns = append(insns, read(3, 8, -16)...)
	}
	insns = append(insns,
		asm.LoadMem(asm.R7, asm.R6, 8, asm.DWord),
		asm.StoreImm(asm.RFP, -20, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -20),
		asm.LoadMapPtr(asm.R1, 0).WithReference("seen"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.StoreMem(asm.R0, 0, asm.R7, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.DWord), asm.StoreMem(asm.R0, 8, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord), asm.StoreMem(asm.R0, 16, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R0, 24, asm.DWord), asm.Add.Imm(asm.R1, 1), asm.StoreMem(asm.R0, 24, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return())
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"seen": {Name: "seen", Type: ebpf.Array, KeySize: 4, ValueSize: 32, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"observe": {
			Name: "observe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: hook, AttachTarget: target, License: "GPL", Instructions: insns,
		}},
	}
}

type wrapperRecord struct {
	Site  uint64
	Key   uint64
	Value uint64
	Count uint64
}

// skipUnlessFrameRounding16 skips where the product would plan with the
// 32-byte frame rule: the wrapper's frame fits only under the 16-byte rule.
func skipUnlessFrameRounding16(t *testing.T) {
	t.Helper()
	if r := RunningKernelFrameRounding(); r != 16 {
		t.Skipf("skipping: kernel uses %d-byte frame rounding; the wrapper needs the 16-byte rule", r)
	}
}

func TestBpfLookupWrapper(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const site = 12 // the fixture's helper slot: fixture slot 11 plus the deep store
	hitKey, missKey := uint32(7), uint32(9)
	packet := func(key uint32) []byte {
		p := make([]byte, 64)
		binary.NativeEndian.PutUint32(p, key)
		return p
	}
	for _, when := range []LookupWhen{LookupHit, LookupMiss, LookupAny} {
		t.Run(string(when), func(t *testing.T) {
			skipUnlessFrameRounding16(t)
			plain := loadOrSkip(t, deepLookupFixture(-504))
			t.Cleanup(plain.Close)
			work := deepLookupFixture(-504)
			plan, err := transformLookup(work, deepReq(-504, when))
			if err != nil {
				t.Fatal(err)
			}
			if plan.sites[0].Wrapper == "" {
				t.Fatalf("site is not wrapped: %+v", plan.sites[0])
			}
			coll := loadHooked(t, work, plan.hooks)
			t.Cleanup(coll.Close)
			for _, c := range []*ebpf.Collection{plain, coll} {
				if err := c.Maps["sessions"].Put(hitKey, [2]uint64{2, 1234}); err != nil {
					t.Fatal(err)
				}
			}
			observers := map[string]*ebpf.Collection{}
			for _, hook := range plan.hooks {
				spec := wrapperObserver(coll.Programs["p"], hook.Name, hook.When == string(LookupHit))
				obs := loadOrSkip(t, spec)
				t.Cleanup(obs.Close)
				attached := attachTracingOrSkip(t, obs.Programs["observe"])
				t.Cleanup(func() { _ = attached.Close() })
				observers[hook.When] = obs
			}
			for _, key := range []uint32{hitKey, missKey} {
				in := packet(key)
				po, io := make([]byte, 64), make([]byte, 64)
				pr, err := plain.Programs["p"].Run(&ebpf.RunOptions{Data: in, DataOut: po, Repeat: 1})
				if err != nil {
					t.Fatal(err)
				}
				ir, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: in, DataOut: io, Repeat: 1})
				if err != nil {
					t.Fatal(err)
				}
				if pr != ir || !bytes.Equal(po, io) {
					t.Fatalf("key %d: plain=%d/%x wrapped=%d/%x", key, pr, po, ir, io)
				}
				want := map[uint32]uint32{hitKey: 2, missKey: 1}[key]
				if ir != want {
					t.Fatalf("key %d: action %d, want %d", key, ir, want)
				}
			}
			for armWhen, obs := range observers {
				var got wrapperRecord
				if err := obs.Maps["seen"].Lookup(uint32(0), &got); err != nil {
					t.Fatal(err)
				}
				want := wrapperRecord{Site: site, Key: uint64(hitKey), Value: 2, Count: 1}
				if armWhen == string(LookupMiss) {
					want = wrapperRecord{Site: site, Key: uint64(missKey), Count: 1}
				}
				if got != want {
					t.Fatalf("%s observer = %+v, want %+v", armWhen, got, want)
				}
			}
			// Plain and wrapped maps must hold the same state afterwards.
			var a, b [2]uint64
			if err := plain.Maps["sessions"].Lookup(hitKey, &a); err != nil {
				t.Fatal(err)
			}
			if err := coll.Maps["sessions"].Lookup(hitKey, &b); err != nil || a != b {
				t.Fatalf("map state %v, %v: %v", a, b, err)
			}
		})
	}
}

func TestBpfLookupWrapperGeneric(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, static := range []bool{false, true} {
		t.Run(fmt.Sprintf("static=%t", static), func(t *testing.T) {
			if static {
				skipUnlessFrameRounding16(t)
			}
			work := mapInMapDeepFixture()
			req := deepReq(-504, LookupAny)
			req.StaticUntrusted = static
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			coll := loadHooked(t, work, plan.hooks)
			t.Cleanup(coll.Close)
			inner, err := ebpf.NewMap(mapInMapDeepFixture().Maps["outer"].InnerMap)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = inner.Close() })
			if err := inner.Put(uint32(7), [2]uint64{2, 1234}); err != nil {
				t.Fatal(err)
			}
			if err := coll.Maps["outer"].Put(uint32(0), inner); err != nil {
				t.Fatal(err)
			}
			p := make([]byte, 64)
			binary.NativeEndian.PutUint32(p, 7)
			if ret, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: p, Repeat: 1}); err != nil || ret != 2 {
				t.Fatalf("hit: action=%d err=%v", ret, err)
			}
			binary.NativeEndian.PutUint32(p, 9)
			if ret, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: p, Repeat: 1}); err != nil || ret != 1 {
				t.Fatalf("miss: action=%d err=%v", ret, err)
			}
		})
	}
}

// With 8 bytes free in a callee frame under a 504-byte chain the same applies.
func TestBpfLookupWrapperNoSpillInSubprogram(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	skipUnlessFrameRounding16(t)
	work := subprogramLookupFixture("register")
	insns := work.Programs["p"].Instructions
	for i := range insns {
		if insns[i].Symbol() == "sub" {
			// the callee frame reaches fp-496, leaving no room for three slots
			work.Programs["p"].Instructions = append(insns[:i+1:i+1], append(asm.Instructions{asm.StoreImm(asm.RFP, -496, 0, asm.Word)}, insns[i+1:]...)...)
			break
		}
	}
	req := autoReq()
	req.Stack = StackAudit{Frames: map[string]int16{"p": 0, "sub": -496}, Source: "verifier", FrameRounding: 16}
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.sites[0].Wrapper == "" || plan.sites[0].CtxSource != "r6" {
		t.Fatalf("site = %+v", plan.sites[0])
	}
	coll := loadHooked(t, work, plan.hooks)
	t.Cleanup(coll.Close)
	if ret, err := coll.Programs["p"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1}); err != nil || ret != 2 {
		t.Fatalf("action=%d err=%v", ret, err)
	}
}
