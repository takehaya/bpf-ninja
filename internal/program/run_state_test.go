package program

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestRunLayout(t *testing.T) {
	// Independent Go representation checks the offsets consumed by BPF.
	var frame struct {
		owner, id  uint64
		tag, state uint32
		ctx        uint64
	}
	var stack struct {
		depth, poison uint32
		reserved      uint64
		frames        [8][32]byte
	}
	for _, tc := range []struct {
		field     string
		got, want uintptr
	}{
		{"depth", unsafe.Offsetof(stack.depth), runDepth}, {"poison", unsafe.Offsetof(stack.poison), runPoison},
		{"frames", unsafe.Offsetof(stack.frames), runFrames}, {"stack size", unsafe.Sizeof(stack), runSize},
		{"owner", unsafe.Offsetof(frame.owner), runOwner}, {"id", unsafe.Offsetof(frame.id), runID},
		{"tag", unsafe.Offsetof(frame.tag), runTag}, {"state", unsafe.Offsetof(frame.state), runState},
		{"ctx", unsafe.Offsetof(frame.ctx), runCtx}, {"frame size", unsafe.Sizeof(frame), runStride},
	} {
		if tc.got != tc.want {
			t.Errorf("%s offset/size %d, want %d", tc.field, tc.got, tc.want)
		}
	}
	// Literal sizes independently pin the map ABI.
	state, seq := runStateMapSpec(), runSequenceMapSpec()
	if state.Type != ebpf.PerCPUArray || state.ValueSize != 272 || state.MaxEntries != 1 ||
		seq.Type != ebpf.PerCPUArray || seq.ValueSize != 16 || seq.MaxEntries != 1 {
		t.Fatalf("state=%+v sequence=%+v", state, seq)
	}
}

func TestRunResidual(t *testing.T) {
	for _, tc := range []struct {
		name   string
		depth  uint32
		poison bool
		state  uint32
		id     uint64
		tag    uint32
		want   runResidual
	}{
		{"empty", 0, false, runTracked, 1, 7, runResidual{}},
		{"pending", 1, false, runPending, 0, 7, runResidual{Depth: 1}},
		{"blocked", 1, false, runBlocked, 0, 7, runResidual{Depth: 1, Blocked: 1}},
		{"tag-zero", 1, false, runTracked, 1, 0, runResidual{Depth: 1, Tracked: 1}},
		{"tag-nonzero", 1, false, runTracked, 1, 7, runResidual{Depth: 1, Tracked: 1}},
		{"flags", 8, false, runTracked | 1<<8, 1, 7, runResidual{Depth: 8, Tracked: 8}},
		{"overflow", 9, false, runTracked, 1, 7, runResidual{Depth: 9, Tracked: 8}},
		{"poison", 1, true, runTracked, 1, 7, runResidual{Depth: 1, Tracked: 1, Poisoned: true}},
		{"reserved-state", 1, false, 3, 0, 7, runResidual{Depth: 1, Invalid: 1}},
		{"missing-id", 1, false, runTracked, 0, 7, runResidual{Depth: 1, Invalid: 1}},
		{"unexpected-id", 1, false, runPending, 1, 7, runResidual{Depth: 1, Invalid: 1}},
		{"blocked-with-id", 1, false, runBlocked, 1, 7, runResidual{Depth: 1, Invalid: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := runFixture(tc.depth, tc.poison, tc.state, tc.id, tc.tag)
			got, err := inspectRunState(raw)
			if err != nil || got != tc.want {
				t.Fatalf("residual=%+v err=%v, want %+v", got, err, tc.want)
			}
		})
	}
	for _, size := range []int{0, runSize - 1, runSize + 1} {
		if _, err := inspectRunState(make([]byte, size)); err == nil {
			t.Fatalf("accepted %d-byte snapshot", size)
		}
	}
}

func runFixture(depth uint32, poison bool, state uint32, id uint64, tag uint32) []byte {
	raw := make([]byte, runSize)
	binary.NativeEndian.PutUint32(raw[runDepth:], depth)
	if poison {
		binary.NativeEndian.PutUint32(raw[runPoison:], 1)
	}
	for i := range runSlots {
		frame := raw[runFrames+i*runStride:]
		binary.NativeEndian.PutUint64(frame[runOwner:], 0xb000+uint64(i))
		binary.NativeEndian.PutUint64(frame[runCtx:], 0xc000+uint64(i))
		binary.NativeEndian.PutUint64(frame[runID:], id)
		binary.NativeEndian.PutUint32(frame[runTag:], tag)
		binary.NativeEndian.PutUint32(frame[runState:], state)
	}
	return raw
}

func TestObserverMisses(t *testing.T) {
	calls := 0
	got, err := observerMisses(3, func(i int) (uint64, error) {
		calls++
		return []uint64{0, 2, 3}[i], nil
	})
	if err != nil || got != 5 || calls != 3 {
		t.Fatalf("misses=%d err=%v reads=%d", got, err, calls)
	}
	failure := errors.New("program info unavailable")
	got, err = observerMisses(3, func(i int) (uint64, error) {
		if i == 1 {
			return 0, failure
		}
		return 7, nil
	})
	if got != 0 || !errors.Is(err, failure) {
		t.Fatalf("unavailable stats became a successful sample: %d, %v", got, err)
	}
}

func TestObserverMissesKernel(t *testing.T) {
	for _, tc := range []struct {
		major, minor, patch int
		ok                  bool
		want                string
	}{
		{0, 0, 0, false, "observer miss diagnostics: cannot determine kernel version"},
		{7, 0, 0, false, "observer miss diagnostics: cannot determine kernel version"},
		{5, 15, 0, true, "observer miss diagnostics require Linux 6.1 or newer, got 5.15.0"},
		{6, 0, 99, true, "observer miss diagnostics require Linux 6.1 or newer, got 6.0.99"},
		{6, 1, 0, true, ""}, {6, 1, 188, true, ""}, {6, 10, 0, true, ""},
		{7, 0, 0, true, ""}, {8, 0, 0, true, ""},
	} {
		err := checkObserverMissesKernel(tc.major, tc.minor, tc.patch, tc.ok)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tc.want {
			t.Errorf("kernel %d.%d.%d parsed=%v: error %q, want %q", tc.major, tc.minor, tc.patch, tc.ok, got, tc.want)
		}
	}
}

func TestRunInstructions(t *testing.T) {
	// Pin complete little-endian programs, including resolved jumps, map FD
	// 123 and a shared success/failure tail. No BPF loading is needed.
	for _, tc := range []struct {
		name string
		ins  asm.Instructions
		hex  string
	}{
		{"sequence", emitRunSequence(123, "test", "bad"), "850000000800000025001800ffff000067000000300000007b0a30ff00000000" +
			"620af0ff00000000181100007b0000000000000000000000bfa2000000000000" +
			"07020000f0ffffff850000000100000015000f00000000007901080000000000" +
			"55010d0000000000b701000001000000db1000000100000018020000ffffffff" +
			"00000000ffff0000ad21030000000000b7020000010000007b20080000000000" +
			"0500050000000000070100000100000079a030ff000000004f10000000000000" +
			"b7000000020000009500000000000000b7000000010000009500000000000000"},
		{"lookup", emitRunLookup(123, "bad"), "620af0ff00000000181100007b0000000000000000000000bfa2000000000000" +
			"07020000f0ffffff85000000010000001500020000000000b700000002000000" +
			"9500000000000000b7000000010000009500000000000000"},
		{"top", emitRunTop(123, "bad"), "620af0ff00000000181100007b0000000000000000000000bfa2000000000000" +
			"07020000f0ffffff850000000100000015000a00000000006101040000000000" +
			"5501080000000000610100000000000017010000010000003501050008000000" +
			"270100002000000007010000100000000f10000000000000b700000002000000" +
			"9500000000000000b7000000010000009500000000000000"},
		{"identity", emitRunIdentity(asm.R9, asm.R7, "bad"), "79911800000000005d71020000000000" +
			"b7000000020000009500000000000000b7000000010000009500000000000000"},
		{"counter", emitRunCounter(8), "b701000001000000db10080000000000b7000000020000009500000000000000" +
			"b7000000010000009500000000000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ins := runTestTail(tc.ins)
			var encoded bytes.Buffer
			if err := ins.Marshal(&encoded, binary.LittleEndian); err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded.Bytes(), want) {
				t.Fatalf("instruction bytes %x, want %x", encoded.Bytes(), want)
			}
			decoded, err := asm.AppendInstructions(nil, bytes.NewReader(want), binary.LittleEndian, "linux")
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip bytes.Buffer
			if err := decoded.Marshal(&roundtrip, binary.LittleEndian); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(roundtrip.Bytes(), want) {
				t.Fatalf("round trip bytes %x, want %x", roundtrip.Bytes(), want)
			}
		})
	}
}

func TestBpfRunSequence(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, cpu := range allowedCPUs(t) {
		t.Run(fmt.Sprintf("cpu%d", cpu), func(t *testing.T) { testRunSequence(t, cpu) })
	}
}

func testRunSequence(t *testing.T, cpu int) {
	seq := newRunTestMap(t, runSequenceMapSpec())
	result := newRunTestMap(t, &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 1})
	ins, interleaved, invalidCPU := runSequenceFixture(seq.FD(), result.FD())
	plainProgram, interleavedProgram := newRunTestProgram(t, ins), newRunTestProgram(t, interleaved)
	invalidCPUProgram := newRunTestProgram(t, invalidCPU)
	for _, tc := range []struct {
		name      string
		initial   [2]uint64
		sequences []uint64 // zero means allocation must fail
		final     [2]uint64
		program   *ebpf.Program
	}{
		{"fresh", [2]uint64{}, []uint64{1, 2, 3}, [2]uint64{3, 0}, plainProgram},
		{"boundary", [2]uint64{runSeqMax - 2, 0}, []uint64{runSeqMax - 1, runSeqMax, 0, 0}, [2]uint64{runSeqMax + 1, 1}, plainProgram},
		{"invalid-cpu", [2]uint64{7, 0}, []uint64{0, 0}, [2]uint64{7, 0}, invalidCPUProgram},
		{"sticky", [2]uint64{0, 1}, []uint64{0, 0}, [2]uint64{0, 1}, plainProgram},
		{"interleaved", [2]uint64{}, []uint64{1, 3, 5}, [2]uint64{6, 0}, interleavedProgram},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinTest(t, cpu)
			cpus, err := ebpf.PossibleCPU()
			if err != nil {
				t.Fatal(err)
			}
			values := make([][2]uint64, cpus)
			values[cpu] = tc.initial
			if err := seq.Update(uint32(0), values, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if err := result.Update(uint32(0), [2]uint64{}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			var successes uint64
			for _, want := range tc.sequences {
				ret := runTestProgram(t, tc.program)
				if want == 0 {
					if ret != 1 {
						t.Fatalf("rejected allocator returned %d", ret)
					}
					continue
				}
				var got [2]uint64
				if err := result.Lookup(uint32(0), &got); err != nil {
					t.Fatal(err)
				}
				if ret != 2 || got != [2]uint64{uint64(cpu)<<48 | want, successes + 1} {
					t.Fatalf("ret=%d result=%v want sequence=%d counter=%d", ret, got, want, successes+1)
				}
				successes++
			}
			if err := seq.Lookup(uint32(0), &values); err != nil {
				t.Fatal(err)
			}
			if values[cpu] != tc.final {
				t.Fatalf("final sequence state %v, want %v", values[cpu], tc.final)
			}
		})
	}
	// Smoke-test Stats availability only; XDP test runs do not drive recursion misses.
	misses, err := (&Probe{progs: []*ebpf.Program{plainProgram, interleavedProgram}}).ObserverMisses()
	if err != nil || misses != 0 {
		t.Fatalf("observer stats: misses=%d err=%v", misses, err)
	}
}

func TestBpfRunFrame(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	cpu := affinityCPUs(t)[0]
	state := newRunTestMap(t, runStateMapSpec())
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	values := make([][]byte, cpus)
	for i := range values {
		values[i] = make([]byte, runSize)
	}
	raw := values[cpu]
	// Each field and level has its own value, so neither a parent frame nor
	// a wrong field offset can accidentally satisfy the expected top frame.
	for i := range runSlots {
		frame := raw[runFrames+i*runStride:]
		binary.NativeEndian.PutUint64(frame[runOwner:], 0x1000+uint64(i))
		binary.NativeEndian.PutUint64(frame[runID:], 0x1234567800002000+uint64(i))
		binary.NativeEndian.PutUint32(frame[runTag:], 0x3000+uint32(i))
		binary.NativeEndian.PutUint32(frame[runState:], runTracked|(uint32(i+1)<<8))
		binary.NativeEndian.PutUint64(frame[runCtx:], 0xffff888000005000+(uint64(i)<<32))
	}
	check := func(name string, depth uint32, expected []byte, want uint32) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			pinTest(t, cpu)
			binary.NativeEndian.PutUint32(raw[runDepth:], depth)
			if err := state.Update(uint32(0), values, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			ins := runFrameFixture(state.FD(), expected)
			if got := runTestProgram(t, newRunTestProgram(t, ins)); got != want {
				t.Fatalf("depth=%d result=%d, want %d; expected frame %x", depth, got, want, expected[:runStride])
			}
		})
	}
	first := slices.Clone(raw[runFrames : runFrames+runStride])
	check("empty", 0, first, 3)
	// Simulate root entries followed by exits, retaining the distinct frames.
	for depth := uint32(1); depth <= runSlots; depth++ {
		check(fmt.Sprintf("push%d", depth), depth, raw[runFrames+int(depth-1)*runStride:], 2)
	}
	check("overflow9", 9, first, 3)
	check("overflow10", 10, first, 3)

	top := raw[runFrames+(runSlots-1)*runStride:]
	parent := slices.Clone(raw[runFrames+(runSlots-2)*runStride : runFrames+(runSlots-1)*runStride])
	expected := slices.Clone(top)
	binary.NativeEndian.PutUint64(raw[runFrames+runCtx:], 0)
	check("outer-ctx-mismatch", 8, expected, 2)
	copy(raw[runFrames:], first)
	binary.NativeEndian.PutUint32(raw[runPoison:], 1)
	check("poison", 8, expected, 3)
	binary.NativeEndian.PutUint32(raw[runPoison:], 0)
	{
		copy(top, expected)
		binary.NativeEndian.PutUint64(top[runCtx:], binary.NativeEndian.Uint64(expected[runCtx:])^(1<<40))
		check("top-ctx-high-mismatch", 8, expected, 1)
		binary.NativeEndian.PutUint64(top[runCtx:], 0)
		check("top-ctx-mismatch", 8, expected, 1)
		// The parent matches exactly, but an invalid top must not fall back to it.
		copy(top, parent)
		binary.NativeEndian.PutUint64(top[runCtx:], 0)
		check("matching-parent-ctx", 8, parent, 1)
	}
}

func newRunTestMap(t *testing.T, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func newRunTestProgram(t *testing.T, ins asm.Instructions) *ebpf.Program {
	t.Helper()
	ins = runTestTail(ins)
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: ins})
	if err != nil {
		t.Fatalf("load test program: %+v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func runTestProgram(t *testing.T, p *ebpf.Program) uint32 {
	t.Helper()
	ret, err := p.Run(&ebpf.RunOptions{Data: make([]byte, 64)})
	if err != nil {
		t.Fatal(err)
	}
	return ret
}

func readRunField(raw []byte, offset int16, size asm.Size) uint64 {
	if size == asm.DWord {
		return binary.NativeEndian.Uint64(raw[offset:])
	}
	return uint64(binary.NativeEndian.Uint32(raw[offset:]))
}

func TestRunTableResidual(t *testing.T) {
	if spec := runTableMapSpec(32); spec.Type != ebpf.Hash || spec.KeySize != 8 || spec.ValueSize != 32 || spec.MaxEntries != 2048 || spec.Flags != 0 {
		t.Fatal(spec)
	}
	if runTableMapSpec(2).MaxEntries != 1024 {
		t.Fatal("minimum capacity")
	}
	var entries [][]byte
	for _, state := range []uint32{runPending, runTracked, runBlocked, 3} {
		id := uint64(0)
		if state == runTracked {
			id = 1
		}
		entries = append(entries, runFixture(1, false, state, id, 0)[runFrames:runFrames+runStride])
	}
	got, err := inspectRunTable(entries)
	if err != nil || got != (runResidual{Depth: 4, Tracked: 1, Blocked: 1, Invalid: 1}) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := inspectRunTable([][]byte{{}}); err == nil {
		t.Fatal("accepted malformed frame")
	}
}

func TestRunStackContract(t *testing.T) {
	// Host ranges are independent of the run constants under test. Kunai owns
	// lower slots only while a filter runs, outside every emitter's lifetime.
	host := [][2]int{{-8, 0}, {-12, -8}, {-16, -12}, {-24, -16},
		{-32, -24}, {-40, -32}, {-48, -40}, {-56, -48}, {-120, -56},
		{-128, -120}, {-136, -128}, {-144, -136}, {-160, -144}}
	slots := [][2]int{{runCPUStack, runCPUStack + 8}, {runKeyStack, runKeyStack + 8}, {runFrameStack, runFrameStack + 32}}
	for i, slot := range slots {
		for _, other := range slots[:i] {
			if slot[0] < other[1] && other[0] < slot[1] {
				t.Fatalf("run slots %v and %v overlap", slot, other)
			}
		}
		for _, occupied := range host {
			if slot[0] < occupied[1] && occupied[0] < slot[1] {
				t.Fatalf("run slot %v overlaps host slot %v", slot, occupied)
			}
		}
	}
	if runCPUStack != -208 || runKeyStack != -216 || runFrameStack != -192 || runPacketIDStack != -24 || runArgsStack != -48 {
		t.Fatal("run temporary slots moved outside their reserved ranges")
	}
	emitters := []asm.Instructions{emitRunSequence(123, "seq", "bad"),
		emitRunLookup(123, "bad"), emitRunTop(123, "bad"),
		emitRunIdentity(asm.R8, asm.R6, "bad"), emitRunCounter(8),
		(ctxRuns{123, 124}).create(), (ctxRuns{123, 124}).find("bad", "bad"), (ctxRuns{123, 124}).release()}
	for _, emitter := range emitters {
		for i, ins := range emitter {
			if i > 0 && emitter[i-1].OpCode == asm.Mov.Reg(asm.R2, asm.R10).OpCode && emitter[i-1].Src == asm.R10 && ins.OpCode == asm.Add.Imm(asm.R2, 0).OpCode && ins.Dst == emitter[i-1].Dst {
				if ins.Constant != -16 && ins.Constant != -216 && ins.Constant != -192 {
					t.Fatalf("unexpected stack address: %v", ins)
				}
			}
			if (ins.Dst == asm.R10 && ins.OpCode.Class().IsStore()) ||
				(ins.Src == asm.R10 && ins.OpCode.Class().IsLoad()) {
				start := int(ins.Offset)
				end := start + ins.OpCode.Size().Sizeof()
				if (start < -208 || end > -200) && (start < -16 || end > -12) && (start < -216 || end > -208) && (start < -192 || end > -160) {
					t.Fatalf("unexpected stack access: %v", ins)
				}
			}
		}
	}
	for _, regs := range [][2]asm.Register{{asm.R1, asm.R6}, {asm.R8, asm.R1}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("accepted scratch register as identity input")
				}
			}()
			emitRunIdentity(regs[0], regs[1], "bad")
		}()
	}
}

func runSequenceFixture(seqFD, resultFD int) (asm.Instructions, asm.Instructions, asm.Instructions) {
	ins := emitRunLookup(resultFD, "bad")
	ins = append(ins, asm.Mov.Reg(asm.R8, asm.R0), asm.Mov.Imm(asm.R6, 0xcafe), asm.Mov.Imm(asm.R7, 0xbeef), asm.Mov.Imm(asm.R9, 123))
	ins = append(ins, emitRunSequence(seqFD, "seq", "bad")...)
	ins = append(ins, asm.StoreMem(asm.R8, 0, asm.R0, asm.DWord), asm.Mov.Reg(asm.R0, asm.R8))
	ins = append(ins, emitRunCounter(8)...)
	ins = append(ins, asm.JNE.Imm(asm.R6, 0xcafe, "bad"), asm.JNE.Imm(asm.R7, 0xbeef, "bad"), asm.JNE.Imm(asm.R9, 123, "bad"))
	interleaved := append(asm.Instructions(nil), ins...)
	for i, op := range interleaved {
		if op.OpCode.AtomicOp() == asm.FetchAdd {
			// Simulate another observer allocating after our fetch but before
			// we use its result. Reloading the map here would borrow its ID.
			interleaved = slices.Insert(interleaved, i+1, asm.Mov.Imm(asm.R3, 1), fetchAdd64(asm.R0, asm.R3, runSeqCount))
			break
		}
	}
	invalidCPU := slices.Clone(ins)
	for i, op := range invalidCPU {
		if op.IsBuiltinCall() && asm.BuiltinFunc(op.Constant) == asm.FnGetSmpProcessorId {
			invalidCPU[i] = asm.Mov.Imm(asm.R0, 0x10000)
		}
	}
	return ins, interleaved, invalidCPU
}

func runFrameFixture(stateFD int, expected []byte) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R6, 0x66), asm.Mov.Imm(asm.R7, 0x77),
		asm.Mov.Imm(asm.R8, 0x88), asm.Mov.Imm(asm.R9, 0x99),
	}
	ins = append(ins, emitRunTop(stateFD, "no_frame")...)
	ins = append(ins,
		asm.JNE.Imm(asm.R6, 0x66, "bad"), asm.JNE.Imm(asm.R7, 0x77, "bad"),
		asm.JNE.Imm(asm.R8, 0x88, "bad"), asm.JNE.Imm(asm.R9, 0x99, "bad"),
		asm.Mov.Reg(asm.R8, asm.R0))
	// Read the expected owner through a helper while the frame stays live.
	ins = append(ins, asm.LoadImm(asm.R1, int64(binary.NativeEndian.Uint64(expected[runOwner:])), asm.DWord),
		asm.StoreMem(asm.R10, -40, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R10), asm.Add.Imm(asm.R1, -32),
		asm.Mov.Imm(asm.R2, 8), asm.Mov.Reg(asm.R3, asm.R10), asm.Add.Imm(asm.R3, -40), asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, "bad"), asm.LoadMem(asm.R7, asm.R10, -32, asm.DWord),
		asm.LoadMem(asm.R1, asm.R8, runOwner, asm.DWord), asm.JNE.Reg(asm.R1, asm.R7, "bad"),
		asm.LoadImm(asm.R6, int64(binary.NativeEndian.Uint64(expected[runCtx:])), asm.DWord))
	ins = append(ins, emitRunIdentity(asm.R8, asm.R6, "bad")...)
	for _, field := range []struct {
		offset int16
		size   asm.Size
	}{
		{runID, asm.DWord}, {runTag, asm.Word}, {runState, asm.Word},
	} {
		ins = append(ins, asm.LoadMem(asm.R1, asm.R8, field.offset, field.size),
			asm.LoadImm(asm.R2, int64(readRunField(expected, field.offset, field.size)), asm.DWord),
			asm.JNE.Reg(asm.R1, asm.R2, "bad"))
	}
	ins = append(ins, asm.Ja.Label("ok"), asm.Mov.Imm(asm.R0, 3).WithSymbol("no_frame"), asm.Return(), asm.Mov.Imm(asm.R0, 2).WithSymbol("ok"))
	return ins
}

func TestRunFixturesMarshal(t *testing.T) {
	plain, nested, invalidCPU := runSequenceFixture(123, 124)
	fixtures := []asm.Instructions{plain, nested, invalidCPU}
	for i := range runSlots {
		raw := runFixture(1, false, runTracked, uint64(i+1)<<48|1, 7)
		fixtures = append(fixtures, runFrameFixture(125, raw[runFrames+i*runStride:]))
	}
	for i, ins := range fixtures {
		var buf bytes.Buffer
		if err := runTestTail(ins).Marshal(&buf, binary.LittleEndian); err != nil {
			t.Fatalf("fixture %d: %v", i, err)
		}
	}
}

func runTestTail(ins asm.Instructions) asm.Instructions {
	return append(ins, asm.Mov.Imm(asm.R0, 2), asm.Return(), asm.Mov.Imm(asm.R0, 1).WithSymbol("bad"), asm.Return())
}
