package inject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

var equivFeatures = []string{
	"entry",
	"map-spill",
	"stack-pointer-spill",
	"map-argument",
	"spilled-map-argument",
	"callee-store",
	"global-stack-store",
	"read-only-inner-array",
	"inner-hash",
	"inner-queue",
	"stack-lookup-precise",
	"stack-xdp-load-precise",
	"stack-lookup-fallback",
	"stack-xdp-load-fallback",
}

var equivDefaultSeeds = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}

type equivOp struct {
	Map      int
	Kind     HookKind
	ReadOnly bool
	Pointer  string
	Indirect bool
	Guard    bool
	Salt     int32
}

type equivCase struct {
	Seed             uint64
	Feature          string
	Types            []ebpf.MapType
	Ops              []equivOp
	Floor            int16
	Regs             [4]asm.Register // ctx, accumulator, packet key, packet flags
	Tail             bool
	RequireTransform bool
	ExpectRefusal    bool
}

func newEquivCase(seed uint64) equivCase {
	feature := equivFeatures[(seed-1)%uint64(len(equivFeatures))]
	if feature != "entry" {
		return newEquivFeatureCase(seed, feature)
	}
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	kinds := []ebpf.MapType{ebpf.Hash, ebpf.Array, ebpf.PerCPUArray, ebpf.LRUHash, ebpf.Queue, ebpf.Stack, ebpf.BloomFilter}
	r.Shuffle(len(kinds), func(i, j int) { kinds[i], kinds[j] = kinds[j], kinds[i] })
	c := equivCase{Seed: seed, Feature: feature, Types: kinds[:2+r.IntN(3)], Regs: [4]asm.Register{asm.R6, asm.R7, asm.R8, asm.R9}, Tail: r.IntN(4) == 0}
	r.Shuffle(len(c.Regs), func(i, j int) { c.Regs[i], c.Regs[j] = c.Regs[j], c.Regs[i] })
	c.Floor = []int16{-64, -72, -128, -200, -400, -440, -448, -456, -464}[r.IntN(9)]
	if c.Tail {
		c.Floor = []int16{-64, -128, -192}[r.IntN(3)]
	}
	for n, count := 0, 4+r.IntN(9); n < count; n++ {
		m := r.IntN(len(c.Types))
		ops := []HookKind{HookLookup, HookUpdate, HookDelete}
		switch c.Types[m] {
		case ebpf.Queue, ebpf.Stack:
			ops = []HookKind{HookPush, HookPop, HookPeek}
		case ebpf.BloomFilter:
			ops = []HookKind{HookPush, HookPeek}
		}
		op := equivOp{Map: m, Kind: ops[r.IntN(len(ops))], Indirect: r.IntN(5) == 0, Guard: r.IntN(3) == 0, Salt: int32(r.IntN(6))}
		// Output buffers must be writable. Bloom peek is an input buffer.
		op.ReadOnly = r.IntN(4) == 0 && (op.Kind == HookUpdate || op.Kind == HookPush || op.Kind == HookDelete || op.Kind == HookLookup || c.Types[m] == ebpf.BloomFilter)
		if op.ReadOnly {
			op.Pointer = equivPointerShapes[r.IntN(len(equivPointerShapes))]
		}
		c.Ops = append(c.Ops, op)
	}
	return c
}

var equivPointerShapes = []string{"direct", "copy", "spill", "alias-spill", "join", "spill-join", "lookup", "lookup-spill", "offset"}

func (c equivCase) spec() *ebpf.CollectionSpec {
	if c.Feature != "entry" {
		return c.featureSpec()
	}
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	spec := &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian, Maps: map[string]*ebpf.MapSpec{}, Programs: map[string]*ebpf.ProgramSpec{}}
	for i, typ := range c.Types {
		name := fmt.Sprintf("m%d", i)
		m := &ebpf.MapSpec{Name: name, Type: typ, KeySize: 4, ValueSize: 8, MaxEntries: 8, Key: u32, Value: u64}
		if typ == ebpf.Queue || typ == ebpf.Stack || typ == ebpf.BloomFilter {
			m.KeySize, m.Key = 0, nil
			if typ == ebpf.BloomFilter {
				// Both filters must use the same hashes, including false positives.
				m.Flags = unix.BPF_F_ZERO_SEED
			}
		} else if typ != ebpf.PerCPUArray {
			m.Contents = []ebpf.MapKV{{Key: uint32(0), Value: uint64(0x11223344)}, {Key: uint32(1), Value: uint64(0x55667788)}}
		}
		spec.Maps[name] = m
	}
	spec.Maps["ro"] = &ebpf.MapSpec{Name: "ro", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1,
		Key: u32, Value: u64, Flags: unix.BPF_F_RDONLY_PROG, Contents: []ebpf.MapKV{{Key: uint32(0), Value: uint64(1)}}}
	ctx, acc, key, flags := c.Regs[0], c.Regs[1], c.Regs[2], c.Regs[3]
	var ins asm.Instructions
	emit := func(is ...asm.Instruction) { ins = append(ins, is...) }
	addr := func(reg asm.Register, off int16) { emit(asm.Mov.Reg(reg, asm.RFP), asm.Add.Imm(reg, int32(off))) }
	arg := func(reg asm.Register, off int16, ro bool) {
		if ro {
			emit(asm.LoadMem(reg, asm.RFP, -24, asm.DWord))
		} else {
			addr(reg, off)
		}
	}
	// Reload packet bounds after helpers instead of preserving a fifth register.
	packet := func() {
		emit(asm.LoadMem(asm.R1, ctx, 0, asm.Word), asm.LoadMem(asm.R2, ctx, 4, asm.Word),
			asm.Mov.Reg(asm.R3, asm.R1), asm.Add.Imm(asm.R3, 384), asm.JGT.Reg(asm.R3, asm.R2, "short"))
	}
	emit(asm.Mov.Reg(ctx, asm.R1))
	packet()
	emit(asm.LoadMem(key, asm.R1, 0, asm.Word), asm.LoadMem(flags, asm.R1, 4, asm.Word), asm.LoadMem(acc, asm.R1, 8, asm.DWord),
		asm.StoreMem(asm.RFP, -40, key, asm.DWord), asm.StoreMem(asm.RFP, -48, flags, asm.DWord),
		asm.StoreMem(asm.RFP, -56, acc, asm.DWord), asm.StoreMem(asm.RFP, c.Floor, acc, asm.DWord),
		asm.Mov.Imm(asm.R1, 0), asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord), asm.StoreMem(asm.RFP, -16, acc, asm.DWord))
	for i, op := range c.Ops {
		end, call := fmt.Sprintf("end%d", i), fmt.Sprintf("call%d", i)
		if op.Guard {
			emit(asm.JSet.Imm(key, 1<<uint(i%4), end))
		}
		emit(asm.Mov.Reg(asm.R1, key), asm.Add.Imm(asm.R1, op.Salt), asm.Mod.Imm(asm.R1, 6),
			asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord), asm.Mov.Reg(asm.R1, acc), asm.Xor.Reg(asm.R1, flags),
			asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord))
		if op.ReadOnly {
			if strings.HasPrefix(op.Pointer, "lookup") {
				emit(asm.StoreImm(asm.RFP, -32, 0, asm.Word))
				addr(asm.R2, -32)
				emit(asm.LoadMapPtr(asm.R1, 0).WithReference("ro"), asm.FnMapLookupElem.Call(),
					asm.JEq.Imm(asm.R0, 0, end), asm.Mov.Reg(asm.R5, asm.R0))
			} else {
				emit(asm.LoadMapValue(asm.R5, 0, 0).WithReference("ro"))
			}
			switch op.Pointer {
			case "copy":
				emit(asm.Mov.Reg(asm.R0, asm.R5), asm.Mov.Reg(asm.R4, asm.R0), asm.Mov.Reg(asm.R5, asm.R4))
			case "spill", "lookup-spill":
				emit(asm.StoreMem(asm.RFP, -24, asm.R5, asm.DWord), asm.LoadMem(asm.R5, asm.RFP, -24, asm.DWord))
			case "alias-spill":
				addr(asm.R0, -24)
				emit(asm.StoreMem(asm.R0, 0, asm.R5, asm.DWord), asm.LoadMem(asm.R5, asm.R0, 0, asm.DWord))
			case "join", "spill-join":
				join := fmt.Sprintf("join%d", i)
				if op.Pointer == "spill-join" {
					emit(asm.StoreMem(asm.RFP, -24, asm.R5, asm.DWord), asm.JSet.Imm(flags, 1, join))
					addr(asm.R5, -16)
					emit(asm.StoreMem(asm.RFP, -24, asm.R5, asm.DWord), asm.LoadMem(asm.R5, asm.RFP, -24, asm.DWord).WithSymbol(join))
				} else {
					emit(asm.JSet.Imm(flags, 1, join))
					addr(asm.R5, -16)
					emit(asm.Mov.Reg(asm.R5, asm.R5).WithSymbol(join))
				}
			case "offset":
				emit(asm.Add.Imm(asm.R5, 4), asm.Sub.Imm(asm.R5, 4))
			}
			emit(asm.StoreMem(asm.RFP, -24, asm.R5, asm.DWord))
		}
		arg(asm.R2, -16, op.ReadOnly)
		emit(asm.LoadMem(asm.R4, asm.R2, 0, asm.DWord))
		packet()
		emit(asm.StoreMem(asm.R1, int16(88+16*i), asm.R4, asm.DWord))
		fn := asm.FnMapLookupElem
		switch op.Kind {
		case HookLookup:
			arg(asm.R2, -8, op.ReadOnly)
			if c.Types[op.Map] == ebpf.PerCPUArray && i%2 == 0 {
				fn = asm.FnMapLookupPercpuElem
				emit(asm.Mov.Reg(asm.R3, flags))
			}
		case HookUpdate:
			fn = asm.FnMapUpdateElem
			arg(asm.R2, -8, op.ReadOnly)
			arg(asm.R3, -16, op.ReadOnly)
			emit(asm.Mov.Reg(asm.R4, flags))
		case HookDelete:
			fn = asm.FnMapDeleteElem
			arg(asm.R2, -8, op.ReadOnly)
		case HookPush:
			fn = asm.FnMapPushElem
			arg(asm.R2, -16, op.ReadOnly)
			emit(asm.Mov.Reg(asm.R3, flags))
		case HookPop, HookPeek:
			fn = asm.FnMapPopElem
			if op.Kind == HookPeek {
				fn = asm.FnMapPeekElem
			}
			arg(asm.R2, -16, op.ReadOnly)
		}
		emit(asm.LoadMapPtr(asm.R1, 0).WithReference(fmt.Sprintf("m%d", op.Map)))
		if op.Indirect {
			emit(asm.JEq.Imm(flags, 0, call), asm.Mov.Reg(asm.R1, asm.R1))
		}
		emit(fn.Call().WithSymbol(call))
		if op.Kind == HookLookup {
			emit(asm.JEq.Imm(asm.R0, 0, "miss"+call), asm.LoadMem(asm.R0, asm.R0, 0, asm.DWord), asm.Ja.Label("fold"+call),
				asm.Mov.Imm(asm.R0, -123).WithSymbol("miss"+call))
		}
		emit(asm.Xor.Reg(acc, asm.R0).WithSymbol("fold"+call), asm.Mul.Imm(acc, 33),
			asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord), asm.Add.Reg(acc, asm.R1))
		packet()
		emit(asm.StoreMem(asm.R1, int16(80+16*i), acc, asm.DWord), asm.Mov.Reg(acc, acc).WithSymbol(end))
	}
	for i, typ := range c.Types {
		if typ == ebpf.Queue || typ == ebpf.Stack || typ == ebpf.BloomFilter {
			continue
		}
		label := fmt.Sprintf("read%d", i)
		addr(asm.R2, -8)
		emit(asm.LoadMapPtr(asm.R1, 0).WithReference(fmt.Sprintf("m%d", i)), asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, label), asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord), asm.Xor.Reg(acc, asm.R1),
			asm.Mov.Reg(acc, acc).WithSymbol(label))
	}
	emit(asm.Mov.Imm(asm.R1, 0), asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord))
	addr(asm.R2, -8)
	emit(asm.LoadMapPtr(asm.R1, 0).WithReference("ro"), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "ro_done"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord), asm.Xor.Reg(acc, asm.R1), asm.Mov.Reg(acc, acc).WithSymbol("ro_done"))
	packet()
	emit(asm.StoreMem(asm.R1, 16, acc, asm.DWord), asm.StoreMem(asm.R1, 24, key, asm.DWord), asm.StoreMem(asm.R1, 32, flags, asm.DWord))
	for i, off := range []int16{-40, -48, -56, c.Floor} {
		emit(asm.LoadMem(asm.R2, asm.RFP, off, asm.DWord), asm.StoreMem(asm.R1, int16(40+8*i), asm.R2, asm.DWord), asm.Xor.Reg(acc, asm.R2))
	}
	if c.Tail {
		emit(asm.Mov.Reg(asm.R1, ctx), asm.LoadMapPtr(asm.R2, 0).WithReference("jmp"), asm.Mov.Reg(asm.R3, flags), asm.FnTailCall.Call())
		spec.Maps["jmp"] = &ebpf.MapSpec{Name: "jmp", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 2}
		spec.Programs["target"] = tailTargetFixture().Programs["target"]
	}
	emit(asm.Mov.Reg(asm.R0, acc), asm.And.Imm(asm.R0, 3), asm.Add.Imm(asm.R0, 1), asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("short"), asm.Return())
	ins[0] = btf.WithFuncMetadata(ins[0].WithSymbol("p").WithSource(asm.Comment("generated equivalence fixture")), xdpFunc("p"))
	ins = equivResolveBranches(ins)
	spec.Programs["p"] = &ebpf.ProgramSpec{Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: ins}
	return spec
}

func (c equivCase) packets(cpus int) [][]byte {
	if c.Feature != "entry" {
		return c.featurePackets()
	}
	r := rand.New(rand.NewPCG(c.Seed, 0x7061636b657473))
	var packets [][]byte
	// Repeated flags fill and drain queues and cover high bits and invalid CPUs.
	for _, flags := range []uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 3, 4, 0x80000000, uint32(cpus), 0} {
		packet := make([]byte, 384)
		for i := range packet {
			packet[i] = byte(r.Uint32())
		}
		binary.LittleEndian.PutUint32(packet, r.Uint32()%6)
		binary.LittleEndian.PutUint32(packet[4:], flags)
		packets = append(packets, packet)
	}
	return packets
}

func newEquivFeatureCase(seed uint64, feature string) equivCase {
	c := equivCase{Seed: seed, Feature: feature, Floor: -32, RequireTransform: true}
	if feature == "stack-lookup-precise" || feature == "stack-xdp-load-precise" ||
		feature == "stack-lookup-fallback" || feature == "stack-xdp-load-fallback" {
		c.Floor = -248
	}
	if feature == "stack-lookup-fallback" || feature == "stack-xdp-load-fallback" {
		c.RequireTransform, c.ExpectRefusal = false, true
	}
	return c
}

func (c equivCase) featureSpec() *ebpf.CollectionSpec {
	switch c.Feature {
	case "map-spill", "stack-pointer-spill", "map-argument", "spilled-map-argument", "callee-store", "global-stack-store":
		return c.readOnlyFeatureSpec()
	case "read-only-inner-array", "inner-hash", "inner-queue":
		return c.innerMapFeatureSpec()
	case "stack-lookup-precise", "stack-xdp-load-precise", "stack-lookup-fallback", "stack-xdp-load-fallback":
		return c.stackFeatureSpec()
	default:
		panic("unknown equivalence feature: " + c.Feature)
	}
}

func (c equivCase) featurePackets() [][]byte {
	r := rand.New(rand.NewPCG(c.Seed, 0x6665617475726573))
	makePacket := func() []byte {
		packet := make([]byte, 64)
		for i := range packet {
			packet[i] = byte(r.Uint32())
		}
		return packet
	}
	if c.Feature == "inner-queue" {
		var packets [][]byte
		for _, step := range [][2]uint32{{11, 0}, {22, 0}, {33, 1}, {0, 2}} {
			packet := makePacket()
			binary.LittleEndian.PutUint32(packet, step[0])
			binary.LittleEndian.PutUint32(packet[4:], step[1])
			packets = append(packets, packet)
		}
		return packets
	}
	var packets [][]byte
	for i := uint32(0); i < 4; i++ {
		packet := makePacket()
		binary.LittleEndian.PutUint32(packet, i%3)
		packets = append(packets, packet)
	}
	return packets
}

func (c equivCase) readOnlyFeatureSpec() *ebpf.CollectionSpec {
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	maps := map[string]*ebpf.MapSpec{
		"ro": {Name: "ro", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG,
			Key: u32, Value: u64, Contents: []ebpf.MapKV{{Key: uint32(0), Value: uint64(42)}}},
		"q": {Name: "q", Type: ebpf.Queue, ValueSize: 8, MaxEntries: 8, Value: u64},
	}
	push := func() asm.Instructions {
		return asm.Instructions{
			asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
			asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
		}
	}
	var ins asm.Instructions
	switch c.Feature {
	case "map-spill":
		ins = asm.Instructions{
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, 0).WithReference("ro"),
			asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord), asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "done"), asm.Mov.Reg(asm.R2, asm.R0),
		}
		ins = append(ins, push()...)
	case "stack-pointer-spill":
		ins = asm.Instructions{
			asm.LoadMapValue(asm.R6, 0, 0).WithReference("ro"), asm.StoreMem(asm.RFP, -8, asm.R6, asm.DWord),
			asm.Mov.Reg(asm.R7, asm.RFP), asm.StoreMem(asm.RFP, -16, asm.R7, asm.DWord),
			asm.LoadMem(asm.R7, asm.RFP, -16, asm.DWord), asm.LoadMem(asm.R2, asm.R7, -8, asm.DWord),
		}
		ins = append(ins, push()...)
	case "map-argument", "spilled-map-argument":
		ins = asm.Instructions{
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, 0).WithReference("ro"),
		}
		if c.Feature == "spilled-map-argument" {
			ins = append(ins, asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord), asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord))
		}
		ins = append(ins,
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.Call.Label("source"),
			asm.JEq.Imm(asm.R0, 0, "done"), asm.Mov.Reg(asm.R2, asm.R0))
		ins = append(ins, push()...)
		ins = append(ins,
			btf.WithFuncMetadata(asm.FnMapLookupElem.Call().WithSymbol("source").WithSource(asm.Comment("read-only map source")), staticFunc("source")),
			asm.Return())
	case "callee-store":
		ins = asm.Instructions{
			asm.LoadMapValue(asm.R2, 0, 0).WithReference("ro"),
			asm.Mov.Reg(asm.R1, asm.RFP), asm.StoreMem(asm.RFP, -24, asm.R1, asm.DWord),
			asm.LoadMem(asm.R1, asm.RFP, -24, asm.DWord), asm.Add.Imm(asm.R1, -16), asm.Call.Label("sink"),
			asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord),
		}
		ins = append(ins, push()...)
		ins = append(ins,
			btf.WithFuncMetadata(asm.StoreMem(asm.R1, 0, asm.R2, asm.DWord).WithSymbol("sink").WithSource(asm.Comment("read-only pointer sink")), equivStoreFunc("sink")),
			asm.Mov.Imm(asm.R0, 0), asm.Return())
	case "global-stack-store":
		ins = asm.Instructions{
			asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Call.Label("sink"),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16),
			asm.LoadMapPtr(asm.R1, 0).WithReference("ro"), asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "done"), asm.Mov.Reg(asm.R2, asm.R0),
		}
		ins = append(ins, push()...)
		ins = append(ins,
			btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("sink").WithSource(asm.Comment("global stack sink")), equivStackStoreFunc("sink")),
			asm.JEq.Imm(asm.R1, 0, "sink_done"), asm.StoreMem(asm.R1, 0, asm.R0, asm.DWord), asm.Return().WithSymbol("sink_done"))
	}
	ins = equivResolveBranches(ins)
	ins[0] = btf.WithFuncMetadata(ins[0].WithSymbol("p").WithSource(asm.Comment("generated equivalence fixture")), xdpFunc("p"))
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian, Maps: maps,
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: ins}}}
}

func equivStoreFunc(name string) *btf.Func {
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	u64 := &btf.Int{Name: "u64", Size: 8}
	return &btf.Func{Name: name, Linkage: btf.StaticFunc, Type: &btf.FuncProto{Return: i32, Params: []btf.FuncParam{
		{Name: "dst", Type: &btf.Pointer{Target: u64}},
		{Name: "src", Type: &btf.Pointer{Target: &btf.Const{Type: u64}}},
	}}}
}

func equivStackStoreFunc(name string) *btf.Func {
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	u64 := &btf.Int{Name: "u64", Size: 8}
	return &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: i32,
		Params: []btf.FuncParam{{Name: "dst", Type: &btf.Pointer{Target: u64}}}}}
}

func (c equivCase) innerMapFeatureSpec() *ebpf.CollectionSpec {
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	inner := &ebpf.MapSpec{Name: "inner", KeySize: 4, ValueSize: 8, MaxEntries: 8, Key: u32, Value: u64}
	maps := map[string]*ebpf.MapSpec{}
	var ins asm.Instructions
	switch c.Feature {
	case "read-only-inner-array":
		inner.Type, inner.MaxEntries, inner.Flags = ebpf.Array, 1, unix.BPF_F_RDONLY_PROG
		maps["q"] = &ebpf.MapSpec{Name: "q", Type: ebpf.Queue, ValueSize: 8, MaxEntries: 8, Value: u64}
		ins = asm.Instructions{
			asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
			asm.LoadMapPtr(asm.R1, 0).WithReference("outer"), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "done"),
			asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "done"), asm.Mov.Reg(asm.R2, asm.R0),
			asm.LoadMapPtr(asm.R1, 0).WithReference("q"), asm.Mov.Imm(asm.R3, 0), asm.FnMapPushElem.Call(),
			asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
		}
	case "inner-hash":
		inner.Type = ebpf.Hash
		ins = asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.LoadMem(asm.R4, asm.R1, 4, asm.Word),
			asm.Mov.Reg(asm.R3, asm.R2), asm.Add.Imm(asm.R3, 4), asm.JGT.Reg(asm.R3, asm.R4, "miss"),
			asm.LoadMem(asm.R5, asm.R2, 0, asm.Word), asm.StoreMem(asm.RFP, -4, asm.R5, asm.Word),
			asm.StoreImm(asm.RFP, -8, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
			asm.LoadMapPtr(asm.R1, 0).WithReference("outer"), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "miss"),
			asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "miss"), asm.LoadMem(asm.R0, asm.R0, 0, asm.DWord), asm.Return(),
			asm.Mov.Imm(asm.R0, 1).WithSymbol("miss"), asm.Return(),
		}
	case "inner-queue":
		inner.Type, inner.KeySize, inner.Key, inner.MaxEntries = ebpf.Queue, 0, nil, 2
		ins = equivInnerQueueInstructions()
	}
	maps["outer"] = &ebpf.MapSpec{Name: "outer", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: inner}
	ins = equivResolveBranches(ins)
	ins[0] = btf.WithFuncMetadata(ins[0].WithSymbol("p").WithSource(asm.Comment("generated map-in-map fixture")), xdpFunc("p"))
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian, Maps: maps,
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: ins}}}
}

func equivInnerQueueInstructions() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R2, asm.R6, 0, asm.Word), asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R2), asm.Add.Imm(asm.R4, 8), asm.JGT.Reg(asm.R4, asm.R3, "short"),
		asm.LoadMem(asm.R8, asm.R2, 0, asm.Word), asm.LoadMem(asm.R9, asm.R2, 4, asm.Word), asm.StoreMem(asm.RFP, -16, asm.R8, asm.DWord),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("outer"), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "short"),
		asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16), asm.JEq.Imm(asm.R9, 2, "pop"),
		asm.Mov.Reg(asm.R3, asm.R9), asm.LSh.Imm(asm.R3, 1), asm.FnMapPushElem.Call(), asm.Ja.Label("result"),
		asm.FnMapPopElem.Call().WithSymbol("pop"), asm.Mov.Imm(asm.R1, 2).WithSymbol("result"),
		asm.JSGE.Imm32(asm.R0, 0, "return"), asm.Mov.Imm(asm.R1, 1), asm.Mov.Reg(asm.R0, asm.R1).WithSymbol("return"), asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("short"), asm.Return(),
	}
}

func (c equivCase) stackFeatureSpec() *ebpf.CollectionSpec {
	u32, u64 := &btf.Int{Name: "u32", Size: 4}, &btf.Int{Name: "u64", Size: 8}
	ins := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("p").WithSource(asm.Comment("generated stack entry")), xdpFunc("p")),
		asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.RFP, -240, asm.R0, asm.DWord),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16),
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.Mov.Imm(asm.R4, 0), asm.FnMapUpdateElem.Call(),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Call.Label("leaf"), asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	xdpLoad := c.Feature == "stack-xdp-load-precise" || c.Feature == "stack-xdp-load-fallback"
	fallback := c.Feature == "stack-lookup-fallback" || c.Feature == "stack-xdp-load-fallback"
	if xdpLoad {
		leaf := asm.Instructions{
			btf.WithFuncMetadata(asm.Mov.Reg(asm.R3, asm.RFP).WithSymbol("leaf").WithSource(asm.Comment("stack alias leaf")), staticFunc("leaf")),
			asm.Add.Imm(asm.R3, -8),
		}
		if fallback {
			leaf = append(leaf, asm.StoreMem(asm.RFP, -16, asm.R3, asm.DWord), asm.LoadMem(asm.R3, asm.RFP, -16, asm.DWord))
		}
		leaf = append(leaf, asm.Mov.Imm(asm.R2, 0), asm.Mov.Imm(asm.R4, 1), asm.FnXdpLoadBytes.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return())
		ins = append(ins, leaf...)
	} else {
		leaf := asm.Instructions{
			btf.WithFuncMetadata(asm.StoreImm(asm.RFP, -8, 0, asm.Word).WithSymbol("leaf").WithSource(asm.Comment("stack alias leaf")), staticFunc("leaf")),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		}
		if fallback {
			leaf = append(leaf, asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord))
		}
		leaf = append(leaf, asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return())
		ins = append(ins, leaf...)
	}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps:     map[string]*ebpf.MapSpec{"sessions": {Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 8, Key: u32, Value: u64}},
		Programs: map[string]*ebpf.ProgramSpec{"p": {Name: "p", Type: ebpf.XDP, License: "GPL", Instructions: ins}}}
}

func equivResolveBranches(ins asm.Instructions) asm.Instructions {
	labels := map[string]asm.RawInstructionOffset{}
	it := ins.Iterate()
	for it.Next() {
		if symbol := it.Ins.Symbol(); symbol != "" {
			labels[symbol] = it.Offset
		}
	}
	it = ins.Iterate()
	for it.Next() {
		if !it.Ins.OpCode.Class().IsJump() || it.Ins.OpCode.JumpOp() == asm.Call || it.Ins.Reference() == "" {
			continue
		}
		target, ok := labels[it.Ins.Reference()]
		if !ok {
			panic("missing generator label: " + it.Ins.Reference())
		}
		it.Ins.Offset = int16(int(target) - int(it.Offset) - 1)
		*it.Ins = it.Ins.WithReference("")
	}
	return ins
}

func TestEquivGenerator(t *testing.T) {
	for seed := uint64(1); seed <= 64; seed++ {
		c := newEquivCase(seed)
		spec := c.spec()
		var buf bytes.Buffer
		if err := spec.Programs["p"].Instructions.Marshal(&buf, binary.LittleEndian); err != nil {
			t.Fatalf("seed=%d marshal: %v\n%v", seed, err, spec.Programs["p"].Instructions)
		}
		if _, err := transformLookup(c.spec(), c.request("static-any")); err != nil && !errors.Is(err, ErrRefused) {
			t.Fatalf("seed=%d transform: %v", seed, err)
		}
	}
}
