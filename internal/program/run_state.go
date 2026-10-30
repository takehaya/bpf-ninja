package program

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Run correlation associates hook observations with one root invocation.
// Both tracking modes share these frame offsets and sequence allocation.
// These offsets describe map values, separate from the 28-byte record header.
const (
	runDepth  = 0
	runPoison = 4
	runFrames = 16
	runSlots  = 8

	runOwner  = 0
	runID     = 8
	runTag    = 16
	runState  = 20
	runCtx    = 24
	runStride = 32
	runSize   = runFrames + runSlots*runStride

	runStateMask = 3
	runPending   = 0
	runTracked   = 1
	runBlocked   = 2
	runRejected  = 4

	runSeqCount     = 0
	runSeqExhausted = 8
	runSeqSize      = 16
	runSeqMax       = (1 << packetIDCPUShift) - 1
)

func runStateMapSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: "ninja_runs", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: runSize, MaxEntries: 1}
}

// runTableMapSpec preallocates entries so insertion does not allocate under BH.
func runTableMapSpec(possibleCPUs int) *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: "ninja_run_table", Type: ebpf.Hash, KeySize: 8, ValueSize: runStride, MaxEntries: uint32(max(1024, 64*possibleCPUs))}
}

// Run temporaries live only within one emitter. Never keep them across a
// filter, hook prologue or identity sequence. Kunai reuses these bytes during
// filter evaluation; they do not overlap any host capture temporaries.
const (
	runCPUStack    = -208 // u64 CPU bits; sequence allocator only
	runKeyStack    = -216 // u64 root ctx; locator operations only
	runLookupStack = -16  // u32 map key; existing shared lookup scratch
)

func runSequenceMapSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: "ninja_run_seq", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: runSeqSize, MaxEntries: 1}
}

// emitRunSequence returns cpu<<48 | sequence in R0. FetchAdd returns the old
// count, so nested observers cannot borrow the same sequence. Exhaustion is
// sticky and never wraps into CPU bits. Labels use prefix; bad is caller-owned.
// Clobbers R0-R5, bytes -208 through -201 and -16 through -13; preserves R6-R9.
// CPU must remain pinned between the CPU read and lookup; LIFO is not required.
// bad combines lookup failure, unsupported CPU and exhaustion; the sticky
// runSeqExhausted flag distinguishes exhaustion in a quiesced snapshot.
func emitRunSequence(fd int, prefix, bad string) asm.Instructions {
	ins := asm.Instructions{
		asm.FnGetSmpProcessorId.Call(),
		asm.JGT.Imm(asm.R0, 0xffff, bad),
		asm.LSh.Imm(asm.R0, packetIDCPUShift),
		asm.StoreMem(asm.R10, runCPUStack, asm.R0, asm.DWord),
	}
	ins = append(ins, emitRunLookup(fd, bad)...)
	return append(ins,
		asm.LoadMem(asm.R1, asm.R0, runSeqExhausted, asm.DWord),
		asm.JNE.Imm(asm.R1, 0, bad),
		asm.Mov.Imm(asm.R1, 1),
		fetchAdd64(asm.R0, asm.R1, runSeqCount),
		asm.LoadImm(asm.R2, runSeqMax, asm.DWord),
		asm.JLT.Reg(asm.R1, asm.R2, prefix+"_id"),
		asm.Mov.Imm(asm.R2, 1),
		asm.StoreMem(asm.R0, runSeqExhausted, asm.R2, asm.DWord),
		asm.Ja.Label(bad),
		asm.Add.Imm(asm.R1, 1).WithSymbol(prefix+"_id"),
		asm.LoadMem(asm.R0, asm.R10, runCPUStack, asm.DWord),
		asm.Or.Reg(asm.R0, asm.R1),
	)
}

// emitRunLookup returns map key 0's value in R0, or jumps to bad.
// Clobbers R0-R5 and stack bytes -16 through -13; preserves R6-R9.
func emitRunLookup(fd int, bad string) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.R10, runLookupStack, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, fd),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, runLookupStack),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, bad),
	}
}

// emitRunTop returns the current frame in R0, or jumps to bad for a failed
// lookup, empty stack, overflow or poison. It never borrows an outer frame.
// Callers move a found frame from R0 to R8 and re-find it after any filter
// or prologue that uses R8 for data_end.
// The caller owns depth changes, poison lifetime and diagnostic counters.
// Clobbers R0-R5 and stack bytes -16 through -13; preserves R6-R9.
func emitRunTop(fd int, bad string) asm.Instructions {
	ins := emitRunLookup(fd, bad)
	return append(ins,
		asm.LoadMem(asm.R1, asm.R0, runPoison, asm.Word),
		asm.JNE.Imm(asm.R1, 0, bad),
		asm.LoadMem(asm.R1, asm.R0, runDepth, asm.Word),
		asm.Sub.Imm(asm.R1, 1),
		asm.JGE.Imm(asm.R1, runSlots, bad),
		asm.Mul.Imm(asm.R1, runStride),
		asm.Add.Imm(asm.R1, runFrames),
		asm.Add.Reg(asm.R0, asm.R1),
	)
}

// emitRunIdentity checks root ctx identity, which survives packet head changes.
// The caller owns poisoning/counting on bad; never search for a matching parent.
// Clobbers R1; frame and ctx must be distinct from scratch R1.
func emitRunIdentity(frame, ctx asm.Register, bad string) asm.Instructions {
	if frame == asm.R1 || ctx == asm.R1 {
		panic("run identity inputs must not use scratch R1")
	}
	return asm.Instructions{
		asm.LoadMem(asm.R1, frame, runCtx, asm.DWord),
		asm.JNE.Reg(asm.R1, ctx, bad),
	}
}

// emitRunCounter atomically increments a diagnostic counter at R0+offset.
// Clobbers R1; preserves R0 and R2-R9.
func emitRunCounter(offset int16) asm.Instructions {
	add := asm.StoreXAdd(asm.R0, asm.R1, asm.DWord)
	add.Offset = offset
	return asm.Instructions{asm.Mov.Imm(asm.R1, 1), add}
}

func fetchAdd64(dst, src asm.Register, offset int16) asm.Instruction {
	ins := asm.FetchAdd.Mem(dst, src, asm.DWord, offset)
	// cilium/ebpf v0.22.0 Marshal caches Constant before extracting AtomicOp.
	// Set the wire immediate too, otherwise FetchAdd is encoded as plain XADD.
	// FetchAnd/Or/Xor, Xchg and CmpXchg have the same issue; StoreXAdd does not.
	// Remove this assignment after upgrading to a Marshal that encodes the
	// extracted atomic immediate, with TestRunInstructions still passing.
	// https://github.com/cilium/ebpf/blob/v0.22.0/asm/instruction.go#L150-L210
	ins.Constant = int64(asm.FetchAdd >> 8)
	return ins
}

// runResidual describes a quiesced snapshot, not a recovery heuristic. Reading
// it during capture cannot establish that a run has finished. Tag 0 is valid.
// Depths above runSlots only report overflow in Depth; inspect stored frames
// up to runSlots. Tracked frames require an ID; pending and blocked require 0.
type runResidual struct {
	Depth, Tracked, Blocked, Invalid uint32
	Poisoned                         bool
}

func inspectRunState(raw []byte) (runResidual, error) {
	var out runResidual
	if len(raw) != runSize {
		return out, fmt.Errorf("run state has %d bytes, want %d", len(raw), runSize)
	}
	out.Depth = binary.NativeEndian.Uint32(raw[runDepth:])
	out.Poisoned = binary.NativeEndian.Uint32(raw[runPoison:]) != 0
	for i := uint32(0); i < min(out.Depth, runSlots); i++ {
		frame := raw[runFrames+int(i)*runStride:]
		state := binary.NativeEndian.Uint32(frame[runState:]) & runStateMask
		id := binary.NativeEndian.Uint64(frame[runID:])
		if state == runBlocked && id == 0 {
			out.Blocked++
		} else if state == runTracked && id != 0 {
			out.Tracked++
		} else if state == runStateMask || (state == runTracked) != (id != 0) {
			out.Invalid++
		}
	}
	return out, nil
}

// inspectRunTable reports each residual hash entry using the shared frame ABI.
// The caller takes the snapshot only after the in-flight run barrier.
func inspectRunTable(entries [][]byte) (runResidual, error) {
	var out runResidual
	for _, frame := range entries {
		if len(frame) != runStride {
			return out, fmt.Errorf("run frame has %d bytes, want %d", len(frame), runStride)
		}
		raw := make([]byte, runSize)
		binary.NativeEndian.PutUint32(raw[runDepth:], 1)
		copy(raw[runFrames:], frame)
		one, _ := inspectRunState(raw)
		out.Depth++
		out.Tracked += one.Tracked
		out.Blocked += one.Blocked
		out.Invalid += one.Invalid
	}
	return out, nil
}
