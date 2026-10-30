package program

import (
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// Locators consume root ctx in R6 and return a frame in R8. R7/R9 are
// preserved for packet emission; R0-R5 and the named run stack slots are scratch.
// Each locator method is emitted at most once per observer program.
// No pointer survives filter evaluation: find again once its scratch is dead.
type runLocator interface {
	create() asm.Instructions
	find(bad, mismatch string) asm.Instructions
	release() asm.Instructions
}

type perCPURuns struct{ fd, stats int }
type ctxRuns struct{ fd, stats int }

func runKey() asm.Instructions {
	return asm.Instructions{asm.StoreMem(asm.R10, runKeyStack, asm.R6, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, runKeyStack)}
}
func (l ctxRuns) lookup(bad string) asm.Instructions {
	ins := runKey()
	ins = append(ins,
		asm.LoadMapPtr(asm.R1, l.fd),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, bad))
	return ins
}
func (l ctxRuns) find(bad, _ string) asm.Instructions {
	return append(l.lookup(bad),
		asm.Mov.Reg(asm.R8, asm.R0))
}

// Stack space for the initial HASH value, dead before any filter/prologue.
const runFrameStack = -192 // 32 bytes, -192 through -161
func (l ctxRuns) create() asm.Instructions {
	ins := asm.Instructions{asm.Mov.Imm(asm.R1, 0)}
	for off := 0; off < runStride; off += 8 {
		ins = append(ins,
			asm.StoreMem(asm.R10, runFrameStack+int16(off), asm.R1, asm.DWord))
	}
	ins = append(ins,
		asm.StoreMem(asm.R10, runFrameStack+runCtx, asm.R6, asm.DWord),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.R10, runFrameStack+runOwner, asm.R0, asm.DWord))
	ins = append(ins, runKey()...)
	ins = append(ins,
		asm.LoadMapPtr(asm.R1, l.fd),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, runFrameStack),
		asm.Mov.Imm(asm.R4, 1),
		asm.FnMapUpdateElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "created"),
		// Helper errno is signed in the low 32 bits.
		asm.JNE.Imm32(asm.R0, -int32(unix.EEXIST), "insert_failed"))
	ins = append(ins, l.lookup("insert_failed")...)
	ins = append(ins,
		asm.Mov.Imm(asm.R1, runBlocked),
		asm.StoreMem(asm.R0, runState, asm.R1, asm.Word),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.R0, runID, asm.R1, asm.DWord))
	ins = append(ins, emitRunStat(l.stats, runCollision)...)
	ins = append(ins,
		asm.Ja.Label("exit"))
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("insert_failed"))
	ins = append(ins, emitRunStat(l.stats, runInsertFailed)...)
	ins = append(ins, l.lookup("exit")...)
	ins = append(ins,
		asm.Mov.Imm(asm.R1, runBlocked),
		asm.StoreMem(asm.R0, runState, asm.R1, asm.Word),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.R0, runID, asm.R1, asm.DWord),
	)
	ins = append(ins,
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("created"))
	// HASH update copies the value; fetch a map-value pointer for the caller.
	return append(ins, l.find("exit", "exit")...)
}
func (l ctxRuns) release() asm.Instructions {
	ins := asm.Instructions{asm.LoadMem(asm.R1, asm.R8, runState, asm.Word),
		asm.JSet.Imm(asm.R1, runRejected, "delete"),
		asm.And.Imm(asm.R1, runStateMask),
		asm.JNE.Imm(asm.R1, runBlocked, "delete")}
	ins = append(ins, emitRunStat(l.stats, runStaleReclaimed)...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("delete"))
	ins = append(ins, runKey()...)
	ins = append(ins,
		asm.LoadMapPtr(asm.R1, l.fd),
		asm.FnMapDeleteElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"))
	return append(ins, emitRunStat(l.stats, runLookupFailed)...)
}
func (l perCPURuns) create() asm.Instructions {
	ins := emitRunLookup(l.fd, "exit")
	// Store the increment even on overflow so exits can balance every entry.
	ins = append(ins,
		asm.LoadMem(asm.R2, asm.R0, runDepth, asm.Word),
		asm.Mov.Reg(asm.R3, asm.R2),
		asm.Add.Imm(asm.R3, 1),
		asm.StoreMem(asm.R0, runDepth, asm.R3, asm.Word),
		asm.JGE.Imm(asm.R2, runSlots, "overflow"),
		asm.Mul.Imm(asm.R2, runStride),
		asm.Add.Imm(asm.R2, runFrames),
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.Add.Reg(asm.R8, asm.R2),
		asm.Mov.Imm(asm.R1, 0))
	for _, off := range []int16{runOwner, runID, runTag} {
		ins = append(ins,
			asm.StoreMem(asm.R8, off, asm.R1, asm.DWord))
	}
	ins = append(ins,
		asm.StoreMem(asm.R8, runCtx, asm.R6, asm.DWord),
		asm.LoadMem(asm.R1, asm.R0, runPoison, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "unpoisoned_entry"),
		asm.Mov.Imm(asm.R1, runBlocked),
		asm.StoreMem(asm.R8, runState, asm.R1, asm.Word),
		asm.Ja.Label("exit"),
		asm.FnGetCurrentPidTgid.Call().WithSymbol("unpoisoned_entry"),
		asm.StoreMem(asm.R8, runOwner, asm.R0, asm.DWord),
		asm.Ja.Label("created"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("overflow"))
	ins = append(ins, emitRunStat(l.stats, runOverflow)...)
	return append(ins,
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("created"))
}
func (l perCPURuns) find(bad, mismatch string) asm.Instructions {
	ins := emitRunTop(l.fd, bad)
	ins = append(ins,
		asm.Mov.Reg(asm.R8, asm.R0))
	return append(ins, emitRunIdentity(asm.R8,
		asm.R6, mismatch)...)
}
func (l perCPURuns) release() asm.Instructions {
	ins := emitRunLookup(l.fd, "exit")
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.R0, runDepth, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "exit"),
		asm.Sub.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, runDepth, asm.R1, asm.Word),
		asm.JNE.Imm(asm.R1, 0, "exit"),
		asm.StoreMem(asm.R0, runPoison, asm.R1, asm.Word))
	return ins
}
func (l perCPURuns) poison() asm.Instructions {
	ins := emitRunLookup(l.fd, "exit")
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.R0, runPoison, asm.Word),
		asm.JNE.Imm(asm.R1, 0, "already_poisoned"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, runPoison, asm.R1, asm.Word))
	ins = append(ins, emitRunStat(l.stats, runPoisoned)...)
	return append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("already_poisoned"))
}
