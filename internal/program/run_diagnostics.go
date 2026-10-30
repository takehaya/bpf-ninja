package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	runMismatch = iota
	runPoisoned
	runBlockedHook
	runCollision
	runInsertFailed
	runUntrackedHook
	runExitWithoutEntry
	runStaleReclaimed
	runOverflow
	runSequenceExhausted
	runLookupFailed
	runReadFailed
	runPreTracking
	runStatCount
)

var runStatNames = [runStatCount]string{"run_mismatch", "run_poisoned", "run_blocked_hook", "run_collision", "run_insert_failed", "run_untracked_hook", "run_exit_without_entry", "run_stale_reclaimed", "run_overflow", "run_sequence_exhausted", "run_lookup_failed", "run_read_failed", "run_pre_tracking"}

func emitRunStat(fd, index int) asm.Instructions {
	ins := asm.Instructions{asm.StoreImm(asm.R10, runLookupStack, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, fd),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, runLookupStack),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit")}
	return append(ins, emitRunCounter(int16(index*8))...)
}

// RunDiagnostics is a snapshot; residuals are meaningful only after Quiesce.
type RunDiagnostics struct {
	Counters                                          [runStatCount]uint64
	Residual                                          uint64
	ResidualTracked, ResidualBlocked, ResidualInvalid uint64
}

// Mismatches reports ctx identity failures in per-CPU mode.
func (d RunDiagnostics) Mismatches() uint64 { return d.Counters[runMismatch] }

func (d RunDiagnostics) Incomplete() bool {
	if d.Residual != 0 {
		return true
	}
	for i, v := range d.Counters {
		if i != runPreTracking && v != 0 {
			return true
		}
	}
	return false
}
func (d RunDiagnostics) String() string {
	s := fmt.Sprintf("run_residual=%d run_residual_tracked=%d run_residual_blocked=%d run_residual_invalid=%d", d.Residual, d.ResidualTracked, d.ResidualBlocked, d.ResidualInvalid)
	for i, v := range d.Counters {
		s += fmt.Sprintf(" %s=%d", runStatNames[i], v)
	}
	return s
}
func (p *Probe) RunDiagnostics(residual bool) (RunDiagnostics, error) {
	var d RunDiagnostics
	if p.runs == nil {
		return d, nil
	}
	var perCPU [][runStatCount]uint64
	if err := p.runs.stats.Lookup(uint32(0), &perCPU); err != nil {
		return d, err
	}
	for _, one := range perCPU {
		for i, v := range one {
			d.Counters[i] += v
		}
	}
	if !residual {
		return d, nil
	}
	if p.runs.mode == "ctx" {
		var key uint64
		var value [runStride]byte
		var entries [][]byte
		it := p.runs.state.Iterate()
		for it.Next(&key, &value) {
			entries = append(entries, append([]byte(nil), value[:]...))
		}
		if err := it.Err(); err != nil {
			return d, err
		}
		r, err := inspectRunTable(entries)
		d.Residual = uint64(r.Depth)
		d.ResidualTracked = uint64(r.Tracked)
		d.ResidualBlocked = uint64(r.Blocked)
		d.ResidualInvalid = uint64(r.Invalid)
		return d, err
	}
	var values [][]byte
	if err := p.runs.state.Lookup(uint32(0), &values); err != nil {
		return d, err
	}
	for _, raw := range values {
		r, err := inspectRunState(raw)
		if err != nil {
			return d, err
		}
		d.Residual += uint64(r.Depth)
		d.ResidualTracked += uint64(r.Tracked)
		d.ResidualBlocked += uint64(r.Blocked)
		d.ResidualInvalid += uint64(r.Invalid)
		if r.Poisoned && r.Depth == 0 {
			d.Residual++
		}
	}
	return d, nil
}
func (p *Probe) RunTracking() (string, string) {
	if p.runs == nil {
		return "", ""
	}
	return p.runs.mode, p.runs.reason
}
func runStatsSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: "ninja_run_stats", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: runStatCount * 8, MaxEntries: 1}
}
