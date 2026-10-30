package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// HookCaptureOptions separates selecting records from start predicates.
// An absent start predicate must not be inferred from empty compiled code.
type HookCaptureOptions struct {
	Tracking     string
	EntryStart   bool
	Starts       map[string]string
	TableEntries uint32
}
type runCapture struct {
	admissionSets     []*setmap.Set
	observerBase      []uint64
	seqFD, statsFD    int
	mode, reason      string
	state, seq, stats *ebpf.Map
	locator           runLocator
}

const (
	runRunning  = 0
	runStopped  = 1
	runStarting = 2

	runArgsStack     = -48 // saved tracing arguments across locator helpers
	runPacketIDStack = -24 // run ID until ringbuf header emission
)

type hookPredicate struct {
	out   codegen.Output
	slots *pktSetSlots
	refs  []string
}

func LoadHookCapture(targets []attach.Target, expr string, filters []filter.TargetFilters, useDSL bool, sets []*setmap.Set, cfg HookCaptureOptions) (p *Probe, err error) {
	root, err := validateHookPoints(targets, []Stage{{}})
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Program.Close() }()
	if filters != nil && len(filters) != len(targets) {
		return nil, fmt.Errorf("hook filters length mismatch")
	}
	if cfg.Tracking == "" {
		cfg.Tracking = "auto"
	}
	major, minor, _, known := kernelVersion()
	mode, reason, err := selectRunTracking(cfg.Tracking, major, minor, known, kernelRT(), root.Type)
	if err != nil {
		return nil, err
	}
	p = &Probe{runs: &runCapture{mode: mode, reason: reason}}
	createdProbe := p
	defer func() {
		if err != nil {
			_ = createdProbe.Close()
		}
	}()
	p.EventsMap, p.InnerMaps, err = createShardedRingbuf("hook")
	if err != nil {
		return nil, err
	}
	p.maps = append(p.maps, p.EventsMap)
	p.maps = append(p.maps, p.InnerMaps...)
	if err = p.initExportStats(); err != nil {
		return nil, err
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	stateSpec := runStateMapSpec()
	if mode == "ctx" {
		stateSpec = runTableMapSpec(cpus)
		if cfg.TableEntries > 0 {
			stateSpec.MaxEntries = cfg.TableEntries
		}
	}
	for _, item := range []struct {
		dst  **ebpf.Map
		spec *ebpf.MapSpec
	}{{&p.runs.state, stateSpec}, {&p.runs.seq, runSequenceMapSpec()}, {&p.runs.stats, runStatsSpec()}, {&p.holdStop, &ebpf.MapSpec{Name: "ninja_run_stop", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}}} {
		*item.dst, err = ebpf.NewMap(item.spec)
		if err != nil {
			return nil, err
		}
		p.maps = append(p.maps, *item.dst)
	}
	err = startHookCapture(func(state uint32) error {
		return p.holdStop.Update(uint32(0), state, ebpf.UpdateAny)
	}, func() error {
		p.runs.seqFD, p.runs.statsFD = p.runs.seq.FD(), p.runs.stats.FD()
		p.runs.locator = perCPURuns{p.runs.state.FD(), p.runs.stats.FD()}
		if mode == "ctx" {
			p.runs.locator = ctxRuns{p.runs.state.FD(), p.runs.stats.FD()}
		}
		gateFD, err := p.initTagBarrier()
		if err != nil {
			return err
		}
		h, _ := hook.ByProgramType(root.Type)
		compile := func(expr string) (hookPredicate, error) {
			var c hookPredicate
			if len(sets) > 0 {
				c.slots = newPktSetSlots(sets)
			}
			c.out, err = compileFilterWithSlots(expr, useDSL, false, root.Type, c.slots)
			if err != nil {
				return c, err
			}
			if c.slots != nil && c.slots.allocErr() != nil {
				return c, c.slots.allocErr()
			}
			c.refs = referencedSets(c.out.Extractions)
			if SnaplenOverride > 0 {
				c.out.Capture.MaxCapLen = SnaplenOverride
			}
			p.Warnings = append(p.Warnings, c.out.Warnings...)
			return c, nil
		}
		entry, err := compile(expr)
		if err != nil {
			return err
		}
		starts := make([]hookPredicate, len(targets))
		selected := map[string]bool{}
		for i, t := range targets {
			selected[t.FuncName] = true
			hookExpr := expr
			if x, ok := cfg.Starts[t.FuncName]; ok {
				if x == "" {
					return fmt.Errorf("empty start predicate for %s", t.FuncName)
				}
				hookExpr = x
			}
			starts[i], err = compile(hookExpr)
			if err != nil {
				return err
			}
		}
		for name := range cfg.Starts {
			if !selected[name] {
				return fmt.Errorf("start hook %q is not selected", name)
			}
		}
		used := map[string]bool{}
		if cfg.EntryStart || expr != "" {
			for _, name := range entry.refs {
				used[name] = true
			}
		}
		for i, target := range targets {
			if _, ok := cfg.Starts[target.FuncName]; ok {
				for _, name := range starts[i].refs {
					used[name] = true
				}
			}
		}
		for _, set := range sets {
			if used[set.Name] {
				p.runs.admissionSets = append(p.runs.admissionSets, set)
			}
		}
		scratch, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ninja_run_sc", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: scratchBufSize, MaxEntries: 1})
		if err != nil {
			return err
		}
		p.maps = append(p.maps, scratch)
		p.extensionGuard, err = attach.NewExtensionGuard()
		if err != nil {
			return err
		}
		// Exit exists before entry; stop remains set until all observers exist.
		exit := buildRunExit(p.runs, p.holdStop.FD())
		if err = attachTracingProbe(p, root.Program, "ninja_run_exit", root.FuncName, ebpf.AttachTraceFExit, exit, false, root.FuncAvailability(root.FuncName)); err != nil {
			return err
		}
		for i, t := range targets {
			selectedHook := h
			if h.Kind == hook.KindXDP {
				spec, e := p.extensionGuard.Spec(t.Program)
				if e != nil {
					return e
				}
				var fn *btf.Func
				if e = spec.TypeByName(t.FuncName, &fn); e != nil {
					return e
				}
				if fn.Linkage == btf.StaticFunc {
					fallback, e := staticXDPNeedsProbeRead(t.Program, t.FuncName, ebpf.AttachTraceFEntry, t.Availability)
					if e != nil {
						return e
					}
					if fallback {
						selectedHook = staticXDPHook(h, false)
					}
				}
			}
			tf := filter.TargetFilters{}
			if filters != nil {
				tf = filters[i]
			}
			_, hasStart := cfg.Starts[t.FuncName]
			ins, e := buildRunHook(selectedHook, starts[i], tf, p.runs, p.EventsMap.FD(), scratch.FD(), p.StatsMap.FD(), gateFD, p.holdStop.FD(), uint8(i+1), hasStart)
			if e != nil {
				return e
			}
			if err = attachTracingProbe(p, t.Program, "ninja_run_hook", t.FuncName, ebpf.AttachTraceFEntry, ins, t.AllowDispatcherSlot, t.Availability); err != nil {
				return err
			}
		}
		ins, err := buildRunEntry(h, entry, p.runs, scratch.FD(), gateFD, p.holdStop.FD(), cfg.EntryStart || expr != "" || len(cfg.Starts) == 0)
		if err != nil {
			return err
		}
		if err = attachTracingProbe(p, root.Program, "ninja_run_entry", root.FuncName, ebpf.AttachTraceFEntry, ins, false, root.FuncAvailability(root.FuncName)); err != nil {
			return err
		}
		return nil
	}, p.Barrier, func() error {
		if _, err = p.ObserverMisses(); err != nil {
			return err
		}
		p.runs.observerBase = make([]uint64, len(p.progs))
		for i, prog := range p.progs {
			stats, e := prog.Stats()
			if e != nil {
				return e
			}
			p.runs.observerBase[i] = stats.RecursionMisses
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// startHookCapture keeps admission closed until attached startup runs drain
// and recursion-miss baselines have been sampled.
func startHookCapture(stop func(uint32) error, attach, barrier, baseline func() error) error {
	if err := stop(runStarting); err != nil {
		return err
	}
	for _, step := range []func() error{attach, barrier, baseline} {
		if err := step(); err != nil {
			return err
		}
	}
	return stop(runRunning)
}

func runStopCheck(stopFD int, stopped string) asm.Instructions {
	ins := emitRunLookup(stopFD, "exit")
	return append(ins,
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.JNE.Imm(asm.R1, 0, stopped))
}
func runFind(r *runCapture, bad, mismatch string) asm.Instructions {
	return r.locator.find(bad, mismatch)
}
func runMismatchTail(r *runCapture, stopFD int, next string) asm.Instructions {
	if r.mode == "ctx" {
		return nil
	}
	ins := asm.Instructions{asm.Mov.Imm(asm.R0, 0).WithSymbol("mismatch")}
	// A nested invocation that entered after stop has no frame of its own.
	// Do not poison or pop its still-finishing parent's frame.
	ins = append(ins, emitRunLookup(stopFD, "exit")...)
	ins = append(ins, asm.LoadMem(asm.R1, asm.R0, 0, asm.Word), asm.JEq.Imm(asm.R1, runStopped, "exit"))
	ins = append(ins, emitRunStat(r.statsFD, runMismatch)...)
	if l, ok := r.locator.(perCPURuns); ok {
		ins = append(ins, l.poison()...)
	}
	return append(ins,
		asm.Ja.Label(next))
}

// Only admission checks the tombstone. Already tracked runs finish with their
// inherited tag even when userspace has blocked new starts for that tag.
func runStart(r *runCapture, gateFD int) asm.Instructions {
	ins := emitTagBarrierPolicy(gateFD, "start_denied")
	ins = append(ins, runFind(r, "untracked", "mismatch")...)
	ins = append(ins, emitRunSequence(r.seqFD, "start", "seq_failed")...)
	ins = append(ins,
		asm.StoreMem(asm.R8, runID, asm.R0, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, tagSlot, asm.DWord),
		asm.StoreMem(asm.R8, runTag, asm.R1, asm.Word),
		asm.Mov.Imm(asm.R1, runTracked),
		asm.StoreMem(asm.R8, runState, asm.R1, asm.Word),
		asm.Ja.Label("started"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("seq_failed"))
	ins = append(ins, emitRunStat(r.statsFD, runSequenceExhausted)...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("start_denied"))
	ins = append(ins, runFind(r, "exit", "mismatch")...)
	ins = append(ins,
		asm.Mov.Imm(asm.R1, runBlocked|runRejected),
		asm.StoreMem(asm.R8, runState, asm.R1, asm.Word),
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("started"))
	return ins
}
func buildRunEntry(h *hook.Hook, c hookPredicate, r *runCapture, scratchFD, gateFD, stopFD int, start bool) (asm.Instructions, error) {
	ins := asm.Instructions{asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
		asm.StoreMem(asm.R10, runArgsStack, asm.R1, asm.DWord)}
	ins = append(ins, emitRunLookup(stopFD, "exit")...)
	ins = append(ins,
		asm.LoadMem(asm.R9, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R9, runStopped, "exit"),
	)
	ins = append(ins, r.locator.create()...)
	ins = append(ins, asm.JNE.Imm(asm.R9, 0, "pre_tracking"))
	if start {
		ins = append(ins,
			asm.LoadMem(asm.R1, asm.R10, runArgsStack, asm.DWord))
		gate, err := h.PacketPrologue()
		if err != nil {
			return nil, err
		}
		body, err := buildFilterBodyPolicy(h, c.out, filter.TargetFilters{}, scratchFD, c.slots, c.refs, "start_denied", "predicate_failed")
		if err != nil {
			return nil, err
		}
		gate = append(gate, body...)
		ins = append(ins, gate...)
		ins = append(ins, runStart(r, gateFD)...)
	}
	if start {
		ins = append(ins,
			asm.Ja.Label("exit"))
		ins = append(ins, runMismatchTail(r, stopFD, "exit")...)
		ins = append(ins,
			asm.Mov.Imm(asm.R0, 0).WithSymbol("untracked"))
		ins = append(ins, emitRunStat(r.statsFD, runLookupFailed)...)
	}
	ins = append(ins,
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R1, runBlocked|runRejected).WithSymbol("pre_tracking"),
		asm.StoreMem(asm.R8, runState, asm.R1, asm.Word),
	)
	ins = append(ins, emitRunStat(r.statsFD, runPreTracking)...)
	ins = append(ins, asm.Ja.Label("exit"))
	ins = appendRunReadFailure(ins, r)
	return finishProgram(ins, c.out, 0), nil
}
func buildRunExit(r *runCapture, stopFD int) asm.Instructions {
	ins := asm.Instructions{asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord)}
	ins = append(ins, runFind(r, "untracked", "mismatch")...)
	ins = append(ins,
		asm.Ja.Label("release"))
	ins = append(ins, runMismatchTail(r, stopFD, "release")...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("untracked"))
	ins = append(ins, emitRunLookup(stopFD, "exit")...)
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R1, runStarting, "pre_tracking"),
		asm.JNE.Imm(asm.R1, 0, "exit"),
	)
	ins = append(ins, emitRunStat(r.statsFD, runExitWithoutEntry)...)
	if r.mode == "ctx" {
		ins = append(ins,
			asm.Ja.Label("exit"))
	}
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("release"))
	ins = append(ins, r.locator.release()...)
	ins = append(ins, asm.Ja.Label("exit"), asm.Mov.Imm(asm.R0, 0).WithSymbol("pre_tracking"))
	ins = append(ins, emitRunStat(r.statsFD, runPreTracking)...)
	return finishProgram(ins, codegen.Output{}, 0)
}
func buildRunHook(h *hook.Hook, c hookPredicate, tf filter.TargetFilters, r *runCapture, eventsFD, scratchFD, statsFD, gateFD, stopFD int, site uint8, start bool) (asm.Instructions, error) {
	ins, err := h.PacketPrologue()
	if err != nil {
		return nil, err
	}
	for i, op := range ins {
		if op.Reference() == "exit" {
			ins[i] = op.WithReference("hook_read_failed")
		}
	}
	ins = append(ins, buildArgFilter(tf.Args)...)
	ins = append(ins, emitSetFiltersPolicy(tf.Sets, "exit")...)
	ins = append(ins, runFind(r, "untracked", "mismatch")...)
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.R8, runState, asm.Word),
		asm.JSet.Imm(asm.R1, runRejected, "exit"),
		asm.And.Imm(asm.R1, runStateMask),
		asm.JEq.Imm(asm.R1, runTracked, "record"),
		asm.JEq.Imm(asm.R1, runBlocked, "blocked"))
	if start {
		body, err := buildFilterBodyPolicy(h, c.out, filter.TargetFilters{}, scratchFD, c.slots, c.refs, "start_denied", "predicate_failed")
		if err != nil {
			return nil, err
		}
		ins = append(ins, body...)
		ins = append(ins, runStart(r, gateFD)...)
	} else {
		ins = append(ins,
			asm.Ja.Label("exit"))
	}
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.R8, runTag, asm.Word).WithSymbol("record"),
		asm.StoreMem(asm.R10, tagSlot, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R8, runID, asm.DWord),
		asm.StoreMem(asm.R10, runPacketIDStack, asm.R1, asm.DWord))
	packetID := asm.Instructions{asm.LoadMem(asm.R1, asm.R10, runPacketIDStack, asm.DWord)}
	ins = append(ins, captureWithRingbufSite(eventsFD, statsFD, false, c.out.Capture.MaxCapLen, packetID, site)...)
	ins = append(ins,
		asm.Ja.Label("rb_submitted"))
	ins = append(ins, runMismatchTail(r, stopFD, "untracked")...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("untracked"))
	ins = append(ins, runStopCheck(stopFD, "exit")...)
	ins = append(ins, emitRunStat(r.statsFD, runUntrackedHook)...)
	ins = append(ins,
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("blocked"))
	ins = append(ins, emitRunStat(r.statsFD, runBlockedHook)...)
	ins = append(ins,
		asm.Ja.Label("exit"))
	ins = append(ins, emitExportTerminals(statsFD)...)
	for _, op := range ins {
		if op.Reference() == "hook_read_failed" {
			ins = append(ins,
				asm.Mov.Imm(asm.R0, 0).WithSymbol("hook_read_failed"))
			ins = append(ins, emitRunStat(r.statsFD, runReadFailed)...)
			ins = append(ins,
				asm.Ja.Label("exit"))
			break
		}
	}
	ins = appendRunReadFailure(ins, r)
	if !start {
		c.out.Callbacks = nil
	}
	return finishProgram(ins, c.out, 0), nil
}

func appendRunReadFailure(ins asm.Instructions, r *runCapture) asm.Instructions {
	for _, in := range ins {
		if in.Reference() == "predicate_failed" {
			ins = append(ins,
				asm.Mov.Imm(asm.R0, 0).WithSymbol("predicate_failed"))
			ins = append(ins, emitRunStat(r.statsFD, runReadFailed)...)
			return append(ins,
				asm.Ja.Label("start_denied"))
		}
	}
	return ins
}

// AdmissionSets are the sets referenced by start predicates, which alone
// define the tags participating in per-tag limits and finalization.
func (p *Probe) AdmissionSets() []*setmap.Set {
	if p.runs == nil {
		return nil
	}
	return p.runs.admissionSets
}
