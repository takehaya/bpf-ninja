// Package program — per-CPU sharded ringbuf helper.
//
// Shared by the XDP-native path (LoadXDPNative in program_xdp.go) and
// the tracing path (LoadEntry / LoadExit via loadProbe in program.go).
// One outer ARRAY_OF_MAPS of size numCPUs holds one inner RingBuf per
// CPU; the BPF prologue looks the inner up by bpf_get_smp_processor_id
// and reserves/submits on it. Same-CPU producer + same-CPU userspace
// reader (pinned in capture/) gives mutex-free shard ownership.
package program

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// createShardedRingbuf builds the outer ARRAY_OF_MAPS + per-CPU inner
// RingBuf pair used by every attach mode. label is a short prefix
// ("xdp", "entry", "exit") that shows up in the map name for bpftool
// readability.
//
// Total ringbuf capacity = RingbufSize MiB split evenly across CPUs,
// floored at 64 KiB per shard so we always have at least one page of
// data area on systems with > 1024 CPUs.
//
// On error the caller receives no half-built state: any inner created
// before the failure is closed before returning. Inner maps are
// created in parallel because each ebpf.NewMap is a syscall in the
// 100s-of-µs range; 64 CPUs serial takes ~tens of ms.
func createShardedRingbuf(label string) (outer *ebpf.Map, inners []*ebpf.Map, err error) {
	numCPUs := runtime.NumCPU()
	innerSize := max(RingbufSize/uint32(numCPUs), 65536)
	innerSpec := &ebpf.MapSpec{
		Name: fmt.Sprintf("ninja_%s_rb_in", label), Type: ebpf.RingBuf, MaxEntries: innerSize,
	}
	inners = make([]*ebpf.Map, numCPUs)
	innerErrs := make([]error, numCPUs)
	var wg sync.WaitGroup
	for i := range numCPUs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m, err := ebpf.NewMap(innerSpec)
			if err != nil {
				innerErrs[i] = err
				return
			}
			inners[i] = m
		}(i)
	}
	wg.Wait()

	success := false
	defer func() {
		if success {
			return
		}
		for _, m := range inners {
			if m != nil {
				_ = m.Close()
			}
		}
		if outer != nil {
			_ = outer.Close()
		}
	}()

	for i, ierr := range innerErrs {
		if ierr != nil {
			return nil, nil, fmt.Errorf("creating inner ringbuf %d: %w", i, ierr)
		}
	}

	outer, err = ebpf.NewMap(&ebpf.MapSpec{
		Name: fmt.Sprintf("ninja_%s_rb_outer", label), Type: ebpf.ArrayOfMaps,
		KeySize: 4, ValueSize: 4, MaxEntries: uint32(numCPUs), InnerMap: innerSpec,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating outer array_of_maps: %w", err)
	}
	for i, inner := range inners {
		if err := outer.Put(uint32(i), inner); err != nil {
			return nil, nil, fmt.Errorf("populating outer[%d]: %w", i, err)
		}
	}
	success = true
	return outer, inners, nil
}

// emitShardedRBReserve emits the BPF asm prologue that, for the
// caller's current CPU, looks up the inner RingBuf in the outer
// ARRAY_OF_MAPS and reserves a fixed-size record on it. Shared by
// captureWithRingbuf (fentry/fexit) and captureXDPNative.
//
// Pre-conditions on entry:
//
//	stack[-16] = u32 cpu_id (caller already stored it; the call to
//	             bpf_get_smp_processor_id lives in the caller because
//	             its placement vs the timestamp prologue differs per
//	             attach type)
//	eventsFD   = outer ARRAY_OF_MAPS file descriptor
//
// Post-conditions on success:
//
//	R0          = reservation pointer (also saved at stack[-32])
//	stack[-32]  = reservation pointer (consumed by the matching
//	              bpf_ringbuf_submit emitted by the caller)
//
// On either map_lookup or ringbuf_reserve returning NULL, jumps to
// the "exit" symbol the caller is responsible for emitting.
func emitShardedRBReserve(eventsFD int, reserveSize int32) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R1, eventsFD),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),

		asm.Mov.Reg(asm.R1, asm.R0),
		asm.Mov.Imm(asm.R2, reserveSize),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.StoreMem(asm.R10, -32, asm.R0, asm.DWord),
	}
}
