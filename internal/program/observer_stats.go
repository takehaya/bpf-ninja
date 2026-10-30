package program

import "fmt"

// ObserverMisses sums the kernel recursion-miss counters of the attached BPF
// programs. Hook capture checks samples from
// start, periodic checks, after waiting for in-flight runs, and shutdown.
// A miss diagnoses loss; it cannot repair earlier output.
func (p *Probe) ObserverMisses() (uint64, error) {
	major, minor, patch, known := kernelVersion()
	if known || p.runs == nil || p.runs.mode != "ctx" {
		if err := checkObserverMissesKernel(major, minor, patch, known); err != nil {
			return 0, err
		}
	}
	return observerMisses(len(p.progs), func(i int) (uint64, error) {
		stats, err := p.progs[i].Stats()
		if err != nil {
			return 0, err
		}
		misses := stats.RecursionMisses
		if p.runs != nil && len(p.runs.observerBase) == len(p.progs) {
			misses -= min(misses, p.runs.observerBase[i])
		}
		return misses, nil
	})
}

func checkObserverMissesKernel(major, minor, patch int, ok bool) error {
	if !ok {
		return fmt.Errorf("observer miss diagnostics: cannot determine kernel version")
	}
	// Project policy requires the supported Linux 6.1 baseline (the field
	// exists since 5.12). Older kernels can silently
	// return zero for absent prog_info fields instead of reporting an error.
	if major < 6 || (major == 6 && minor < 1) {
		return fmt.Errorf("observer miss diagnostics require Linux 6.1 or newer, got %d.%d.%d", major, minor, patch)
	}
	return nil
}

func observerMisses(n int, read func(int) (uint64, error)) (uint64, error) {
	var total uint64
	for i := range n {
		misses, err := read(i)
		if err != nil {
			return 0, fmt.Errorf("reading observer %d recursion misses: %w", i, err)
		}
		total += misses
	}
	return total, nil
}

// BoundaryMisses reports root-entry and root-exit recursion misses separately.
// A boundary miss can invalidate later IDs/tags when a ctx address is reused;
// misses in hook observers only remove records. Trampoline rewrites are not
// included in the kernel recursion-miss counters.
func (p *Probe) BoundaryMisses() (entry, exit uint64, err error) {
	if p.runs == nil || len(p.progs) < 2 {
		return 0, 0, nil
	}
	return boundaryMisses(func(i int) (uint64, error) {
		stats, e := p.progs[i].Stats()
		if e != nil {
			return 0, e
		}
		misses := stats.RecursionMisses
		if p.runs != nil && len(p.runs.observerBase) == len(p.progs) {
			misses -= min(misses, p.runs.observerBase[i])
		}
		return misses, nil
	}, len(p.progs))
}
func boundaryMisses(read func(int) (uint64, error), n int) (entry, exit uint64, err error) {
	entry, err = read(n - 1)
	if err != nil {
		return 0, 0, err
	}
	exit, err = read(0)
	if err != nil {
		return 0, 0, err
	}
	return entry, exit, nil
}
