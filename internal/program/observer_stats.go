package program

import "fmt"

// ObserverMisses sums the kernel recursion-miss counters of the attached BPF
// programs. Capture does not use it yet. A consumer must compare samples from
// start, periodic checks, after waiting for in-flight runs, and shutdown.
// A miss diagnoses loss; it cannot repair earlier output.
func (p *Probe) ObserverMisses() (uint64, error) {
	if err := checkObserverMissesKernel(kernelVersion()); err != nil {
		return 0, err
	}
	return observerMisses(len(p.progs), func(i int) (uint64, error) {
		stats, err := p.progs[i].Stats()
		if err != nil {
			return 0, err
		}
		return stats.RecursionMisses, nil
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
