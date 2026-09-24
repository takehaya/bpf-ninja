package capture

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

var affinityFailures atomic.Uint64
var affinityWarning sync.Once

// ReaderAffinityFailures reports unsuccessful pin attempts. Readers continue
// on their inherited allowed mask, so an offline CPU does not lose its shard.
func ReaderAffinityFailures() uint64 { return affinityFailures.Load() }

func readerCPUs(shards int) ([]int, error) {
	if DisableCPUAffinity {
		return make([]int, shards), nil
	}
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return nil, fmt.Errorf("reader CPU affinity: %w", err)
	}
	var allowed []int
	for i := 0; i < len(set)*64; i++ {
		if set.IsSet(i) {
			allowed = append(allowed, i)
		}
	}
	return planReaderCPUs(shards, allowed, SplitCoreRX)
}

func planReaderCPUs(shards int, allowed []int, split int) ([]int, error) {
	if split < 0 {
		return nil, fmt.Errorf("rx-cores must be nonnegative")
	}
	consumers := allowed
	if split > 0 {
		consumers = nil
		for _, cpu := range allowed {
			if cpu >= split {
				consumers = append(consumers, cpu)
			}
		}
	}
	if len(consumers) == 0 {
		return nil, fmt.Errorf("no allowed reader CPUs at or above rx-cores=%d", split)
	}
	result := make([]int, shards)
	for idx := range result {
		result[idx] = consumers[idx%len(consumers)]
		if split == 0 && slices.Contains(consumers, idx) {
			result[idx] = idx
		}
	}
	return result, nil
}

// A successful pin keeps the thread locked until the reader exits. A failed
// pin leaves the inherited mask intact and releases the thread to the runtime.
func pinReaderToCPU(cpu int) {
	if DisableCPUAffinity {
		return
	}
	var set unix.CPUSet
	var err error
	if cpu < 0 || cpu >= len(set)*64 {
		err = fmt.Errorf("CPU ID %d exceeds affinity mask", cpu)
	} else {
		set.Set(cpu)
		runtime.LockOSThread()
		err = unix.SchedSetaffinity(0, &set)
		if err != nil {
			runtime.UnlockOSThread()
		}
	}
	if err != nil {
		affinityFailures.Add(1)
		affinityWarning.Do(func() {
			fmt.Fprintf(os.Stderr, "warning: reader CPU pinning failed; continuing on allowed CPUs: %v\n", err)
		})
	}
}
