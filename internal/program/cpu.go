package program

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// possibleCPUSlots is an ID span, not the observer's usable CPU count. Reserve
// holes and offline CPUs too: array indices remain kernel CPU IDs, and CPUs
// brought online during capture already have a shard.
func possibleCPUSlots() (int, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/possible")
	if err != nil {
		return 0, fmt.Errorf("reading possible CPU IDs: %w", err)
	}
	return cpuIDSpan(string(data))
}

func cpuIDSpan(list string) (int, error) {
	last := -1
	for _, part := range strings.Split(strings.TrimSpace(list), ",") {
		lo, hi, rangeFound := strings.Cut(part, "-")
		first, err := strconv.ParseUint(lo, 10, 31)
		if err != nil {
			return 0, fmt.Errorf("invalid CPU list %q", list)
		}
		end := first
		if rangeFound {
			end, err = strconv.ParseUint(hi, 10, 31)
			if err != nil {
				return 0, fmt.Errorf("invalid CPU range %q", part)
			}
		}
		if int(first) <= last || end < first || end == 1<<31-1 {
			return 0, fmt.Errorf("invalid CPU range %q", part)
		}
		last = int(end)
	}
	return last + 1, nil
}
