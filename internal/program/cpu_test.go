package program

import "testing"

func TestCPUIDSpan(t *testing.T) {
	for input, want := range map[string]int{"0": 1, "0-63\n": 64, "0-3,8,12-15": 16, "3": 4, "1-4,9": 10} {
		got, err := cpuIDSpan(input)
		if err != nil || got != want {
			t.Errorf("%q: %d, %v; want %d", input, got, err, want)
		}
	}
	for _, input := range []string{"", "-1", "3-1", "0-3,2", "0-3,", "0-3garbage", "0-2147483647"} {
		if _, err := cpuIDSpan(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}
