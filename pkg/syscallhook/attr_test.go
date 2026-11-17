package syscallhook

import "testing"

// A load with prog_ifindex is offloaded unless it carries
// BPF_F_XDP_DEV_BOUND_ONLY, which only binds the program to the device.
func TestOffloaded(t *testing.T) {
	for _, tc := range []struct {
		ifindex, flags uint32
		want           bool
	}{
		{0, 0, false},
		{0, devBoundOnly, false},
		{3, 0, true},
		{3, 1 << 5, true}, // BPF_F_XDP_HAS_FRAGS alone
		{3, devBoundOnly, false},
		{3, devBoundOnly | 1<<5, false},
	} {
		attr := make([]byte, progAttrSize)
		put32(attr, 64, tc.ifindex)
		put32(attr, 44, tc.flags)
		if got := offloaded(attr); got != tc.want {
			t.Errorf("ifindex %d flags %#x: offloaded %v, want %v", tc.ifindex, tc.flags, got, tc.want)
		}
	}
}
