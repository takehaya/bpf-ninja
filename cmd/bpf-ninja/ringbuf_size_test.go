package main

import "testing"

func TestRingbufBytes(t *testing.T) {
	for _, tc := range []struct {
		mib  int
		want uint32
		ok   bool
	}{
		{64, 64 << 20, true},
		{1, 1 << 20, true},
		{2048, 2048 << 20, true},
		{4096, 0, false},
		{6144, 0, false},
		{4097, 0, false},
		{3, 0, false},
		{0, 0, false},
		{-64, 0, false},
	} {
		got, err := ringbufBytes(tc.mib)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ringbufBytes(%d) = %d, %v; want %d, ok=%v", tc.mib, got, err, tc.want, tc.ok)
		}
	}
}
