package inject

import (
	"errors"
	"testing"
)

func TestKernelFrameRounding(t *testing.T) {
	for _, tc := range []struct {
		release, jit string
		readErr      error
		want         int
	}{
		{"6.9.0", "1\n", nil, 16},
		{"7.0.0-rc1", "2\n", nil, 16},
		{"6.8.12", "1\n", nil, 32},
		{"6.12.0", "0\n", nil, 32},
		{"unknown", "1\n", nil, 32},
		{"7.0.0", "", errors.New("denied"), 32},
	} {
		if got := KernelFrameRounding(tc.release, tc.jit, tc.readErr); got != tc.want {
			t.Errorf("release=%q jit=%q err=%v: got %d want %d", tc.release, tc.jit, tc.readErr, got, tc.want)
		}
	}
}
