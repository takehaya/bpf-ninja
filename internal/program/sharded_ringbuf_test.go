package program

import (
	"math/bits"
	"testing"
)

// isValidRingbufSize mirrors the kernel constraint on BPF_MAP_TYPE_RINGBUF
// byte size: a power of two that is also a multiple of the page size (any
// power of two >= 4096 satisfies both).
func isValidRingbufSize(sz uint32) bool {
	return sz >= 4096 && bits.OnesCount32(sz) == 1
}

func TestShardRingbufSize(t *testing.T) {
	cases := []struct {
		total   uint32
		numCPUs int
		want    uint32
	}{
		// 4 MiB / 6 = 699050 (the reported failure) -> round down to 512 KiB.
		{4 * 1024 * 1024, 6, 512 * 1024},
		// power-of-two CPU count divides cleanly.
		{64 * 1024 * 1024, 8, 8 * 1024 * 1024},
		{64 * 1024 * 1024, 16, 4 * 1024 * 1024},
		// already a power of two per shard stays put.
		{8 * 1024 * 1024, 4, 2 * 1024 * 1024},
		// odd CPU counts.
		{16 * 1024 * 1024, 3, 4 * 1024 * 1024}, // 5.33 MiB -> 4 MiB
		{16 * 1024 * 1024, 12, 1024 * 1024},    // 1.33 MiB -> 1 MiB
		// tiny budget / huge CPU count floors at 64 KiB.
		{1 * 1024 * 1024, 4096, 64 * 1024},
	}

	for _, c := range cases {
		got := shardRingbufSize(c.total, c.numCPUs)
		if got != c.want {
			t.Errorf("shardRingbufSize(%d, %d) = %d, want %d", c.total, c.numCPUs, got, c.want)
		}
		if !isValidRingbufSize(got) {
			t.Errorf("shardRingbufSize(%d, %d) = %d is not a valid ringbuf size", c.total, c.numCPUs, got)
		}
	}
}

// TestShardRingbufSizeAlwaysValid sweeps every plausible CPU count against
// several budgets and asserts the result is always a kernel-valid ringbuf
// size, guarding against the "not a multiple of page size" regression.
func TestShardRingbufSizeAlwaysValid(t *testing.T) {
	budgets := []uint32{
		1 * 1024 * 1024,
		4 * 1024 * 1024,
		16 * 1024 * 1024,
		64 * 1024 * 1024,
		256 * 1024 * 1024,
	}
	for _, total := range budgets {
		for cpus := 1; cpus <= 512; cpus++ {
			got := shardRingbufSize(total, cpus)
			if !isValidRingbufSize(got) {
				t.Fatalf("shardRingbufSize(%d, %d) = %d is not a valid ringbuf size", total, cpus, got)
			}
		}
	}
}
