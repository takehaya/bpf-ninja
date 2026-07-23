package hook

import (
	"testing"
)

// TestSkBuffPacketOffsetsResolvesValidOffsets pins the offsets fit
// in int16 — loadPacketPointers casts them to int16 for LDX
// immediates, so a future kernel with sk_buff > 32KB would silently
// wrap rather than fail loudly.
func TestSkBuffPacketOffsetsResolvesValidOffsets(t *testing.T) {
	t.Helper()
	dataOff, lenOff, err := skBuffPacketOffsets()
	if err != nil {
		t.Skipf("kernel BTF not available (skBuff resolve failed): %v", err)
	}
	if dataOff == 0 {
		t.Errorf("data offset = 0; expected non-zero member offset in struct sk_buff")
	}
	if lenOff == 0 {
		t.Errorf("len offset = 0; expected non-zero member offset in struct sk_buff")
	}
	const int16Max = 32767
	if dataOff > int16Max {
		t.Errorf("data offset %d exceeds int16 LDX immediate range", dataOff)
	}
	if lenOff > int16Max {
		t.Errorf("len offset %d exceeds int16 LDX immediate range", lenOff)
	}
}

// TestSkBuffPacketOffsetsCachesResult pins the sync.Once cache: two
// successive calls return the same offsets without re-resolving
// (which would re-load kernel BTF, an expensive operation). The
// sticky package-level err is also a stable interface value, so a
// direct equality compare is the right check.
func TestSkBuffPacketOffsetsCachesResult(t *testing.T) {
	t.Helper()
	d1, l1, err1 := skBuffPacketOffsets()
	d2, l2, err2 := skBuffPacketOffsets()
	if err1 != err2 {
		t.Errorf("two calls returned different errors (cache not sticky): %v vs %v", err1, err2)
	}
	if d1 != d2 || l1 != l2 {
		t.Errorf("offsets differ across calls: (%d,%d) vs (%d,%d) — cache not working", d1, l1, d2, l2)
	}
}
