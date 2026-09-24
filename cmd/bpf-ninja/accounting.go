package main

import (
	"fmt"
	"sync/atomic"

	"github.com/takehaya/bpf-ninja/internal/program"
)

// claimPackets bounds concurrent shard reservations; failed writes are not
// retried with the same budget, since their persistence is indeterminate.
func claimPackets(used *atomic.Int64, limit, wanted int64) int64 {
	for {
		old := used.Load()
		n := min(wanted, max(int64(0), limit-old))
		if n == 0 || used.CompareAndSwap(old, old+n) {
			return n
		}
	}
}

func captureReport(k program.ExportStats, statsErr, errorResult error, c *captureControl) string {
	if c.stats == nil {
		return "capture status=incomplete transport=unavailable (reader did not start)"
	}
	read := c.stats.Consumed.Load()
	bad := c.stats.Malformed.Load()
	written := c.written.Load()
	limited := c.limited.Load()
	discarded := c.nullRecords.Load()
	unconfirmed := uint64(0)
	if read > written+limited+discarded+bad {
		unconfirmed = read - written - limited - discarded - bad
	}
	status := "complete"
	if limited > 0 {
		status = "limited"
	}
	if discarded > 0 {
		status = "discarded"
	}
	if statsErr != nil || errorResult != nil || bad > 0 || unconfirmed > 0 || written+limited+discarded+bad > read || k.ReserveFail+k.LookupMiss+k.CopyFail > 0 || k.Submitted != read {
		status = "incomplete"
	}
	producer := fmt.Sprintf("selected=%d exported=%d ringbuf_reserve_fail=%d lookup_miss=%d copy_fail=%d", k.Submitted+k.ReserveFail+k.LookupMiss+k.CopyFail, k.Submitted, k.ReserveFail, k.LookupMiss, k.CopyFail)
	if statsErr != nil {
		producer = "selected=unknown exported=unknown ringbuf_reserve_fail=unknown lookup_miss=unknown copy_fail=unknown"
	}
	return fmt.Sprintf("capture status=%s %s consumed=%d written=%d intentional_limit=%d null_discard=%d malformed=%d persistence_unconfirmed=%d drained_at_stop=%d affinity_failures=%d filtered_or_parse_rejected=unmeasured", status, producer, read, written, limited, discarded, bad, unconfirmed, c.stats.DrainedAtStop.Load(), c.stats.AffinityFailures.Load())
}
