package main

import (
	"errors"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/program"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCaptureReportOutcomes(t *testing.T) {
	for _, kind := range []string{"complete", "reserve", "lookup", "copy", "malformed", "write", "limit", "null", "unknown", "unread", "overcount"} {
		t.Run(kind, func(t *testing.T) {
			c := &captureControl{stats: &capture.SessionStats{}}
			c.stats.Consumed.Store(10)
			c.written.Store(10)
			k := program.ExportStats{Submitted: 10}
			var statsErr, writeErr error
			want := "incomplete"
			switch kind {
			case "complete":
				want = "complete"
			case "reserve":
				k.ReserveFail = 1
			case "lookup":
				k.LookupMiss = 1
			case "copy":
				k.CopyFail = 1
			case "malformed":
				c.stats.Malformed.Store(1)
				c.written.Store(9)
			case "write":
				writeErr = errors.New("ENOSPC")
			case "limit":
				c.limited.Store(3)
				c.written.Store(7)
				want = "limited"
			case "null":
				c.nullRecords.Store(10)
				c.written.Store(0)
				want = "discarded"
			case "unknown":
				statsErr = errors.New("lookup")
			case "overcount":
				c.written.Store(20)
			case "unread":
				k.Submitted = 11
			}
			report := captureReport(k, statsErr, writeErr, c)
			if !strings.Contains(report, "status="+want+" ") {
				t.Fatal(report)
			}
			if kind == "unknown" && !strings.Contains(report, "exported=unknown") {
				t.Fatal(report)
			}
		})
	}
}
func TestConcurrentCountBudget(t *testing.T) {
	var count, total atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				total.Add(claimPackets(&count, 107, 19))
			}
		}()
	}
	wg.Wait()
	if total.Load() != 107 || count.Load() != 107 {
		t.Fatalf("total=%d count=%d", total.Load(), count.Load())
	}
}
