package main

import (
	"context"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

// --no-wakeup must set capture.NoWakeup: the probe's submit flags and the
// fast reader's poll both follow it, and a shard that blocks while
// producers skip wakeups would see nothing until stop.
func TestNoWakeupSetsCaptureNoWakeup(t *testing.T) {
	t.Cleanup(func() { capture.NoWakeup = false })
	// --in-memory-buffer fails right after the wakeup flags are applied.
	argv := []string{"bpf-ninja", "-i", "nonexist0", "--fast-reader", "--no-wakeup", "--in-memory-buffer", "1"}
	err := newRootCommand().Run(context.Background(), argv)
	if err == nil || !strings.Contains(err.Error(), "--in-memory-buffer requires --raw-dump") {
		t.Fatalf("err = %v, want the --in-memory-buffer check after the wakeup flags", err)
	}
	if !capture.NoWakeup {
		t.Fatal("--no-wakeup left capture.NoWakeup false")
	}
}
