package output

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

func TestWriterRetainsFlushFailure(t *testing.T) {
	for _, mode := range []string{"0", "1"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("BPF_NINJA_FAST_PCAPNG", mode)
			w, err := NewWriter("/dev/full", Config{})
			if err != nil {
				t.Fatal(err)
			}
			p := capture.Packet{Timestamp: time.Now(), Data: []byte{1, 2, 3}}
			if err := w.Write(p); err != nil {
				t.Fatal(err)
			}
			w.EnablePeriodicFlush(time.Millisecond)
			deadline := time.Now().Add(time.Second)
			for {
				w.flushMu.Lock()
				failure := w.failure
				w.flushMu.Unlock()
				if failure != nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("periodic flush did not retain failure")
				}
				time.Sleep(time.Millisecond)
			}
			for attempt := range 3 {
				for _, err := range []error{w.Flush(), w.Write(p), w.Close()} {
					if !errors.Is(err, syscall.ENOSPC) {
						t.Fatalf("attempt %d: error %v, want ENOSPC", attempt, err)
					}
				}
			}
		})
	}
}

func TestWriterConcurrentCloseIsIdempotent(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "out.pcap"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	w.EnablePeriodicFlush(time.Millisecond)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := w.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := w.Write(capture.Packet{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}
