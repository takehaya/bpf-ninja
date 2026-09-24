package capture

import (
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"sync"
	"sync/atomic"
)

// SessionStats counts transport records, independently of packet/output caps.
// Values become stable after Stop has joined every shard.
type SessionStats struct {
	Consumed         atomic.Uint64
	Malformed        atomic.Uint64
	DrainedAtStop    atomic.Uint64
	AffinityFailures atomic.Uint64
	warning          sync.Once
}

type shardSession struct {
	stopCh       chan struct{}
	failure      chan struct{}
	cursors      []*fastrb.Cursor
	final        []uint64
	acknowledged []atomic.Uint64
	done         sync.WaitGroup
	once         sync.Once
	stats        SessionStats
	mu           sync.Mutex
	err          error
}

func newShardSession(cursors []*fastrb.Cursor) *shardSession {
	return &shardSession{stopCh: make(chan struct{}), failure: make(chan struct{}), cursors: cursors, final: make([]uint64, len(cursors)), acknowledged: make([]atomic.Uint64, len(cursors))}
}
func (s *shardSession) fail(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
		close(s.failure)
	}
	s.mu.Unlock()
}
func (s *shardSession) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *shardSession) stopping() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

// Producers must be quiescent before stop. Readers then drain a finite backlog.
func (s *shardSession) stop() {
	s.once.Do(func() {
		for i, c := range s.cursors {
			s.final[i] = c.Produced()
		}
		close(s.stopCh)
		s.done.Wait()
		for _, c := range s.cursors {
			s.fail(c.Close())
		}
	})
}

// Barrier snapshots every producer position. A shard publishes its consumed
// position only after the sink (including writer registration) has returned.
// Polling completion is nonblocking, so SIGINT/errors can still stop capture.
func (s *shardSession) Barrier() func() (bool, error) {
	targets := make([]uint64, len(s.cursors))
	for i, c := range s.cursors {
		targets[i] = c.Produced()
	}
	return func() (bool, error) {
		if err := s.Err(); err != nil {
			return false, err
		}
		for i, n := range targets {
			if s.acknowledged[i].Load() < n {
				return false, nil
			}
		}
		return true, nil
	}
}
func (s *shardSession) acknowledge(i int) { s.acknowledged[i].Store(s.cursors[i].Consumed()) }
