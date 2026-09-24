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
}

type shardSession struct {
	stopCh  chan struct{}
	cursors []*fastrb.Cursor
	final   []uint64
	done    sync.WaitGroup
	once    sync.Once
	stats   SessionStats
	mu      sync.Mutex
	err     error
}

func newShardSession(cursors []*fastrb.Cursor) *shardSession {
	return &shardSession{stopCh: make(chan struct{}), cursors: cursors, final: make([]uint64, len(cursors))}
}
func (s *shardSession) fail(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
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
