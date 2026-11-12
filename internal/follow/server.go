package follow

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"time"
)

// Server is the supervisor's end: it accepts captures and announces loads.
type Server struct {
	opts Options
	ln   *net.UnixListener
	slot int

	mu     sync.Mutex
	subs   []*subscriber
	seq    uint64
	conns  map[*net.UnixConn]struct{} // every accepted connection still open
	closed bool
	wg     sync.WaitGroup // the accept loop and one goroutine per connection
}

// subscriber is one connected capture.
type subscriber struct {
	wire  *wire
	pid   int32
	hooks []string
	acks  chan message  // from the reader goroutine
	gone  chan struct{} // closed when the connection ended
}

// Listen binds the first free slot.
func Listen(opts Options) (*Server, error) {
	for slot := range Slots {
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: opts.address(slot), Net: "unix"})
		if err != nil {
			continue // taken by another supervisor
		}
		s := &Server{opts: opts, ln: ln, slot: slot, conns: map[*net.UnixConn]struct{}{}}
		s.wg.Add(1)
		go s.accept()
		return s, nil
	}
	return nil, fmt.Errorf("all %d sockets %s .. are in use", Slots, opts.address(0))
}

// Slot is the slot this server bound.
func (s *Server) Slot() int { return s.slot }

// Close stops accepting, drops every capture and waits for the server's
// goroutines. Announce must not be running.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.mu.Lock()
	s.closed = true
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serve(conn)
	}
}

func (s *Server) serve(conn *net.UnixConn) {
	defer s.wg.Done()
	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	pid, err := s.opts.checkPeer(conn)
	if err != nil {
		s.opts.logf("refused a capture: %v", err)
		return
	}
	w := newWire(conn)
	hello, err := w.receive(handshakeTimeout)
	if err == nil && (hello.Type != typeHello || hello.Version != Version) {
		err = fmt.Errorf("it speaks protocol version %d, this inject-run version %d", hello.Version, Version)
	}
	if err == nil {
		err = w.send(message{Type: typeHello, Version: Version}, handshakeTimeout)
	}
	if err != nil {
		s.opts.logf("refused capture pid %d: %v", pid, err)
		return
	}
	sub := &subscriber{wire: w, pid: pid, hooks: hello.Hooks, acks: make(chan message, 64), gone: make(chan struct{})}
	s.mu.Lock()
	s.subs = append(s.subs, sub)
	s.mu.Unlock()
	s.opts.logf("capture pid %d follows %v", pid, hello.Hooks)
	for {
		m, err := w.receive(0)
		if err != nil {
			break
		}
		if m.Type != typeAck {
			continue
		}
		select {
		case sub.acks <- m:
		default: // a capture flooding acks; Announce treats it as silent
		}
	}
	close(sub.gone)
	s.mu.Lock()
	s.subs = slices.DeleteFunc(s.subs, func(x *subscriber) bool { return x == sub })
	s.mu.Unlock()
	s.opts.logf("capture pid %d disconnected", pid)
}

// Announce tells each capture that follows one of hooks about the program
// and returns when all of them have acked or the deadline for
// this load has passed. The caller keeps the loader stopped meanwhile. It
// returns how many captures it notified and how many of them it waited for
// successfully. Calls must not overlap.
func (s *Server) Announce(progID uint32, hooks []string) (notified, held int) {
	s.mu.Lock()
	s.seq++
	seq := s.seq
	var subs []*subscriber
	for _, sub := range s.subs {
		if slices.ContainsFunc(hooks, func(h string) bool { return slices.Contains(sub.hooks, h) }) {
			subs = append(subs, sub)
		}
	}
	s.mu.Unlock()
	limit := s.opts.deadline()
	deadline := time.Now().Add(limit)
	type result struct {
		sub      *subscriber
		ok       bool
		timedOut bool
	}
	sent := make(chan *subscriber, len(subs))
	results := make(chan result, len(subs))
	for _, sub := range subs {
		go func() {
			if sub.wire.send(message{Type: typeLoad, Seq: seq, ProgID: progID, Hooks: hooks}, time.Until(deadline)) != nil {
				_ = sub.wire.conn.Close()
				sent <- nil
				return
			}
			sent <- sub
		}()
	}
	for range subs {
		sub := <-sent
		if sub == nil {
			continue
		}
		notified++
		go func() {
			ok, timedOut := sub.wait(seq, deadline)
			if remaining := time.Until(deadline); remaining > 0 {
				if sub.wire.send(message{Type: typeResume, Seq: seq, Held: ok}, remaining) != nil {
					_ = sub.wire.conn.Close()
				}
			} else {
				_ = sub.wire.conn.Close()
			}
			results <- result{sub, ok, timedOut}
		}()
	}
	for range notified {
		result := <-results
		if result.timedOut {
			s.opts.logf("capture pid %d did not confirm its observers on program id=%d within %s; the load continues and the connection is closed; if the capture reconnects, the next load waits up to %s again", result.sub.pid, progID, limit, limit)
		}
		if result.ok {
			held++
		}
	}
	return notified, held
}

// wait blocks until the capture acks seq, disconnects, or the load's
// deadline fires.
func (sub *subscriber) wait(seq uint64, deadline time.Time) (acked, timedOut bool) {
	for {
		if time.Until(deadline) <= 0 {
			return false, true
		}
		select {
		case m := <-sub.acks:
			if m.Seq == seq {
				if time.Until(deadline) <= 0 {
					return false, true
				}
				return true, false
			}
			continue
		default:
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, true
		}
		timer := time.NewTimer(remaining)
		select {
		case m := <-sub.acks:
			timer.Stop()
			if m.Seq == seq {
				if time.Until(deadline) <= 0 {
					return false, true
				}
				return true, false
			}
		case <-sub.gone:
			timer.Stop()
			return false, false
		case <-timer.C:
			return false, true
		}
	}
}
