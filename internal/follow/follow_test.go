package follow

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testNamespace atomic.Int32

// testOptions gives each test its own sockets and accepts this user.
func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		Namespace: fmt.Sprintf("bpf-ninja-test/%d/%d", os.Getpid(), testNamespace.Add(1)),
		PeerUID:   uint32(os.Getuid()),
		Deadline:  200 * time.Millisecond,
		Logf:      t.Logf,
	}
}

func listen(t *testing.T, opts Options) *Server {
	t.Helper()
	s, err := Listen(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// capture is a client that records what it was told.
type capture struct {
	mu     sync.Mutex
	loads  []uint32
	held   []bool
	attach time.Duration // how long its handler takes
	client *Client
}

func dial(t *testing.T, opts Options, attach time.Duration, hooks ...string) *capture {
	t.Helper()
	c := &capture{attach: attach}
	c.client = NewClient(hooks, func(l Load) func(bool) {
		c.mu.Lock()
		c.loads = append(c.loads, l.ProgID)
		wait := c.attach
		c.mu.Unlock()
		time.Sleep(wait)
		return func(held bool) {
			c.mu.Lock()
			c.held = append(c.held, held)
			c.mu.Unlock()
		}
	}, opts)
	t.Cleanup(c.client.Close)
	return c
}

func (c *capture) state() ([]uint32, []bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.loads), slices.Clone(c.held)
}

// waitSubscribers waits until the server registered n captures; Dial
// returns when the handshake is done, slightly before that.
func waitSubscribers(t *testing.T, s *Server, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		s.mu.Lock()
		got := len(s.subs)
		s.mu.Unlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d subscribers, want %d", got, n)
		}
	}
}

// waitHeld waits until the capture saw n resumes.
func waitHeld(t *testing.T, c *capture, n int) []bool {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if _, held := c.state(); len(held) >= n {
			return held
		}
		if time.Now().After(deadline) {
			t.Fatalf("no resume %d", n)
		}
	}
}

func TestAnnounceWaitsForAck(t *testing.T) {
	opts := testOptions(t)
	s := listen(t, opts)
	c := dial(t, opts, 50*time.Millisecond, "hook_a", "hook_b")
	if n := c.client.Dial(); n != 1 {
		t.Fatalf("connections %d, want 1", n)
	}
	waitSubscribers(t, s, 1)

	start := time.Now()
	notified, held := s.Announce(7, []string{"hook_b", "other"})
	if elapsed := time.Since(start); notified != 1 || held != 1 || elapsed < 50*time.Millisecond || elapsed >= opts.Deadline {
		t.Fatalf("notified %d, held %d after %s; want 1, 1 after the capture's 50ms", notified, held, elapsed)
	}
	if loads, _ := c.state(); !slices.Equal(loads, []uint32{7}) {
		t.Fatalf("loads %v", loads)
	}
	if got := waitHeld(t, c, 1); !slices.Equal(got, []bool{true}) {
		t.Fatalf("held %v", got)
	}
	// A load without any hook the capture follows is not announced to it.
	start = time.Now()
	if notified, held := s.Announce(8, []string{"other"}); notified != 0 || held != 0 || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("unrelated load: notified %d, held %d after %s", notified, held, time.Since(start))
	}
	if loads, _ := c.state(); len(loads) != 1 {
		t.Fatalf("loads %v", loads)
	}
}

// TestAnnounceDeadline covers a capture that attaches too slowly: the load
// continues at the deadline and the capture is disconnected.
func TestAnnounceDeadline(t *testing.T) {
	opts := testOptions(t)
	var logMu sync.Mutex
	var logs []string
	opts.Logf = func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	s := listen(t, opts)
	c := dial(t, opts, 2*opts.Deadline, "hook_a")
	c.client.Dial()
	waitSubscribers(t, s, 1)

	start := time.Now()
	notified, held := s.Announce(1, []string{"hook_a"})
	if elapsed := time.Since(start); notified != 1 || held != 0 || elapsed < opts.Deadline || elapsed > opts.Deadline+opts.Deadline/2 {
		t.Fatalf("slow capture: notified %d, held %d after %s; want 1, 0 at the %s deadline", notified, held, elapsed, opts.Deadline)
	}
	waitSubscribers(t, s, 0)
	if got := waitHeld(t, c, 1); !slices.Equal(got, []bool{false}) {
		t.Fatalf("timed-out capture held %v, want [false]", got)
	}
	if notified, held := s.Announce(2, []string{"hook_a"}); notified != 0 || held != 0 {
		t.Fatalf("load after disconnect: notified %d, held %d; want 0, 0", notified, held)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if !slices.ContainsFunc(logs, func(line string) bool {
		return strings.Contains(line, "if the capture reconnects, the next load waits")
	}) {
		t.Fatalf("timeout diagnostic does not describe reconnection: %v", logs)
	}
}

func TestWaitRejectsAckPastDeadline(t *testing.T) {
	sub := &subscriber{acks: make(chan message, 1), gone: make(chan struct{})}
	sub.acks <- message{Type: typeAck, Seq: 1}
	if acked, timedOut := sub.wait(1, time.Now().Add(-time.Second)); acked || !timedOut {
		t.Fatalf("past deadline: acked=%v timedOut=%v", acked, timedOut)
	}
}

func TestRegisterPublishesBeforeHelloAndRemovesOnFailure(t *testing.T) {
	s := &Server{}
	sub := &subscriber{}
	if err := s.register(sub, func() error {
		if len(s.subs) != 1 || s.subs[0] != sub {
			t.Fatal("subscriber was not registered before hello")
		}
		return fmt.Errorf("send failed")
	}); err == nil {
		t.Fatal("failed hello was accepted")
	}
	if len(s.subs) != 0 {
		t.Fatalf("failed hello left %d subscribers", len(s.subs))
	}
}

// rawPeer is a connection that speaks the protocol by hand.
func rawPeer(t *testing.T, opts Options, hello message) *wire {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: opts.address(0), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	w := newWire(conn)
	if err := w.send(hello, time.Second); err != nil {
		t.Fatal(err)
	}
	return w
}

// TestAnnounceUnresponsiveAndGone covers a capture that never acks and one
// that disconnects while the load waits for it.
func TestAnnounceUnresponsiveAndGone(t *testing.T) {
	opts := testOptions(t)
	s := listen(t, opts)
	silent := rawPeer(t, opts, message{Type: typeHello, Version: Version, Hooks: []string{"hook_a"}})
	if m, err := silent.receive(time.Second); err != nil || m.Type != typeHello || m.Version != Version {
		t.Fatalf("handshake: %+v, %v", m, err)
	}
	waitSubscribers(t, s, 1)
	start := time.Now()
	if notified, held := s.Announce(1, []string{"hook_a"}); notified != 1 || held != 0 || time.Since(start) < opts.Deadline {
		t.Fatalf("silent capture: notified %d, held %d after %s", notified, held, time.Since(start))
	}
	want := message{Type: typeLoad, Seq: 1, ProgID: 1, Hooks: []string{"hook_a"}}
	if m, err := silent.receive(time.Second); err != nil || m.Type != want.Type || m.Seq != want.Seq || m.ProgID != want.ProgID || m.Held {
		t.Fatalf("message %+v, %v; want %+v", m, err, want)
	}
	if m, err := silent.receive(time.Second); err == nil {
		t.Fatalf("timed-out capture remained connected and received %+v", m)
	}
	waitSubscribers(t, s, 0)

	// A capture that goes away during the hold ends the wait at once.
	leaving := rawPeer(t, opts, message{Type: typeHello, Version: Version, Hooks: []string{"hook_a"}})
	if _, err := leaving.receive(time.Second); err != nil {
		t.Fatal(err)
	}
	waitSubscribers(t, s, 1)
	go func() {
		if _, err := leaving.receive(time.Second); err == nil { // the load
			_ = leaving.conn.Close()
		}
	}()
	start = time.Now()
	if notified, held := s.Announce(2, []string{"hook_a"}); notified != 1 || held != 0 || time.Since(start) > opts.Deadline/2 {
		t.Fatalf("capture that left: notified %d, held %d after %s", notified, held, time.Since(start))
	}
}

func TestAnnounceDropsUnresponsiveCapture(t *testing.T) {
	opts := testOptions(t)
	opts.Deadline = 50 * time.Millisecond
	s := listen(t, opts)
	silent := rawPeer(t, opts, message{Type: typeHello, Version: Version, Hooks: []string{"hook_a"}})
	if _, err := silent.receive(time.Second); err != nil {
		t.Fatal(err)
	}
	waitSubscribers(t, s, 1)
	_ = silent.conn.SetReadBuffer(1024)
	_ = s.subs[0].wire.conn.SetWriteBuffer(1024)
	acks := make(chan uint64)
	acksDone := make(chan struct{})
	go func() {
		defer close(acksDone)
		for seq := range acks {
			time.Sleep(time.Millisecond)
			_ = silent.send(message{Type: typeAck, Seq: seq}, time.Second)
		}
	}()

	done := make(chan struct{})
	go func() {
		for id := uint32(1); id <= 500; id++ {
			acks <- uint64(id)
			s.Announce(id, []string{"hook_a"})
		}
		close(acks)
		<-acksDone
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = silent.conn.Close()
		t.Fatal("Announce blocked while writing to an unresponsive capture")
	}
}

// TestAnnounceTogether checks that every capture is asked at once and all
// acknowledgements share one deadline.
func TestAnnounceTogether(t *testing.T) {
	opts := testOptions(t)
	s := listen(t, opts)
	first := dial(t, opts, 60*time.Millisecond, "hook_a")
	first.client.Dial()
	waitSubscribers(t, s, 1)
	second := dial(t, opts, 0, "hook_a")
	second.client.Dial()
	waitSubscribers(t, s, 2)

	done := make(chan [2]int, 1)
	go func() {
		n, h := s.Announce(1, []string{"hook_a"})
		done <- [2]int{n, h}
	}()
	time.Sleep(30 * time.Millisecond)
	if loads, _ := second.state(); !slices.Equal(loads, []uint32{1}) {
		t.Fatalf("second capture loads %v; it was not notified with the first", loads)
	}
	if got := <-done; got != [2]int{2, 2} {
		t.Fatalf("notified, held = %v, want [2 2]", got)
	}
	// The first capture now uses up the whole deadline, but the second still
	// attaches while the loader is held.
	first.mu.Lock()
	first.attach = 2 * opts.Deadline
	first.mu.Unlock()
	start := time.Now()
	if n, h := s.Announce(2, []string{"hook_a"}); n != 2 || h != 1 || time.Since(start) > 2*opts.Deadline {
		t.Fatalf("shared deadline: notified %d, held %d after %s; want 2, 1", n, h, time.Since(start))
	}
	if got := waitHeld(t, second, 2); !slices.Equal(got, []bool{true, true}) {
		t.Fatalf("second capture held %v", got)
	}
}

func TestVersionAndPeerChecks(t *testing.T) {
	opts := testOptions(t)
	s := listen(t, opts)
	// A capture with another protocol version is dropped by the server.
	old := rawPeer(t, opts, message{Type: typeHello, Version: Version + 1, Hooks: []string{"hook_a"}})
	if m, err := old.receive(time.Second); err == nil {
		t.Fatalf("a capture with another version got %+v", m)
	}
	waitSubscribers(t, s, 0)

	// A supervisor with another version is not used by the capture.
	other := testOptions(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: other.address(0), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		w := newWire(conn)
		if _, err := w.receive(time.Second); err == nil {
			_ = w.send(message{Type: typeHello, Version: Version + 1}, time.Second)
		}
	}()
	if n := dial(t, other, 0, "hook_a").client.Dial(); n != 0 {
		t.Fatalf("connections to a supervisor with another version: %d", n)
	}

	// Each side refuses a peer that is not the required user.
	stranger := opts
	stranger.PeerUID++
	if n := dial(t, stranger, 0, "hook_a").client.Dial(); n != 0 {
		t.Fatalf("the capture accepted a supervisor of another user")
	}
	strict := testOptions(t)
	strict.PeerUID++
	listen(t, strict)
	lax := strict
	lax.AnyPeerUID = true
	if n := dial(t, lax, 0, "hook_a").client.Dial(); n != 0 {
		t.Fatalf("the supervisor accepted a capture of another user")
	}
}

// TestSlots checks that supervisors take successive slots and a capture
// reaches all of them, also one started after its first Dial.
func TestSlots(t *testing.T) {
	opts := testOptions(t)
	a, b := listen(t, opts), listen(t, opts)
	if a.Slot() != 0 || b.Slot() != 1 {
		t.Fatalf("slots %d and %d, want 0 and 1", a.Slot(), b.Slot())
	}
	c := dial(t, opts, 0, "hook_a")
	if n := c.client.Dial(); n != 2 {
		t.Fatalf("connections %d, want 2", n)
	}
	late := listen(t, opts)
	if n := c.client.Dial(); n != 3 || late.Slot() != 2 {
		t.Fatalf("connections %d after a third supervisor in slot %d", n, late.Slot())
	}
	waitSubscribers(t, late, 1)
	if n, h := late.Announce(5, []string{"hook_a"}); n != 1 || h != 1 {
		t.Fatalf("notified %d, held %d", n, h)
	}
	// A supervisor that exits frees its slot and its connection.
	_ = a.Close()
	for deadline := time.Now().Add(5 * time.Second); c.client.Dial() != 2; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the closed supervisor's connection stayed")
		}
	}
}
