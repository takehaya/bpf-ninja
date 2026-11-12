package follow

import (
	"fmt"
	"net"
	"sync"
)

// Load is one announced program.
type Load struct {
	ProgID uint32
	Hooks  []string
}

// Handler attaches the capture's observers to an announced program while
// its loader is stopped. The function it returns is called once the
// supervisor has said whether the loader was held until the capture's ack
// (false also when the supervisor went away).
type Handler func(Load) (finish func(held bool))

// Client is a capture's end: its connections to the reachable supervisors.
type Client struct {
	opts   Options
	hooks  []string
	handle Handler

	mu     sync.Mutex
	conns  map[int]*net.UnixConn // by slot
	closed bool
	wg     sync.WaitGroup
}

// NewClient returns a client that follows hooks. It has no connections
// until Dial.
func NewClient(hooks []string, handle Handler, opts Options) *Client {
	return &Client{opts: opts, hooks: hooks, handle: handle, conns: map[int]*net.UnixConn{}}
}

// Dial subscribes to every supervisor this client is not connected to yet
// and returns the number of connections it has. A capture calls it again
// from time to time, since a supervisor may start later.
func (c *Client) Dial() int {
	for slot := range Slots {
		c.mu.Lock()
		_, connected := c.conns[slot]
		closed := c.closed
		c.mu.Unlock()
		if closed {
			break
		}
		if connected {
			continue
		}
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.opts.address(slot), Net: "unix"})
		if err != nil {
			continue // no supervisor in this slot
		}
		w, err := c.subscribe(conn)
		if err != nil {
			c.opts.logf("not following through %s: %v", c.opts.address(slot), err)
			_ = conn.Close()
			continue
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = conn.Close()
			break
		}
		c.conns[slot] = conn
		c.wg.Add(1)
		c.mu.Unlock()
		go c.serve(slot, w)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

func (c *Client) subscribe(conn *net.UnixConn) (*wire, error) {
	if _, err := c.opts.checkPeer(conn); err != nil {
		return nil, err
	}
	w := newWire(conn)
	if err := w.send(message{Type: typeHello, Version: Version, Hooks: c.hooks}, handshakeTimeout); err != nil {
		return nil, err
	}
	hello, err := w.receive(handshakeTimeout)
	if err != nil {
		return nil, err
	}
	if hello.Type != typeHello || hello.Version != Version {
		return nil, fmt.Errorf("it speaks protocol version %d, this capture version %d", hello.Version, Version)
	}
	return w, nil
}

func (c *Client) serve(slot int, w *wire) {
	defer c.wg.Done()
	defer func() {
		_ = w.conn.Close()
		c.mu.Lock()
		delete(c.conns, slot)
		c.mu.Unlock()
	}()
	for {
		m, err := w.receive(0)
		if err != nil {
			return
		}
		if m.Type != typeLoad {
			continue
		}
		finish := c.handle(Load{ProgID: m.ProgID, Hooks: m.Hooks})
		err = w.send(message{Type: typeAck, Seq: m.Seq}, c.opts.deadline())
		held := false
		// The resume follows the ack at once, unless another capture uses
		// the rest of the shared deadline.
		for err == nil {
			var r message
			if r, err = w.receive(c.opts.deadline() + handshakeTimeout); err == nil && r.Type == typeResume && r.Seq == m.Seq {
				held = r.Held
				break
			}
		}
		finish(held)
		if err != nil {
			return
		}
	}
}

// Close ends every connection and waits for a handler in progress.
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	for _, conn := range c.conns {
		_ = conn.Close()
	}
	c.mu.Unlock()
	c.wg.Wait()
}
