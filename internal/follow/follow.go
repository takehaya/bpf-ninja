// Package follow is the protocol between inject-run and the captures that
// follow a generated hook across program loads.
//
// A capture that finds new programs by polling program IDs attaches after
// the loader already has the program, so the program may run unobserved.
// inject-run can do better: its supervisor has the loader stopped when a
// rewritten program is loaded. It announces the load to every subscribed
// capture and resumes the loader only when they have confirmed their
// observers, or when a deadline passes.
//
// The transport is a stream unix socket in the abstract namespace,
// "@bpf-ninja/inject-run/<slot>" for slot 0..31. A supervisor binds the
// first free slot and a capture dials every slot, so there are no paths,
// stale files or flags. Abstract sockets belong to a network namespace; a
// capture in another one reaches no supervisor and keeps polling. Both
// sides require the peer to run as root.
//
// Messages are JSON objects, one per line:
//
//	capture     hello{version, hooks}     the hook function names it follows
//	supervisor  hello{version}
//	supervisor  load{seq, prog_id, hooks} a program with one of those hooks
//	capture     ack{seq}                  its observers are attached, or failed
//	supervisor  resume{seq, held}         held: the loader waited for the ack
//
// An ack only says the capture is done; a failed attach is the capture's to
// report and never delays or refuses the load.
package follow

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// Version is the protocol version; peers with another are not used.
	Version = 1
	// Slots is the number of supervisors one network namespace can hold.
	Slots = 32
	// HoldDeadline is how long one load waits for all captures together.
	HoldDeadline = time.Second
	// DefaultNamespace prefixes the socket names.
	DefaultNamespace = "bpf-ninja/inject-run"

	handshakeTimeout = time.Second
)

const (
	typeHello  = "hello"
	typeLoad   = "load"
	typeAck    = "ack"
	typeResume = "resume"
)

type message struct {
	Type    string   `json:"type"`
	Version int      `json:"version,omitempty"`
	Hooks   []string `json:"hooks,omitempty"`
	Seq     uint64   `json:"seq,omitempty"`
	ProgID  uint32   `json:"prog_id,omitempty"`
	Held    bool     `json:"held,omitempty"`
}

// Options are shared by both ends. The zero value is the production setup.
type Options struct {
	// Namespace replaces DefaultNamespace, so tests do not meet a real
	// supervisor.
	Namespace string
	// PeerUID is the user the peer must run as: root unless AnyPeerUID.
	PeerUID    uint32
	AnyPeerUID bool
	// Deadline replaces HoldDeadline.
	Deadline time.Duration
	// Logf receives diagnostics; nil discards them.
	Logf func(format string, args ...any)
}

func (o Options) address(slot int) string {
	ns := o.Namespace
	if ns == "" {
		ns = DefaultNamespace
	}
	return fmt.Sprintf("@%s/%d", ns, slot)
}

func (o Options) deadline() time.Duration {
	if o.Deadline > 0 {
		return o.Deadline
	}
	return HoldDeadline
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// checkPeer refuses a peer that does not run as the required user and
// returns its process ID.
func (o Options) checkPeer(conn *net.UnixConn) (int32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	if !o.AnyPeerUID && cred.Uid != o.PeerUID {
		return cred.Pid, fmt.Errorf("peer pid %d runs as uid %d, not %d", cred.Pid, cred.Uid, o.PeerUID)
	}
	return cred.Pid, nil
}

// wire reads and writes messages on one connection. Writes come from one
// goroutine at a time on each side.
type wire struct {
	conn *net.UnixConn
	in   *bufio.Scanner
	out  *json.Encoder
}

func newWire(conn *net.UnixConn) *wire {
	return &wire{conn: conn, in: bufio.NewScanner(conn), out: json.NewEncoder(conn)}
}

func (w *wire) send(m message, timeout time.Duration) error {
	if err := w.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return w.out.Encode(m)
}

// receive reads the next message; a zero timeout waits forever.
func (w *wire) receive(timeout time.Duration) (message, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if err := w.conn.SetReadDeadline(deadline); err != nil {
		return message{}, err
	}
	if !w.in.Scan() {
		if err := w.in.Err(); err != nil {
			return message{}, err
		}
		return message{}, net.ErrClosed
	}
	var m message
	if err := json.Unmarshal(w.in.Bytes(), &m); err != nil {
		return message{}, fmt.Errorf("malformed message: %w", err)
	}
	return m, nil
}
