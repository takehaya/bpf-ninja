//go:build linux && amd64

package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/bpf-ninja/internal/follow"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
)

// TestAnnounceInjections checks the OnInject inject-run installs: the
// load is announced with its hook names before the hooks file callback,
// and the callback returns only after the capture confirmed.
func TestAnnounceInjections(t *testing.T) {
	opts := follow.Options{Namespace: fmt.Sprintf("bpf-ninja-test/inject-run/%d", os.Getpid()), PeerUID: uint32(os.Getuid())}
	server, err := follow.Listen(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	var mu sync.Mutex
	var order []string
	note := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, step)
	}
	confirmed := make(chan follow.Load, 1)
	client := follow.NewClient([]string{"ninja_sessions"}, func(l follow.Load) func(bool) {
		time.Sleep(50 * time.Millisecond) // attaching
		note("capture")
		confirmed <- l
		return func(bool) {}
	}, opts)
	defer client.Close()
	if client.Dial() != 1 {
		t.Fatal("the capture did not reach the server")
	}
	var logs []string
	onInject := announceInjections(func(syscallhook.Injection) { note("hooks-json") }, server,
		func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) })
	// The server registers a capture just after its handshake.
	for deadline := time.Now().Add(5 * time.Second); !slices.ContainsFunc(logs, func(l string) bool { return strings.Contains(l, "held the load") }); {
		if time.Now().After(deadline) {
			t.Fatalf("no held load: %v", logs)
		}
		onInject(syscallhook.Injection{Program: "p", ProgID: 7, Hooks: []inject.LookupHook{{Name: "ninja_sessions"}, {Name: "ninja_other"}}})
		time.Sleep(time.Millisecond)
	}
	note("resumed")
	if l := <-confirmed; l.ProgID != 7 || !slices.Equal(l.Hooks, []string{"ninja_sessions", "ninja_other"}) {
		t.Fatalf("announced %+v", l)
	}
	if n := len(order); n < 3 || !slices.Equal(order[n-3:], []string{"capture", "hooks-json", "resumed"}) {
		t.Fatalf("order %v", order)
	}
	if last := logs[len(logs)-1]; !strings.Contains(last, `program "p" (id=7): held the load`) || !strings.HasSuffix(last, "for 1 of 1 following captures") {
		t.Fatalf("log %q", last)
	}
	// A load whose ID could not be read is not announced, and one without a
	// followed hook returns at once.
	before := len(logs)
	onInject(syscallhook.Injection{Program: "p", Hooks: []inject.LookupHook{{Name: "ninja_sessions"}}})
	onInject(syscallhook.Injection{Program: "p", ProgID: 8, Hooks: []inject.LookupHook{{Name: "ninja_other"}}})
	announceInjections(nil, server, t.Logf)(syscallhook.Injection{Program: "p", ProgID: 9})
	if len(logs) != before || len(confirmed) != 0 {
		t.Fatalf("unexpected announcements: %v", logs[before:])
	}
}
