package program

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"golang.org/x/sys/unix"
)

func TestFollowerLinkDecision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		total, own int
		scanErr    error
		want       bool
	}{
		{"no observer", 0, 0, nil, false},
		{"own observer", 1, 1, nil, false},
		{"other observer", 2, 1, nil, true},
		{"incomplete read", 0, 0, unix.EAGAIN, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := followerLinkDecision(tc.total, tc.own, tc.scanErr)
			if errors.Is(err, ErrObservedByOther) != tc.want {
				t.Fatalf("followerLinkDecision(%d, %d, %v) = %v, refusal=%v", tc.total, tc.own, tc.scanErr, err, tc.want)
			}
		})
	}
}

func TestDetachFollowersAfterQuiesce(t *testing.T) {
	pr := new(ebpf.Program)
	p := &Probe{progs: []*ebpf.Program{pr}, owner: map[*ebpf.Program]uint32{pr: 7}, detached: true}
	p.DetachFollowers(7)
}

func TestFollowerSnapshotEntries(t *testing.T) {
	targets := []attach.Target{{Generated: true}}
	if got := recordSnapshotEntries(targets, false); got != 1 {
		t.Fatalf("--no-follow snapshot entries=%d, want origin/main value 1", got)
	}
	if got := recordSnapshotEntries(targets, true); got != 1+followerSnapKeys {
		t.Fatalf("following snapshot entries=%d, want %d", got, 1+followerSnapKeys)
	}
}

func TestTracingLinksRetriesAndFailsClosed(t *testing.T) {
	calls := 0
	if got, err := tracingLinksOnWith(func() (int, error) {
		calls++
		if calls < 3 {
			return 0, unix.EAGAIN
		}
		return 0, nil
	}); got != 0 || err != nil || calls != 3 {
		t.Fatalf("transient EAGAIN: links=%d err=%v calls=%d, want 0, nil, 3", got, err, calls)
	}
	calls = 0
	if got, err := tracingLinksOnWith(func() (int, error) {
		calls++
		return 0, unix.EAGAIN
	}); err == nil || calls != 3 {
		t.Fatalf("persistent EAGAIN: links=%d err=%v calls=%d, want error after 3 attempts", got, err, calls)
	}
	if _, err := tracingLinksOnWith(func() (int, error) { return 0, unix.EIO }); err == nil {
		t.Fatal("non-EAGAIN link read error was discarded")
	}
}
