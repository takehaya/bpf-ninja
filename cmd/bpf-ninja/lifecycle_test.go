package main

import (
	"fmt"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/setmap"
)

func TestHookFinalizationRequiresDeletionFlagOrCap(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		deleted, flag, capped bool
		wantLive              bool
	}{
		{"plain-tag-set", false, false, false, true},
		{"deleted-without-flag", true, false, false, true},
		{"deleted-with-flag", true, true, false, false},
		{"active-with-flag", false, true, false, true},
		{"capped-without-flag", false, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTagFinalizer("", output.Config{}, 1)
			f.stateFor(7)
			var caps *byteCaps
			if tc.capped {
				caps = newByteCaps(false, 1)
				ctr := caps.counterFor(7)
				ctr.limit.Store(1)
				caps.addTag(ctr, 1)
			}
			l := newCapLifecycle(caps, f, nil, "", false)
			l.hookRuns = true
			l.finalizeOnDel = tc.flag
			var infos []setmap.TagInfo
			if !tc.deleted {
				infos = []setmap.TagInfo{{Tag: 7, State: setmap.StateActive}}
			}
			got := l.finalizationLiveTags(infos)
			begins := 0
			f.begin = func(uint32) (func() (bool, error), error) {
				begins++
				return func() (bool, error) { return false, nil }, nil
			}
			f.step(got, l.keepTagLive)
			if begins != map[bool]int{true: 0, false: 1}[tc.wantLive] {
				t.Fatalf("barriers=%d", begins)
			}
		})
	}
}

func TestHookDeletionNewTagAfterSnapshot(t *testing.T) {
	for _, finalize := range []bool{false, true} {
		t.Run(fmt.Sprint(finalize), func(t *testing.T) {
			f := newTagFinalizer("unused", output.Config{}, 1)
			l := newCapLifecycle(nil, f, nil, "unused", false)
			l.hookRuns = true
			l.finalizeOnDel = finalize
			live := l.finalizationLiveTags(nil)
			// A shard registers a previously unknown tag after the lifecycle snapshot.
			f.stateFor(77)
			calls := 0
			f.begin = func(uint32) (func() (bool, error), error) {
				calls++
				return func() (bool, error) { return true, nil }, nil
			}
			done := f.step(live, l.keepTagLive)
			if (calls > 0) != finalize || (len(done) > 0) != finalize {
				t.Fatalf("finalize=%v calls=%d done=%v", finalize, calls, done)
			}
		})
	}
}
