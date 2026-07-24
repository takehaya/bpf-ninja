package main

import (
	"sync"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/setmap"
)

func TestNewByteCapsNilWhenOff(t *testing.T) {
	if c := newByteCaps(false, 0); c != nil {
		t.Fatalf("newByteCaps(false, 0) = %v, want nil", c)
	}
	if c := newByteCaps(true, 0); c == nil {
		t.Fatal("newByteCaps(true, 0) = nil, want non-nil")
	}
	if c := newByteCaps(false, 1); c == nil {
		t.Fatal("newByteCaps(false, 1) = nil, want non-nil")
	}
}

func TestAddTagCapTransitionOnce(t *testing.T) {
	c := newByteCaps(true, 0)
	c.refreshLimits([]setmap.TagInfo{{Tag: 7, MaxBytes: 100}})
	ctr := c.counterFor(7)
	if c.counterFor(7) != ctr {
		t.Fatal("counterFor returned a different counter for the same tag")
	}

	if c.addTag(ctr, 99) {
		t.Fatal("capped below the limit")
	}
	if ctr.capped.Load() {
		t.Fatal("capped flag set below the limit")
	}
	if !c.addTag(ctr, 1) {
		t.Fatal("no capped transition at the limit")
	}
	if c.addTag(ctr, 50) {
		t.Fatal("capped transition reported twice")
	}
	if !ctr.capped.Load() {
		t.Fatal("capped flag not sticky")
	}
	if got := c.cappedTags(); len(got) != 1 || got[0] != 7 {
		t.Fatalf("cappedTags = %v, want [7]", got)
	}
}

func TestAddTagUncappedNeverCaps(t *testing.T) {
	c := newByteCaps(true, 0)
	ctr := c.counterFor(3) // no refreshLimits: limit stays 0 = uncapped
	if c.addTag(ctr, 1<<40) {
		t.Fatal("uncapped tag reported a cap transition")
	}
	if ctr.capped.Load() || c.anyCapped() {
		t.Fatal("uncapped tag marked capped")
	}
}

func TestEffectiveLimits(t *testing.T) {
	// Shared-tag entries must reduce deterministically whatever the
	// iteration order: 0 (uncapped) dominates, otherwise the max wins.
	infos := []setmap.TagInfo{
		{Tag: 1, MaxBytes: 100},
		{Tag: 1, MaxBytes: 200},
		{Tag: 2, MaxBytes: 300},
		{Tag: 2, MaxBytes: 0},
		{Tag: 3, MaxBytes: 0},
		{Tag: 3, MaxBytes: 50},
		{Tag: 0, MaxBytes: 42},
	}
	for range 2 { // forward and (via map re-iteration) arbitrary orders
		got := effectiveLimits(infos)
		if got[1] != 200 || got[2] != 0 || got[3] != 0 {
			t.Fatalf("effectiveLimits = %v, want {1:200 2:0 3:0}", got)
		}
		if _, hasZero := got[0]; hasZero {
			t.Fatal("tag 0 got a limit")
		}
		// reverse the slice to simulate a different iteration order
		for i, j := 0, len(infos)-1; i < j; i, j = i+1, j-1 {
			infos[i], infos[j] = infos[j], infos[i]
		}
	}
}

func TestRefreshLimitsRuntimeCap(t *testing.T) {
	c := newByteCaps(true, 0)
	ctr := c.counterFor(5)
	c.addTag(ctr, 500)

	// A cap added at runtime applies on the next write.
	c.refreshLimits([]setmap.TagInfo{{Tag: 5, MaxBytes: 400}})
	if !c.addTag(ctr, 1) {
		t.Fatal("no transition once a runtime cap dropped below the running total")
	}
	// Tag 0 never gets a counter from refresh.
	c.refreshLimits([]setmap.TagInfo{{Tag: 0, MaxBytes: 1}})
	c.mu.Lock()
	_, hasZero := c.tags[0]
	c.mu.Unlock()
	if hasZero {
		t.Fatal("refreshLimits created a counter for tag 0")
	}
}

func TestAddTagConcurrentSingleTransition(t *testing.T) {
	c := newByteCaps(true, 0)
	c.refreshLimits([]setmap.TagInfo{{Tag: 1, MaxBytes: 1000}})
	ctr := c.counterFor(1)

	const goroutines = 8
	const addsPer = 100
	transitions := make(chan struct{}, goroutines*addsPer)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range addsPer {
				if c.addTag(ctr, 10) {
					transitions <- struct{}{}
				}
			}
		})
	}
	wg.Wait()
	close(transitions)
	n := 0
	for range transitions {
		n++
	}
	if n != 1 {
		t.Fatalf("capped transitions = %d, want exactly 1", n)
	}
	if got := ctr.bytes.Load(); got != goroutines*addsPer*10 {
		t.Fatalf("bytes = %d, want %d (adds must not stop at the cap)", got, goroutines*addsPer*10)
	}
}

func TestTotalReached(t *testing.T) {
	c := newByteCaps(false, 100)
	if c.totalReached() {
		t.Fatal("totalReached before any bytes")
	}
	if c.addTotal(99) {
		t.Fatal("addTotal reported reached below the limit")
	}
	if !c.addTotal(1) {
		t.Fatal("addTotal did not report reached at the limit")
	}
	if !c.totalReached() {
		t.Fatal("totalReached false after the limit")
	}

	// perTag-only caps never report total reached.
	p := newByteCaps(true, 0)
	if p.addTotal(1 << 40) {
		t.Fatal("addTotal reported reached with totalLimit = 0")
	}
	if p.totalReached() {
		t.Fatal("totalReached with totalLimit = 0")
	}
}

func TestAllCapped(t *testing.T) {
	c := newByteCaps(true, 0)

	if c.allCapped(nil) {
		t.Fatal("allCapped(empty) must be false (nothing participates = keep running)")
	}
	// Only uncapped entries: nothing participates.
	if c.allCapped([]setmap.TagInfo{{Tag: 1}, {Tag: 2}}) {
		t.Fatal("uncapped-only snapshot reported all-capped")
	}

	infos := []setmap.TagInfo{
		{Tag: 1, MaxBytes: 10},
		{Tag: 2, MaxBytes: 10},
		{Tag: 3}, // uncapped: never participates
		{Tag: 0, MaxBytes: 10},
	}
	c.refreshLimits(infos)
	c.addTag(c.counterFor(1), 10)
	if c.allCapped(infos) {
		t.Fatal("tag 2 still active+uncapped but reported all-capped")
	}
	c.addTag(c.counterFor(2), 10)
	if !c.allCapped(infos) {
		t.Fatal("all capped entries reached their cap but not reported")
	}

	// A parked entry (state != active) counts as satisfied even without
	// a local counter.
	parked := []setmap.TagInfo{
		{Tag: 1, MaxBytes: 10},
		{Tag: 9, MaxBytes: 10, State: setmap.StateCapped},
	}
	if !c.allCapped(parked) {
		t.Fatal("parked entry not treated as capped")
	}

	// Mixed capped/uncapped entries on one tag: the tag is effectively
	// uncapped and must NOT participate — otherwise the exit could never
	// come (its counter can never cap).
	mixed := []setmap.TagInfo{
		{Tag: 1, MaxBytes: 10},
		{Tag: 5, MaxBytes: 10},
		{Tag: 5, MaxBytes: 0},
	}
	if !c.allCapped(mixed) {
		t.Fatal("effectively-uncapped mixed tag blocked the exit")
	}
	if c.allCapped([]setmap.TagInfo{{Tag: 5, MaxBytes: 10}, {Tag: 5}}) {
		t.Fatal("only-mixed snapshot has no participant and must be false")
	}
}

func TestActiveTags(t *testing.T) {
	infos := []setmap.TagInfo{
		{Tag: 1},
		{Tag: 1}, // dup
		{Tag: 2, State: setmap.StateCapped},
		{Tag: 3, State: setmap.StateFinalized},
		{Tag: 0},
	}
	got := activeTags(infos)
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("activeTags = %v, want [1]", got)
	}
}
