package main

import (
	"sync"
	"testing"
)

func TestNewByteCapsNilWhenOff(t *testing.T) {
	if c := newByteCaps(0, 0); c != nil {
		t.Fatalf("newByteCaps(0, 0) = %v, want nil", c)
	}
	if c := newByteCaps(1, 0); c == nil {
		t.Fatal("newByteCaps(1, 0) = nil, want non-nil")
	}
	if c := newByteCaps(0, 1); c == nil {
		t.Fatal("newByteCaps(0, 1) = nil, want non-nil")
	}
}

func TestAddTagCapTransitionOnce(t *testing.T) {
	c := newByteCaps(100, 0)
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
}

func TestAddTagConcurrentSingleTransition(t *testing.T) {
	c := newByteCaps(1000, 0)
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
	c := newByteCaps(0, 100)
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
	p := newByteCaps(100, 0)
	p.addTotal(1 << 40)
	if p.totalReached() {
		t.Fatal("totalReached with totalLimit = 0")
	}
}

func TestAllCapped(t *testing.T) {
	c := newByteCaps(10, 0)

	if c.allCapped(nil) {
		t.Fatal("allCapped(empty) must be false (no live tags = keep running)")
	}

	c.addTag(c.counterFor(1), 10)
	if !c.allCapped([]uint32{1}) {
		t.Fatal("single capped tag not reported as all-capped")
	}
	// A live tag with no traffic yet has no counter: not capped.
	if c.allCapped([]uint32{1, 2}) {
		t.Fatal("unseen tag counted as capped")
	}
	c.addTag(c.counterFor(2), 5)
	if c.allCapped([]uint32{1, 2}) {
		t.Fatal("uncapped tag counted as capped")
	}
	c.addTag(c.counterFor(2), 5)
	if !c.allCapped([]uint32{1, 2}) {
		t.Fatal("all tags capped but not reported")
	}
}

func TestAnyCapped(t *testing.T) {
	c := newByteCaps(10, 0)
	if c.anyCapped() {
		t.Fatal("anyCapped with no counters")
	}
	c.addTag(c.counterFor(1), 5)
	if c.anyCapped() {
		t.Fatal("anyCapped with only uncapped counters")
	}
	c.addTag(c.counterFor(1), 5)
	if !c.anyCapped() {
		t.Fatal("anyCapped false after a tag capped")
	}
}
