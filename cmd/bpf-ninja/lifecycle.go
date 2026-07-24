package main

import (
	"fmt"
	"os"

	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/setmap"
)

// capLifecycle drives the once-per-second snapshot work of the capture
// poll loop: refreshing per-entry cap limits, parking capped tags
// (state=capped), stepping the finalizer, and deciding when
// --exit-when-capped may stop the capture. Extracting it from
// pumpShards keeps the poll loop itself down to signal/count checks and
// makes the refresh → park → finalize → exit ordering a documented,
// unit-testable sequence.
type capLifecycle struct {
	caps           *byteCaps
	fin            *tagFinalizer
	sets           []*setmap.Set
	basePath       string
	exitWhenCapped bool

	// everActive remembers tags seen with an active entry during THIS
	// run. Entries already parked at startup (leftover state from a
	// previous run) never enter it, so they count as settled without
	// this process having produced their ack.
	everActive map[uint32]bool
	parkLogged map[uint32]bool
	errWarned  bool
}

func newCapLifecycle(caps *byteCaps, fin *tagFinalizer, sets []*setmap.Set, basePath string, exitWhenCapped bool) *capLifecycle {
	return &capLifecycle{
		caps:           caps,
		fin:            fin,
		sets:           sets,
		basePath:       basePath,
		exitWhenCapped: exitWhenCapped,
		everActive:     map[uint32]bool{},
		parkLogged:     map[uint32]bool{},
	}
}

// tick runs one snapshot cycle and reports whether --exit-when-capped
// is satisfied. Order matters and is part of the contract:
//
//  1. refresh limits (runtime cap changes apply)
//  2. park capped tags — self-healing: a capped tag is re-parked
//     whenever the snapshot still shows an active entry for it, so a
//     concurrent `set add` that clobbered the state write (or added a
//     new key under a capped tag) is healed within one cycle instead
//     of leaking kernel work forever
//  3. step the finalizer (park → quiesce → merge → state=finalized)
//  4. exit decision LAST, so a tag merged this cycle already counts —
//     and with --finalize-on-del the exit waits for every
//     participating tag's ack, making state=finalized the guaranteed
//     terminal state instead of racing the finalizer
//
// A snapshot read failure warns once and skips the cycle: nothing is
// parked, finalized, or exited on missing data.
func (l *capLifecycle) tick() (exitNow bool) {
	infos, err := unionTagInfos(l.sets)
	if err != nil {
		if !l.errWarned {
			fmt.Fprintf(os.Stderr, "warning: reading set map entries: %v (will keep capturing)\n", err)
			l.errWarned = true
		}
		return false
	}

	if l.caps != nil && l.caps.perTag {
		l.caps.refreshLimits(infos)
	}

	hasActive := map[uint32]bool{}
	for _, in := range infos {
		if in.Tag != 0 && in.State == setmap.StateActive {
			hasActive[in.Tag] = true
			l.everActive[in.Tag] = true
		}
	}

	if l.fin != nil && l.caps != nil {
		for _, tag := range l.caps.cappedTags() {
			if !hasActive[tag] {
				continue
			}
			ok := true
			for _, s := range l.sets {
				if _, serr := s.Def.SetState(tag, setmap.StateCapped); serr != nil {
					fmt.Fprintf(os.Stderr, "warning: parking capped tag %d: %v (will retry)\n", tag, serr)
					ok = false
				}
			}
			if ok && !l.parkLogged[tag] {
				l.parkLogged[tag] = true
				fmt.Fprintf(os.Stderr, "tag %d parked (state=capped)\n", tag)
			}
		}
	}

	if l.fin != nil {
		for _, tag := range l.fin.step(activeTags(infos)) {
			if err := l.fin.finalize(tag); err != nil {
				fmt.Fprintf(os.Stderr, "warning: %v\n", err)
				continue
			}
			for _, s := range l.sets {
				if _, serr := s.Def.SetState(tag, setmap.StateFinalized); serr != nil {
					fmt.Fprintf(os.Stderr, "warning: marking tag %d finalized: %v\n", tag, serr)
				}
			}
			fmt.Fprintf(os.Stderr, "tag %d finalized -> %s\n", tag, output.TagMergedPath(l.basePath, tag))
		}
	}

	if l.exitWhenCapped && l.caps != nil && l.exitReady(infos, hasActive) {
		fmt.Fprintf(os.Stderr, "\nevery entry with a max-bytes cap reached it (--exit-when-capped); stopping\n")
		return true
	}
	return false
}

// exitReady reports whether every participating tag (effective cap > 0)
// is settled. A tag with an active entry is settled only when its
// counter capped AND no finalizer is configured — with --finalize-on-del
// a capped-but-still-active tag must first be parked and finalized. A
// tag with no active entry is settled when this run produced its ack
// (merged), or when it was never active in this run at all (parked by a
// previous run: not this run's job, counts immediately — so a capture
// started against a fully pre-parked map exits right away instead of
// idling forever). No participating tag at all = not ready.
func (l *capLifecycle) exitReady(infos []setmap.TagInfo, hasActive map[uint32]bool) bool {
	participating := false
	for tag, lim := range effectiveLimits(infos) {
		if lim == 0 {
			continue
		}
		participating = true
		if hasActive[tag] {
			if l.fin != nil || !l.caps.isCapped(tag) {
				return false
			}
			continue
		}
		if l.fin != nil && l.everActive[tag] && !l.fin.isMerged(tag) {
			return false
		}
	}
	return participating
}
