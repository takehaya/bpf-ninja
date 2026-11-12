package program

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/record"
	"golang.org/x/sys/unix"
)

// followerSnapKeys is the number of followed programs that can record in
// filter mode at once. Each needs its own snapshot key, because an observer
// of one program can interrupt an observer of another on the same CPU.
const followerSnapKeys = 1024

// ErrProbeStopped is returned when a target is added after Quiesce.
var ErrProbeStopped = errors.New("the capture has stopped")

// ErrObservedByOther is returned when another capture or tool already has
// a tracing link on a follower target, or the link list cannot be read.
var ErrObservedByOther = errors.New("another observer is attached to the program")

// ErrLayoutChanged is returned for a target whose record layout decodes
// differently from the layout of the site it would join.
var ErrLayoutChanged = errors.New("the record layout differs from the site's")

// AttachFollower attaches this capture's observers to t, a program loaded
// after the capture started that has the function the initial target at
// index slot has. The observers are built like the initial ones, with the
// same maps and the slot's site id, so their records reach the same rings,
// counters and pcapng interface; tf and rec are t's own argument filters and
// record layout, resolved against its BTF. rec must decode like the slot's
// layout (record.SameComment), since the reader has only that one.
//
// A failure leaves the probe as it was. The returned diagnostics do not
// refuse the target.
func (p *Probe) AttachFollower(slot int, t attach.Target, tf filter.TargetFilters, rec *record.Layout) ([]attach.TargetDiagnostic, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	plan := p.plan
	switch {
	case p.detached:
		return nil, ErrProbeStopped
	case plan == nil:
		return nil, errors.New("this probe takes no further targets")
	case plan.gated:
		return nil, errors.New("a gated (entry + exit) capture takes exactly one target function")
	case slot < 0 || slot >= plan.slots:
		return nil, fmt.Errorf("site %d is not one of the capture's %d sites", slot, plan.slots)
	}
	if h, ok := hook.ByProgramType(t.EffectiveHookType()); !ok || h != plan.hook {
		return nil, fmt.Errorf("program (id=%d) is not a %s program", t.ProgID, plan.hook.Kind)
	}
	var slotRec *record.Layout
	if plan.records != nil {
		slotRec = plan.records[slot]
	}
	if !record.SameComment(slotRec, rec) {
		return nil, ErrLayoutChanged
	}
	total, scanErr := tracingLinksOn(t.ProgID)
	if err := followerLinkDecision(total, p.observerLinksLocked(t.ProgID), scanErr); err != nil {
		return nil, err
	}
	// The freplace checks need the links as they are now, not as they were
	// when the capture started.
	guard, err := attach.NewExtensionGuard()
	if err != nil {
		return nil, err
	}
	p.extensionGuard = guard

	snapKey := slot
	ownKey := rec != nil && rec.Mode == record.ModeFilter
	if ownKey {
		if len(rec.Fields) > plan.maxFields {
			return nil, fmt.Errorf("the record has %d fields, the capture's sites at most %d", len(rec.Fields), plan.maxFields)
		}
		if len(p.snapFree) == 0 {
			return nil, fmt.Errorf("%d followed programs already record filter fields", followerSnapKeys)
		}
		snapKey = p.snapFree[len(p.snapFree)-1]
		p.snapFree = p.snapFree[:len(p.snapFree)-1]
	}
	startProgs := len(p.progs)
	notes, reason, err := p.attachTarget(plan, slot, snapKey, t, tf, rec)
	if err != nil {
		if ownKey {
			p.snapFree = append(p.snapFree, snapKey)
		}
		if reason != "" {
			err = fmt.Errorf("%s: %w", reason, err)
		}
		return notes, err
	}
	if ownKey {
		if p.followerSnap == nil {
			p.followerSnap = map[*ebpf.Program]int{}
		}
		for _, pr := range p.progs[startProgs:] {
			p.followerSnap[pr] = snapKey
		}
	}
	return notes, nil
}

// DetachFollowers rolls back this capture's observers on one follower program.
func (p *Probe) DetachFollowers(progID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.progs) - 1; i >= 0; i-- {
		pr := p.progs[i]
		if p.owner[pr] != progID {
			continue
		}
		_ = p.links[i].Close()
		_ = pr.Close()
		delete(p.owner, pr)
		if snapKey, ok := p.followerSnap[pr]; ok {
			p.snapFree = append(p.snapFree, snapKey)
			delete(p.followerSnap, pr)
		}
		p.links = append(p.links[:i], p.links[i+1:]...)
		p.progs = append(p.progs[:i], p.progs[i+1:]...)
	}
}

// ObserverLinks reports how many of this probe's links are attached to the
// program with the given ID. Each holds one kernel reference on it.
func (p *Probe) ObserverLinks(progID uint32) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.observerLinksLocked(progID)
}

func (p *Probe) observerLinksLocked(progID uint32) int {
	if len(p.links) != len(p.progs) {
		return 0
	}
	n := 0
	for _, pr := range p.progs {
		if p.owner[pr] == progID {
			n++
		}
	}
	return n
}

func followerLinkDecision(total, own int, scanErr error) error {
	if scanErr != nil {
		return fmt.Errorf("%w: cannot read all tracing links: %v", ErrObservedByOther, scanErr)
	}
	if total != own {
		return fmt.Errorf("%w: found %d tracing links, %d held by this capture", ErrObservedByOther, total, own)
	}
	return nil
}

// tracingLinksOn counts the tracing links whose target object has the given
// ID. A link being published is retried; any unreadable walk fails closed.
func tracingLinksOn(progID uint32) (int, error) {
	return tracingLinksOnWith(func() (int, error) { return scanTracingLinksOn(progID) })
}

func tracingLinksOnWith(scan func() (int, error)) (int, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var n int
		n, err = scan()
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, unix.EAGAIN) {
			return 0, err
		}
		time.Sleep(time.Millisecond)
	}
	return 0, err
}

func scanTracingLinksOn(progID uint32) (int, error) {
	it := new(link.Iterator)
	defer it.Close()
	n := 0
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			return 0, err
		}
		if info.Type != link.TracingType {
			continue
		}
		if tr := info.Tracing(); tr != nil && tr.TargetObjectId == progID {
			n++
		}
	}
	if it.Err() != nil {
		return 0, it.Err()
	}
	return n, nil
}
