package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/follow"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/program"
	"github.com/takehaya/bpf-ninja/internal/record"
	"golang.org/x/sys/unix"
)

// A capture at a hook inject-run generated follows that hook across program
// instances: a reload gives the datapath new programs, and the capture's
// observers stay on the old ones. The manager finds each later program that
// carries one of the capture's hooks and gives it observers in the site of
// the first initial target with that
// function name, so its records join the same rings, counters and pcapng
// interface.
//
// It learns of a program in two ways. It subscribes to every inject-run it
// can reach (internal/follow): inject-run announces each load and keeps the
// loader stopped until the capture has attached, so the program cannot run
// unobserved. It also polls BPF program IDs, which finds the programs of an
// inject-run it cannot reach. A program found only that way may have run
// before its observers were attached, so that attach is reported as a gap,
// with the time since the program was loaded, and makes the capture's
// status incomplete. An observer that cannot be attached is a gap too; it
// never stops the capture.
//
// An observer's link holds a reference on its program. The capture keeps
// every program it observes loaded until the capture exits.

const (
	// followPollInterval is how often the manager looks for new program IDs.
	followPollInterval = 20 * time.Millisecond
	// followRedialInterval is how often it looks for inject-run processes
	// that started after the capture.
	followRedialInterval = 2 * time.Second
	// followAnnounceGrace is how long an attach found by polling waits for
	// its announcement before it counts as late. The poller can see a new
	// ID a moment before the capture reads inject-run's message.
	followAnnounceGrace = follow.HoldDeadline
)

// Gap reasons, as printed in a FOLLOW GAP line.
const (
	gapLate             = "late"
	gapAttachFailed     = "attach_failed"
	gapFilterUnresolved = "filter_unresolved"
	gapLayoutChanged    = "layout_changed"
	gapObservedByOther  = "observed_by_other"
)

// followStats are the follow fields of the capture's status line.
type followStats struct {
	attached atomic.Uint64 // follower observers attached to other programs
	held     atomic.Uint64 // of those, attached while the load was held
	gaps     atomic.Uint64 // late or failed attaches
	gapMs    atomic.Uint64 // unobserved time of those gaps
}

func (s *followStats) String() string {
	return fmt.Sprintf("follow_attached=%d follow_held=%d follow_gaps=%d follow_gap_ms=%d",
		s.attached.Load(), s.held.Load(), s.gaps.Load(), s.gapMs.Load())
}

// followProgram carries at least one of the capture's hooks.
type followProgram struct {
	id       uint32
	loadedAt time.Duration // CLOCK_BOOTTIME of the load
	targets  []attach.Target
	// failed are the hooks the program has but that did not resolve to a
	// target, with the reason.
	failed map[string]error
	close  func()
}

// followSource is the kernel as the manager sees it; tests replace it.
type followSource interface {
	// NextID returns the smallest program ID above after.
	NextID(after uint32) (uint32, bool)
	// Open returns the program if it has one of the named hooks; a program
	// that is not a target returns nil without an error.
	Open(id uint32, hooks []string) (*followProgram, error)
	// Now is the current CLOCK_BOOTTIME.
	Now() time.Duration
}

// followProbe is the part of program.Probe the manager uses.
type followProbe interface {
	AttachFollower(slot int, t attach.Target, tf filter.TargetFilters, rec *record.Layout) ([]attach.TargetDiagnostic, error)
	DetachFollowers(progID uint32)
	ObserverLinks(progID uint32) int
}

// followConfig is how the capture resolved its initial targets, to be
// applied to each later one.
type followConfig struct {
	// boundaryID is the last program present when capture startup began;
	// following starts above it.
	boundaryID uint32
	startedAt  time.Duration
	// filters resolves the capture's --arg-filter expressions against a
	// target's own parameters.
	filters func(t attach.Target) (filter.TargetFilters, error)
	// layout builds a target's record layout; nil when the capture records
	// nothing.
	layout func(t attach.Target, tf filter.TargetFilters) (*record.Layout, error)
	// newClient subscribes to the reachable inject-run processes; nil
	// leaves the capture to polling alone.
	newClient func(hooks []string, handle follow.Handler) followClient
	// lock serializes admission and attach with other capture processes.
	lock   func() (func(), error)
	stderr io.Writer
	logf   func(format string, args ...any)
}

// followClient is the capture's follow.Client; tests replace it.
type followClient interface {
	// Dial connects to supervisors not yet connected and returns the
	// number of connections.
	Dial() int
	Close()
}

// pendingAttach is a later program with observers attached whose load may
// or may not have been held for them.
type pendingAttach struct {
	funcs []string
	ms    uint64        // from the program's load to the attach
	at    time.Duration // when it was attached
	// announced is set once inject-run's message for the program arrived;
	// its resume then decides, and the grace period no longer applies.
	announced bool
}

// followReadFailure is a program the poller could not classify. It remains
// separate from lastID so one unreadable program cannot hide later IDs.
type followReadFailure struct {
	at       time.Duration
	err      error
	reported bool
}

type followManager struct {
	probe  followProbe
	source followSource
	cfg    followConfig
	// slots maps a hook function name to the site its followers join.
	slots map[string]int
	names []string
	stats followStats

	mu     sync.Mutex // serializes examine; guards the fields below
	lastID uint32
	retry  map[uint32]*followReadFailure
	// pending are the attaches not yet counted as held or late. connected
	// is the number of inject-run processes the capture is subscribed to.
	pending   map[uint32]*pendingAttach
	client    followClient
	connected int
	// examined holds the programs already looked at, with the time, so one
	// that reaches the manager both by announcement and by polling is
	// attached, or reported, once.
	examined map[uint32]time.Duration

	stopOnce sync.Once
	stopCh   chan struct{}
	done     chan struct{}
}

// newFollowManager returns the manager for a capture, or nil when none of
// its attached targets is a generated hook.
func newFollowManager(probe followProbe, source followSource, targets []attach.Target, attached []int, cfg followConfig) *followManager {
	m := &followManager{probe: probe, source: source, cfg: cfg, slots: map[string]int{},
		lastID:   cfg.boundaryID,
		pending:  map[uint32]*pendingAttach{},
		retry:    map[uint32]*followReadFailure{},
		examined: map[uint32]time.Duration{},
		stopCh:   make(chan struct{}), done: make(chan struct{})}
	for _, i := range attached {
		t := targets[i]
		if !t.Generated {
			continue
		}
		if _, ok := m.slots[t.FuncName]; !ok {
			m.slots[t.FuncName] = i
			m.names = append(m.names, t.FuncName)
		}
	}
	if len(m.slots) == 0 {
		return nil
	}
	return m
}

// start subscribes to the reachable inject-run processes and begins polling
// for programs loaded after the startup boundary.
func (m *followManager) start() {
	if m.cfg.lock != nil {
		unlock, err := m.cfg.lock()
		if err == nil {
			unlock()
		} else if !errors.Is(err, program.ErrFollowerLockTimeout) {
			_, _ = fmt.Fprintf(m.cfg.stderr, "warning: following cannot set up the follower lock: %v\n", err)
		}
	}
	if m.cfg.newClient != nil {
		m.client = m.cfg.newClient(m.names, m.announced)
		m.redial()
	}
	if m.connected == 0 {
		_, _ = fmt.Fprintf(m.cfg.stderr, "following %d generated hook(s) by polling: no inject-run is reachable in this network namespace, so a program loaded later may run before it is observed\n", len(m.names))
	}
	go func() {
		defer close(m.done)
		tick := time.NewTicker(followPollInterval)
		defer tick.Stop()
		lastRedial := m.source.Now()
		for {
			m.poll()
			m.mu.Lock()
			m.expirePending()
			now := m.source.Now()
			slow := now-lastRedial >= followRedialInterval
			if slow {
				lastRedial = now
				m.forgetExamined(now)
			}
			m.mu.Unlock()
			if slow && m.client != nil {
				m.redial() // an inject-run may have started since
			}
			select {
			case <-m.stopCh:
				return
			case <-tick.C:
			}
		}
	}()
}

// redial connects to the inject-run processes not connected yet.
func (m *followManager) redial() {
	n := m.client.Dial()
	m.mu.Lock()
	defer m.mu.Unlock()
	if n != m.connected {
		m.cfg.logf("following %d generated hook(s): subscribed to %d inject-run process(es); their loads wait for this capture's observers", len(m.names), n)
	}
	m.connected = n
}

// stop ends polling and the subscriptions, and waits for an attach in
// progress. The capture calls it before it detaches its observers.
func (m *followManager) stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() { close(m.stopCh) })
	<-m.done
	if m.client != nil {
		m.client.Close()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanUnobservedAtStop()
	for id := range m.pending {
		m.settle(id, false)
	}
	for id, failure := range m.retry {
		if !failure.reported {
			m.gap(id, "unknown", gapAttachFailed, failure.at, failure.err)
		}
		delete(m.retry, id)
	}
}

// scanUnobservedAtStop classifies programs loaded beyond the poll cursor
// without attaching to them, since the capture is already stopping.
func (m *followManager) scanUnobservedAtStop() {
	for {
		id, ok := m.source.NextID(m.lastID)
		if !ok {
			return
		}
		m.lastID = id
		if _, done := m.examined[id]; done || m.probe.ObserverLinks(id) > 0 {
			continue
		}
		p, err := m.source.Open(id, m.names)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			m.rememberReadFailure(id, err)
			continue
		}
		if p == nil {
			continue
		}
		for name, err := range p.failed {
			m.observationGap(p, name, gapAttachFailed, err)
		}
		for _, target := range p.targets {
			m.observationGap(p, target.FuncName, gapAttachFailed, program.ErrProbeStopped)
		}
		p.close()
		m.examined[id] = m.source.Now()
	}
}

func (m *followManager) stopped() bool {
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

// poll retries unreadable programs and examines every program ID above the
// last one seen. A read failure never holds the scan cursor back.
func (m *followManager) poll() {
	m.mu.Lock()
	for id, failure := range m.retry {
		if err := m.examine(id); err != nil {
			failure.err = err
			continue
		}
		delete(m.retry, id)
		if failure.reported {
			delete(m.pending, id)
		} else if m.connected == 0 {
			m.settle(id, false)
		}
	}
	m.mu.Unlock()
	for !m.stopped() {
		m.mu.Lock()
		id, ok := m.source.NextID(m.lastID)
		if !ok {
			m.mu.Unlock()
			return
		}
		m.lastID = id
		err := m.examine(id)
		if err != nil {
			m.rememberReadFailure(id, err)
		}
		// Without a subscription nothing can have held the load.
		if err == nil && m.connected == 0 {
			m.settle(id, false)
		}
		m.mu.Unlock()
	}
}

func (m *followManager) rememberReadFailure(id uint32, err error) *followReadFailure {
	failure := m.retry[id]
	if failure == nil {
		failure = &followReadFailure{at: m.source.Now()}
		m.retry[id] = failure
	}
	failure.err = err
	return failure
}

// announced handles inject-run's message that it loaded a program with one
// of the capture's hooks and holds the loader. It attaches the observers;
// the returned function receives whether the loader was held until then.
func (m *followManager) announced(l follow.Load) func(held bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.examine(l.ProgID); err != nil {
		failure := m.rememberReadFailure(l.ProgID, err)
		if !failure.reported {
			for _, name := range l.Hooks {
				if _, followed := m.slots[name]; followed {
					m.reportGap(l.ProgID, name, gapAttachFailed, 0, err)
				}
			}
			failure.reported = true
		}
	} else {
		delete(m.retry, l.ProgID)
	}
	if p := m.pending[l.ProgID]; p != nil {
		p.announced = true
	}
	return func(held bool) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.settle(l.ProgID, held)
	}
}

// examine attaches the capture's observers to program id if it is a later
// program with one of the capture's hooks. The attach stays pending until
// settle says whether the program could run before it.
func (m *followManager) examine(id uint32) error {
	if _, done := m.examined[id]; done || m.probe.ObserverLinks(id) > 0 {
		return nil // already looked at, or an initial target
	}
	p, err := m.source.Open(id, m.names)
	if errors.Is(err, os.ErrNotExist) {
		m.examined[id] = m.source.Now()
		return nil
	}
	if err != nil {
		return err
	}
	m.examined[id] = m.source.Now()
	if p == nil {
		return nil
	}
	loadedAt := p.loadedAt
	pending := &pendingAttach{}
	attached := m.observe(p, func(funcName string) {
		m.stats.attached.Add(1)
		pending.funcs = append(pending.funcs, funcName)
	})
	if !attached {
		return nil
	}
	pending.at = m.source.Now()
	if d := pending.at - loadedAt; d > 0 {
		pending.ms = uint64((d + time.Millisecond - 1) / time.Millisecond)
	}
	m.pending[id] = pending
	return nil
}

// forgetExamined drops the programs the poller has passed long enough ago
// that no announcement for them can still be on its way.
func (m *followManager) forgetExamined(now time.Duration) {
	for id, at := range m.examined {
		if id <= m.lastID && now-at > 10*follow.HoldDeadline {
			delete(m.examined, id)
		}
	}
}

// settle counts the pending attach of program id: held when the loader was
// stopped until the observers were attached, else as a late gap.
func (m *followManager) settle(id uint32, held bool) {
	p := m.pending[id]
	if p == nil {
		return
	}
	delete(m.pending, id)
	for _, funcName := range p.funcs {
		if held {
			m.stats.held.Add(1)
			m.cfg.logf("following %s to program id=%d: attached while its load was held", funcName, id)
			continue
		}
		m.reportGap(id, funcName, gapLate, p.ms, nil)
	}
}

// expirePending counts as late the attaches the poller made for which no
// announcement came within the grace period.
func (m *followManager) expirePending() {
	now := m.source.Now()
	for id, p := range m.pending {
		if !p.announced && now-p.at >= followAnnounceGrace {
			m.settle(id, false)
		}
	}
}

// observe attaches the capture's observers to each hook of p and closes p.
// It calls onAttach per attached hook, reports each failure as a gap
// counted from p's load, and returns whether any hook was attached.
func (m *followManager) observe(p *followProgram, onAttach func(funcName string)) (attached bool) {
	defer p.close()
	var attachedNames []string
	for name, err := range p.failed {
		m.observationGap(p, name, gapAttachFailed, err)
	}
	if len(p.targets) > 0 && m.cfg.lock != nil {
		unlock, err := m.cfg.lock()
		if err != nil {
			reason := gapAttachFailed
			if errors.Is(err, program.ErrFollowerLockTimeout) {
				reason = gapObservedByOther
			}
			m.observationGap(p, p.targets[0].FuncName, reason, err)
			return false
		}
		defer unlock()
	}
	for i, t := range p.targets {
		if m.stopped() {
			m.reportStoppedTargets(p, p.targets[i:])
			return attached
		}
		reason, err := m.attach(t)
		if errors.Is(err, program.ErrProbeStopped) {
			m.reportStoppedTargets(p, p.targets[i:])
			return attached
		}
		if err != nil {
			m.observationGap(p, t.FuncName, reason, err)
			if reason == gapObservedByOther {
				m.probe.DetachFollowers(p.id)
				return false
			}
			continue
		}
		attached = true
		attachedNames = append(attachedNames, t.FuncName)
	}
	for _, name := range attachedNames {
		onAttach(name)
	}
	return attached
}

func (m *followManager) reportStoppedTargets(p *followProgram, targets []attach.Target) {
	for _, target := range targets {
		m.observationGap(p, target.FuncName, gapAttachFailed, program.ErrProbeStopped)
	}
}

func (m *followManager) observationGap(p *followProgram, name, reason string, err error) {
	since := p.loadedAt
	if since < m.cfg.startedAt {
		since = m.cfg.startedAt
	}
	m.gap(p.id, name, reason, since, err)
}

// attach resolves the capture's filters and record layout against t and
// attaches its observers. On failure it returns the gap reason.
func (m *followManager) attach(t attach.Target) (string, error) {
	tf, err := m.cfg.filters(t)
	if err != nil {
		return gapFilterUnresolved, err
	}
	var rec *record.Layout
	if m.cfg.layout != nil {
		if rec, err = m.cfg.layout(t, tf); err != nil {
			return gapLayoutChanged, err
		}
	}
	notes, err := m.probe.AttachFollower(m.slots[t.FuncName], t, tf, rec)
	for _, n := range notes {
		m.cfg.logf("%s", n)
	}
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, program.ErrLayoutChanged):
		return gapLayoutChanged, err
	case errors.Is(err, program.ErrObservedByOther):
		return gapObservedByOther, err
	}
	return gapAttachFailed, err
}

// gap reports a hook of program id that ran, or may have run, without the
// capture's observers since the given time. For a late attach the
// unobserved time ends now; for a failed one it is the time so far, and the
// hook stays unobserved.
func (m *followManager) gap(id uint32, funcName, reason string, since time.Duration, err error) {
	ms := uint64(0)
	if d := m.source.Now() - since; d > 0 {
		ms = uint64((d + time.Millisecond - 1) / time.Millisecond)
	}
	m.reportGap(id, funcName, reason, ms, err)
}

func (m *followManager) reportGap(id uint32, funcName, reason string, ms uint64, err error) {
	m.stats.gaps.Add(1)
	m.stats.gapMs.Add(ms)
	if err != nil {
		_, _ = fmt.Fprintf(m.cfg.stderr, "warning: following %s to program id=%d: %v\n", funcName, id, err)
	}
	_, _ = fmt.Fprintf(m.cfg.stderr, "warning: FOLLOW GAP: prog=%d func=%s reason=%s unobserved_ms=%d\n", id, funcName, reason, ms)
}

// bootNow reads CLOCK_BOOTTIME, the clock of a program's load time.
func bootNow() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}

// kernelFollowSource finds later programs in the running kernel.
type kernelFollowSource struct {
	hook         *hook.Hook // the capture's hook kind
	allowSlot    bool
	openProg     func(uint32) (*ebpf.Program, ebpf.ProgramType, time.Duration, error)
	btfSpec      func(*ebpf.Program) (*btf.Spec, error)
	availability func(*attach.ProgInfo, string) attach.FuncAvailability
}

func (s *kernelFollowSource) open(id uint32) (*ebpf.Program, ebpf.ProgramType, time.Duration, error) {
	if s.openProg != nil {
		return s.openProg(id)
	}
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return nil, 0, 0, err
	}
	info, err := prog.Info()
	if err != nil {
		_ = prog.Close()
		return nil, 0, 0, err
	}
	loadedAt, _ := info.LoadTime()
	return prog, info.Type, loadedAt, nil
}

func (s *kernelFollowSource) Now() time.Duration { return bootNow() }

func (s *kernelFollowSource) NextID(after uint32) (uint32, bool) {
	id, err := ebpf.ProgramGetNextID(ebpf.ProgramID(after))
	return uint32(id), err == nil
}

func (s *kernelFollowSource) Open(id uint32, hooks []string) (*followProgram, error) {
	// Most new programs are not candidates (other hook kinds, the capture's
	// own observers, inject-run's trial loads, which are gone by now), so
	// check the type before parsing any BTF.
	prog, progType, loadedAt, err := s.open(id)
	if err != nil {
		return nil, err
	}
	if h, known := hook.ByProgramType(progType); !known || h != s.hook {
		if prog != nil {
			_ = prog.Close()
		}
		return nil, nil
	}
	loadSpec := s.btfSpec
	if loadSpec == nil {
		loadSpec = attach.BTFSpec
	}
	spec, err := loadSpec(prog)
	if err != nil {
		if prog != nil {
			_ = prog.Close()
		}
		if errors.Is(err, ebpf.ErrNotSupported) {
			return nil, nil // programs without BTF cannot carry a generated hook
		}
		return nil, err
	}
	pi := &attach.ProgInfo{ProgID: id, Program: prog, Type: progType, HookType: progType, Spec: spec}
	closeProg := func() {
		if prog != nil {
			_ = prog.Close()
		}
	}
	p := &followProgram{id: id, loadedAt: loadedAt, failed: map[string]error{}, close: closeProg}
	for _, name := range hooks {
		// A function that only has the hook's name is not the hook, and one
		// the verifier removed has nothing to observe.
		availability := pi.FuncAvailability(name)
		if s.availability != nil {
			availability = s.availability(pi, name)
		}
		if !attach.IsGeneratedHook(spec, name) || availability.Unavailable() {
			continue
		}
		targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{pi}, []string{name}, s.allowSlot)
		if err != nil {
			p.failed[name] = err
			continue
		}
		p.targets = append(p.targets, targets...)
	}
	if len(p.targets) == 0 && len(p.failed) == 0 {
		p.close()
		return nil, nil
	}
	return p, nil
}
