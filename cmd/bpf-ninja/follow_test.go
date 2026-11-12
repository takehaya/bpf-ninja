package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/follow"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
	"github.com/takehaya/bpf-ninja/internal/program"
	"github.com/takehaya/bpf-ninja/internal/record"
)

// fakeFollowSource is a kernel with a fixed set of programs.
type fakeFollowSource struct {
	now     time.Duration
	progs   map[uint32]*followProgram // candidates; other IDs are not
	maxID   uint32
	opened  []uint32
	closed  int
	openErr map[uint32]error
}

type concurrentFollowSource struct {
	firstOpen  chan struct{}
	secondOpen chan struct{}
	release    chan struct{}
	opens      atomic.Int32
}

func (s *concurrentFollowSource) Now() time.Duration { return time.Second }
func (s *concurrentFollowSource) NextID(after uint32) (uint32, bool) {
	return 6, after < 6
}
func (s *concurrentFollowSource) Open(id uint32, _ []string) (*followProgram, error) {
	switch s.opens.Add(1) {
	case 1:
		close(s.firstOpen)
		<-s.release
	case 2:
		close(s.secondOpen)
	}
	return &followProgram{id: id, loadedAt: time.Second, targets: []attach.Target{followTarget(id, "hook_a")}, close: func() {}}, nil
}

func (s *fakeFollowSource) Now() time.Duration { return s.now }
func (s *fakeFollowSource) NextID(after uint32) (uint32, bool) {
	return after + 1, after < s.maxID
}
func (s *fakeFollowSource) Open(id uint32, _ []string) (*followProgram, error) {
	if err := s.openErr[id]; err != nil {
		return nil, err
	}
	s.opened = append(s.opened, id)
	p := s.progs[id]
	if p != nil {
		p.id, p.close = id, func() { s.closed++ }
	}
	return p, nil
}

// fakeFollowProbe records the attaches and fails those in errs.
type fakeFollowProbe struct {
	observed map[uint32]int
	errs     map[uint32]error
	attached []string
}

func (p *fakeFollowProbe) ObserverLinks(id uint32) int { return p.observed[id] }
func (p *fakeFollowProbe) DetachFollowers(id uint32) {
	p.observed[id] = 0
	prefix := fmt.Sprintf("%d/", id)
	p.attached = slices.DeleteFunc(p.attached, func(s string) bool { return strings.HasPrefix(s, prefix) })
}
func (p *fakeFollowProbe) AttachFollower(slot int, t attach.Target, tf filter.TargetFilters, rec *record.Layout) ([]attach.TargetDiagnostic, error) {
	if err := p.errs[t.ProgID]; err != nil {
		return nil, err
	}
	p.observed[t.ProgID]++
	p.attached = append(p.attached, fmt.Sprintf("%d/%s@%d", t.ProgID, t.FuncName, slot))
	return nil, nil
}

func followTarget(id uint32, name string) attach.Target {
	return attach.Target{ProgID: id, FuncName: name, Generated: true}
}

func TestNoFollowUsesOriginMainLoader(t *testing.T) {
	got := runtime.FuncForPC(reflect.ValueOf(captureLoadProbe(false)).Pointer()).Name()
	want := runtime.FuncForPC(reflect.ValueOf(program.LoadMultiPointRecord).Pointer()).Name()
	if got != want {
		t.Fatalf("--no-follow loader=%s, want %s", got, want)
	}
}

func followSpec(t *testing.T, tagged bool) *btf.Spec {
	t.Helper()
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}}
	var tags []string
	if tagged {
		tags = []string{hookabi.HookTag}
	}
	builder, err := btf.NewBuilder([]btf.Type{
		&btf.Func{Name: "entry", Type: proto, Linkage: btf.GlobalFunc},
		&btf.Func{Name: "hook_a", Type: proto, Linkage: btf.GlobalFunc, Tags: tags},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestKernelFollowSourceUsesExplicitHookRegardlessOfLoadTime(t *testing.T) {
	spec := followSpec(t, true)
	h, _ := hook.ByProgramType(ebpf.XDP)
	s := &kernelFollowSource{
		hook: h,
		openProg: func(uint32) (*ebpf.Program, ebpf.ProgramType, time.Duration, error) {
			return nil, ebpf.XDP, time.Second, nil
		},
		btfSpec: func(*ebpf.Program) (*btf.Spec, error) { return spec, nil },
	}
	p, err := s.Open(7, []string{"hook_a"})
	if err != nil || p == nil || len(p.targets) != 1 {
		t.Fatalf("generated hook loaded before capture start disappeared: %+v", p)
	}
}

func TestKernelFollowSourceRejectsHookLookalikes(t *testing.T) {
	h, _ := hook.ByProgramType(ebpf.XDP)
	for _, tc := range []struct {
		name         string
		progType     ebpf.ProgramType
		tagged       bool
		availability attach.FuncAvailability
	}{
		{"wrong program type", ebpf.SchedCLS, true, attach.FuncAvailability{}},
		{"missing hook tag", ebpf.XDP, false, attach.FuncAvailability{}},
		{"absent func_info", ebpf.XDP, true, attach.FuncAvailability{Reason: attach.FuncAbsent}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &kernelFollowSource{
				hook: h,
				openProg: func(uint32) (*ebpf.Program, ebpf.ProgramType, time.Duration, error) {
					return nil, tc.progType, time.Second, nil
				},
				btfSpec: func(*ebpf.Program) (*btf.Spec, error) { return followSpec(t, tc.tagged), nil },
				availability: func(*attach.ProgInfo, string) attach.FuncAvailability {
					return tc.availability
				},
			}
			if p, err := s.Open(7, []string{"hook_a"}); err != nil || p != nil {
				t.Fatalf("lookalike hook accepted: program=%+v err=%v", p, err)
			}
		})
	}
}

func TestKernelFollowSourceSkipsProgramWithoutBTF(t *testing.T) {
	h, _ := hook.ByProgramType(ebpf.XDP)
	s := &kernelFollowSource{
		hook: h,
		openProg: func(uint32) (*ebpf.Program, ebpf.ProgramType, time.Duration, error) {
			return nil, ebpf.XDP, time.Second, nil
		},
		btfSpec: func(*ebpf.Program) (*btf.Spec, error) {
			return nil, fmt.Errorf("BTF unavailable: %w", ebpf.ErrNotSupported)
		},
	}
	if p, err := s.Open(7, []string{"hook_a"}); err != nil || p != nil {
		t.Fatalf("Open on a program without BTF = %+v, %v; want nil, nil", p, err)
	}
}

// hostlessSource keeps a kernelFollowSource's Open and hides the host's
// program IDs, so a stop-time scan run as root finds nothing to report.
type hostlessSource struct{ *kernelFollowSource }

func (hostlessSource) NextID(uint32) (uint32, bool) { return 0, false }

func TestFollowManagerReportsAnnouncedReadFailureAtStop(t *testing.T) {
	for _, failAt := range []string{"open", "btf"} {
		t.Run(failAt, func(t *testing.T) {
			h, _ := hook.ByProgramType(ebpf.XDP)
			src := &kernelFollowSource{
				hook: h,
				openProg: func(uint32) (*ebpf.Program, ebpf.ProgramType, time.Duration, error) {
					if failAt == "open" {
						return nil, 0, 0, syscall.EMFILE
					}
					return nil, ebpf.XDP, time.Second, nil
				},
				btfSpec: func(*ebpf.Program) (*btf.Spec, error) { return nil, syscall.EMFILE },
			}
			probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
			var stderr bytes.Buffer
			m := newFollowManager(probe, hostlessSource{src}, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{stderr: &stderr, logf: func(string, ...any) {}})
			m.announced(follow.Load{ProgID: 6, Hooks: []string{"hook_a"}})(true)
			if m.stats.gaps.Load() != 0 || stderr.Len() != 0 {
				t.Fatalf("announced read failure was reported before retry: %s; stderr=%q", m.stats.String(), stderr.String())
			}
			close(m.done)
			m.stop()
			if got := m.stats.String(); m.stats.gaps.Load() != 1 ||
				strings.Count(stderr.String(), "func=unknown reason=attach_failed") != 1 {
				t.Fatalf("announced read failure at stop: %s; stderr=%q", got, stderr.String())
			}
		})
	}
}

func TestFollowManagerRetriesReadFailure(t *testing.T) {
	src := &fakeFollowSource{now: time.Second, maxID: 6, openErr: map[uint32]error{6: syscall.EMFILE}, progs: map[uint32]*followProgram{
		6: {loadedAt: time.Second, targets: []attach.Target{followTarget(6, "hook_a")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: io.Discard, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
	})
	m.poll()
	delete(src.openErr, 6)
	m.poll()
	if !slices.Equal(probe.attached, []string{"6/hook_a@0"}) {
		t.Fatalf("transient read failure was not retried: attached=%v", probe.attached)
	}
}

func TestFollowManagerRetryAfterAnnouncedFailureIsLate(t *testing.T) {
	for _, held := range []bool{false, true} {
		t.Run(fmt.Sprintf("resume-held=%v", held), func(t *testing.T) {
			src := &fakeFollowSource{now: time.Second, maxID: 6, openErr: map[uint32]error{6: syscall.EMFILE}, progs: map[uint32]*followProgram{
				6: {loadedAt: 400 * time.Millisecond, targets: []attach.Target{followTarget(6, "hook_a")}},
			}}
			probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
			var stderr bytes.Buffer
			m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
				stderr: &stderr, logf: func(string, ...any) {},
				filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
			})
			m.connected = 1
			finish := m.announced(follow.Load{ProgID: 6, Hooks: []string{"hook_a"}})
			delete(src.openErr, 6)
			m.poll()
			finish(held)
			if got := m.stats.String(); got != "follow_attached=1 follow_held=0 follow_gaps=1 follow_gap_ms=600" {
				t.Fatalf("retry was not counted once as late: stats=%q stderr=%q", got, stderr.String())
			}
			if n := strings.Count(stderr.String(), "FOLLOW GAP: prog=6 func=hook_a reason=late unobserved_ms=600"); n != 1 {
				t.Fatalf("retry produced %d late gap lines, want 1: %q", n, stderr.String())
			}
		})
	}
}

func TestFollowManagerAnnouncedReadThenAttachFailureReportsOnce(t *testing.T) {
	src := &fakeFollowSource{now: time.Second, maxID: 6, openErr: map[uint32]error{6: syscall.EMFILE}, progs: map[uint32]*followProgram{
		6: {loadedAt: 400 * time.Millisecond, targets: []attach.Target{followTarget(6, "hook_a")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: &stderr, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) {
			return filter.TargetFilters{}, errors.New("no member port")
		},
	})
	m.connected = 1
	finish := m.announced(follow.Load{ProgID: 6, Hooks: []string{"hook_a"}})
	delete(src.openErr, 6)
	m.poll()
	finish(true)
	if m.stats.gaps.Load() != 1 || strings.Count(stderr.String(), "FOLLOW GAP: prog=6 func=hook_a") != 1 {
		t.Fatalf("one hook was reported more than once: stats=%s stderr=%q", m.stats.String(), stderr.String())
	}
}

func TestFollowManagerIgnoresVanishedProgram(t *testing.T) {
	src := &fakeFollowSource{now: time.Second, maxID: 6, openErr: map[uint32]error{6: os.ErrNotExist}, progs: map[uint32]*followProgram{}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: &stderr, logf: func(string, ...any) {},
	})
	m.poll()
	close(m.done)
	m.stop()
	if m.stats.gaps.Load() != 0 || stderr.Len() != 0 {
		t.Fatalf("vanished program became a gap: stats=%s stderr=%q", m.stats.String(), stderr.String())
	}
}

func TestFollowManagerReportsUnreadableProgramThatVanishes(t *testing.T) {
	src := &fakeFollowSource{now: time.Second, maxID: 6, openErr: map[uint32]error{6: syscall.ENOMEM}, progs: map[uint32]*followProgram{}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: &stderr, logf: func(string, ...any) {},
	})
	m.poll()
	src.now = 5 * time.Second
	src.openErr[6] = os.ErrNotExist
	m.poll()
	if got := m.stats.String(); got != "follow_attached=0 follow_held=0 follow_gaps=1 follow_gap_ms=4000" ||
		strings.Count(stderr.String(), "prog=6 func=unknown reason=attach_failed unobserved_ms=4000") != 1 {
		t.Fatalf("vanished unreadable program: stats=%s stderr=%q", got, stderr.String())
	}
}

func TestFollowManagerReadFailureDoesNotStarve(t *testing.T) {
	src := &fakeFollowSource{now: time.Second, maxID: 7, openErr: map[uint32]error{6: syscall.EMFILE}, progs: map[uint32]*followProgram{
		7: {loadedAt: time.Second, targets: []attach.Target{followTarget(7, "hook_a")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: &stderr, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
	})
	m.poll()
	if probe.observed[7] == 0 {
		t.Fatalf("first poll stopped at id=%d and starved hook 7; stats=%s stderr=%q", m.lastID, m.stats.String(), stderr.String())
	}
	for range 99 {
		m.poll()
		src.now += followPollInterval
	}
	close(m.done)
	m.stop()
	if m.lastID != 7 {
		t.Fatalf("scan cursor = %d, want 7", m.lastID)
	}
	if n := strings.Count(stderr.String(), "FOLLOW GAP: prog=6 func=unknown reason=attach_failed"); n != 1 {
		t.Fatalf("unresolved read failure reported %d times, want once; stderr=%q", n, stderr.String())
	}
}

func TestFollowManagerStartBoundary(t *testing.T) {
	src := &fakeFollowSource{now: 2 * time.Hour, maxID: 7, progs: map[uint32]*followProgram{
		7: {loadedAt: time.Hour, targets: []attach.Target{followTarget(7, "hook_a")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}, errs: map[uint32]error{7: errors.New("verifier failed")}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		boundaryID: 7, startedAt: 2 * time.Hour, stderr: &stderr, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
	})
	m.poll()
	if len(src.opened) != 0 || len(probe.attached) != 0 || m.stats.gaps.Load() != 0 || stderr.Len() != 0 {
		t.Fatalf("unnamed startup program was followed: opened=%v attached=%v stats=%s stderr=%q",
			src.opened, probe.attached, m.stats.String(), stderr.String())
	}
}

func TestFollowManager(t *testing.T) {
	// Sites: 0 is a plain function, 1 and 2 are hook_a in two programs, 3 is
	// hook_b, which was refused at start and so is not followed.
	initial := []attach.Target{
		{ProgID: 5, FuncName: "plain"}, followTarget(5, "hook_a"), followTarget(6, "hook_a"), followTarget(6, "hook_b"),
	}
	late := func(id uint32, names ...string) *followProgram {
		p := &followProgram{loadedAt: 900 * time.Millisecond}
		for _, n := range names {
			p.targets = append(p.targets, followTarget(id, n))
		}
		return p
	}
	filterErr := errors.New("value has no member port")
	src := &fakeFollowSource{now: time.Second, maxID: 16, progs: map[uint32]*followProgram{
		5:  late(5, "hook_a"), // already observed: never opened
		10: late(10, "hook_a"),
		11: late(11, "hook_a"),
		12: late(12, "hook_a"),
		13: late(13, "hook_a"),
		14: late(14, "hook_a"),
		15: {loadedAt: 999*time.Millisecond + 1, failed: map[string]error{"hook_a": errors.New("no BTF parameters")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 2, 6: 1}, errs: map[uint32]error{
		11: fmt.Errorf("site 1: %w", program.ErrLayoutChanged),
		12: program.ErrObservedByOther,
		13: errors.New("verifier said no"),
	}}
	var stderr bytes.Buffer
	cfg := followConfig{stderr: &stderr, logf: func(string, ...any) {},
		filters: func(t attach.Target) (filter.TargetFilters, error) {
			if t.ProgID == 14 {
				return filter.TargetFilters{}, filterErr
			}
			return filter.TargetFilters{}, nil
		}}
	m := newFollowManager(probe, src, initial, []int{0, 1, 2}, cfg)
	if m == nil || !slices.Equal(m.names, []string{"hook_a"}) || m.slots["hook_a"] != 1 {
		t.Fatalf("manager %+v", m)
	}
	m.poll()
	m.poll() // nothing new: no program is examined twice
	if want := []uint32{1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}; !slices.Equal(src.opened, want) {
		t.Fatalf("opened %v, want %v", src.opened, want)
	}
	if !slices.Equal(probe.attached, []string{"10/hook_a@1"}) || src.closed != 6 {
		t.Fatalf("attached %v, closed %d programs", probe.attached, src.closed)
	}
	wantLines := []string{
		"warning: FOLLOW GAP: prog=10 func=hook_a reason=late unobserved_ms=100",
		"warning: FOLLOW GAP: prog=11 func=hook_a reason=layout_changed unobserved_ms=100",
		"warning: FOLLOW GAP: prog=12 func=hook_a reason=observed_by_other unobserved_ms=100",
		"warning: following hook_a to program id=13: verifier said no",
		"warning: FOLLOW GAP: prog=13 func=hook_a reason=attach_failed unobserved_ms=100",
		"warning: following hook_a to program id=14: value has no member port",
		"warning: FOLLOW GAP: prog=14 func=hook_a reason=filter_unresolved unobserved_ms=100",
		"warning: FOLLOW GAP: prog=15 func=hook_a reason=attach_failed unobserved_ms=1",
	}
	for _, line := range wantLines {
		if !strings.Contains(stderr.String(), line+"\n") {
			t.Errorf("stderr lacks %q:\n%s", line, stderr.String())
		}
	}
	if got, want := m.stats.String(), "follow_attached=1 follow_held=0 follow_gaps=6 follow_gap_ms=501"; got != want {
		t.Fatalf("stats %q, want %q", got, want)
	}

	// An attach made while the loader is held is not a gap.
	src.progs[20] = late(20, "hook_a")
	m.announced(follow.Load{ProgID: 20, Hooks: []string{"hook_a"}})(true)
	if got, want := m.stats.String(), "follow_attached=2 follow_held=1 follow_gaps=6 follow_gap_ms=501"; got != want {
		t.Fatalf("stats after a held attach %q, want %q", got, want)
	}

	// A capture with no generated hook has nothing to follow.
	if m := newFollowManager(probe, src, initial, []int{0}, cfg); m != nil {
		t.Fatalf("manager for a plain function: %+v", m)
	}
}

func TestFollowManagerLocksOneProgramAttach(t *testing.T) {
	locked := false
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	src := &fakeFollowSource{now: time.Second, maxID: 6, progs: map[uint32]*followProgram{
		6: {loadedAt: time.Second, targets: []attach.Target{followTarget(6, "hook_a"), followTarget(6, "hook_b")}},
	}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src,
		[]attach.Target{followTarget(5, "hook_a"), followTarget(5, "hook_b")}, []int{0, 1}, followConfig{
			stderr: &stderr, logf: func(string, ...any) {},
			filters: func(attach.Target) (filter.TargetFilters, error) {
				if !locked {
					t.Fatal("filter resolution ran outside the follower lock")
				}
				return filter.TargetFilters{}, nil
			},
			lock: func() (func(), error) {
				if locked {
					t.Fatal("one program acquired the follower lock more than once")
				}
				locked = true
				return func() { locked = false }, nil
			},
		})
	m.poll()
	if locked || !slices.Equal(probe.attached, []string{"6/hook_a@0", "6/hook_b@1"}) {
		t.Fatalf("locked=%v attached=%v", locked, probe.attached)
	}
}

func TestFollowManagerReportsFollowerLockTimeoutPerHook(t *testing.T) {
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	src := &fakeFollowSource{now: time.Second, maxID: 6, progs: map[uint32]*followProgram{
		6: {loadedAt: time.Second, targets: []attach.Target{followTarget(6, "hook_a"), followTarget(6, "hook_b")}},
	}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src,
		[]attach.Target{followTarget(5, "hook_a"), followTarget(5, "hook_b")}, []int{0, 1}, followConfig{
			stderr: &stderr, logf: func(string, ...any) {},
			filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
			lock:    func() (func(), error) { return nil, program.ErrFollowerLockTimeout },
		})
	m.poll()
	if len(probe.attached) != 0 || m.stats.gaps.Load() != 2 || strings.Count(stderr.String(), "reason=observed_by_other") != 2 ||
		!strings.Contains(stderr.String(), "func=hook_a") || !strings.Contains(stderr.String(), "func=hook_b") {
		t.Fatalf("attached=%v stats=%s stderr=%q", probe.attached, m.stats.String(), stderr.String())
	}
}

func TestFollowManagerReportsFollowerLockSetupError(t *testing.T) {
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	src := &fakeFollowSource{now: time.Second, maxID: 6, progs: map[uint32]*followProgram{
		6: {loadedAt: time.Second, targets: []attach.Target{followTarget(6, "hook_a")}},
	}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: &stderr, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
		lock:    func() (func(), error) { return nil, syscall.EACCES },
	})
	m.poll()
	if len(probe.attached) != 0 || m.stats.gaps.Load() != 1 ||
		!strings.Contains(stderr.String(), "permission denied") ||
		!strings.Contains(stderr.String(), "reason=attach_failed") ||
		strings.Contains(stderr.String(), "reason=observed_by_other") {
		t.Fatalf("attached=%v stats=%s stderr=%q", probe.attached, m.stats.String(), stderr.String())
	}
}

type refusingFollowProbe struct {
	fakeFollowProbe
	refuse string
}

func (p *refusingFollowProbe) AttachFollower(slot int, t attach.Target, tf filter.TargetFilters, rec *record.Layout) ([]attach.TargetDiagnostic, error) {
	if t.FuncName == p.refuse {
		return nil, program.ErrObservedByOther
	}
	return p.fakeFollowProbe.AttachFollower(slot, t, tf, rec)
}

func TestFollowManagerRollsBackProgramOnLaterRefusal(t *testing.T) {
	src := &fakeFollowSource{now: 1100 * time.Millisecond, maxID: 7, progs: map[uint32]*followProgram{
		7: {loadedAt: time.Second, targets: []attach.Target{
			followTarget(7, "hook_a"), followTarget(7, "hook_b"), followTarget(7, "hook_c"),
		}},
	}}
	probe := &refusingFollowProbe{fakeFollowProbe: fakeFollowProbe{observed: map[uint32]int{5: 3}}, refuse: "hook_b"}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src,
		[]attach.Target{followTarget(5, "hook_a"), followTarget(5, "hook_b"), followTarget(5, "hook_c")}, []int{0, 1, 2}, followConfig{
			boundaryID: 5, startedAt: time.Second, stderr: &stderr, logf: func(string, ...any) {},
			filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
			lock:    func() (func(), error) { return func() {}, nil },
		})
	m.connected = 1
	m.poll()
	if len(probe.attached) != 0 || probe.observed[7] != 0 ||
		m.stats.attached.Load() != 0 || m.stats.gaps.Load() != 3 ||
		strings.Count(stderr.String(), "FOLLOW GAP: prog=7") != 3 {
		t.Fatalf("attached=%v links=%d stats=%s stderr=%q", probe.attached, probe.observed[7], m.stats.String(), stderr.String())
	}
}

func TestFollowManagerWarnsFollowerLockSetupAtStart(t *testing.T) {
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	src := &fakeFollowSource{now: time.Second, maxID: 5, progs: map[uint32]*followProgram{}}
	var stderr bytes.Buffer
	lockCalls := 0
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		boundaryID: 5, stderr: &stderr, logf: func(string, ...any) {},
		lock: func() (func(), error) {
			lockCalls++
			return nil, syscall.EROFS
		},
	})
	m.start()
	m.stop()
	if lockCalls != 1 || strings.Count(stderr.String(), "read-only file system") != 1 {
		t.Fatalf("lock calls=%d stderr=%q", lockCalls, stderr.String())
	}
}

// TestFollowManagerStops checks that stop waits for the poller and reports a
// hook that could not be attached because the probe had stopped.
func TestFollowManagerStops(t *testing.T) {
	src := &fakeFollowSource{now: time.Second, maxID: 9, progs: map[uint32]*followProgram{
		9: {loadedAt: time.Second, targets: []attach.Target{followTarget(9, "hook_a")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{}, errs: map[uint32]error{9: program.ErrProbeStopped}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: &stderr, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil }})
	m.poll()
	if m.stats.gaps.Load() != 1 || !strings.Contains(stderr.String(), "prog=9 func=hook_a reason=attach_failed") {
		t.Fatalf("stopped probe did not report the unattached hook: stderr %q, gaps %d", stderr.String(), m.stats.gaps.Load())
	}
	m.start()
	m.stop()
	m.stop()
	if !strings.Contains(stderr.String(), "following 1 generated hook(s) by polling: no inject-run is reachable") || m.stats.gaps.Load() != 1 {
		t.Fatalf("stderr %q, gaps %d", stderr.String(), m.stats.gaps.Load())
	}
	var none *followManager
	none.stop() // a capture that follows nothing
}

func TestFollowManagerSecondStopDoesNotScanNewPrograms(t *testing.T) {
	src := &fakeFollowSource{now: time.Second, maxID: 5, progs: map[uint32]*followProgram{}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		boundaryID: 5, startedAt: time.Second, stderr: &stderr, logf: func(string, ...any) {},
	})
	m.start()
	m.stop()
	src.now = 4 * time.Second
	src.maxID = 6
	src.progs[6] = &followProgram{loadedAt: 4 * time.Second, targets: []attach.Target{followTarget(6, "hook_a")}}
	m.stop()
	if m.stats.gaps.Load() != 0 || strings.Contains(stderr.String(), "prog=6") {
		t.Fatalf("second stop scanned a post-capture program: stats=%s stderr=%q", m.stats.String(), stderr.String())
	}
}

func TestFollowManagerCountsAttachBeforeStopBetweenHooks(t *testing.T) {
	src := &fakeFollowSource{now: 1100 * time.Millisecond, maxID: 6, progs: map[uint32]*followProgram{
		6: {loadedAt: time.Second, targets: []attach.Target{followTarget(6, "hook_a"), followTarget(6, "hook_b")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 2}}
	var stderr bytes.Buffer
	var m *followManager
	m = newFollowManager(probe, src,
		[]attach.Target{followTarget(5, "hook_a"), followTarget(5, "hook_b")}, []int{0, 1}, followConfig{
			stderr: &stderr, logf: func(string, ...any) {},
			filters: func(tg attach.Target) (filter.TargetFilters, error) {
				if tg.FuncName == "hook_a" {
					m.stopOnce.Do(func() { close(m.stopCh) })
				}
				return filter.TargetFilters{}, nil
			},
		})
	m.mu.Lock()
	err := m.examine(6)
	m.mu.Unlock()
	if err != nil || m.stats.attached.Load() != 1 || len(m.pending[6].funcs) != 1 || m.pending[6].funcs[0] != "hook_a" {
		t.Fatalf("partial attach was not returned: err=%v attached=%v stats=%s pending=%+v", err, probe.attached, m.stats.String(), m.pending[6])
	}
}

func TestFollowManagerStopSettlesPendingAttach(t *testing.T) {
	src := &fakeFollowSource{now: 10 * time.Second, maxID: 6, progs: map[uint32]*followProgram{
		6: {loadedAt: 9950 * time.Millisecond, targets: []attach.Target{followTarget(6, "hook_a")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: &stderr, logf: func(string, ...any) {},
		filters:   func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
		newClient: func([]string, follow.Handler) followClient { return &fakeFollowClient{supervisors: 1} },
	})
	m.start()
	for deadline := time.Now().Add(time.Second); m.stats.attached.Load() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("program was not attached")
		}
	}
	m.stop()
	if gaps := m.stats.gaps.Load(); gaps != 1 {
		t.Fatalf("gaps = %d, want 1 for the unheld pending attach", gaps)
	}
}

func TestFollowManagerStopScansNewestPrograms(t *testing.T) {
	src := &fakeFollowSource{now: 1100 * time.Millisecond, maxID: 7, progs: map[uint32]*followProgram{
		7: {loadedAt: time.Second, targets: []attach.Target{followTarget(7, "hook_a")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		startedAt: time.Second, stderr: &stderr, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
	})
	m.lastID = 5
	close(m.done)
	m.stop()
	if m.stats.gaps.Load() != 1 || !strings.Contains(stderr.String(), "FOLLOW GAP: prog=7 func=hook_a reason=attach_failed unobserved_ms=100") {
		t.Fatalf("newest program was dropped at stop: stats=%s stderr=%q", m.stats.String(), stderr.String())
	}
}

func TestFollowManagerStopSkipsExaminedProgram(t *testing.T) {
	src := &fakeFollowSource{now: 1100 * time.Millisecond, maxID: 7, progs: map[uint32]*followProgram{
		7: {loadedAt: time.Second, targets: []attach.Target{followTarget(7, "hook_a")}},
	}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}, errs: map[uint32]error{7: program.ErrObservedByOther}}
	var stderr bytes.Buffer
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		boundaryID: 5, startedAt: time.Second, stderr: &stderr, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
		lock:    func() (func(), error) { return func() {}, nil },
	})
	m.connected = 1
	m.announced(follow.Load{ProgID: 7, Hooks: []string{"hook_a"}})(true)
	close(m.done) // stop before polling advances past the announcement
	m.stop()
	if n := strings.Count(stderr.String(), "FOLLOW GAP: prog=7"); n != 1 {
		t.Fatalf("examined program reported %d times, want once: stats=%s stderr=%q", n, m.stats.String(), stderr.String())
	}
}

func TestCaptureReportFollow(t *testing.T) {
	c := &captureControl{stats: &capture.SessionStats{}}
	c.stats.Consumed.Store(10)
	c.written.Store(10)
	k := program.ExportStats{Submitted: 10}
	if report := captureReport(k, nil, nil, c); strings.Contains(report, "follow_") {
		t.Fatalf("a capture that follows nothing reports follow fields: %s", report)
	}
	c.follow = &followStats{}
	c.follow.attached.Store(2)
	c.follow.held.Store(2)
	if report := captureReport(k, nil, nil, c); !strings.Contains(report, "status=complete ") ||
		!strings.HasSuffix(report, " follow_attached=2 follow_held=2 follow_gaps=0 follow_gap_ms=0") {
		t.Fatal(report)
	}
	c.follow.gaps.Store(1)
	c.follow.gapMs.Store(7)
	if report := captureReport(k, nil, nil, c); !strings.Contains(report, "status=incomplete ") || !strings.HasSuffix(report, " follow_gaps=1 follow_gap_ms=7") {
		t.Fatal(report)
	}
}

// fakeFollowClient is a subscription to a fixed number of supervisors.
type fakeFollowClient struct {
	supervisors int
	closed      bool
}

func (c *fakeFollowClient) Dial() int { return c.supervisors }
func (c *fakeFollowClient) Close()    { c.closed = true }

// TestFollowManagerSubscribed covers a capture subscribed to an inject-run:
// an attach is held or late according to the supervisor's resume, also when
// the poller saw the program first, and a program nobody announces is late
// after the grace period.
func TestFollowManagerSubscribed(t *testing.T) {
	late := func(id uint32) *followProgram {
		return &followProgram{loadedAt: 10 * time.Second, targets: []attach.Target{followTarget(id, "hook_a")}}
	}
	src := &fakeFollowSource{now: 10*time.Second + 3*time.Millisecond, maxID: 6, progs: map[uint32]*followProgram{6: late(6)}}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}, errs: map[uint32]error{9: errors.New("verifier said no")}}
	var stderr bytes.Buffer
	client := &fakeFollowClient{supervisors: 1}
	var handler follow.Handler
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: &stderr, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
		newClient: func(hooks []string, h follow.Handler) followClient {
			if !slices.Equal(hooks, []string{"hook_a"}) {
				t.Errorf("subscribed to %v", hooks)
			}
			handler = h
			return client
		}})
	m.client = m.cfg.newClient(m.names, m.announced)
	m.redial()
	stats := func(step, want string) {
		t.Helper()
		if got := m.stats.String(); got != want {
			t.Fatalf("%s: stats %q, want %q\n%s", step, got, want, stderr.String())
		}
	}
	tick := func() {
		m.mu.Lock()
		m.expirePending()
		m.mu.Unlock()
	}

	// The poller sees program 6 before its announcement arrives: undecided.
	m.poll()
	tick()
	stats("found by polling", "follow_attached=1 follow_held=0 follow_gaps=0 follow_gap_ms=0")
	// The announcement and a held resume make it a held attach.
	finish := handler(follow.Load{ProgID: 6})
	src.now += followAnnounceGrace // the resume may take longer than the grace
	tick()
	finish(true)
	stats("announced and held", "follow_attached=1 follow_held=1 follow_gaps=0 follow_gap_ms=0")

	// Announced first; the supervisor gave up waiting: late by the time the
	// attach took.
	src.progs[7] = late(7)
	src.now = 10*time.Second + 40*time.Millisecond
	handler(follow.Load{ProgID: 7})(false)
	stats("announced, not held", "follow_attached=2 follow_held=1 follow_gaps=1 follow_gap_ms=40")

	// A program from an inject-run the capture is not subscribed to: late
	// once the grace period passed without an announcement.
	src.progs[8], src.maxID = late(8), 8
	src.now = 10*time.Second + 5*time.Millisecond
	m.poll()
	src.now += followAnnounceGrace - time.Millisecond
	tick()
	stats("within the grace period", "follow_attached=3 follow_held=1 follow_gaps=1 follow_gap_ms=40")
	src.now += time.Millisecond
	tick()
	stats("after the grace period", "follow_attached=3 follow_held=1 follow_gaps=2 follow_gap_ms=45")

	// A held load whose observer cannot be attached is still a gap.
	src.progs[9] = late(9)
	src.now = 10*time.Second + 105*time.Millisecond
	handler(follow.Load{ProgID: 9})(true)
	stats("held but failed", "follow_attached=3 follow_held=1 follow_gaps=3 follow_gap_ms=150")
	for _, want := range []string{
		"FOLLOW GAP: prog=7 func=hook_a reason=late unobserved_ms=40\n",
		"FOLLOW GAP: prog=8 func=hook_a reason=late unobserved_ms=5\n",
		"FOLLOW GAP: prog=9 func=hook_a reason=attach_failed unobserved_ms=105\n",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
		}
	}
	if strings.Contains(stderr.String(), "prog=6") {
		t.Errorf("the held program was reported:\n%s", stderr.String())
	}
	// An announcement for a program without the hook, or already observed,
	// changes nothing, and the poller does not look at an announced program
	// again, whether it was attached (7) or failed (9).
	handler(follow.Load{ProgID: 4})(true)
	handler(follow.Load{ProgID: 6})(false)
	src.maxID = 9
	m.poll()
	tick()
	stats("unrelated announcements", "follow_attached=3 follow_held=1 follow_gaps=3 follow_gap_ms=150")
	// The record of examined programs is dropped once the poller is past
	// them and no announcement can still arrive.
	m.mu.Lock()
	m.forgetExamined(src.now + 11*follow.HoldDeadline)
	left := len(m.examined)
	m.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d examined programs remembered", left)
	}

	m.start()
	m.stop()
	if !client.closed {
		t.Fatal("the subscription outlived the manager")
	}
}

func TestFollowManagerSerializesAnnouncementAndPolling(t *testing.T) {
	src := &concurrentFollowSource{firstOpen: make(chan struct{}), secondOpen: make(chan struct{}), release: make(chan struct{})}
	probe := &fakeFollowProbe{observed: map[uint32]int{5: 1}}
	m := newFollowManager(probe, src, []attach.Target{followTarget(5, "hook_a")}, []int{0}, followConfig{
		stderr: io.Discard, logf: func(string, ...any) {},
		filters: func(attach.Target) (filter.TargetFilters, error) { return filter.TargetFilters{}, nil },
	})
	pollDone := make(chan struct{})
	go func() { m.poll(); close(pollDone) }()
	<-src.firstOpen
	finish := make(chan func(bool), 1)
	go func() { finish <- m.announced(follow.Load{ProgID: 6, Hooks: []string{"hook_a"}}) }()
	select {
	case <-src.secondOpen:
	case <-time.After(20 * time.Millisecond):
	}
	close(src.release)
	<-pollDone
	(<-finish)(false)
	if got := probe.observed[6]; got != 1 {
		t.Fatalf("announcement and polling attached %d observers, want 1", got)
	}
}

func TestFollowAnnounceGraceCoversHoldDeadline(t *testing.T) {
	if followAnnounceGrace < follow.HoldDeadline {
		t.Fatalf("announcement grace %s is shorter than hold deadline %s", followAnnounceGrace, follow.HoldDeadline)
	}
}
