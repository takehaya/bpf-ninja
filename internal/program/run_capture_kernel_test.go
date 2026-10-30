package program

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfRunCaptureModes(t *testing.T) {
	for _, mode := range []string{"percpu", "ctx"} {
		t.Run(mode, func(t *testing.T) {
			coll, targets, _ := hookFixture(t)
			old := RingbufSize
			RingbufSize = 4 << 20
			defer func() { RingbufSize = old }()
			p, err := LoadHookCapture(targets, "", nil, true, nil, HookCaptureOptions{Tracking: mode})
			if err != nil {
				t.Fatalf("load: %+v", err)
			}
			defer func() { _ = p.Close() }()
			var readers []*fastrb.Reader
			for _, m := range p.InnerMaps {
				rd, e := fastrb.New(m.FD(), int(m.MaxEntries()))
				if e != nil {
					t.Fatal(e)
				}
				defer func() { _ = rd.Close() }()
				readers = append(readers, rd)
			}
			for i := range 4 {
				frame := make([]byte, 64)
				frame[0] = byte(i)
				if _, _, e := coll.Programs["hook_root"].Test(frame); e != nil {
					t.Fatal(e)
				}
			}
			if err := p.Quiesce(); err != nil {
				t.Fatal(err)
			}
			n := 0
			ids := map[uint64]byte{}
			for _, rd := range readers {
				rd.ReadBatch(func(raw []byte) {
					pkt, e := capture.ParseRawSample(raw)
					if e != nil {
						t.Fatal(e)
					}
					if pkt.PacketID == 0 {
						t.Error("zero ID")
					}
					if marker, ok := ids[pkt.PacketID]; ok && marker != pkt.Data[0] {
						t.Error("misattribution")
					}
					ids[pkt.PacketID] = pkt.Data[0]
					n++
				})
			}
			if n != 11 || len(ids) != 4 {
				t.Fatalf("records=%d IDs=%d", n, len(ids))
			}
			d, e := p.RunDiagnostics(true)
			if e != nil || d.Incomplete() {
				t.Fatalf("%s err=%v", d, e)
			}
		})
	}
}

func runFixtureCapture(t *testing.T, rootName, mode string, capacity uint32) (*ebpf.Collection, *Probe, []*fastrb.Reader) {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	obj := os.Getenv("BPF_NINJA_RUN_TEST_OBJECT")
	if obj == "" {
		source, e := os.ReadFile("testdata/run-capture.c")
		if e != nil {
			t.Fatal(e)
		}
		obj = testutil.CompileBPFSource(t, string(source))
	}
	spec, e := ebpf.LoadCollectionSpec(obj)
	if e != nil {
		t.Fatal(e)
	}
	// Avoid loading independent roots which share globals with the selected root.
	for name := range spec.Programs {
		if name != rootName {
			delete(spec.Programs, name)
		}
	}
	coll, e := ebpf.NewCollection(spec)
	if e != nil {
		t.Fatalf("fixture: %+v", e)
	}
	t.Cleanup(coll.Close)
	info, e := coll.Programs[rootName].Info()
	if e != nil {
		t.Fatal(e)
	}
	id, _ := info.ID()
	root, e := attach.FindBPFProgramByID(uint32(id))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = root.Program.Close() })
	suffix := "xdp"
	if strings.HasSuffix(rootName, "tc") {
		suffix = "tc"
	}
	names := []string{"run_hook_" + suffix}
	if strings.Contains(rootName, "stress") {
		names = []string{"run_begin_" + suffix, "run_hook_" + suffix}
	}
	targets, _, e := attach.ResolveTargets([]*attach.ProgInfo{root}, names, false)
	if e != nil {
		t.Fatal(e)
	}
	old := RingbufSize
	RingbufSize = 4 << 20
	defer func() { RingbufSize = old }()
	p, e := LoadHookCapture(targets, "", nil, true, nil, HookCaptureOptions{Tracking: mode, TableEntries: capacity})
	if e != nil {
		t.Fatalf("capture: %+v", e)
	}
	t.Cleanup(func() { _ = p.Close() })
	var readers []*fastrb.Reader
	for _, m := range p.InnerMaps {
		rd, e := fastrb.New(m.FD(), int(m.MaxEntries()))
		if e != nil {
			t.Fatal(e)
		}
		readers = append(readers, rd)
		t.Cleanup(func() { _ = rd.Close() })
	}
	return coll, p, readers
}
func drainRunRecords(t *testing.T, readers []*fastrb.Reader) []capture.Packet {
	t.Helper()
	var out []capture.Packet
	for _, rd := range readers {
		rd.ReadBatch(func(raw []byte) {
			pkt, e := capture.ParseRawSample(raw)
			if e != nil {
				t.Fatal(e)
			}
			pkt.Data = append([]byte(nil), pkt.Data...)
			out = append(out, pkt)
		})
	}
	return out
}
func TestBpfRunInterleaving(t *testing.T) {
	for _, kind := range []string{"xdp", "tc"} {
		for _, mode := range []string{"percpu", "ctx"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				coll, p, readers := runFixtureCapture(t, "run_stress_"+kind, mode, 0)
				cpu := affinityCPUs(t)[0]
				start := make(chan struct{})
				errs := make(chan error, 2)
				for thread := range 2 {
					go func() {
						unpin, e := pinThread(cpu)
						if e != nil {
							errs <- e
							return
						}
						defer func() { _ = unpin() }()
						<-start
						for i := range 200 {
							frame := make([]byte, 64)
							binary.LittleEndian.PutUint32(frame, uint32(1+thread*200+i))
							if _, e := coll.Programs["run_stress_"+kind].Run(&ebpf.RunOptions{Data: frame, Repeat: 1}); e != nil {
								errs <- e
								return
							}
						}
						errs <- nil
					}()
				}
				close(start)
				for range 2 {
					if e := <-errs; e != nil {
						t.Fatal(e)
					}
				}
				if e := p.Quiesce(); e != nil {
					t.Fatal(e)
				}
				d, e := p.RunDiagnostics(true)
				if e != nil {
					t.Fatal(e)
				}
				misses, e := p.ObserverMisses()
				if e != nil {
					t.Fatal(e)
				}
				entryMisses, exitMisses, err := p.BoundaryMisses()
				if err != nil {
					t.Fatal(err)
				}
				hookMisses := misses - entryMisses - exitMisses
				markers := map[uint64]uint32{}
				records := drainRunRecords(t, readers)
				if dir := os.Getenv("BPF_NINJA_HOOK_TEST_DIR"); dir != "" {
					raw, e := json.MarshalIndent(records, "", "  ")
					if e != nil {
						t.Fatal(e)
					}
					if e = os.WriteFile(filepath.Join(dir, "interleaving-"+kind+"-"+mode+".json"), raw, 0644); e != nil {
						t.Fatal(e)
					}
				}
				misattributed, unpaired := 0, 0
				allMarkers := map[uint64]uint32{}
				for _, pkt := range records {
					marker := binary.LittleEndian.Uint32(pkt.Data)
					if pkt.SiteID == 1 {
						if _, ok := markers[pkt.PacketID]; ok {
							misattributed++
						}
						markers[pkt.PacketID] = marker
					}
					if old, ok := allMarkers[pkt.PacketID]; ok && old != marker {
						misattributed++
					}
					allMarkers[pkt.PacketID] = marker
					if pkt.PacketID == 0 {
						misattributed++
					}
					if pkt.SiteID != 1 {
						if expected, ok := markers[pkt.PacketID]; ok {
							if expected != marker {
								misattributed++
							}
						} else {
							unpaired++
						}
					}
				}
				export, err := p.ExportStats()
				if err != nil {
					t.Fatal(err)
				}
				accounted := uint64(len(records)) + d.Counters[runUntrackedHook] + d.Counters[runBlockedHook] + d.Counters[runReadFailed] + export.ReserveFail + export.LookupMiss + export.CopyFail + hookMisses
				if accounted != 800 || export.Submitted != uint64(len(records)) {
					t.Fatalf("hook accounting records=%d/800 accounted=%d: %s export=%+v observer_misses=%d entry_misses=%d exit_misses=%d hook_misses=%d", len(records), accounted, d, export, misses, entryMisses, exitMisses, hookMisses)
				}
				major, minor, _, _ := kernelVersion()
				wantMismatch := mode == "percpu" && (major < 6 || major == 6 && minor < 3)
				if misattributed != 0 || (misses == 0 && (d.Residual != 0 || unpaired != 0)) {
					t.Fatalf("misattributed=%d unpaired=%d residual=%d misses=%d", misattributed, unpaired, d.Residual, misses)
				}
				if wantMismatch {
					if d.Mismatches() == 0 || !d.Incomplete() {
						t.Fatalf("expected incomplete mismatch: %s", d)
					}
				} else if misses == 0 && (d.Incomplete() || len(records) != 800) {
					t.Fatalf("records=%d/800 %s", len(records), d)
				}
				t.Logf("runs=400/400 records=%d/800 misattributed=%d unpaired=%d mismatch=%d incomplete=%v misses=%d hook_misses=%d residual=%d", len(records), misattributed, unpaired, d.Counters[runMismatch], d.Incomplete() || misses > 0, misses, hookMisses, d.Residual)
			})
		}
	}
}
func TestBpfRunAdjustedIdentity(t *testing.T) {
	for _, kind := range []string{"xdp", "tc"} {
		for _, mode := range []string{"percpu", "ctx"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				coll, p, readers := runFixtureCapture(t, "run_adjust_"+kind, mode, 0)
				frame := make([]byte, 64)
				frame[4] = 71
				ret, _, e := coll.Programs["run_adjust_"+kind].Test(frame)
				want := uint32(2)
				if kind == "tc" {
					want = 0
				}
				if e != nil || ret != want {
					t.Fatalf("adjust ret=%d want=%d err=%v", ret, want, e)
				}
				if e := p.Quiesce(); e != nil {
					t.Fatal(e)
				}
				records := drainRunRecords(t, readers)
				if len(records) != 1 || records[0].PacketID == 0 {
					t.Fatalf("records=%v", records)
				}
				if kind == "xdp" && (records[0].Data[0] != 71 || len(records[0].Data) != 60) {
					t.Fatalf("adjusted record=%v", records[0])
				}
				d, e := p.RunDiagnostics(true)
				if e != nil || d.Incomplete() {
					t.Fatalf("%s %v", d, e)
				}
			})
		}
	}
}
func TestBpfRunStaleEntry(t *testing.T) {
	coll, p, readers := runFixtureCapture(t, "run_stress_xdp", "ctx", 0)
	unpin, e := pinThread(affinityCPUs(t)[0])
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = unpin() }()
	prog := coll.Programs["run_stress_xdp"]
	if _, _, e := prog.Test(make([]byte, 64)); e != nil {
		t.Fatal(e)
	}
	_ = drainRunRecords(t, readers)
	var key uint64
	if e := coll.Maps["seen"].Lookup(uint32(0), &key); e != nil {
		t.Fatal(e)
	}
	value := make([]byte, runStride)
	binary.NativeEndian.PutUint64(value[runCtx:], key)
	if e := p.runs.state.Update(key, value, ebpf.UpdateNoExist); e != nil {
		t.Fatal(e)
	}
	if _, _, e := prog.Test(make([]byte, 64)); e != nil {
		t.Fatal(e)
	}
	if e := p.Quiesce(); e != nil {
		t.Fatal(e)
	}
	d, e := p.RunDiagnostics(true)
	want := RunDiagnostics{}
	want.Counters[runCollision], want.Counters[runBlockedHook], want.Counters[runStaleReclaimed] = 1, 2, 1
	if e != nil || d != want {
		t.Fatalf("got %s want %s err=%v", d, want, e)
	}
	if got := drainRunRecords(t, readers); len(got) != 0 {
		t.Fatalf("blocked run emitted %d records", len(got))
	}
	t.Log(d)
}
func TestBpfRunTableFull(t *testing.T) {
	coll, p, readers := runFixtureCapture(t, "run_stress_xdp", "ctx", 1)
	cpus := affinityCPUs(t)
	if len(cpus) < 2 {
		t.Skip("need two CPUs")
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, cpu := range cpus[:2] {
		go func() {
			unpin, e := pinThread(cpu)
			if e != nil {
				errs <- e
				return
			}
			defer func() { _ = unpin() }()
			<-start
			for range 20 {
				if _, _, e := coll.Programs["run_stress_xdp"].Test(make([]byte, 64)); e != nil {
					errs <- e
					return
				}
			}
			errs <- nil
		}()
	}
	close(start)
	for range 2 {
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
	}
	if e := p.Quiesce(); e != nil {
		t.Fatal(e)
	}
	d, e := p.RunDiagnostics(true)
	if e != nil || d.Counters[runInsertFailed] == 0 || !d.Incomplete() || d.Residual != 0 {
		t.Fatalf("%s %v", d, e)
	}
	records := drainRunRecords(t, readers)
	if uint64(len(records))+d.Counters[runUntrackedHook] != 80 ||
		d.Counters[runUntrackedHook] != 2*d.Counters[runInsertFailed] ||
		d.Counters[runExitWithoutEntry] != d.Counters[runInsertFailed] {
		t.Fatalf("40 runs, records=%d/80: %s", len(records), d)
	}
	for _, pkt := range records {
		if pkt.PacketID == 0 {
			t.Fatal("untracked record")
		}
	}
	t.Log(d)
}
func TestBpfRunQuiesceInFlight(t *testing.T) {
	for _, mode := range []string{"percpu", "ctx"} {
		t.Run(mode, func(t *testing.T) {
			coll, p, _ := runFixtureCapture(t, "run_stress_slow_xdp", mode, 0)
			cpus := affinityCPUs(t)
			if len(cpus) < 2 {
				t.Skip("need two CPUs")
			}
			unpin, e := pinThread(cpus[1])
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = unpin() }()
			done := make(chan error, 1)
			go func() {
				u, e := pinThread(cpus[0])
				if e != nil {
					done <- e
					return
				}
				defer func() { _ = u() }()
				_, _, e = coll.Programs["run_stress_slow_xdp"].Test(make([]byte, 64))
				done <- e
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				d, e := p.RunDiagnostics(true)
				if e != nil {
					t.Fatal(e)
				}
				if d.Residual > 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("did not observe in-flight run")
				}
				runtime.Gosched()
			}
			if e := p.Quiesce(); e != nil {
				t.Fatal(e)
			}
			d, e := p.RunDiagnostics(true)
			if e != nil || d.Residual != 0 {
				t.Fatalf("%s %v", d, e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestBpfRunStartAndTag(t *testing.T) {
	for _, mode := range []string{"percpu", "ctx"} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/late=%v", mode, late), func(t *testing.T) {
				coll, targets, _ := hookFixture(t)
				pin := fmt.Sprintf("/sys/fs/bpf/run_start_%d", os.Getpid())
				if e := setmap.Create(pin, "dst:u64", "", 16); e != nil {
					t.Fatal(e)
				}
				defer func() { _ = os.Remove(pin) }()
				set, e := setmap.OpenSet(setmap.SpecRef{Name: "macs", Path: pin})
				if e != nil {
					t.Fatal(e)
				}
				defer set.Def.Close()
				key := "00:00:00:00:00:00"
				if late {
					key = "00:2a:00:00:00:00"
				}
				if e := set.Def.Add(map[string]string{"dst": key}, setmap.EntryValue{Tag: 7}); e != nil {
					t.Fatal(e)
				}
				cfg := HookCaptureOptions{Tracking: mode}
				expr := "eth[dst in @macs]"
				if late {
					cfg.Starts = map[string]string{targets[1].FuncName: expr}
					expr = ""
				} else {
					cfg.EntryStart = true
					cfg.Starts = map[string]string{targets[1].FuncName: "eth[dst==00:2a:00:00:00:00]"}
				}
				old := RingbufSize
				RingbufSize = 4 << 20
				defer func() { RingbufSize = old }()
				p, e := LoadHookCapture(targets, expr, nil, true, []*setmap.Set{set}, cfg)
				if e != nil {
					t.Fatalf("load start: %+v", e)
				}
				defer func() { _ = p.Close() }()
				var readers []*fastrb.Reader
				for _, m := range p.InnerMaps {
					rd, e := fastrb.New(m.FD(), int(m.MaxEntries()))
					if e != nil {
						t.Fatal(e)
					}
					defer func() { _ = rd.Close() }()
					readers = append(readers, rd)
				}
				frame := make([]byte, 64)
				if _, _, e := coll.Programs["hook_root"].Test(frame); e != nil {
					t.Fatal(e)
				}
				records := drainRunRecords(t, readers)
				want := 3
				if late {
					want = 2
				}
				if len(records) != want {
					t.Fatalf("records=%d want=%d", len(records), want)
				}
				for _, pkt := range records {
					if pkt.Tag != 7 || pkt.PacketID != records[0].PacketID {
						t.Fatalf("inherited tag/id: %+v", pkt)
					}
				}
				if e := p.BlockTag(7); e != nil {
					t.Fatal(e)
				}
				if e := set.Def.Add(map[string]string{"dst": key}, setmap.EntryValue{Tag: 7}); e != nil {
					t.Fatal(e)
				}
				if _, _, e := coll.Programs["hook_root"].Test(frame); e != nil {
					t.Fatal(e)
				}
				if got := drainRunRecords(t, readers); len(got) != 0 {
					t.Fatalf("blocked tag restarted: %d records", len(got))
				}
				if e := p.Quiesce(); e != nil {
					t.Fatal(e)
				}
				d, e := p.RunDiagnostics(true)
				if e != nil || d.Incomplete() {
					t.Fatalf("%s err=%v", d, e)
				}
			})
		}
	}
}

func TestBpfRunPreTracking(t *testing.T) {
	for _, mode := range []string{"percpu", "ctx"} {
		t.Run(mode, func(t *testing.T) {
			coll, p, readers := runFixtureCapture(t, "run_stress_slow_xdp", mode, 0)
			cpus := affinityCPUs(t)
			if len(cpus) < 2 {
				t.Skip("need two CPUs")
			}
			u, err := pinThread(cpus[1])
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = u() }()
			if err = p.holdStop.Update(uint32(0), uint32(2), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				u, e := pinThread(cpus[0])
				if e != nil {
					done <- e
					return
				}
				defer func() { _ = u() }()
				_, _, e = coll.Programs["run_stress_slow_xdp"].Test(make([]byte, 64))
				done <- e
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				d, e := p.RunDiagnostics(false)
				if e != nil {
					t.Fatal(e)
				}
				if d.Counters[runPreTracking] == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("did not observe startup entry")
				}
				runtime.Gosched()
			}
			// The run entered before tracking, but reaches its later hook after arming.
			if err = p.holdStop.Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if got := drainRunRecords(t, readers); len(got) != 0 {
				t.Fatalf("pre-tracking run emitted %d records", len(got))
			}
			if _, _, err = coll.Programs["run_stress_slow_xdp"].Test(make([]byte, 64)); err != nil {
				t.Fatal(err)
			}
			if err = p.Quiesce(); err != nil {
				t.Fatal(err)
			}
			d, err := p.RunDiagnostics(true)
			want := RunDiagnostics{}
			want.Counters[runPreTracking] = 1
			if err != nil || d != want {
				t.Fatalf("got %s want %s err=%v", d, want, err)
			}
			if got := drainRunRecords(t, readers); len(got) != 2 {
				t.Fatalf("tracked run records=%d/2", len(got))
			}
		})
	}
}

func TestBpfRunStartupInFlight(t *testing.T) {
	for _, mode := range []string{"percpu", "ctx"} {
		t.Run(mode, func(t *testing.T) {
			coll, old, _ := runFixtureCapture(t, "run_stress_slow_xdp", mode, 0)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			cpus := affinityCPUs(t)
			if len(cpus) < 2 {
				t.Skip("need two CPUs")
			}
			u, err := pinThread(cpus[1])
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = u() }()
			prog := coll.Programs["run_stress_slow_xdp"]
			info, err := prog.Info()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := info.ID()
			root, err := attach.FindBPFProgramByID(uint32(id))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Program.Close() }()
			targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{root}, []string{"run_begin_xdp", "run_hook_xdp"}, false)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				u, e := pinThread(cpus[0])
				if e != nil {
					done <- e
					return
				}
				defer func() { _ = u() }()
				_, _, e = prog.Test(make([]byte, 64))
				done <- e
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				var key uint64
				if err = coll.Maps["seen"].Lookup(uint32(0), &key); err != nil {
					t.Fatal(err)
				}
				if key != 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("root did not start")
				}
				runtime.Gosched()
			}
			p, err := LoadHookCapture(targets, "", nil, true, nil, HookCaptureOptions{Tracking: mode})
			if err != nil {
				t.Fatalf("startup: %+v", err)
			}
			defer func() { _ = p.Close() }()
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if err = p.Quiesce(); err != nil {
				t.Fatal(err)
			}
			d, err := p.RunDiagnostics(true)
			if err != nil || d.Incomplete() {
				t.Fatalf("startup losses: %s %v", d, err)
			}
			t.Logf("startup with an existing root: %s", d)
		})
	}
}

func TestBpfRunPoisonRecovery(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	state := newRunTestMap(t, runStateMapSpec())
	cpu := affinityCPUs(t)[0]
	pinTest(t, cpu)
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	values := make([][]byte, cpus)
	for i := range values {
		values[i] = make([]byte, runSize)
	}
	binary.NativeEndian.PutUint32(values[cpu][runDepth:], 2)
	binary.NativeEndian.PutUint32(values[cpu][runPoison:], 1)
	if err = state.Update(uint32(0), values, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	l := perCPURuns{fd: state.FD()}
	ins := l.release()
	ins = append(ins, asm.Mov.Imm(asm.R0, 2).WithSymbol("exit"), asm.Return())
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: ins})
	if err != nil {
		t.Fatalf("release fixture: %+v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	for _, tc := range []struct {
		name                                       string
		initialDepth, initialPoison, depth, poison uint32
	}{{"inner-exit", 2, 1, 1, 1}, {"outer-exit", 1, 1, 0, 0}, {"empty-exit", 0, 0, 0, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			pinTest(t, cpu)
			binary.NativeEndian.PutUint32(values[cpu][runDepth:], tc.initialDepth)
			binary.NativeEndian.PutUint32(values[cpu][runPoison:], tc.initialPoison)
			if err := state.Update(uint32(0), values, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if got := runTestProgram(t, prog); got != 2 {
				t.Fatal(got)
			}
			if err = state.Lookup(uint32(0), &values); err != nil {
				t.Fatal(err)
			}
			raw := values[cpu]
			if depth, poison := binary.NativeEndian.Uint32(raw[runDepth:]), binary.NativeEndian.Uint32(raw[runPoison:]); depth != tc.depth || poison != tc.poison {
				t.Fatalf("depth=%d poison=%d want=%d,%d", depth, poison, tc.depth, tc.poison)
			}
		})
	}
}

func TestBpfRunPoisonedEntry(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	cpu := affinityCPUs(t)[0]
	pinTest(t, cpu)
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	state := newRunTestMap(t, runStateMapSpec())
	stats := newRunTestMap(t, runStatsSpec())
	values := make([][]byte, cpus)
	for i := range values {
		values[i] = make([]byte, runSize)
	}
	binary.NativeEndian.PutUint32(values[cpu][runDepth:], 1)
	binary.NativeEndian.PutUint32(values[cpu][runPoison:], 1)
	if err = state.Update(uint32(0), values, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	ins := asm.Instructions{asm.Mov.Imm(asm.R6, 0x1234)}
	ins = append(ins, (perCPURuns{fd: state.FD(), stats: stats.FD()}).create()...)
	// Linux 6.1 XDP test programs cannot call the tracing owner helper.
	// Stub this diagnostic-only call; poisoned entries never execute it.
	for i, op := range ins {
		if op.IsBuiltinCall() && asm.BuiltinFunc(op.Constant) == asm.FnGetCurrentPidTgid {
			ins[i] = asm.Mov.Imm(asm.R0, 0).WithSymbol(op.Symbol())
		}
	}
	ins = append(ins, asm.Mov.Imm(asm.R0, 2).WithSymbol("exit"), asm.Return())
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: ins})
	if err != nil {
		t.Fatalf("create fixture: %+v", err)
	}
	defer func() { _ = prog.Close() }()
	if got := runTestProgram(t, prog); got != 2 {
		t.Fatal(got)
	}
	if err = state.Lookup(uint32(0), &values); err != nil {
		t.Fatal(err)
	}
	raw := values[cpu]
	frame := raw[runFrames+runStride:]
	if binary.NativeEndian.Uint32(raw[runDepth:]) != 2 || binary.NativeEndian.Uint32(raw[runPoison:]) != 1 || binary.NativeEndian.Uint32(frame[runState:]) != runBlocked || binary.NativeEndian.Uint64(frame[runID:]) != 0 || binary.NativeEndian.Uint64(frame[runCtx:]) != 0x1234 {
		t.Fatalf("poisoned entry is not blocked: %x", raw)
	}
}

func TestBpfRunStartupMismatchDrain(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	cpu := affinityCPUs(t)[0]
	pinTest(t, cpu)
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	for _, stop := range []uint32{runRunning, runStopped, runStarting} {
		t.Run(fmt.Sprint(stop), func(t *testing.T) {
			pinTest(t, cpu)
			state := newRunTestMap(t, runStateMapSpec())
			stats := newRunTestMap(t, runStatsSpec())
			hold := newRunTestMap(t, &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
			if err := hold.Update(uint32(0), stop, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			values := make([][]byte, cpus)
			for i := range values {
				values[i] = make([]byte, runSize)
			}
			binary.NativeEndian.PutUint32(values[cpu][runDepth:], 1)
			binary.NativeEndian.PutUint64(values[cpu][runFrames+runCtx:], 0x1234)
			if err := state.Update(uint32(0), values, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			r := &runCapture{mode: "percpu", statsFD: stats.FD(), locator: perCPURuns{state.FD(), stats.FD()}}
			ins := asm.Instructions{asm.Mov.Imm(asm.R6, 0x5678)}
			ins = append(ins, runFind(r, "exit", "mismatch")...)
			ins = append(ins, asm.Ja.Label("exit"))
			ins = append(ins, runMismatchTail(r, hold.FD(), "release")...)
			ins = append(ins, asm.Mov.Imm(asm.R0, 0).WithSymbol("release"))
			ins = append(ins, r.locator.release()...)
			ins = append(ins, asm.Mov.Imm(asm.R0, 2).WithSymbol("exit"), asm.Return())
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: ins})
			if err != nil {
				t.Fatalf("mismatch fixture: %+v", err)
			}
			t.Cleanup(func() { _ = prog.Close() })
			if got := runTestProgram(t, prog); got != 2 {
				t.Fatal(got)
			}
			if err := state.Lookup(uint32(0), &values); err != nil {
				t.Fatal(err)
			}
			wantDepth := uint32(0)
			wantMismatch := uint64(1)
			if stop == runStopped {
				wantDepth = 1
				wantMismatch = 0
			}
			var counters [][runStatCount]uint64
			if err := stats.Lookup(uint32(0), &counters); err != nil {
				t.Fatal(err)
			}
			if depth, poison := binary.NativeEndian.Uint32(values[cpu][runDepth:]), binary.NativeEndian.Uint32(values[cpu][runPoison:]); depth != wantDepth || poison != 0 || counters[cpu][runMismatch] != wantMismatch {
				t.Fatalf("stop=%d depth=%d poison=%d counters=%v", stop, depth, poison, counters[cpu])
			}
		})
	}
}
