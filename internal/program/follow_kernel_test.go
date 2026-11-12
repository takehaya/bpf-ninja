package program

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// followerTarget resolves funcName of an already loaded program the way the
// capture does for a program it finds later.
func followerTarget(t *testing.T, id uint32, funcName string) attach.Target {
	t.Helper()
	info, err := attach.FindBPFProgramByID(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = info.Program.Close() })
	targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{info}, []string{funcName}, false)
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets %+v: %v", targets, err)
	}
	return targets[0]
}

func progID(t *testing.T, prog *ebpf.Program) uint32 {
	t.Helper()
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	return uint32(id)
}

// TestBpfFollowerAttach adds a second program's capture_pt to a running
// probe and checks both programs reach the same rings.
func TestBpfFollowerAttach(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	gen1 := loadXDPByName(t, multiNoinlineSource("xdp_gen1"), "xdp_gen1")
	initial := followerTarget(t, progID(t, gen1), "capture_pt")
	probe, err := LoadMultiEntry([]attach.Target{initial}, "", nil, true, nil)
	if err != nil {
		t.Fatalf("LoadMultiEntry: %v", err)
	}
	defer func() { _ = probe.Close() }()

	gen2 := loadXDPByName(t, multiNoinlineSource("xdp_gen2"), "xdp_gen2")
	id1, id2 := progID(t, gen1), progID(t, gen2)
	follower := followerTarget(t, id2, "capture_pt")
	if _, err := probe.AttachFollower(1, follower, filter.TargetFilters{}, nil); err == nil {
		t.Fatal("a follower joined a site the capture does not have")
	}
	if _, err := probe.AttachFollower(0, follower, filter.TargetFilters{}, nil); err != nil {
		t.Fatalf("AttachFollower: %v", err)
	}
	if got := []int{probe.AttachCount(), probe.ObserverLinks(id1), probe.ObserverLinks(id2)}; !slices.Equal(got, []int{2, 1, 1}) {
		t.Fatalf("attach count, links on gen1, links on gen2 = %v, want [2 1 1]", got)
	}
	runWithMarker(t, gen1, 0x11)
	runWithMarker(t, gen2, 0x22)
	if m := drainMarkers(t, probe, 2); m[0x11] != 1 || m[0x22] != 1 {
		t.Fatalf("markers %v, want one record from each generation", m)
	}
	if err := probe.Quiesce(); err != nil {
		t.Fatal(err)
	}
	if _, err := probe.AttachFollower(0, follower, filter.TargetFilters{}, nil); !errors.Is(err, ErrProbeStopped) {
		t.Fatalf("AttachFollower after Quiesce: %v, want ErrProbeStopped", err)
	}
}

// TestBpfFollowerRecordSite loads the injected fixture twice and captures
// at the first generation's hooks. The second generation joins the same
// sites: its records carry the same site ids and decode to the same
// comments, in filter and in entry mode, and a layout that decodes
// differently is refused.
func TestBpfFollowerRecordSite(t *testing.T) {
	elf := recordFixtureELF(t)
	req := inject.LookupRequest{ProgramName: "record_target", Auto: true,
		Updates: inject.CallAny, StaticUntrusted: true, HookName: "rec", Stack: inject.StackAudit{LowestOffset: -64}}
	names := []string{"rec_pols", "rec_pols_update"}
	exprs := map[string][]string{"rec_pols": {"value->pol_rc>=3", "key->policy_index<=9"}, "rec_pols_update": {"value->pol_rc>=20"}}
	for _, mode := range []record.Mode{record.ModeFilter, record.ModeEntry} {
		t.Run(string(mode), func(t *testing.T) {
			_, id1 := loadInjected(t, elf, req)
			_, id2 := loadInjected(t, elf, req)
			seedRecordMaps(t, id1)
			seedRecordMaps(t, id2)
			opt := recordbuild.Options{Mode: mode, MaxBytes: 256}
			// build resolves one generation's targets, filters and layouts.
			build := func(id uint32) ([]attach.Target, []filter.TargetFilters, []*record.Layout) {
				var targets []attach.Target
				var filters []filter.TargetFilters
				var layouts []*record.Layout
				for _, n := range names {
					tg := followerTarget(t, id, n)
					var tf filter.TargetFilters
					if mode == record.ModeFilter {
						args, err := filter.ParseAndValidateFilters(exprs[n], tg.Params)
						if err != nil {
							t.Fatal(err)
						}
						tf.Args = args
					}
					l, err := recordbuild.Build(tg, tf, opt)
					if err != nil || l == nil {
						t.Fatalf("layout %s: %v", n, err)
					}
					targets, filters, layouts = append(targets, tg), append(filters, tf), append(layouts, l)
				}
				return targets, filters, layouts
			}
			targets1, filters1, layouts1 := build(id1)
			probe, err := LoadMultiPointRecordFollow(targets1, []Stage{{}}, filters1, true, nil, EmitBoth, layouts1)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = probe.Close() }()
			targets2, filters2, layouts2 := build(id2)
			// A layout of the other site decodes differently and is refused.
			if _, err := probe.AttachFollower(0, targets2[0], filters2[0], layouts2[1]); !errors.Is(err, ErrLayoutChanged) {
				t.Fatalf("AttachFollower with another site's layout: %v, want ErrLayoutChanged", err)
			}
			for i := range targets2 {
				if _, err := probe.AttachFollower(i, targets2[i], filters2[i], layouts2[i]); err != nil {
					t.Fatalf("AttachFollower %s: %v", names[i], err)
				}
			}
			// Byte 1 tells the generations apart; byte 0 selects the policy.
			for gen, id := range []uint32{id1, id2} {
				prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
				if err != nil {
					t.Fatal(err)
				}
				for _, idx := range []byte{1, 2, 3, 5} {
					data := make([]byte, 64)
					data[0], data[1] = idx, byte(gen)
					if _, err := prog.Run(&ebpf.RunOptions{Data: data}); err != nil {
						t.Fatal(err)
					}
				}
				_ = prog.Close()
			}
			var pkts [2][]capture.Packet
			for _, inner := range probe.InnerMaps {
				rd, err := fastrb.New(inner.FD(), int(inner.MaxEntries()))
				if err != nil {
					t.Fatal(err)
				}
				rd.ReadBatch(func(raw []byte) {
					p, err := capture.ParseRawSample(raw)
					if err != nil {
						t.Fatal(err)
					}
					p.Data, p.Record = append([]byte(nil), p.Data...), append([]byte(nil), p.Record...)
					pkts[p.Data[1]] = append(pkts[p.Data[1]], p)
				})
				_ = rd.Close()
			}
			var epbs [2][]recordEPB
			for gen := range pkts {
				// Both files are decoded with the first generation's layouts,
				// as the capture's writer does.
				path := filepath.Join(t.TempDir(), "r.pcapng")
				w, err := output.NewWriter(path, output.Config{Hooks: names, Records: layouts1, NoRunIDs: true})
				if err != nil {
					t.Fatal(err)
				}
				if err := w.WriteBatch(pkts[gen]); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				epbs[gen] = readRecordEPBs(t, path)
			}
			if len(epbs[0]) == 0 || !slices.Equal(epbs[0], epbs[1]) {
				t.Fatalf("generation 1 records %+v\ngeneration 2 records %+v", epbs[0], epbs[1])
			}
			ifaces := map[uint32]bool{}
			for _, e := range epbs[1] {
				ifaces[e.iface] = true
				if e.note == "" {
					t.Fatalf("record without a comment: %+v", e)
				}
			}
			if len(ifaces) != len(names) {
				t.Fatalf("generation 2 wrote to interfaces %v, want one per site", ifaces)
			}
		})
	}
}
