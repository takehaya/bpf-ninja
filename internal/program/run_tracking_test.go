package program

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
)

func TestRunTrackingChoice(t *testing.T) {
	for _, tc := range []struct {
		major, minor int
		want         string
	}{{5, 15, "ctx"}, {6, 1, "ctx"}, {6, 2, "ctx"}, {6, 3, "percpu"}, {6, 6, "percpu"}, {7, 0, "percpu"}} {
		for _, override := range []string{"auto", "ctx", "percpu"} {
			mode, reason, e := selectRunTracking(override, tc.major, tc.minor, true, false, ebpf.XDP)
			want := tc.want
			if override != "auto" {
				want = override
			}
			if e != nil || mode != want || reason == "" {
				t.Fatalf("%+v %s: %s %s %v", tc, override, mode, reason, e)
			}
		}
	}
	for _, override := range []string{"auto", "ctx", "percpu"} {
		mode, _, err := selectRunTracking(override, 0, 0, false, false, ebpf.XDP)
		want := override
		if override == "auto" {
			want = "ctx"
		}
		if override == "percpu" {
			if err == nil || !strings.Contains(err.Error(), "use --run-tracking=ctx") {
				t.Fatal(err)
			}
		} else if err != nil || mode != want {
			t.Fatalf("unknown version: %s %s %v", override, mode, err)
		}
		for _, tc := range []struct {
			rt   bool
			pt   ebpf.ProgramType
			text string
		}{
			{true, ebpf.XDP, "PREEMPT_RT"}, {false, ebpf.Kprobe, "XDP or SchedCLS"},
		} {
			_, _, err := selectRunTracking(override, 6, 3, true, tc.rt, tc.pt)
			if err == nil || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("%+v: %v", tc, err)
			}
		}
	}

	if _, _, e := selectRunTracking("invalid", 7, 0, true, false, ebpf.XDP); e == nil {
		t.Fatal("invalid mode")
	}
}
func TestRunPositiveRT(t *testing.T) {
	for _, tc := range []struct {
		rt, v, c string
		want     bool
	}{{"1\n", "", "", true}, {"", "#1 PREEMPT_RT SMP", "", true}, {"", "", "CONFIG_PREEMPT_RT=y\n", true}, {"", "PREEMPT_DYNAMIC", "# CONFIG_PREEMPT_RT is not set", false}, {"0", "PREEMPT", "CONFIG_PREEMPT_RT=n", false}, {"", "", "", false}} {
		if got := positiveRT(tc.rt, tc.v, tc.c); got != tc.want {
			t.Fatalf("%+v got=%v", tc, got)
		}
	}
}
func TestRunCaptureMarshal(t *testing.T) {
	h, _ := hook.ByProgramType(ebpf.XDP)
	for _, mode := range []string{"percpu", "ctx"} {
		r := &runCapture{mode: mode, seqFD: 125, statsFD: 124, locator: perCPURuns{123, 124}}
		if mode == "ctx" {
			r.locator = ctxRuns{123, 124}
		}
		for _, stage := range []string{"entry", "entry-start", "hook", "hook-start", "static-hook-start", "exit"} {
			t.Run(mode+"/"+stage, func(t *testing.T) {
				c := hookPredicate{}
				c.out.Capture.MaxCapLen = 64
				var ins asm.Instructions
				var err error
				selected := h
				if stage == "static-hook-start" {
					selected = staticXDPHook(h, false)
				}
				if strings.Contains(stage, "start") {
					c.out, err = compileFilter("eth[dst==00:00:00:00:00:00]", true, false, ebpf.XDP)
					if err != nil {
						t.Fatal(err)
					}
				}
				switch stage {
				case "entry", "entry-start":
					ins, err = buildRunEntry(selected, c, r, 121, 125, 126, stage == "entry-start")
				case "exit":
					ins = buildRunExit(r, 126)
				default:
					ins, err = buildRunHook(selected, c, filter.TargetFilters{}, r, 120, 121, 122, 125, 126, 1, strings.Contains(stage, "start"))
				}
				if err != nil {
					t.Fatal(err)
				}
				var buf bytes.Buffer
				if err = ins.Marshal(&buf, binary.LittleEndian); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join("testdata", "run-"+mode+"-"+stage+".hex")
				if os.Getenv("UPDATE_RUN_GOLDEN") == "1" {
					if err = os.WriteFile(path, []byte(hex.EncodeToString(buf.Bytes())+"\n"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				asmPath := strings.TrimSuffix(path, ".hex") + ".asm"
				display := append(asm.Instructions(nil), ins...)
				for i := range display {
					if display[i].Reference() != "" {
						display[i].Offset = 0
					}
				}
				listing := regexp.MustCompile(`(?m)^\s*\d+: `).ReplaceAllString(fmt.Sprintf("%v\n", display), "")
				if os.Getenv("UPDATE_RUN_GOLDEN") == "1" {
					if err = os.WriteFile(asmPath, []byte(listing), 0644); err != nil {
						t.Fatal(err)
					}
				}
				text, err := os.ReadFile(asmPath)
				if err != nil || string(text) != listing {
					t.Fatalf("assembly golden changed: %s: %v", asmPath, err)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				want, err := hex.DecodeString(strings.TrimSpace(string(raw)))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf.Bytes(), want) {
					t.Fatalf("instruction golden changed: %s", path)
				}
			})
		}
	}
}

func TestRunStatNames(t *testing.T) {
	for i, name := range runStatNames {
		if name == "" {
			t.Fatalf("unnamed counter %d", i)
		}
	}
}

func TestBoundaryMisses(t *testing.T) {
	entry, exit, err := boundaryMisses(func(i int) (uint64, error) { return []uint64{2, 99, 3}[i], nil }, 3)
	if err != nil || entry != 3 || exit != 2 {
		t.Fatalf("entry=%d exit=%d err=%v", entry, exit, err)
	}
	for _, bad := range []int{0, 2} {
		_, _, err := boundaryMisses(func(i int) (uint64, error) {
			if i == bad {
				return 0, fmt.Errorf("read failure")
			}
			return 1, nil
		}, 3)
		if err == nil {
			t.Fatal("lost boundary read failure")
		}
	}
}

func TestPreTrackingIsNotLoss(t *testing.T) {
	var d RunDiagnostics
	d.Counters[runPreTracking] = 3
	if d.Incomplete() {
		t.Fatal("pre-tracking runs are expected")
	}
	d.Counters[runExitWithoutEntry] = 1
	if !d.Incomplete() {
		t.Fatal("missing tracked exit is loss")
	}
}

func TestRunStartupOrder(t *testing.T) {
	want := []string{"stop=2", "attach", "barrier", "baseline", "stop=0"}
	for fail := -1; fail < len(want); fail++ {
		var got []string
		record := func(name string) error {
			got = append(got, name)
			if len(got)-1 == fail {
				return fmt.Errorf("injected %s failure", name)
			}
			return nil
		}
		err := startHookCapture(func(state uint32) error { return record(fmt.Sprintf("stop=%d", state)) }, func() error { return record("attach") }, func() error { return record("barrier") }, func() error { return record("baseline") })
		n := len(want)
		if fail >= 0 {
			n = fail + 1
		}
		if !slices.Equal(got, want[:n]) || (err != nil) != (fail >= 0) {
			t.Fatalf("fail=%d got=%v err=%v", fail, got, err)
		}
	}
}
