package regionval

import (
	"maps"
	"path/filepath"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	rd "github.com/takehaya/bpf-ninja/tools/regionval/dafny/regionvaldafny"
)

// Real captures (Linux 6.12, x86-64). Each pins the verdict and the number of
// windows per obligation kind, so a change to window cutting or to the core
// shows up here. scripts/corpus.sh runs the same check on a full directory.
func TestCaptures(t *testing.T) {
	for _, c := range []struct {
		file  string
		ok    bool
		stage string // structure stage that fails, if any
		kinds map[string]int
	}{
		{
			file:  "xdp-tools--xdp-tools--xsk_def_xdp_prog_5.3.o--xsk_def_prog.json",
			ok:    true,
			kinds: map[string]int{"prologue-P1": 1, "site": 1, "hook-P7": 1},
		},
		{
			file:  "dae--dae-bpf_bpfel.o--tproxy_lan_egress_l2.json",
			ok:    true,
			kinds: map[string]int{"prologue-P1": 1, "site": 24, "hook-P7": 10, "prologue-P9": 3, "passload-P9": 2},
		},
		{
			file:  "Calico--calico-to_wep_no_log-notrap.o--calico_tc_skb_ipv4_frag.json",
			ok:    true,
			kinds: map[string]int{"prologue-P1": 1, "site": 37, "hook-P7": 34, "prologue-P1b": 1},
		},
		{
			file:  "xvs--xvs-layer3.o--xdp_forward_func.json",
			ok:    true,
			kinds: map[string]int{"prologue-P1": 1, "site-P8": 34, "hook-P7": 19},
		},
		{
			// The entry prologue and the prelude of the first site touch,
			// so the windows cannot be cut apart.
			file:  "xdp-tools--xdp-tools--xdp_trafficgen.bpf.o--xdp_redirect_notouch.json",
			stage: "windows",
			kinds: map[string]int{},
		},
	} {
		t.Run(c.file, func(t *testing.T) {
			r := Run(filepath.Join("testdata", "captures", c.file))
			if r.Validated != c.ok || r.Structure.Stage != c.stage {
				t.Fatalf("validated %v, failed stage %q; want %v, %q (%+v)", r.Validated, r.Structure.Stage, c.ok, c.stage, r.Structure)
			}
			got := map[string]int{}
			for _, w := range r.Windows {
				got[w.CoreKind]++
				if c.ok && !w.Validated {
					t.Errorf("window %s [%d,%d): %s", w.CoreKind, w.Start, w.End, w.Reason)
				}
			}
			if !maps.Equal(got, c.kinds) {
				t.Errorf("windows by kind %v, want %v", got, c.kinds)
			}
		})
	}
}

// The Dafny core decides; the Go core gives the rule. On every capture under
// testdata the two cores agree on every window.
func TestCoresAgree(t *testing.T) {
	var files []string
	for _, g := range []string{"testdata/captures/*.json", "testdata/export/*/*.json"} {
		fs, _ := filepath.Glob(g)
		files = append(files, fs...)
	}
	if len(files) < 59 {
		t.Fatalf("%d capture files under testdata, want at least 59", len(files))
	}
	for _, f := range files {
		r := Run(f)
		for _, w := range r.Windows {
			if w.Disagree || w.Validated != w.GoValidated {
				t.Errorf("%s: %s [%d,%d): Dafny %v (%s), Go %v (%s)", f, w.CoreKind, w.Start, w.End, w.Validated, w.DafnyReason, w.GoValidated, w.Reason)
			}
		}
		if r.Counts.Disagree != 0 {
			t.Errorf("%s: counts.disagree = %d", f, r.Counts.Disagree)
		}
	}
}

// A window the Go core validates and the Dafny core rejects is not
// validated and carries rule "dafny"; the reverse keeps the Go core's rule.
// Both are marked as disagreeing.
func TestMerge(t *testing.T) {
	var wr WindowResult
	wr.merge(core.Verdict{Validated: true, Paths: 2}, rd.Verdict{Reason: "too many branches"})
	if wr.Validated || !wr.GoValidated || !wr.Disagree || wr.Rule != "dafny" || wr.DafnyReason != "too many branches" || wr.Paths != 2 {
		t.Errorf("Go only: %+v", wr)
	}
	wr = WindowResult{}
	wr.merge(core.Verdict{Rule: "C2", Reason: "C2: r6"}, rd.Verdict{Validated: true})
	if !wr.Validated || wr.GoValidated || !wr.Disagree || wr.Rule != "C2" || wr.DafnyReason != "" {
		t.Errorf("Dafny only: %+v", wr)
	}
	wr = WindowResult{}
	wr.merge(core.Verdict{Rule: "C1", Reason: "C1: x"}, rd.Verdict{Reason: "store"})
	if wr.Validated || wr.Disagree || wr.Rule != "C1" || wr.DafnyReason != "store" {
		t.Errorf("both reject: %+v", wr)
	}
}
