package syscallhook

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// fakeLoader stands in for the kernel: accepts says whether it loads the
// program with the sites of keep. Every trial is recorded, with the sites it
// kept, as the artifact the trial returns.
type fakeLoader struct {
	sites   []retrySite
	accepts func(keep []uint32) bool
	trials  []fakeTrial
}

type fakeTrial struct {
	keep []uint32
	ok   bool
}

func (f *fakeLoader) trial(drop map[uint32]string) ([]uint32, bool, string, error) {
	var keep []uint32
	for _, site := range f.sites {
		if _, ok := drop[site.pc]; !ok {
			keep = append(keep, site.pc)
		}
	}
	ok := f.accepts(keep)
	f.trials = append(f.trials, fakeTrial{keep, ok})
	if !ok {
		return keep, false, fmt.Sprintf("refused %v", keep), nil
	}
	return keep, true, "", nil
}

// refusing accepts a set unless it holds one of bad.
func refusing(bad ...uint32) func([]uint32) bool {
	return func(keep []uint32) bool { return !slices.ContainsFunc(keep, func(pc uint32) bool { return slices.Contains(bad, pc) }) }
}

// testSites are sites 10, 20, ... of hooks h0, h1, ..., one each unless hook
// names a site's hook.
func testSites(n int, hook map[uint32]string) []retrySite {
	var sites []retrySite
	for i := range n {
		pc := uint32(10 * (i + 1))
		sites = append(sites, retrySite{pc, cmp.Or(hook[pc], fmt.Sprintf("h%d", i))})
	}
	return sites
}

// checkRetry checks what every retry result must satisfy: the kept rewrite
// is one a trial accepted, every site is kept or dropped, and a site dropped
// as refused was the one site a refused trial (or the first load) added to
// sites that loaded.
func checkRetry(t *testing.T, f *fakeLoader, out retryResult[[]uint32], budget int) {
	t.Helper()
	if out.trials != len(f.trials) || out.trials > budget {
		t.Fatalf("trials %d, recorded %d, budget %d", out.trials, len(f.trials), budget)
	}
	if !slices.Equal(out.art, out.kept) || !slices.ContainsFunc(f.trials, func(tr fakeTrial) bool { return tr.ok && slices.Equal(tr.keep, out.art) }) {
		t.Fatalf("kept %v was not accepted by a trial: %+v", out.art, f.trials)
	}
	// The first, real load was refused with every site.
	var all []uint32
	for _, site := range f.sites {
		all = append(all, site.pc)
	}
	trials := append(slices.Clone(f.trials), fakeTrial{all, false})
	for _, site := range f.sites {
		_, dropped := out.dropped[site.pc]
		if dropped == slices.Contains(out.kept, site.pc) {
			t.Fatalf("site %d kept=%v dropped=%v", site.pc, slices.Contains(out.kept, site.pc), dropped)
		}
		reason := out.dropped[site.pc]
		if !dropped || reason == budgetUsedUp {
			continue
		}
		if !strings.HasPrefix(reason, "load: refused in this combination") || strings.Contains(reason, "invalid") {
			t.Fatalf("site %d reason %q", site.pc, reason)
		}
		own := slices.ContainsFunc(trials, func(refused fakeTrial) bool {
			return !refused.ok && slices.Contains(refused.keep, site.pc) && slices.ContainsFunc(trials, func(passed fakeTrial) bool {
				return passed.ok && len(passed.keep)+1 == len(refused.keep) &&
					!slices.Contains(passed.keep, site.pc) && !slices.ContainsFunc(passed.keep, func(pc uint32) bool { return !slices.Contains(refused.keep, pc) })
			})
		})
		if !own {
			t.Fatalf("site %d dropped without a trial of its own: %+v", site.pc, f.trials)
		}
	}
}

func runRetry(t *testing.T, sites []retrySite, accepts func([]uint32) bool, budget int) (*fakeLoader, retryResult[[]uint32]) {
	t.Helper()
	f := &fakeLoader{sites: sites, accepts: accepts}
	out, err := retry(sites, "refused all", budget, f.trial)
	if err != nil {
		t.Fatal(err)
	}
	return f, out
}

func TestRetryDropsRefusedSites(t *testing.T) {
	for _, tc := range []struct {
		name string
		hook map[uint32]string
		bad  []uint32
	}{
		{"one site", nil, []uint32{30}},
		{"two sites", nil, []uint32{30, 70}},
		{"last site", nil, []uint32{80}},
		{"first site", nil, []uint32{10}},
		// Every site of one callee is refused; each gets its own trial.
		{"whole callee", map[uint32]string{20: "x", 50: "x", 60: "x"}, []uint32{20, 50, 60}},
		// One site of a callee is refused, its other sites stay.
		{"one site of a callee", map[uint32]string{20: "x", 50: "x", 60: "x"}, []uint32{50}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, out := runRetry(t, testSites(8, tc.hook), refusing(tc.bad...), trialBudget)
			checkRetry(t, f, out, trialBudget)
			if !out.loaded || !slices.Equal(slices.Sorted(maps.Keys(out.dropped)), tc.bad) {
				t.Fatalf("loaded %v dropped %v, want %v; trials %+v", out.loaded, out.dropped, tc.bad, f.trials)
			}
			t.Logf("%d trials", out.trials)
		})
	}
}

// With every site refused the budget runs out: the last accepted set loads,
// and the sites not kept by then say so.
func TestRetryBudgetUsedUp(t *testing.T) {
	sites := testSites(40, nil)
	var bad []uint32
	for _, site := range sites[5:] {
		bad = append(bad, site.pc)
	}
	f, out := runRetry(t, sites, refusing(bad...), trialBudget)
	checkRetry(t, f, out, trialBudget)
	if !out.loaded || out.trials != trialBudget || len(out.kept) != 5 {
		t.Fatalf("loaded %v trials %d kept %v", out.loaded, out.trials, out.kept)
	}
	budgetDrops := 0
	for _, reason := range out.dropped {
		if reason == budgetUsedUp {
			budgetDrops++
		}
	}
	if budgetDrops == 0 {
		t.Fatalf("no site dropped for the budget: %v", out.dropped)
	}
	// A smaller budget, as left after the jump-limit diagnostic load.
	f, out = runRetry(t, sites, refusing(bad...), 3)
	checkRetry(t, f, out, 3)
}

// A kernel that refuses two sites together but loads each alone: the
// result is still a set a trial accepted, never a union of accepted sets.
func TestRetryNonMonotone(t *testing.T) {
	sites := testSites(6, nil)
	accepts := func(keep []uint32) bool { return !slices.Contains(keep, 20) || !slices.Contains(keep, 50) }
	f, out := runRetry(t, sites, accepts, trialBudget)
	checkRetry(t, f, out, trialBudget)
	if !accepts(out.kept) || len(out.dropped) != 1 {
		t.Fatalf("kept %v dropped %v", out.kept, out.dropped)
	}
}

// A refused base ends the retry: nothing loads, and degrade says so.
func TestRetryBaseRefused(t *testing.T) {
	f := &fakeLoader{sites: testSites(4, nil), accepts: func([]uint32) bool { return false }}
	out, _, err := degrade(f.sites, "refused all", trialBudget, f.trial, func([]uint32) (int64, error) {
		t.Fatal("loaded although no trial passed")
		return 0, nil
	})
	if !errors.Is(err, errNothingLoads) || out.loaded || len(f.trials) != 1 || len(f.trials[0].keep) != 0 {
		t.Fatalf("err %v loaded %v trials %+v", err, out.loaded, f.trials)
	}
}

// The final load is the kept rewrite exactly; when the kernel refuses it
// although its trial passed, degrade returns that error and tries nothing
// else.
func TestDegradeFinalLoadRefused(t *testing.T) {
	f := &fakeLoader{sites: testSites(4, nil), accepts: refusing(20)}
	refusal := errors.New("refused at the final load")
	var loaded [][]uint32
	out, _, err := degrade(f.sites, "refused all", trialBudget, f.trial, func(art []uint32) (int64, error) {
		loaded = append(loaded, art)
		return 0, refusal
	})
	if !errors.Is(err, refusal) || len(loaded) != 1 || !slices.Equal(loaded[0], []uint32{10, 30, 40}) || !slices.Equal(out.kept, loaded[0]) {
		t.Fatalf("err %v loaded %v kept %v", err, loaded, out.kept)
	}
}

// Sites are tried by kind, then pc; an explicitly selected lookup is not
// one the retry may drop.
func TestRetrySites(t *testing.T) {
	site := func(pc uint32) inject.LookupSite { return inject.LookupSite{SitePC: pc} }
	hooks := []inject.LookupHook{
		{Name: "obs_bpf_get_numa_node_id", Kind: inject.HookCall, Call: "bpf_get_numa_node_id", Sites: []inject.LookupSite{site(5)}},
		{Name: "obs_bpf_jiffies64", Kind: inject.HookCall, Call: "bpf_jiffies64", Sites: []inject.LookupSite{site(40), site(3)}},
		{Name: "obs", Kind: inject.HookLookup, Sites: []inject.LookupSite{site(50)}},
		{Name: "obs_miss", Kind: inject.HookLookup, Sites: []inject.LookupSite{site(50)}},
		{Name: "obs_entry", Kind: inject.HookEntry},
		{Name: "obs_tail_call", Kind: inject.HookTailCall, Sites: []inject.LookupSite{site(60)}},
	}
	want := []retrySite{{50, "obs"}, {60, "obs_tail_call"}, {3, "obs_bpf_jiffies64"}, {40, "obs_bpf_jiffies64"}, {5, "obs_bpf_get_numa_node_id"}}
	if got := retrySites(hooks, true); !slices.Equal(got, want) {
		t.Fatalf("auto: %v", got)
	}
	if got := retrySites(hooks, false); !slices.Equal(got, want[1:]) {
		t.Fatalf("explicit: %v", got)
	}
}

func TestLastLogLine(t *testing.T) {
	log := "0: R1=ctx() R10=fp0\nglobal function calls are not allowed with preemption disabled\nprocessed 12 insns (limit 1000000)\nverification time 5 usec\nstack depth 8\n"
	if got := lastLogLine(log); got != "global function calls are not allowed with preemption disabled" {
		t.Fatalf("lastLogLine = %q", got)
	}
}
