package syscallhook

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// trialBudget bounds the extra verifications of one program load whose
// rewrite the kernel refused: every trial call of the retry and the
// jump-limit diagnostic load (hitJumpLimit) count.
const trialBudget = 24

// retrySite is an emitted site the retry may drop, and the hook it calls.
type retrySite struct {
	pc   uint32
	hook string
}

// retrySites lists the sites of hooks in the order the retry tries them
// (inject.RetryRank, then pc). An explicitly selected lookup (not auto) is
// not one: the rule names it, so dropping it refuses the rewrite.
func retrySites(hooks []inject.LookupHook, auto bool) []retrySite {
	type ranked struct {
		retrySite
		rank int
	}
	var sites []ranked
	seen := map[uint32]bool{}
	for _, h := range hooks {
		if h.Kind == inject.HookLookup && !auto {
			continue
		}
		for _, site := range h.Sites {
			if seen[site.SitePC] || site.SitePC == inject.DispatchEntrySite {
				continue
			}
			seen[site.SitePC] = true
			sites = append(sites, ranked{retrySite{site.SitePC, h.Name}, inject.RetryRank(h)})
		}
	}
	slices.SortFunc(sites, func(a, b ranked) int { return cmp.Or(a.rank-b.rank, cmp.Compare(a.pc, b.pc)) })
	out := make([]retrySite, len(sites))
	for i, site := range sites {
		out[i] = site.retrySite
	}
	return out
}

// baseHooksNothing says whether the retry's base, hooks without any of
// sites, hooks nothing: entry is false and every site of hooks is one the
// retry may drop. The transform refuses such a request; it stands for the
// original program.
func baseHooksNothing(hooks []inject.LookupHook, sites []retrySite, entry bool) bool {
	if entry {
		return false
	}
	droppable := map[uint32]bool{}
	for _, site := range sites {
		droppable[site.pc] = true
	}
	for _, h := range hooks {
		if h.Kind == inject.HookEntry || slices.ContainsFunc(h.Sites, func(site inject.LookupSite) bool { return !droppable[site.SitePC] }) {
			return false
		}
	}
	return true
}

// refusedHere is the reason of a site whose trial the kernel refused: the
// sites kept so far loaded without it and did not with it. It says nothing
// about the site alone.
func refusedHere(why string) string {
	return "load: refused in this combination (the kept sites plus this one): " + why
}

// budgetUsedUp is the reason of a site the retry did not keep before its
// budget ran out.
var budgetUsedUp = fmt.Sprintf("load: not kept: the budget of %d trial loads was used up", trialBudget)

// retryResult is what retry found. art is the last rewrite a trial load
// accepted, with the sites in kept; loaded is false when none was, the base
// included. dropped gives every other site's reason.
type retryResult[A any] struct {
	art     A
	loaded  bool
	kept    []uint32
	dropped map[uint32]string
	trials  int
}

// retry looks for sites the kernel accepts after it refused all of sites,
// with why (its message). It is a bounded heuristic, not a search for one
// culprit. trial rewrites the program without the sites of drop, trial-loads
// it, and reports whether the kernel accepted it, with the verifier's last
// log line when not; an error ends the search. At most budget trials run.
//
// The base, without any of sites, is tried first; when it is refused nothing
// loads. When bare, the base hooks nothing: it is the original program, so
// it is neither tried nor charged to the budget and is never the result.
// Then, while sites are left: the longest prefix of them that loads
// with the sites kept so far is found by bisection and kept, the next site is
// dropped as refused in this combination, the other sites of its hook are
// tried together and then each on its own, and the kept sites plus the rest
// are tried. A site is dropped only after a trial in which it was the one
// added to sites that loaded. When the budget ends, sites not kept by then are
// dropped with budgetUsedUp. The result is always a set a trial accepted.
func retry[A any](sites []retrySite, why string, budget int, bare bool, trial func(drop map[uint32]string) (A, bool, string, error)) (retryResult[A], error) {
	out := retryResult[A]{dropped: map[uint32]string{}}
	refused := map[uint32]string{}
	try := func(keep []retrySite) (bool, string, error) {
		in := map[uint32]bool{}
		for _, site := range keep {
			in[site.pc] = true
		}
		drop := map[uint32]string{}
		for _, site := range sites {
			if !in[site.pc] {
				drop[site.pc] = cmp.Or(refused[site.pc], budgetUsedUp)
			}
		}
		budget--
		out.trials++
		art, ok, why, err := trial(drop)
		if err == nil && ok {
			out.art, out.loaded, out.kept = art, true, nil
			for _, site := range keep {
				out.kept = append(out.kept, site.pc)
			}
		}
		return ok, why, err
	}
	finish := func() (retryResult[A], error) {
		for _, site := range sites {
			if out.loaded && !slices.Contains(out.kept, site.pc) {
				out.dropped[site.pc] = cmp.Or(refused[site.pc], budgetUsedUp)
			}
		}
		return out, nil
	}
	if budget <= 0 || len(sites) == 0 {
		return out, nil
	}
	if !bare {
		if ok, _, err := try(nil); err != nil || !ok {
			return out, err
		}
	}
	with := func(good []retrySite, more ...retrySite) []retrySite { return append(slices.Clone(good), more...) }
	var good []retrySite
	rest, known := sites, true // known: good plus rest is refused, with why
	for len(rest) != 0 {
		if !known {
			if budget <= 0 {
				break
			}
			ok, w, err := try(with(good, rest...))
			if err != nil {
				return out, err
			}
			if ok {
				good, rest = with(good, rest...), nil
				break
			}
			why = w
		}
		known = false
		lo, hi := 0, len(rest) // good+rest[:lo] loads, good+rest[:hi] is refused with why
		for hi-lo > 1 && budget > 0 {
			mid := (lo + hi) / 2
			ok, w, err := try(with(good, rest[:mid]...))
			if err != nil {
				return out, err
			}
			if ok {
				lo = mid
			} else {
				hi, why = mid, w
			}
		}
		if hi-lo > 1 {
			break
		}
		culprit := rest[lo]
		good, rest = with(good, rest[:lo]...), rest[lo+1:]
		refused[culprit.pc] = refusedHere(why)
		var same []retrySite
		for _, site := range rest {
			if site.hook == culprit.hook {
				same = append(same, site)
			}
		}
		if len(same) > 1 && budget > 0 {
			ok, _, err := try(with(good, same...))
			if err != nil {
				return out, err
			}
			if ok {
				good, same = with(good, same...), nil
			}
		}
		for _, site := range same {
			if budget <= 0 {
				break
			}
			ok, w, err := try(with(good, site))
			if err != nil {
				return out, err
			}
			if ok {
				good = with(good, site)
			} else {
				refused[site.pc] = refusedHere(w)
			}
		}
		rest = slices.DeleteFunc(slices.Clone(rest), func(site retrySite) bool {
			return refused[site.pc] != "" || slices.Contains(good, site)
		})
	}
	return finish()
}

// errNothingLoads ends a retry in which no trial load passed, not even the
// base without the sites it may drop (when the base hooks something).
var errNothingLoads = errors.New("no trial load passed, not even without every site the retry may drop")

// degrade runs retry and loads exactly the rewrite it kept with load. Its
// error, or errNothingLoads, leaves the caller to load the original program
// or to refuse the load.
func degrade[A any](sites []retrySite, why string, budget int, bare bool, trial func(map[uint32]string) (A, bool, string, error),
	load func(A) (int64, error)) (retryResult[A], int64, error) {
	out, err := retry(sites, why, budget, bare, trial)
	if err == nil && !out.loaded {
		err = errNothingLoads
	}
	if err != nil {
		return out, 0, err
	}
	ret, err := load(out.art)
	return out, ret, err
}

// lastLogLine is the last line of a verifier log that is not one of the
// statistics BPF_LOG_STATS appends.
func lastLogLine(log string) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" && !strings.HasPrefix(line, "processed ") && !strings.HasPrefix(line, "verification time") && !strings.HasPrefix(line, "stack depth") {
			return line
		}
	}
	return ""
}

// droppedSummary lists the dropped sites as "pc A: reason; pc B: reason" in
// pc order.
func droppedSummary(dropped map[uint32]string) string {
	pcs := slices.Sorted(maps.Keys(dropped))
	parts := make([]string, len(pcs))
	for i, pc := range pcs {
		parts[i] = fmt.Sprintf("pc %d: %s", pc, dropped[pc])
	}
	return strings.Join(parts, "; ")
}
