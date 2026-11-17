package syscallhook

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// Sites selects sites of a hook_prefix rule as a listing names them. Build
// is the listing fingerprint (inject.ListingFingerprint) the entries were
// copied from; a load with another fingerprint gets no hooks. Only keeps,
// for each hook unit that has a selected site, just the selected sites, and
// leaves every other unit's sites as the rule selects them; a unit is what
// gets its own hook: a callee, one op of one map, or tail_call. Except
// removes the sites it names. Exactly one of the two is given.
// Removing sites never adds a hook.
type Sites struct {
	Build  string    `json:"build"`
	Only   []SiteRef `json:"only,omitempty"`
	Except []SiteRef `json:"except,omitempty"`
}

// SiteRef is one entry of Sites: a label as the listing prints it, or the
// site's instruction number (the listing's pc) as a JSON number. A label
// without its #N suffix names every site sharing it.
type SiteRef struct {
	Label string
	PC    *uint32
}

func (s *SiteRef) UnmarshalJSON(data []byte) error {
	if len(data) != 0 && data[0] == '"' {
		return json.Unmarshal(data, &s.Label)
	}
	pc, err := strconv.ParseUint(string(data), 10, 32)
	if err != nil {
		return fmt.Errorf("a sites entry is a label string or an instruction number, not %s", data)
	}
	n := uint32(pc)
	s.PC = &n
	return nil
}

func (s SiteRef) MarshalJSON() ([]byte, error) {
	if s.PC != nil {
		return json.Marshal(*s.PC)
	}
	return json.Marshal(s.Label)
}

func (s SiteRef) String() string {
	if s.PC != nil {
		return fmt.Sprintf("pc %d", *s.PC)
	}
	return strconv.Quote(s.Label)
}

func (r Rule) validateSites() error {
	if r.Sites == nil {
		return nil
	}
	switch {
	case r.HookPrefix == "":
		return fmt.Errorf("sites needs a rule written with hook_prefix; a rule written with hook selects sites with map, func, line, all_matches or site_pcs")
	case r.Map != "" || r.Func != "" || r.Line != 0 || r.AllMatches || len(r.SitePCs) != 0:
		return fmt.Errorf("sites does not combine with map, func, line, all_matches or site_pcs")
	case r.Sites.Only != nil && r.Sites.Except != nil:
		return fmt.Errorf("sites takes only or except, not both")
	case r.Sites.Only == nil && r.Sites.Except == nil:
		return fmt.Errorf("sites needs only or except")
	case r.Sites.Build == "":
		return fmt.Errorf("sites.build is required: copy the program's build from the listing")
	}
	return nil
}

// listing is the full discovery of raw as a lookups file lists it: the map
// calls (inject.DiscoverMapCallsRaw) and every other site, with the labels
// and the listing fingerprint of all of them (inject.DiscoverCallSitesRaw).
// raw.Kernel and raw.Modules name kfunc calls. A listing and the load-time
// sites check both call it, so they compute the same fingerprint.
func listing(raw inject.RawProgram) (calls []inject.LookupSite, sites inject.CallDiscovery, err error) {
	err = guard("listing the load", func() (err error) {
		if calls, err = inject.DiscoverMapCallsRaw(raw); err != nil {
			return err
		}
		sites, err = inject.DiscoverCallSitesRaw(raw, calls)
		return err
	})
	if err != nil {
		return nil, inject.CallDiscovery{}, err
	}
	return calls, sites, nil
}

// dropReason is the reason a site left out by Sites is skipped with.
const dropReason = "not selected by the rule's sites"

// drop resolves the selection against the listing of this load: build is
// its fingerprint, sites every site of the full discovery and labels their
// labels by pc (inject.CallDiscovery). It returns the pcs the transform
// drops (inject.LookupRequest.Drop), or an error when the listing is of
// another build or an entry names no site of this program.
func (s *Sites) drop(build string, sites []inject.LookupSite, labels map[uint32]string) (map[uint32]string, error) {
	if build != s.Build {
		return nil, fmt.Errorf("rule sites were listed from build %s but this load is build %s; list again with --lookups-json and copy the sites from the new file", s.Build, build)
	}
	named := map[uint32]bool{}
	for _, ref := range slices.Concat(s.Only, s.Except) {
		found := false
		for pc, label := range labels {
			if ref.PC != nil && *ref.PC == pc || ref.PC == nil && (label == ref.Label || baseLabel(label) == ref.Label) {
				named[pc], found = true, true
			}
		}
		if !found {
			return nil, fmt.Errorf("rule sites: %s names no site of this program", ref)
		}
	}
	drop := map[uint32]string{}
	if s.Except != nil {
		for pc := range named {
			drop[pc] = dropReason
		}
		return drop, nil
	}
	// A unit with a selected site keeps only its selected sites: a callee,
	// one op of one map (the unit that gets its own hook), or tail_call.
	key := func(site inject.LookupSite) string {
		switch site.Op {
		case inject.HookCall:
			return "call " + site.Call
		case inject.HookTailCall:
			return "tail_call"
		}
		return "map " + site.MapName + " " + string(site.Op)
	}
	selected := map[string]bool{}
	for _, site := range sites {
		if named[site.SitePC] {
			selected[key(site)] = true
		}
	}
	for _, site := range sites {
		if selected[key(site)] && !named[site.SitePC] {
			drop[site.SitePC] = dropReason
		}
	}
	return drop, nil
}

// baseLabel is label without its #N suffix (inject.SiteLabels).
func baseLabel(label string) string {
	if i := strings.LastIndexByte(label, '#'); i >= 0 {
		if _, err := strconv.ParseUint(label[i+1:], 10, 32); err == nil {
			return label[:i]
		}
	}
	return label
}
