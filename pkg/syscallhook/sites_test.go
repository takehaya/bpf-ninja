package syscallhook

import (
	"maps"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/pkg/inject"
)

func TestConfigSites(t *testing.T) {
	const build = `"build":"sha256:ab"`
	for input, want := range map[string]string{
		`[{"program":"p","auto":true,"maps":["a"],"ops":["lookup"],"calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{` + build + `,"only":["bpf_ktime_get_ns@p:4#1",12]}}]`: "",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{` + build + `,"except":[3]}}]`:                                                                   "",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook":"h","sites":{` + build + `,"only":[3]}}]`:                                                                            "rule 0: sites needs a rule written with hook_prefix",
		`[{"program":"p","map":"a","hook_prefix":"h","sites":{` + build + `,"only":[3]}}]`:                                                                                        "rule 0: sites does not combine with map, func, line, all_matches or site_pcs",
		`[{"program":"p","map":"a","site_pcs":[5],"hook_prefix":"h","sites":{` + build + `,"only":[3]}}]`:                                                                         "rule 0: sites does not combine with map",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{` + build + `,"only":[3],"except":[4]}}]`:                                                        "rule 0: sites takes only or except, not both",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{` + build + `,"only":[],"except":[]}}]`:                                                          "rule 0: sites takes only or except, not both",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{` + build + `}}]`:                                                                                "rule 0: sites needs only or except",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{"only":[3]}}]`:                                                                                   "rule 0: sites.build is required",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{` + build + `,"only":[-1]}}]`:                                                                    "a sites entry is a label string or an instruction number, not -1",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{` + build + `,"only":[{"pc":3}]}}]`:                                                              "a sites entry is a label string or an instruction number",
		`[{"program":"p","calls":["bpf_ktime_get_ns"],"hook_prefix":"h","sites":{` + build + `,"only":[3],"unknown":1}}]`:                                                         "unknown field",
	} {
		_, err := ParseConfig(strings.NewReader(input))
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: %v, want %q", input, err, want)
		}
	}
}

// sitesListing is a listing with two calls of one helper on one line, a
// third call of it elsewhere, another callee, a lookup and an update of map
// a, a lookup of b and a tail call.
func sitesListing() ([]inject.LookupSite, map[uint32]string) {
	sites := []inject.LookupSite{
		{Op: inject.HookLookup, MapName: "a", SitePC: 2},
		{Op: inject.HookUpdate, MapName: "a", SitePC: 6},
		{Op: inject.HookLookup, MapName: "b", SitePC: 9},
		{Op: inject.HookCall, Call: "bpf_ktime_get_ns", SitePC: 12},
		{Op: inject.HookCall, Call: "bpf_ktime_get_ns", SitePC: 14},
		{Op: inject.HookCall, Call: "bpf_ktime_get_ns", SitePC: 20},
		{Op: inject.HookCall, Call: "bpf_jiffies64", SitePC: 22},
		{Op: inject.HookTailCall, SitePC: 30},
	}
	labels := map[uint32]string{2: "a@p:3", 6: "a.update@p:5", 9: "b@p:7", 12: "bpf_ktime_get_ns@p:9#1", 14: "bpf_ktime_get_ns@p:9#2",
		20: "bpf_ktime_get_ns@p:11", 22: "bpf_jiffies64@p:12", 30: "tail_call@p:14"}
	return sites, labels
}

func pcRef(pc uint32) SiteRef { return SiteRef{PC: &pc} }

func TestSitesDrop(t *testing.T) {
	sites, labels := sitesListing()
	const build = "sha256:ab"
	keep := func(pcs ...uint32) map[uint32]string {
		drop := map[uint32]string{}
		for _, site := range sites {
			drop[site.SitePC] = dropReason
		}
		for _, pc := range pcs {
			delete(drop, pc)
		}
		return drop
	}
	all := []uint32{2, 6, 9, 12, 14, 20, 22, 30}
	for name, c := range map[string]struct {
		sel  Sites
		want map[uint32]string
	}{
		// A name with a selected site keeps only those; other names keep all.
		"only one copy by label":  {Sites{Only: []SiteRef{{Label: "bpf_ktime_get_ns@p:9#2"}}}, keep(2, 6, 9, 14, 22, 30)},
		"only one copy by number": {Sites{Only: []SiteRef{pcRef(12)}}, keep(2, 6, 9, 12, 22, 30)},
		"only the base label":     {Sites{Only: []SiteRef{{Label: "bpf_ktime_get_ns@p:9"}}}, keep(2, 6, 9, 12, 14, 22, 30)},
		"only a unique label":     {Sites{Only: []SiteRef{{Label: "bpf_ktime_get_ns@p:11"}}}, keep(2, 6, 9, 20, 22, 30)},
		"only a map's update":     {Sites{Only: []SiteRef{{Label: "a.update@p:5"}}}, keep(6, 9, 12, 14, 20, 22, 30)},
		"only the tail call":      {Sites{Only: []SiteRef{pcRef(30)}}, keep(all...)},
		"only two names":          {Sites{Only: []SiteRef{pcRef(20), {Label: "b@p:7"}}}, keep(2, 6, 9, 20, 22, 30)},
		"only nothing":            {Sites{Only: []SiteRef{}}, keep(all...)},
		"except one copy":         {Sites{Except: []SiteRef{{Label: "bpf_ktime_get_ns@p:9#1"}}}, map[uint32]string{12: dropReason}},
		"except the base label":   {Sites{Except: []SiteRef{{Label: "bpf_ktime_get_ns@p:9"}}}, map[uint32]string{12: dropReason, 14: dropReason}},
		"except by number":        {Sites{Except: []SiteRef{pcRef(2), pcRef(30)}}, map[uint32]string{2: dropReason, 30: dropReason}},
	} {
		c.sel.Build = build
		got, err := c.sel.drop(build, sites, labels)
		if err != nil || !maps.Equal(got, c.want) {
			t.Errorf("%s: drop %v (%v), want %v", name, got, err, c.want)
		}
	}
	for name, c := range map[string]struct {
		sel  Sites
		want string
	}{
		"another build": {Sites{Build: "sha256:cd", Only: []SiteRef{pcRef(12)}},
			"rule sites were listed from build sha256:cd but this load is build sha256:ab; list again with --lookups-json and copy the sites from the new file"},
		"a label of another program": {Sites{Build: build, Only: []SiteRef{{Label: "bpf_ktime_get_ns@q:9"}}}, `rule sites: "bpf_ktime_get_ns@q:9" names no site of this program`},
		"a copy that is not there":   {Sites{Build: build, Except: []SiteRef{{Label: "bpf_ktime_get_ns@p:9#3"}}}, `rule sites: "bpf_ktime_get_ns@p:9#3" names no site of this program`},
		"a number that is no site":   {Sites{Build: build, Only: []SiteRef{pcRef(13)}}, "rule sites: pc 13 names no site of this program"},
		"a suffix on a unique label": {Sites{Build: build, Only: []SiteRef{{Label: "bpf_jiffies64@p:12#1"}}}, `rule sites: "bpf_jiffies64@p:12#1" names no site of this program`},
	} {
		if got, err := c.sel.drop(build, sites, labels); err == nil || err.Error() != c.want {
			t.Errorf("%s: drop %v, error %v, want %q", name, got, err, c.want)
		}
	}
}
