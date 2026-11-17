package main

import (
	"slices"
	"testing"
)

func TestResolveSite(t *testing.T) {
	const file = `{"version":2,"programs":[{"program":"p","prog_id":7,"tag":"0123456789abcdef","hooks":[
		{"name":"ninja_entry","kind":"entry","sites":[{"kind":"entry","pc":4294967295}]},
		{"name":"ninja_sessions","kind":"typed","site_param":true,"sites":[{"kind":"lookup","pc":12,"label":"sessions@p+12"}]},
		{"name":"ninja_sessions_miss","kind":"typed","site_param":true,"sites":[{"kind":"lookup","pc":12,"label":"sessions@p+12"}]},
		{"name":"ninja_bpf_ktime_get_ns","kind":"call","site_param":true,"sites":[{"kind":"call","pc":2,"label":"bpf_ktime_get_ns@p:9#1"},
			{"kind":"call","pc":6,"label":"bpf_ktime_get_ns@p:9#2"}]},
		{"name":"ninja_any","kind":"generic","sites":[{"kind":"lookup","pc":20,"label":"inner@p+20"}]},
		{"name":"ninja","kind":"dispatch","sites":[{"kind":"lookup","pc":30,"label":"other@p+30"}]},
		{"name":"ninja_flows","kind":"typed","sites":[{"kind":"lookup","pc":40,"label":"flows@p+40"}]}]}]}`
	for _, c := range []struct {
		site  string
		hooks []string
		pc    uint32
	}{
		{"bpf_ktime_get_ns@p:9#2", []string{"ninja_bpf_ktime_get_ns"}, 6},
		{"2", []string{"ninja_bpf_ktime_get_ns"}, 2},
		{"sessions@p+12", []string{"ninja_sessions", "ninja_sessions_miss"}, 12},
	} {
		hooks, pc, err := resolveSite([]byte(file), "hooks.json", 7, "0123456789abcdef", c.site)
		if err != nil || pc != c.pc || !slices.Equal(hooks, c.hooks) {
			t.Errorf("%s: %v pc %d (%v), want %v pc %d", c.site, hooks, pc, err, c.hooks, c.pc)
		}
	}
	for _, c := range []struct {
		progID    uint32
		tag, site string
		want      string
	}{
		{8, "0123456789abcdef", "2", "--site: hooks.json has no program with prog_id 8"},
		{7, "fedcba9876543210", "2", "--site: hooks.json lists prog_id 7 with tag 0123456789abcdef but the loaded program has tag fedcba9876543210; the file is from another load"},
		{7, "0123456789abcdef", "bpf_ktime_get_ns@p:9", `--site: "bpf_ktime_get_ns@p:9" names 2 sites; give one of bpf_ktime_get_ns@p:9#1 bpf_ktime_get_ns@p:9#2`},
		{7, "0123456789abcdef", "bpf_ktime_get_ns@p:", `--site: no site "bpf_ktime_get_ns@p:" in program 7`},
		{7, "0123456789abcdef", "3", `--site: no site "3" in program 7`},
		{7, "0123456789abcdef", "4294967295", `--site: no site "4294967295" in program 7`},
		// A hook without a site parameter cannot be narrowed to one site.
		{7, "0123456789abcdef", "inner@p+20", `--site: hook "ninja_any" is a generic hook, which has no site parameter; capture it with --func ninja_any`},
		{7, "0123456789abcdef", "30", `--site: hook "ninja" is a dispatch hook, which has no site parameter; capture it with --func ninja`},
		{7, "0123456789abcdef", "flows@p+40", `--site: hook "ninja_flows" is a typed hook, which has no site parameter; capture it with --func ninja_flows`},
	} {
		if _, _, err := resolveSite([]byte(file), "hooks.json", c.progID, c.tag, c.site); err == nil || err.Error() != c.want {
			t.Errorf("%d %s %s: %v, want %q", c.progID, c.tag, c.site, err, c.want)
		}
	}
}
