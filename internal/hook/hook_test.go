package hook

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	cgskbhost "github.com/takehaya/bpf-ninja/pkg/kunai/host/cgroupskb"
	tchost "github.com/takehaya/bpf-ninja/pkg/kunai/host/tc"
	xdphost "github.com/takehaya/bpf-ninja/pkg/kunai/host/xdp"
)

func TestByProgramType(t *testing.T) {
	cases := []struct {
		pt   ebpf.ProgramType
		want Kind
		ok   bool
	}{
		{ebpf.XDP, KindXDP, true},
		{ebpf.SchedCLS, KindTC, true},
		{ebpf.SchedACT, KindTC, true},
		{ebpf.CGroupSKB, KindCgroupSKB, true},
		{ebpf.SocketFilter, "", false},
	}
	for _, c := range cases {
		h, ok := ByProgramType(c.pt)
		if ok != c.ok {
			t.Errorf("ByProgramType(%s) ok = %v, want %v", c.pt, ok, c.ok)
			continue
		}
		if ok && h.Kind != c.want {
			t.Errorf("ByProgramType(%s) = %s, want %s", c.pt, h.Kind, c.want)
		}
	}
}

func TestByName(t *testing.T) {
	for _, k := range []Kind{KindXDP, KindTC, KindCgroupSKB} {
		h, ok := ByName(k)
		if !ok || h.Kind != k {
			t.Errorf("ByName(%s) = %v, %v", k, h, ok)
		}
	}
	if _, ok := ByName("nope"); ok {
		t.Error("ByName(nope) should not resolve")
	}
}

// TestHookActionsMatchHostVocab pins the hook registry's verdict tables
// to the kunai host packages' action vocabularies: every verdict value a
// DSL `where action == NAME` atom can produce must have a matching
// pcap-ng interface, with a name derived from the same kernel constant.
func TestHookActionsMatchHostVocab(t *testing.T) {
	cases := []struct {
		hook  Kind
		vocab map[string]int32
		// rename maps the host vocab key to the interface display name
		// (the xdp names predate the registry and drop the XDP_ prefix).
		rename func(key string) string
	}{
		{KindXDP, xdphost.Actions, func(k string) string { return "xdp:" + strings.TrimPrefix(k, "XDP_") }},
		{KindTC, tchost.Actions, func(k string) string { return "tc:" + k }},
		{KindCgroupSKB, cgskbhost.Actions, func(k string) string { return "cgroup-skb:" + k }},
	}
	for _, c := range cases {
		h, ok := ByName(c.hook)
		if !ok {
			t.Fatalf("hook %s not registered", c.hook)
		}
		byValue := map[uint32]string{}
		for _, a := range h.Actions {
			byValue[a.Value] = a.Name
		}
		if len(h.Actions) != len(byValue) {
			t.Errorf("%s: duplicate verdict values in Actions", c.hook)
		}
		if len(byValue) != len(c.vocab) {
			t.Errorf("%s: %d interface actions vs %d host vocab actions", c.hook, len(byValue), len(c.vocab))
		}
		for key, v := range c.vocab {
			name, ok := byValue[uint32(v)]
			if !ok {
				t.Errorf("%s: host action %s (%d) has no interface entry", c.hook, key, v)
				continue
			}
			if want := c.rename(key); name != want {
				t.Errorf("%s: verdict %d interface name = %q, want %q", c.hook, v, name, want)
			}
		}
	}
}
