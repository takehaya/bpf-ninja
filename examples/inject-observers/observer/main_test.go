package main

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestObserverLayout(t *testing.T) {
	objects := map[string]*ebpf.CollectionSpec{
		"count": {
			Programs: map[string]*ebpf.ProgramSpec{"on_push": {}, "on_pop": {}, "on_peek": {}},
			Maps:     map[string]*ebpf.MapSpec{"counters": {Type: ebpf.PerCPUHash}},
		},
		"conditional": {
			Programs: map[string]*ebpf.ProgramSpec{"on_push": {}, "on_pop": {}, "on_peek": {}},
			Maps:     map[string]*ebpf.MapSpec{"events": {Type: ebpf.RingBuf}},
		},
		"latency": {
			Programs: map[string]*ebpf.ProgramSpec{"on_entry": {}, "on_push": {}, "on_seen_push": {}},
			Maps:     map[string]*ebpf.MapSpec{"events": {Type: ebpf.RingBuf}},
		},
	}
	for kind := range objects {
		for object, spec := range objects {
			t.Run(kind+"/"+object, func(t *testing.T) {
				names, _, err := observerLayout(spec, kind)
				if kind != object {
					if err == nil || !strings.Contains(err.Error(), kind+" object") {
						t.Fatalf("mismatched object: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if kind == "latency" && names[0] != "on_entry" {
					t.Fatalf("entry must attach first: %v", names)
				}
			})
		}
	}
	for name, spec := range map[string]*ebpf.CollectionSpec{
		"missing programs": {},
		"missing map":      {Programs: objects["count"].Programs},
		"wrong map type":   {Programs: objects["count"].Programs, Maps: map[string]*ebpf.MapSpec{"counters": {Type: ebpf.Hash}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := observerLayout(spec, "count"); err == nil {
				t.Fatal("expected an object mismatch error")
			}
		})
	}
}
