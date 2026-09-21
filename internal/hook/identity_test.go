package hook

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestIdentityXDP pins the XDP identity to xdp_buff->data_hard_start
// (offset 24), read from the ctx in R6 without touching R0/R6..R9.
func TestIdentityXDP(t *testing.T) {
	insns, err := xdpHook.Identity(asm.R1)
	if err != nil {
		t.Fatal(err)
	}
	want := asm.Instructions{asm.LoadMem(asm.R1, asm.R6, 24, asm.DWord)}
	if len(insns) != 1 || fmt.Sprint(insns[0]) != fmt.Sprint(want[0]) {
		t.Fatalf("xdp identity = %v, want %v", insns, want)
	}
}

// TestIdentitySkb pins tc and cgroup-skb to the sk_buff pointer itself.
func TestIdentitySkb(t *testing.T) {
	for _, h := range []*Hook{tcHook, cgroupSKBHook} {
		insns, err := h.Identity(asm.R1)
		if err != nil {
			t.Fatal(err)
		}
		want := asm.Mov.Reg(asm.R1, asm.R6)
		if len(insns) != 1 || fmt.Sprint(insns[0]) != fmt.Sprint(want) {
			t.Fatalf("%s identity = %v, want %v", h.Kind, insns, want)
		}
	}
}

// TestIdentityEveryHook makes sure no registered hook is left without
// an identity loader (a nil func would panic at capture build time).
func TestIdentityEveryHook(t *testing.T) {
	for _, h := range registry {
		if h.Identity == nil {
			t.Errorf("hook %s has no Identity", h.Kind)
		}
	}
}
