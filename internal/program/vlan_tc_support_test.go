package program

// tc-host VLAN support: the tc host puts the outer VLAN tag the kernel
// keeps in skb metadata back into the filter's copy (hook.OuterVlanTag),
// so every vlan / qinq shape compiles and loads at tc as at XDP. The
// matching itself is checked on a veth pair in vlan_wire_frame_test.go.

import (
	"testing"

	"github.com/cilium/ebpf"
)

// tcVlanExprs load & verify at the tc clsact host.
var tcVlanExprs = []string{
	"eth/vlan?/ipv4/tcp",
	"eth/qinq?/vlan?/ipv4/tcp",
	"eth/vlan*/ipv4/tcp",
	"eth/vlan?/ipv4/tcp[dport==443]",
	"eth/vlan/ipv4/tcp",
	"eth/vlan{1,3}/ipv4/tcp",
	"eth/qinq/vlan/ipv4/tcp",
	"eth/vlan[tci==100]/ipv4/tcp",
	"eth/(vlan|qinq)/ipv4/tcp",
	"eth/qinq/vlan?/ipv4/tcp",
	"eth/vlan[tci==100]?/ipv4/tcp",
	"eth/vlan?/ipv4/tcp where vlan.tci == 100",
	"eth/vlan?/ipv4/tcp capture vlan",
}

func TestVlanTCLoads(t *testing.T) {
	hostProg := loadDummyTC(t) // skips when not root
	for _, expr := range tcVlanExprs {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, hostProg, tcFuncName, expr, false /*exit*/, true /*useDSL*/)
		})
	}
}

func TestVlanTCCompiles(t *testing.T) {
	for _, expr := range tcVlanExprs {
		for _, isFexit := range []bool{false, true} {
			t.Run(expr, func(t *testing.T) {
				out, err := compileFilter(expr, true /*useDSL*/, isFexit, ebpf.SchedCLS)
				if err != nil {
					t.Fatalf("compile %q at tc (fexit=%v): %v", expr, isFexit, err)
				}
				if !out.WireFrame {
					t.Fatalf("compile %q at tc (fexit=%v): the filter does not expect the wire frame", expr, isFexit)
				}
			})
		}
	}
	// A pcap filter reads the bytes as the kernel holds them.
	if out, err := compileFilter("tcp dst port 80", false /*useDSL*/, false, ebpf.SchedCLS); err != nil || out.WireFrame {
		t.Fatalf("pcap filter at tc: WireFrame=%v err=%v; want false, nil", out.WireFrame, err)
	}
}
