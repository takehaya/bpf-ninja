package program

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/setmap"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// dslSetTargetSrc is a passthrough XDP program: the DSL filter runs on
// the packet the fentry observer copies, so the target itself only needs
// to exist and return XDP_PASS.
//
// The e2e uses an eth/ipv4/tcp chain (not gtp): a gtp-depth chain with a
// parser machine does not verify in the fentry scratch-buffer path on
// older kernels (6.6), a pre-existing kunai limitation unrelated to set
// matching. tcp exercises the same packet-field extraction on a chain
// that loads across the CI kernel matrix.
const dslSetTargetSrc = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int xdp_set_e2e_target(struct xdp_md *ctx) {
    return 2; // XDP_PASS
}
char _license[] SEC("license") = "GPL";
`

// tcpPacket builds an eth/ipv4/tcp frame: byte 0 is a per-run marker
// (drainMarkers reads it back), and tcp sport/dport are written
// network-order so the DSL extraction sees the wire bytes.
func tcpPacket(marker byte, sport, dport uint16) []byte {
	p := make([]byte, 64)
	p[0] = marker
	binary.BigEndian.PutUint16(p[12:14], 0x0800) // ethertype IPv4
	p[14] = 0x45                                 // IPv4 version 4, IHL 5
	p[23] = 6                                    // protocol TCP
	binary.BigEndian.PutUint16(p[34:36], sport)  // tcp sport
	binary.BigEndian.PutUint16(p[36:38], dport)  // tcp dport
	p[46] = 0x50                                 // tcp data offset 5 (20 B)
	return p
}

func runTCP(t *testing.T, prog *ebpf.Program, marker byte, sport, dport uint16) {
	t.Helper()
	if _, err := prog.Run(&ebpf.RunOptions{Data: tcpPacket(marker, sport, dport)}); err != nil {
		t.Fatalf("test-run: %v", err)
	}
}

// TestBpfDSLSetMatchPacketField is the end-to-end for DSL packet-field set
// matching: a `tcp[dport in @ports]` filter extracts the TCP dport from
// the packet, and the host looks it up in a pinned set — capturing only
// frames whose dport is a member. It also proves the native/network
// byte-order contract (the map is keyed host-order; the packet carries
// network order) and runtime membership updates without re-attach.
func TestBpfDSLSetMatchPacketField(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/xdpninja_dslset_%d", os.Getpid())
	if err := setmap.Create(pin, "dport:u16", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	set, err := setmap.OpenSet(setmap.SpecRef{Name: "ports", Path: pin})
	if err != nil {
		t.Fatalf("OpenSet: %v", err)
	}
	t.Cleanup(set.Def.Close)

	const memberPort = uint16(0x01BB) // 443
	if err := set.Def.Add(map[string]uint64{"dport": uint64(memberPort)}, 1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	prog := loadXDPByName(t, dslSetTargetSrc, "xdp_set_e2e_target")
	targets := []attach.Target{{Program: prog, FuncName: "xdp_set_e2e_target", Type: ebpf.XDP}}
	probe, err := LoadMultiEntry(targets, "eth/ipv4/tcp[dport in @ports]", nil, true, []*setmap.Set{set})
	if err != nil {
		t.Fatalf("LoadMultiEntry with DSL set: %v", err)
	}
	defer func() { _ = probe.Close() }()

	// (a) membership gates capture: 443 is in the set, 80 is not. Byte
	// order: the map key was written host-order by Add; the packet carries
	// network order; a hit proves kunai's HostTo(BE) normalization matches.
	runTCP(t, prog, 0x44, 1234, memberPort) // marker 0x44 — member, captured
	runTCP(t, prog, 0x55, 1234, 80)         // marker 0x55 — non-member, dropped
	markers := drainMarkers(t, probe, 1)
	if markers[0x44] != 1 {
		t.Fatalf("markers = %v, want one 0x44 (member dport captured)", markers)
	}
	if markers[0x55] != 0 {
		t.Fatalf("markers = %v: non-member dport was captured", markers)
	}

	// (b) runtime add takes effect without re-attach.
	const addedPort = uint16(8080)
	if err := set.Def.Add(map[string]uint64{"dport": uint64(addedPort)}, 2); err != nil {
		t.Fatalf("runtime Add: %v", err)
	}
	runTCP(t, prog, 0x66, 1234, addedPort)
	markers = drainMarkers(t, probe, 1)
	if markers[0x66] != 1 {
		t.Fatalf("markers after runtime add = %v, want one 0x66", markers)
	}

	// (c) runtime delete stops matching.
	if err := set.Def.Delete(map[string]uint64{"dport": uint64(addedPort)}); err != nil {
		t.Fatalf("runtime Delete: %v", err)
	}
	runTCP(t, prog, 0x77, 1234, addedPort)
	markers = drainMarkers(t, probe, 0)
	if markers[0x77] != 0 {
		t.Fatalf("markers after runtime delete = %v, want no 0x77", markers)
	}
}

// TestBpfDSLSetMatchCompositeKey covers a composite key written
// comma-separated in one bracket: tcp[sport in @f, dport in @f]. Both
// fields must match one entry (AND within the key) for capture.
func TestBpfDSLSetMatchCompositeKey(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/xdpninja_dslcomp_%d", os.Getpid())
	if err := setmap.Create(pin, "sport:u16,dport:u16", "", 16); err != nil {
		t.Skipf("creating pinned set map: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	set, err := setmap.OpenSet(setmap.SpecRef{Name: "flows", Path: pin})
	if err != nil {
		t.Fatalf("OpenSet: %v", err)
	}
	t.Cleanup(set.Def.Close)

	const sport, dport = uint16(1111), uint16(443)
	if err := set.Def.Add(map[string]uint64{"sport": uint64(sport), "dport": uint64(dport)}, 1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	prog := loadXDPByName(t, dslSetTargetSrc, "xdp_set_e2e_target")
	targets := []attach.Target{{Program: prog, FuncName: "xdp_set_e2e_target", Type: ebpf.XDP}}
	probe, err := LoadMultiEntry(targets, "eth/ipv4/tcp[sport in @flows, dport in @flows]", nil, true, []*setmap.Set{set})
	if err != nil {
		t.Fatalf("LoadMultiEntry composite: %v", err)
	}
	defer func() { _ = probe.Close() }()

	// Matching (sport, dport) is captured; the same dport with a different
	// sport is not (the composite key differs).
	runTCP(t, prog, 0x44, sport, dport) // (1111, 443) — member
	runTCP(t, prog, 0x55, 2222, dport)  // (2222, 443) — non-member
	markers := drainMarkers(t, probe, 1)
	if markers[0x44] != 1 || markers[0x55] != 0 {
		t.Fatalf("markers = %v, want one 0x44 and no 0x55", markers)
	}
}
