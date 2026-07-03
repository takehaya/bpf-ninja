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
const dslSetTargetSrc = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int xdp_gtp_target(struct xdp_md *ctx) {
    return 2; // XDP_PASS
}
char _license[] SEC("license") = "GPL";
`

// gtpPacket builds an eth/ipv4/udp/gtp frame: byte 0 is a per-run marker
// (drainMarkers reads it back), the GTP TEID is written network-order at
// the GTP header's 4-byte teid field so the DSL extraction sees the wire
// bytes.
func gtpPacket(marker byte, teid uint32) []byte {
	p := make([]byte, 64)
	p[0] = marker
	binary.BigEndian.PutUint16(p[12:14], 0x0800) // ethertype IPv4
	p[14] = 0x45                                 // IPv4 version 4, IHL 5
	p[23] = 17                                   // protocol UDP
	binary.BigEndian.PutUint16(p[36:38], 2152)   // UDP dport (GTP-U)
	p[42] = 0x30                                 // GTP flags: version 1, PT=1
	p[43] = 0xFF                                 // msg_type G-PDU
	binary.BigEndian.PutUint32(p[46:50], teid)   // GTP teid (network order)
	return p
}

func runGTP(t *testing.T, prog *ebpf.Program, marker byte, teid uint32) {
	t.Helper()
	if _, err := prog.Run(&ebpf.RunOptions{Data: gtpPacket(marker, teid)}); err != nil {
		t.Fatalf("test-run: %v", err)
	}
}

// TestBpfDSLSetMatchPacketField is the end-to-end for DSL packet-field set
// matching: a `gtp[teid in @teids]` filter extracts the GTP TEID from the
// packet, and the host looks it up in a pinned set — capturing only frames
// whose TEID is a member. It also proves the native/network byte-order
// contract (the map is keyed host-order; the packet carries network order)
// and runtime membership updates without re-attach.
func TestBpfDSLSetMatchPacketField(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/xdpninja_dslset_%d", os.Getpid())
	if err := setmap.Create(pin, "teid:u32", "", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	set, err := setmap.OpenSet(setmap.SpecRef{Name: "teids", Path: pin})
	if err != nil {
		t.Fatalf("OpenSet: %v", err)
	}
	t.Cleanup(set.Def.Close)

	const memberTeid = uint32(0x11223344)
	if err := set.Def.Add(map[string]uint64{"teid": uint64(memberTeid)}, 1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	prog := loadXDPByName(t, dslSetTargetSrc, "xdp_gtp_target")
	targets := []attach.Target{{Program: prog, FuncName: "xdp_gtp_target", Type: ebpf.XDP}}
	probe, err := LoadMultiEntry(targets, "eth/ipv4/udp/gtp[teid in @teids]", nil, true, []*setmap.Set{set})
	if err != nil {
		t.Fatalf("LoadMultiEntry with DSL set: %v", err)
	}
	defer func() { _ = probe.Close() }()

	// (a) membership gates capture: 0x11223344 is in the set, another TEID
	// is not. Byte order: the map key was written host-order by Add; the
	// packet carries network order; a hit proves kunai's HostTo(BE)
	// normalization matches them.
	runGTP(t, prog, 0x44, memberTeid) // marker 0x44 — member, captured
	runGTP(t, prog, 0x55, 0x99887766) // marker 0x55 — non-member, dropped
	markers := drainMarkers(t, probe, 1)
	if markers[0x44] != 1 {
		t.Fatalf("markers = %v, want one 0x44 (member TEID captured)", markers)
	}
	if markers[0x55] != 0 {
		t.Fatalf("markers = %v: non-member TEID was captured", markers)
	}

	// (b) runtime add takes effect without re-attach.
	const addedTeid = uint32(0x0a0b0c0d)
	if err := set.Def.Add(map[string]uint64{"teid": uint64(addedTeid)}, 2); err != nil {
		t.Fatalf("runtime Add: %v", err)
	}
	runGTP(t, prog, 0x66, addedTeid)
	markers = drainMarkers(t, probe, 1)
	if markers[0x66] != 1 {
		t.Fatalf("markers after runtime add = %v, want one 0x66", markers)
	}

	// (c) runtime delete stops matching.
	if err := set.Def.Delete(map[string]uint64{"teid": uint64(addedTeid)}); err != nil {
		t.Fatalf("runtime Delete: %v", err)
	}
	runGTP(t, prog, 0x77, addedTeid)
	markers = drainMarkers(t, probe, 0)
	if markers[0x77] != 0 {
		t.Fatalf("markers after runtime delete = %v, want no 0x77", markers)
	}
}
