package program

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/internal/testutil"
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

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_dslset_%d", os.Getpid())
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
	if err := set.Def.Add(map[string]string{"dport": fmt.Sprintf("%d", memberPort)}, setmap.EntryValue{Tag: 1}); err != nil {
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
	if err := set.Def.Add(map[string]string{"dport": fmt.Sprintf("%d", addedPort)}, setmap.EntryValue{Tag: 2}); err != nil {
		t.Fatalf("runtime Add: %v", err)
	}
	runTCP(t, prog, 0x66, 1234, addedPort)
	markers = drainMarkers(t, probe, 1)
	if markers[0x66] != 1 {
		t.Fatalf("markers after runtime add = %v, want one 0x66", markers)
	}

	// (c) runtime delete stops matching.
	if err := set.Def.Delete(map[string]string{"dport": fmt.Sprintf("%d", addedPort)}); err != nil {
		t.Fatalf("runtime Delete: %v", err)
	}
	runTCP(t, prog, 0x77, 1234, addedPort)
	markers = drainMarkers(t, probe, 0)
	if markers[0x77] != 0 {
		t.Fatalf("markers after runtime delete = %v, want no 0x77", markers)
	}

	// (d) parking (state=capped) is a KERNEL-side miss: the entry stays
	// in the map but stops matching — the behavior the per-entry cap
	// lifecycle depends on. Userspace discard would mask a wrong state
	// offset here, so this asserts at the BPF level; reactivating
	// resumes matching (the state load really reads the state byte).
	if n, err := set.Def.SetState(1, setmap.StateCapped); err != nil || n != 1 {
		t.Fatalf("SetState(capped) = (%d, %v), want (1, nil)", n, err)
	}
	runTCP(t, prog, 0x88, 1234, memberPort)
	markers = drainMarkers(t, probe, 0)
	if markers[0x88] != 0 {
		t.Fatalf("markers after park = %v: parked entry still matched in BPF", markers)
	}
	if _, err := set.Def.SetState(1, setmap.StateActive); err != nil {
		t.Fatalf("SetState(active): %v", err)
	}
	runTCP(t, prog, 0x99, 1234, memberPort)
	markers = drainMarkers(t, probe, 1)
	if markers[0x99] != 1 {
		t.Fatalf("markers after reactivate = %v, want one 0x99", markers)
	}
}

// TestBpfDSLSetLegacyScalarValue pins the pre-0.23 value layout at the
// BPF level: a plain `tag:u16` value (no state field → no state check
// emitted, narrow tag width → 2-byte load) must still match and carry
// its tag into the record's metadata.
func TestBpfDSLSetLegacyScalarValue(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_dsllegacy_%d", os.Getpid())
	if err := setmap.Create(pin, "dport:u16", "tag:u16", 16); err != nil {
		t.Skipf("creating pinned set map (bpffs unavailable?): %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	set, err := setmap.OpenSet(setmap.SpecRef{Name: "ports", Path: pin})
	if err != nil {
		t.Fatalf("OpenSet: %v", err)
	}
	t.Cleanup(set.Def.Close)
	if set.Def.StateOff() != -1 || set.Def.TagWidth() != 2 {
		t.Fatalf("legacy layout resolved as (stateOff %d, tagWidth %d), want (-1, 2)", set.Def.StateOff(), set.Def.TagWidth())
	}

	const memberPort = uint16(443)
	const wantTag = uint64(7)
	if err := set.Def.Add(map[string]string{"dport": fmt.Sprintf("%d", memberPort)}, setmap.EntryValue{Tag: wantTag}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	prog := loadXDPByName(t, dslSetTargetSrc, "xdp_set_e2e_target")
	targets := []attach.Target{{Program: prog, FuncName: "xdp_set_e2e_target", Type: ebpf.XDP}}
	probe, err := LoadMultiEntry(targets, "eth/ipv4/tcp[dport in @ports]", nil, true, []*setmap.Set{set})
	if err != nil {
		t.Fatalf("LoadMultiEntry with legacy-value set: %v", err)
	}
	defer func() { _ = probe.Close() }()

	runTCP(t, prog, 0xAA, 1234, memberPort)
	runTCP(t, prog, 0xBB, 1234, 80) // non-member

	tags := drainMarkerTags(t, probe, 1)
	if got, ok := tags[0xAA]; !ok || got != uint32(wantTag) {
		t.Fatalf("tags = %v, want marker 0xAA with tag %d (narrow tag load)", tags, wantTag)
	}
	if _, ok := tags[0xBB]; ok {
		t.Fatalf("tags = %v: non-member captured on legacy layout", tags)
	}
}

// drainMarkerTags reads captured records like drainMarkers but returns
// marker → record tag (metadata offset 16, u32), for asserting the tag
// the BPF set lookup copied out.
func drainMarkerTags(t *testing.T, probe *Probe, wantMarkers int) map[byte]uint32 {
	t.Helper()
	tags := map[byte]uint32{}
	innerSize := int(shardRingbufSize(RingbufSize, runtime.NumCPU()))
	readers := make([]*fastrb.Reader, len(probe.InnerMaps))
	for i, m := range probe.InnerMaps {
		rd, err := fastrb.New(m.FD(), innerSize)
		if err != nil {
			t.Fatalf("fastrb on shard %d: %v", i, err)
		}
		readers[i] = rd
	}
	defer func() {
		for _, rd := range readers {
			_ = rd.Close()
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, rd := range readers {
			rd.ReadBatch(func(rec []byte) {
				if len(rec) > metadataSize {
					tags[rec[metadataSize]] = binary.NativeEndian.Uint32(rec[16:20])
				}
			})
		}
		if len(tags) >= wantMarkers || time.Now().After(deadline) {
			return tags
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestBpfDSLSetMatchCompositeKey covers a composite key written
// comma-separated in one bracket: tcp[sport in @f, dport in @f]. Both
// fields must match one entry (AND within the key) for capture.
func TestBpfDSLSetMatchCompositeKey(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_dslcomp_%d", os.Getpid())
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
	if err := set.Def.Add(map[string]string{"sport": fmt.Sprintf("%d", sport), "dport": fmt.Sprintf("%d", dport)}, setmap.EntryValue{Tag: 1}); err != nil {
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

// ipv6Packet builds an eth/ipv6 frame: byte 0 is a per-run marker, and the
// IPv6 destination (an SRv6 active SID) is written network-order at bytes
// 38..54 (ipv6 header offset 24) so the DSL extraction sees the wire bytes.
func ipv6Packet(marker byte, dst net.IP) []byte {
	p := make([]byte, 64)
	p[0] = marker
	binary.BigEndian.PutUint16(p[12:14], 0x86DD) // ethertype IPv6
	p[14] = 0x60                                 // IPv6 version 6
	p[20] = 59                                   // next header = No Next Header
	copy(p[38:54], dst.To16())                   // ipv6 dst = SID (network order)
	return p
}

func runIPv6(t *testing.T, prog *ebpf.Program, marker byte, dst string) {
	t.Helper()
	ip := net.ParseIP(dst)
	if ip == nil {
		t.Fatalf("invalid test IPv6 %q", dst)
	}
	if _, err := prog.Run(&ebpf.RunOptions{Data: ipv6Packet(marker, ip)}); err != nil {
		t.Fatalf("test-run: %v", err)
	}
}

// TestBpfDSLSetMatchIPv6Dst is the end-to-end for a 16-byte packet-field
// key: ipv6[dst in @sids] matches the IPv6 destination (an SRv6 active
// SID) against a pinned set keyed by an ipv6 field. It also locks the
// byte-order contract via a differential check and covers runtime updates.
func TestBpfDSLSetMatchIPv6Dst(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_dslsid_%d", os.Getpid())
	if err := setmap.Create(pin, "sid:ipv6", "", 16); err != nil {
		t.Skipf("creating pinned ipv6 set map: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	set, err := setmap.OpenSet(setmap.SpecRef{Name: "sids", Path: pin})
	if err != nil {
		t.Fatalf("OpenSet: %v", err)
	}
	t.Cleanup(set.Def.Close)

	const memberSID = "fc00::1"

	// Differential: the wire bytes of the member SID must equal the key
	// BuildKey writes for it (extraction side vs add side agree, no swap).
	key, err := set.Def.BuildKey(map[string]string{"sid": memberSID})
	if err != nil {
		t.Fatalf("BuildKey: %v", err)
	}
	if !bytes.Equal(key, net.ParseIP(memberSID).To16()) {
		t.Fatalf("key %x != wire bytes %x (byte-order mismatch)", key, net.ParseIP(memberSID).To16())
	}

	if err := set.Def.Add(map[string]string{"sid": memberSID}, setmap.EntryValue{Tag: 1}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	prog := loadXDPByName(t, dslSetTargetSrc, "xdp_set_e2e_target")
	targets := []attach.Target{{Program: prog, FuncName: "xdp_set_e2e_target", Type: ebpf.XDP}}
	probe, err := LoadMultiEntry(targets, "eth/ipv6[dst in @sids]", nil, true, []*setmap.Set{set})
	if err != nil {
		t.Fatalf("LoadMultiEntry with ipv6 set: %v", err)
	}
	defer func() { _ = probe.Close() }()

	// Membership gates capture: fc00::1 is a member, fc00::2 is not.
	runIPv6(t, prog, 0x44, memberSID) // member, captured
	runIPv6(t, prog, 0x55, "fc00::2") // non-member, dropped
	markers := drainMarkers(t, probe, 1)
	if markers[0x44] != 1 {
		t.Fatalf("markers = %v, want one 0x44 (member SID captured)", markers)
	}
	if markers[0x55] != 0 {
		t.Fatalf("markers = %v: non-member SID was captured", markers)
	}

	// Runtime add / delete without re-attach.
	const addedSID = "2001:db8::9"
	if err := set.Def.Add(map[string]string{"sid": addedSID}, setmap.EntryValue{Tag: 2}); err != nil {
		t.Fatalf("runtime Add: %v", err)
	}
	runIPv6(t, prog, 0x66, addedSID)
	if markers = drainMarkers(t, probe, 1); markers[0x66] != 1 {
		t.Fatalf("markers after runtime add = %v, want one 0x66", markers)
	}
	if err := set.Def.Delete(map[string]string{"sid": addedSID}); err != nil {
		t.Fatalf("runtime Delete: %v", err)
	}
	runIPv6(t, prog, 0x77, addedSID)
	if markers = drainMarkers(t, probe, 0); markers[0x77] != 0 {
		t.Fatalf("markers after runtime delete = %v, want no 0x77", markers)
	}
}

// TestBpfDSLSetMatchSRv6SegmentLoads verifier-loads the srv6 segment set
// filter. Unlike ipv6[dst] (a primary-header field), srv6[segments[N].addr]
// runs the SRH segment walk, a parser-machine self-loop that does not
// execute in the fentry scratch-buffer path (the same limitation the gtp
// note above calls out), so this asserts the extraction VERIFIES on the CI
// kernel matrix rather than capturing. The packet-level match is proven by
// TestAuxStackSrv6SegmentsStaticIndexBracket in pkg/kunai/dsltest (native
// XDP), and the raw-byte store shape by the codegen unit tests.
func TestBpfDSLSetMatchSRv6SegmentLoads(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	pin := fmt.Sprintf("/sys/fs/bpf/bpfninja_dslseg_%d", os.Getpid())
	if err := setmap.Create(pin, "sid:ipv6", "", 16); err != nil {
		t.Skipf("creating pinned ipv6 set map: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(pin) })

	set, err := setmap.OpenSet(setmap.SpecRef{Name: "sids", Path: pin})
	if err != nil {
		t.Fatalf("OpenSet: %v", err)
	}
	t.Cleanup(set.Def.Close)

	// Byte-order differential (host side, no BPF): the SID wire bytes equal
	// the key BuildKey writes, so the raw extraction store and `set add`
	// agree with no swap.
	const memberSID = "fc00::1"
	key, err := set.Def.BuildKey(map[string]string{"sid": memberSID})
	if err != nil {
		t.Fatalf("BuildKey: %v", err)
	}
	if !bytes.Equal(key, net.ParseIP(memberSID).To16()) {
		t.Fatalf("key %x != wire bytes %x (byte-order mismatch)", key, net.ParseIP(memberSID).To16())
	}

	prog := loadXDPByName(t, dslSetTargetSrc, "xdp_set_e2e_target")
	targets := []attach.Target{{Program: prog, FuncName: "xdp_set_e2e_target", Type: ebpf.XDP}}
	probe, err := LoadMultiEntry(targets, "eth/ipv6/srv6[segments[0].addr in @sids]", nil, true, []*setmap.Set{set})
	if err != nil {
		t.Fatalf("LoadMultiEntry with srv6 segment set: %v", err)
	}
	_ = probe.Close()
}
