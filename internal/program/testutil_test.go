package program

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/vishvananda/netlink"
)

// verifierStatsLine pulls the verifier's per-load summary (e.g.
// "processed 1234 insns (limit 1000000) max_states_per_insn 3
// total_states 42 peak_states 27 mark_read 5") out of an
// ebpf.VerifierError's log. Returns "" when the log has no such line.
//
// The cilium/ebpf VerifierError.Error() strips this line from its own
// formatted output, but the raw line is what tells you whether a
// failure was an outright reject ("...is unsafe") or a state-cascade
// blow-up ("Processed 1000001 insn"). Surfacing it before the full
// log makes CI scans faster.
func verifierStatsLine(ve *ebpf.VerifierError) string {
	for _, line := range ve.Log {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "processed ") && strings.Contains(trimmed, " insn") {
			return trimmed
		}
	}
	return ""
}

// dumpVerifierStats prepends the verifier's state-count summary line
// (when present) to the test failure context so a one-screen log scan
// can distinguish "instruction unsafe" rejects from "Processed
// 1000001 insn" state-cascade blow-ups. Setting KUNAI_DEBUG_VERIFIER=1
// additionally dumps the full verifier log via t.Logf so a local
// reproduction can iterate on the cascade structure without re-running.
func dumpVerifierStats(t *testing.T, label string, ve *ebpf.VerifierError) {
	t.Helper()
	if stats := verifierStatsLine(ve); stats != "" {
		t.Logf("verifier stats for %q: %s", label, stats)
	}
	if os.Getenv("KUNAI_DEBUG_VERIFIER") == "1" {
		t.Logf("full verifier log for %q:\n%+v", label, ve)
	}
}

const xdpFuncName = "xdp_pass_test"

const xdpPassSource = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("xdp")
int xdp_pass_test(struct xdp_md *ctx) { return 2; }
char _license[] SEC("license") = "GPL";
`

const xdpSubfuncName = "process_packet"

const tcFuncName = "tc_pass_test"

const tcPassSource = `
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("classifier")
int tc_pass_test(struct __sk_buff *skb) { return TC_ACT_OK; }
char _license[] SEC("license") = "GPL";
`

// loadDummyTC compiles and loads a minimal tc clsact program with
// BTF — peer of loadDummyXDP. The classifier returns TC_ACT_OK; the
// bpf-ninja observer attaches as fentry/fexit and the dummy never
// sees real traffic in unit tests, so the stub body suffices.
func loadDummyTC(t testing.TB) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, tcPassSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}

	var objs struct {
		Prog *ebpf.Program `ebpf:"tc_pass_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading TC program: %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })
	return objs.Prog
}

// loadDummyXDP compiles and loads a minimal XDP_PASS program with BTF.
func loadDummyXDP(t testing.TB) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, xdpPassSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_pass_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading XDP program: %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })
	return objs.Prog
}

// loadDummyXDPWithSubfunc compiles and loads an XDP program with a __noinline subfunction.
// Returns the loaded program (entry = "xdp_subfunc_test", subfunction = "process_packet").
func loadDummyXDPWithSubfunc(t testing.TB) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, testutil.XDPSubfuncSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_subfunc_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading XDP program: %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })
	return objs.Prog
}

// setupVeth creates a veth pair, assigns IPs, attaches the XDP program, and registers cleanup.
func setupVeth(t *testing.T, xdpProg *ebpf.Program, veth0, veth1, ip0, ip1 string) string {
	t.Helper()

	_ = exec.Command("ip", "link", "del", veth0).Run()
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: veth0},
		PeerName:  veth1,
	}); err != nil {
		// vimto's prebuilt kernels (CI matrix) ship without the veth
		// driver in some configurations. Skip cleanly rather than
		// flagging an environment issue as a verifier regression.
		// EOPNOTSUPP = built-in driver disabled; ENOPKG = module not
		// loaded.
		if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOPKG) {
			t.Skipf("veth not supported on this kernel: %v", err)
		}
		t.Fatalf("veth add: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", veth0).Run() })

	nl0, err := netlink.LinkByName(veth0)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", veth0, err)
	}
	nl1, err := netlink.LinkByName(veth1)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", veth1, err)
	}
	if err := netlink.LinkSetUp(nl0); err != nil {
		t.Fatalf("LinkSetUp(%s): %v", veth0, err)
	}
	if err := netlink.LinkSetUp(nl1); err != nil {
		t.Fatalf("LinkSetUp(%s): %v", veth1, err)
	}
	if err := netlink.AddrAdd(nl0, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(ip0), Mask: net.CIDRMask(24, 32)}}); err != nil {
		t.Fatalf("AddrAdd(%s): %v", veth0, err)
	}
	if err := netlink.AddrAdd(nl1, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(ip1), Mask: net.CIDRMask(24, 32)}}); err != nil {
		t.Fatalf("AddrAdd(%s): %v", veth1, err)
	}

	if err := netlink.LinkSetXdpFd(nl0, xdpProg.FD()); err != nil {
		t.Fatalf("XDP attach: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkSetXdpFd(nl0, -1) })

	return veth0
}

// countEvents attaches a probe, sends ping traffic, and returns the number of perf events received.
func countEvents(t *testing.T, targetProg *ebpf.Program, funcName, iface, pingTarget string, isFexit bool, argFilters []filter.ArgFilter, pingCount, maxEvents int) int {
	t.Helper()

	var probe *Probe
	var err error
	if isFexit {
		probe, err = LoadExit(targetProg, funcName, "", argFilters, false)
	} else {
		probe, err = LoadEntry(targetProg, funcName, "", argFilters, false)
	}
	if err != nil {
		t.Fatalf("load probe (%s): %v", funcName, err)
	}
	defer func() { _ = probe.Close() }()

	// EventsMap is now the outer ARRAY_OF_MAPS (R22 sharded-ringbuf
	// hoist); fan out to per-CPU inner ringbufs via the sharded
	// reader so this exercises the same path as `bpf-ninja --mode
	// {entry,exit}` does in production.
	sr, err := capture.NewShardedReader(probe.InnerMaps)
	if err != nil {
		t.Fatalf("sharded reader: %v", err)
	}

	// Give the probe time to attach before sending packets.
	time.Sleep(200 * time.Millisecond)

	var count atomic.Int64
	sink := func(shardIdx int, pkts []capture.Packet) error {
		count.Add(int64(len(pkts)))
		return nil
	}
	stop, err := sr.RunShards(sink)
	if err != nil {
		t.Fatalf("RunShards: %v", err)
	}
	defer stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = exec.Command("ping", "-c", fmt.Sprintf("%d", pingCount), "-W", "1", "-I", iface, pingTarget).CombinedOutput()
	}()

	deadline := time.Now().Add(time.Duration(pingCount+5) * time.Second)
	for time.Now().Before(deadline) {
		if int(count.Load()) >= maxEvents {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	<-done
	return int(count.Load())
}

// runFilterMatrix attaches one probe per filter expression and fails
// the subtest when the verifier rejects the produced bytecode.
func runFilterMatrix(t *testing.T, xdpProg *ebpf.Program, funcName string, exprs []string, exit, useDSL bool) {
	t.Helper()
	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, xdpProg, funcName, expr, exit, useDSL)
		})
	}
}

// loadProbeOrFail loads a probe and fails with verifier output on error.
func loadProbeOrFail(t *testing.T, xdpProg *ebpf.Program, funcName, filterExpr string, exit, useDSL bool) *Probe {
	t.Helper()
	var probe *Probe
	var err error
	if exit {
		probe, err = LoadExit(xdpProg, funcName, filterExpr, nil, useDSL)
	} else {
		probe, err = LoadEntry(xdpProg, funcName, filterExpr, nil, useDSL)
	}
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			dumpVerifierStats(t, filterExpr, ve)
			t.Fatalf("verifier error:\n%+v", ve)
		}
		t.Fatalf("loading probe: %v", err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	return probe
}
