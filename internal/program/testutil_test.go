package program

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/takehaya/xdp-ninja/internal/filter"
	"github.com/takehaya/xdp-ninja/internal/testutil"
	"github.com/vishvananda/netlink"
)

const xdpFuncName = "xdp_pass_test"

const xdpPassSource = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("xdp")
int xdp_pass_test(struct xdp_md *ctx) { return 2; }
char _license[] SEC("license") = "GPL";
`

const xdpSubfuncName = "process_packet"

// loadDummyXDP compiles and loads a minimal XDP_PASS program with BTF.
func loadDummyXDP(t *testing.T) *ebpf.Program {
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
func loadDummyXDPWithSubfunc(t *testing.T) *ebpf.Program {
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
		probe, err = LoadExit(targetProg, funcName, "", argFilters)
	} else {
		probe, err = LoadEntry(targetProg, funcName, "", argFilters)
	}
	if err != nil {
		t.Fatalf("load probe (%s): %v", funcName, err)
	}
	defer func() { _ = probe.Close() }()

	reader, err := perf.NewReader(probe.EventsMap, 64*1024)
	if err != nil {
		t.Fatalf("perf reader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	// Give the probe time to attach before sending packets.
	time.Sleep(200 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = exec.Command("ping", "-c", fmt.Sprintf("%d", pingCount), "-W", "1", "-I", iface, pingTarget).CombinedOutput()
	}()
	defer func() { <-done }()

	reader.SetDeadline(time.Now().Add(time.Duration(pingCount+5) * time.Second))
	count := 0
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if record.LostSamples > 0 {
			continue
		}
		count++
		if count >= maxEvents {
			break
		}
	}
	return count
}

// loadProbeOrFail loads a probe and fails with verifier output on error.
func loadProbeOrFail(t *testing.T, xdpProg *ebpf.Program, funcName, filterExpr string, exit bool) *Probe {
	t.Helper()
	var probe *Probe
	var err error
	if exit {
		probe, err = LoadExit(xdpProg, funcName, filterExpr, nil)
	} else {
		probe, err = LoadEntry(xdpProg, funcName, filterExpr, nil)
	}
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error:\n%+v", ve)
		}
		t.Fatalf("loading probe: %v", err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	return probe
}
