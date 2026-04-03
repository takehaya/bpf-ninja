package program

import (
	"testing"
)

// TestBpfEntryLoad verifies that the fentry program passes the verifier.
func TestBpfEntryLoad(t *testing.T) {
	probe := loadProbeOrFail(t, loadDummyXDP(t), xdpFuncName, "", false)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfExitLoad verifies that the fexit program passes the verifier.
func TestBpfExitLoad(t *testing.T) {
	probe := loadProbeOrFail(t, loadDummyXDP(t), xdpFuncName, "", true)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfEntryWithFilter verifies fentry + cbpfc filter passes the verifier.
func TestBpfEntryWithFilter(t *testing.T) {
	xdpProg := loadDummyXDP(t)
	for _, expr := range []string{"arp", "icmp", "tcp port 80", "host 10.0.0.1"} {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, xdpProg, xdpFuncName, expr, false)
		})
	}
}

// TestBpfExitWithFilter verifies fexit + cbpfc filter passes the verifier.
func TestBpfExitWithFilter(t *testing.T) {
	xdpProg := loadDummyXDP(t)
	for _, expr := range []string{"arp", "icmp", "tcp port 80", "host 10.0.0.1"} {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, xdpProg, xdpFuncName, expr, true)
		})
	}
}

// TestBpfSubfuncEntryLoad verifies fentry on a __noinline subfunction passes the verifier.
func TestBpfSubfuncEntryLoad(t *testing.T) {
	xdpProg := loadDummyXDPWithSubfunc(t)
	probe := loadProbeOrFail(t, xdpProg, xdpSubfuncName, "", false)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfSubfuncExitLoad verifies fexit on a __noinline subfunction passes the verifier.
func TestBpfSubfuncExitLoad(t *testing.T) {
	xdpProg := loadDummyXDPWithSubfunc(t)
	probe := loadProbeOrFail(t, xdpProg, xdpSubfuncName, "", true)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfSubfuncEntryWithFilter verifies fentry on subfunc + filter passes the verifier.
func TestBpfSubfuncEntryWithFilter(t *testing.T) {
	xdpProg := loadDummyXDPWithSubfunc(t)
	for _, expr := range []string{"arp", "icmp", "tcp port 80"} {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, xdpProg, xdpSubfuncName, expr, false)
		})
	}
}
