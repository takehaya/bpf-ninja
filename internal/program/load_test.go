package program

import (
	"testing"
)

// TestBpfEntryLoad verifies that the fentry program passes the verifier.
func TestBpfEntryLoad(t *testing.T) {
	probe := loadProbeOrFail(t, loadDummyXDP(t), xdpFuncName, "", false, false)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfExitLoad verifies that the fexit program passes the verifier.
func TestBpfExitLoad(t *testing.T) {
	probe := loadProbeOrFail(t, loadDummyXDP(t), xdpFuncName, "", true, false)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

var cbpfcFilterExprs = []string{"arp", "icmp", "tcp port 80", "host 10.0.0.1"}

// TestBpfEntryWithFilter verifies fentry + cbpfc filter passes the verifier.
func TestBpfEntryWithFilter(t *testing.T) {
	runFilterMatrix(t, loadDummyXDP(t), xdpFuncName, cbpfcFilterExprs, false, false)
}

// TestBpfExitWithFilter verifies fexit + cbpfc filter passes the verifier.
func TestBpfExitWithFilter(t *testing.T) {
	runFilterMatrix(t, loadDummyXDP(t), xdpFuncName, cbpfcFilterExprs, true, false)
}

// TestBpfSubfuncEntryLoad verifies fentry on a __noinline subfunction passes the verifier.
func TestBpfSubfuncEntryLoad(t *testing.T) {
	xdpProg := loadDummyXDPWithSubfunc(t)
	probe := loadProbeOrFail(t, xdpProg, xdpSubfuncName, "", false, false)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfSubfuncExitLoad verifies fexit on a __noinline subfunction passes the verifier.
func TestBpfSubfuncExitLoad(t *testing.T) {
	xdpProg := loadDummyXDPWithSubfunc(t)
	probe := loadProbeOrFail(t, xdpProg, xdpSubfuncName, "", true, false)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfSubfuncEntryWithFilter verifies fentry on subfunc + filter passes the verifier.
func TestBpfSubfuncEntryWithFilter(t *testing.T) {
	runFilterMatrix(t, loadDummyXDPWithSubfunc(t), xdpSubfuncName, cbpfcFilterExprs[:3], false, false)
}
