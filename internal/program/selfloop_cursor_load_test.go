package program

import "testing"

// selfLoopCursorExprs exercise the parser-machine self-loop callback
// (emitSelfLoopCallback) in the fentry entry-mode scratch path, where the
// running cursor is spilled to the bpf_loop ctx and re-read each
// iteration. A terminal `gtp` (its extension-header walk skips to the
// payload) is the shape that regressed: without clamping the reloaded
// cursor to ScratchBufSize, kernels through ~6.6 reject the
// `window_base + cursor` pointer arithmetic as "register with unbounded
// min value". Mid-chain gtp (FilterSet F7) and the IPv6 extension walk
// take neighbouring paths and are covered by the FilterSet matrix; these
// pin the terminal shapes so the clamp cannot regress on the CI kernels.
var selfLoopCursorExprs = []string{
	"eth/ipv4/udp/gtp",
	"eth/ipv4/udp/gtp[teid==0x3039]",
	"eth/ipv6/srv6",
}

// TestBpfSelfLoopCursorClampEntryLoad loads each self-loop shape via
// fentry entry-mode (the scratch map_value path). Runs on the CI kernel
// matrix (6.1 / 6.6 / ...); a verifier rejection fails the subtest.
func TestBpfSelfLoopCursorClampEntryLoad(t *testing.T) {
	host := loadDummyXDP(t)
	for _, expr := range selfLoopCursorExprs {
		t.Run(expr, func(t *testing.T) {
			probe := loadProbeOrFail(t, host, xdpFuncName, expr, false /*exit*/, true /*useDSL*/)
			_ = probe.Close()
		})
	}
}
