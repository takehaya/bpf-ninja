package program

import "testing"

// TestBpfVerifierStats records the verifier's load cost for the
// canonical F1-F10: the number of instructions the verifier processes
// before accepting each probe, read back from
// bpf_prog_info.verified_insns (kernel 5.16+). Where an equivalent
// pcap-filter expression exists, the cbpfc baseline is measured the
// same way. This is the measurement behind the "verifier" column of
// the eBPF Workshop 2026 paper's filter-set table, which reports the
// largest value across the CI kernel matrix.
//
// The count grows with the verifier's path exploration rather than
// with program size, and it moves with the kernel release itself, so
// the assertions are deliberately loose (nonzero, below the
// one-million verifier limit); the value is telemetry logged for
// cross-kernel comparison, not a pin. Reproduce one kernel locally
// with `make test-bpf`, or a specific version with e.g.
//
//	vimto -sudo -kernel :6.18 -- go test -v -count 1 \
//	    ./internal/program/ -run TestBpfVerifierStats
func TestBpfVerifierStats(t *testing.T) {
	hostProg := loadDummyXDP(t)
	type variant struct {
		id     string
		expr   string
		useDSL bool
	}
	var variants []variant
	for _, fs := range FilterSet {
		variants = append(variants, variant{fs.ID + "/kunai", fs.Expr, true})
		if fs.CBPFCExpr != "" {
			variants = append(variants, variant{fs.ID + "/cbpfc", fs.CBPFCExpr, false})
		}
	}
	for _, v := range variants {
		t.Run(v.id, func(t *testing.T) {
			probe := loadProbeOrFail(t, hostProg, xdpFuncName, v.expr, false /*exit*/, v.useDSL)
			var verified uint64
			for _, p := range probe.progs {
				info, err := p.Info()
				if err != nil {
					t.Fatalf("prog info: %v", err)
				}
				vi, ok := info.VerifiedInstructions()
				if !ok {
					t.Skip("verified_insns needs kernel 5.16+")
				}
				verified += uint64(vi)
			}
			if verified == 0 {
				t.Fatal("verified_insns is zero")
			}
			const verifierLimit = 1_000_000
			if verified >= verifierLimit {
				t.Fatalf("verified_insns %d at or above the one-million verifier limit", verified)
			}
			t.Logf("verified_insns=%d", verified)
		})
	}
}

// TestBpfVerifierStatsMachineChain logs the verifier cost of repeated
// parser-machine layers: an open bound unrolls to MAX_DEPTH machines
// (ipv4 8, ipv6 4), each with its own option or extension walk, so the
// growth per instance across the kernel matrix is what this records.
// Telemetry like TestBpfVerifierStats, not a pin; the FilterSet table
// stays as published.
func TestBpfVerifierStatsMachineChain(t *testing.T) {
	hostProg := loadDummyXDP(t)
	for _, expr := range []string{
		"eth/ipv4{1,2}/tcp",
		"eth/ipv4{1,4}/tcp",
		"eth/ipv4+/tcp",
		"eth/ipv4[options.valid]+/tcp",
		"eth/ipv4@o+/tcp where o.options.RR.kind == 7",
		"eth/ipv6{1,2}/tcp",
		"eth/ipv6+/tcp",
		"eth/ipv6@o+/tcp where o.exts[0].next_header == 6",
	} {
		t.Run(expr, func(t *testing.T) {
			probe := loadProbeOrFail(t, hostProg, xdpFuncName, expr, false /*exit*/, true)
			var verified uint64
			for _, p := range probe.progs {
				info, err := p.Info()
				if err != nil {
					t.Fatalf("prog info: %v", err)
				}
				vi, ok := info.VerifiedInstructions()
				if !ok {
					t.Skip("verified_insns needs kernel 5.16+")
				}
				verified += uint64(vi)
			}
			if verified == 0 {
				t.Fatal("verified_insns is zero")
			}
			if verified >= 1_000_000 {
				t.Fatalf("verified_insns %d at or above the one-million verifier limit", verified)
			}
			t.Logf("verified_insns=%d", verified)
		})
	}
}
