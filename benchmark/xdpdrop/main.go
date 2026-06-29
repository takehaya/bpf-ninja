// Command xdpdrop attaches a filter-only XDP drop program for the
// B4 macrobench (§5.5): every packet runs the filter and is dropped;
// per-CPU counters record processed / matched totals. No capture.
//
// Usage:
//
//	sudo ./xdpdrop -i enp138s0f0np0 -dsl 'eth/ipv4/tcp where tcp.dport == 443' -duration 30
//	sudo ./xdpdrop -i enp138s0f0np0 -pcap 'tcp dst port 443' -duration 30
//	sudo ./xdpdrop -i enp138s0f0np0 -duration 30            # accept-all (no filter insns)
//
// On exit (duration elapsed or SIGINT/SIGTERM) it prints one JSON
// object to stdout: {"iface","path","filter","duration_s","total",
// "matched","mpps"}. The "attached" marker line goes to stderr so
// pipeline scripts can synchronize before starting traffic.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/program"
)

func main() {
	var (
		iface    = flag.String("i", "", "interface to attach to (required)")
		dslExpr  = flag.String("dsl", "", "kunai DSL filter expression")
		pcapExpr = flag.String("pcap", "", "pcap-filter expression (compiled via cbpfc)")
		floor    = flag.Bool("floor", false, "skip window copy + filter entirely (counter + drop only)")
		duration = flag.Duration("duration", 0, "detach after this long (0 = wait for signal)")
	)
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "error: -i <iface> is required")
		os.Exit(2)
	}
	if *dslExpr != "" && *pcapExpr != "" {
		fmt.Fprintln(os.Stderr, "error: -dsl and -pcap are mutually exclusive")
		os.Exit(2)
	}
	if *floor && (*dslExpr != "" || *pcapExpr != "") {
		fmt.Fprintln(os.Stderr, "error: -floor takes no filter")
		os.Exit(2)
	}
	expr, useDSL, path := "", false, "accept_all"
	switch {
	case *floor:
		path = "floor"
	case *dslExpr != "":
		expr, useDSL, path = *dslExpr, true, "kunai"
	case *pcapExpr != "":
		expr, useDSL, path = *pcapExpr, false, "cbpfc"
	}

	state, err := attach.InspectInterface(*iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if state.Existing != nil {
		fmt.Fprintf(os.Stderr, "error: %s already has an XDP program attached; detach it first\n", *iface)
		os.Exit(1)
	}

	bench, err := program.LoadXDPDropBench(state, expr, useDSL, *floor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = bench.Close() }()

	start := time.Now()
	fmt.Fprintf(os.Stderr, "attached: iface=%s path=%s filter=%q\n", *iface, path, expr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	if *duration > 0 {
		select {
		case <-sig:
		case <-time.After(*duration):
		}
	} else {
		<-sig
	}

	elapsed := time.Since(start).Seconds()
	total, matched, err := bench.Counters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"iface":      *iface,
		"path":       path,
		"filter":     expr,
		"duration_s": elapsed,
		"total":      total,
		"matched":    matched,
		"mpps":       float64(total) / elapsed / 1e6,
	})
}
