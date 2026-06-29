// Generate test pcap files for each filter F1-F10.
// Built on top of pkg/kunai/dsltest/builders.go (PacketOpts) so we share
// packet-shape primitives with existing tests. Each filter produces both
// match and nomatch pcaps for use by the bench pipelines (../pipelines/*).
//
// Usage:
//   go run ./benchmark/pcap_gen -filter F1 -count 1000 -match-ratio 0.5 \
//     -out ./benchmark/pcaps
//
// Week 2-T6 task: extend pkg/kunai/dsltest/builders.go::PacketOpts with
// GENEVE inner-ether and SRv6 segment list helpers, then wire them here.

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		filter    = flag.String("filter", "", "filter id (F1..F10)")
		count     = flag.Int("count", 1000, "total packets to emit")
		matchRate = flag.Float64("match-ratio", 0.5, "fraction matching the filter")
		outDir    = flag.String("out", "./pcaps", "output directory")
	)
	flag.Parse()

	if *filter == "" {
		fmt.Fprintln(os.Stderr, "usage: -filter F1..F10 [-count N] [-match-ratio 0.0..1.0] [-out DIR]")
		os.Exit(2)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("(stub) generate %s match=%.0f%% n=%d -> %s\n",
		*filter, *matchRate*100, *count, *outDir)
	fmt.Println("Week 2-T6: implement using pkg/kunai/dsltest/builders.go::PacketOpts")
	fmt.Println("Required helpers:")
	fmt.Println("  F7  GTP-U with inner IPv4 (existing dsltest gtpChain)")
	fmt.Println("  F8  IPv6 + SRv6 segment list (TODO: extend builders.go)")
	fmt.Println("  F9  GENEVE inner-ether chain  (TODO: extend builders.go)")
	fmt.Println("  F10 TCP options including MSS (existing dsltest)")
}
