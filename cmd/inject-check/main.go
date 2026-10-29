// inject-check validates a JSON instruction pair and an untrusted layout
// certificate. It has no dependency on the injection implementation.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

type pair struct {
	Original, Transformed injectcheck.Instructions
	Certificate           injectcheck.Certificate
}

func run(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: inject-check PAIR.json")
		return 2
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var p pair
	if err = json.Unmarshal(b, &p); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	counts, err := injectcheck.Check(asm.Instructions(p.Original), asm.Instructions(p.Transformed), p.Certificate)
	verdict := struct {
		Accepted bool
		Counts   injectcheck.Counts
		Reason   string
	}{Accepted: err == nil, Counts: counts}
	if err != nil {
		verdict.Reason = err.Error()
	}
	if err = json.NewEncoder(os.Stdout).Encode(verdict); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !verdict.Accepted {
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:])) }
