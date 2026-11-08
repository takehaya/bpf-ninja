// Command regionval checks capture files and prints one JSON result per
// line (README.md, Output). It never loads BPF.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/takehaya/bpf-ninja/tools/regionval"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: regionval capture.json...")
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, p := range os.Args[1:] {
		if err := enc.Encode(regionval.Run(p)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
