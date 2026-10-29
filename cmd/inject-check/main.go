// inject-check validates a JSON instruction pair and an untrusted layout
// certificate. It has no dependency on the injection implementation.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: inject-check PAIR.json")
		return 2
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	var p injectcheck.Pair
	if err = json.Unmarshal(b, &p); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	verdict, err := p.Validate()
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if encodeErr := encoder.Encode(verdict); encodeErr != nil {
		_, _ = fmt.Fprintln(stderr, encodeErr)
		return 2
	}
	var input *injectcheck.InputError
	if errors.As(err, &input) {
		return 2
	}
	if !verdict.Accepted {
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
