package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

func TestMapSerializationCLI(t *testing.T) {
	for _, kind := range []string{"identity", "map-swap", "fd-swap", "pseudo-kind"} {
		t.Run(kind, func(t *testing.T) {
			in := injectcheck.Instructions{asm.LoadMapPtr(asm.R1, 100).WithReference("a"), asm.Mov.Imm(asm.R0, 2), asm.Return()}
			out := append(injectcheck.Instructions(nil), in...)
			want := 1
			switch kind {
			case "identity":
				want = 0
			case "map-swap":
				out[0] = out[0].WithReference("b")
			case "fd-swap":
				out[0].Constant = 101
			case "pseudo-kind":
				out[0].Src = asm.PseudoMapValue
			}
			b, err := json.Marshal(pair{Original: in, Transformed: out, Certificate: injectcheck.Certificate{Original: []int{0, 1, 2}}})
			if err != nil {
				t.Fatal(err)
			}
			checkFile(t, b, want)
		})
	}
	for _, field := range []string{`"Metadata":{"Map":{"FD":100}}`, `"Map":{"FD":100}`} {
		checkFile(t, []byte(`{"Original":[{`+field+`}],"Transformed":[],"Certificate":{}}`), 2)
	}
	// Metadata is unsupported even when empty; use injectcheck.Instructions.
	checkFile(t, []byte(`{"Original":[{"OpCode":183,"Constant":2,"Metadata":{}},{"OpCode":149}],"Transformed":[{"OpCode":183,"Constant":2},{"OpCode":149}],"Certificate":{"Original":[0,1]}}`), 2)
}

func checkFile(t *testing.T, b []byte, want int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pair.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{path}); got != want {
		t.Fatalf("run returned %d, want %d: %s", got, want, b)
	}
}
