package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
			b, err := json.Marshal(pair{Original: &in, Transformed: &out, Certificate: &injectcheck.Certificate{Original: []int{0, 1, 2}}})
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

func TestRequiredFieldsCLI(t *testing.T) {
	for _, tc := range []struct {
		name, input, field string
	}{
		{"empty", `{}`, "original"},
		{"missing-original", `{"transformed":[],"certificate":{}}`, "original"},
		{"missing-transformed", `{"original":[],"certificate":{}}`, "transformed"},
		{"missing-certificate", `{"original":[],"transformed":[]}`, "certificate"},
		{"null-original", `{"original":null,"transformed":[],"certificate":{}}`, "original"},
		{"null-transformed", `{"original":[],"transformed":null,"certificate":{}}`, "transformed"},
		{"null-certificate", `{"original":[],"transformed":[],"certificate":null}`, "certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stderr")
			stderr, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stderr.Close() })
			previous := os.Stderr
			os.Stderr = stderr
			defer func() { os.Stderr = previous }()
			checkFile(t, []byte(tc.input), 2)
			message, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(message), `required field "`+tc.field+`"`) {
				t.Fatalf("stderr %q does not name required field %q", message, tc.field)
			}
		})
	}
}

func TestFieldCasingCLI(t *testing.T) {
	for _, fields := range [][3]string{
		{"Original", "Transformed", "Certificate"},
		{"original", "transformed", "certificate"},
		{"ORIGINAL", "TRANSFORMED", "CERTIFICATE"},
		{"oRiGiNaL", "tRaNsFoRmEd", "cErTiFiCaTe"},
	} {
		t.Run(fields[0], func(t *testing.T) {
			instructions := injectcheck.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}
			b, err := json.Marshal(map[string]any{
				fields[0]: instructions,
				fields[1]: instructions,
				fields[2]: injectcheck.Certificate{Original: []int{0, 1}},
			})
			if err != nil {
				t.Fatal(err)
			}
			checkFile(t, b, 0)
		})
	}
}
