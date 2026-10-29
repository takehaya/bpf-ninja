package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

func identityPair() injectcheck.Pair {
	in := injectcheck.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}
	return injectcheck.Pair{Format: injectcheck.FormatVersion, Original: in, Transformed: in, Certificate: injectcheck.Certificate{Original: []int{0, 1}}, Premises: injectcheck.Premises{LowestOffset: -8}}
}
func checkFile(t *testing.T, b []byte, want int) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pair.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{path}, &stdout, &stderr); got != want {
		t.Fatalf("run=%d want=%d stdout=%s stderr=%s input=%s", got, want, stdout.String(), stderr.String(), b)
	}
	return stdout.String(), stderr.String()
}
func TestMapSerializationCLI(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind injectcheck.Kind
	}{
		{"identity", ""}, {"map-swap", injectcheck.OriginalReference}, {"fd-swap", injectcheck.OriginalChanged}, {"pseudo-kind", injectcheck.OriginalChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := identityPair()
			p.Original[0] = asm.LoadMapPtr(asm.R1, 100).WithReference("a")
			p.Transformed = append(injectcheck.Instructions(nil), p.Original...)
			switch tc.name {
			case "map-swap":
				p.Transformed[0] = p.Transformed[0].WithReference("b")
			case "fd-swap":
				p.Transformed[0].Constant = 101
			case "pseudo-kind":
				p.Transformed[0].Src = asm.PseudoMapValue
			}
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			code := 0
			if tc.kind != "" {
				code = 1
			}
			out, _ := checkFile(t, b, code)
			var verdict injectcheck.Verdict
			if err := json.Unmarshal([]byte(out), &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict.Kind != tc.kind || verdict.Accepted != (code == 0) || verdict.Premises != p.Premises {
				t.Fatalf("wrong verdict: %+v", verdict)
			}
		})
	}
}
func TestRequiredFieldsCLI(t *testing.T) {
	b, err := json.Marshal(identityPair())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"original", "transformed", "certificate", "premises", "format"} {
		for _, null := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "-missing", true: "-null"}[null], func(t *testing.T) {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(b, &fields); err != nil {
					t.Fatal(err)
				}
				if null {
					fields[field] = json.RawMessage("null")
				} else {
					delete(fields, field)
				}
				input, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				_, message := checkFile(t, input, 2)
				if !strings.Contains(message, `required field "`+field+`"`) {
					t.Fatalf("stderr %q does not name %s", message, field)
				}
			})
		}
	}
	for _, tc := range []struct{ old, new, field string }{
		{`"lowest_offset":-8`, ``, "lowest_offset"}, {`"lowest_offset":-8`, `"lowest_offset":null`, "lowest_offset"},
		{`"original":[0,1],`, ``, "original"}, {`"original":[0,1]`, `"original":null`, "original"},
	} {
		_, message := checkFile(t, []byte(strings.Replace(string(b), tc.old, tc.new, 1)), 2)
		if !strings.Contains(message, `required field "`+tc.field+`"`) {
			t.Fatalf("stderr=%q", message)
		}
	}
}
func TestStrictJSONCLI(t *testing.T) {
	b, err := json.Marshal(identityPair())
	if err != nil {
		t.Fatal(err)
	}
	valid := string(b)
	for _, tc := range []struct{ name, input string }{
		{"top-unknown", strings.Replace(valid, `"format":1`, `"format":1,"extra":0`, 1)},
		{"top-case", strings.Replace(valid, `"certificate":`, `"Certificate":`, 1)},
		{"top-duplicate", strings.Replace(valid, `"format":1`, `"format":1,"format":1`, 1)},
		{"merged-certificates", strings.Replace(valid, `"format":1`, `"format":1,"Certificate":{"original":[0,1]}`, 1)},
		{"certificate-unknown", strings.Replace(valid, `"original":[0,1]`, `"original":[0,1],"hook":[]`, 1)},
		{"certificate-duplicate", strings.Replace(valid, `"original":[0,1]`, `"original":[0,1],"original":[0,1]`, 1)},
		{"premise-duplicate", strings.Replace(valid, `"lowest_offset":-8`, `"lowest_offset":-8,"lowest_offset":-8`, 1)},
		{"instruction-duplicate", strings.Replace(valid, `"dst":0`, `"dst":0,"dst":0`, 1)},
		{"instruction-case", strings.Replace(valid, `"dst":0`, `"Dst":0`, 1)},
		{"instruction-metadata", strings.Replace(valid, `"dst":0`, `"dst":0,"Metadata":{}`, 1)},
		{"span-duplicate", strings.Replace(valid, `"hooks":null`, `"hooks":[{"start":2,"end":4,"end":4}]`, 1)},
		{"span-case", strings.Replace(valid, `"hooks":null`, `"hooks":[{"Start":2,"end":4}]`, 1)},
		{"artefact-nested-duplicate", strings.Replace(valid, `"format":1`, `"format":1,"request":{"a":{"x":1,"x":2}}`, 1)},
		{"null-instruction", strings.Replace(valid, `"original":[`, `"original":[null,`, 1)},
		{"version", strings.Replace(valid, `"format":1`, `"format":2`, 1)},
		{"trailing", valid + `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.input == valid {
				t.Fatal("ineffective fixture mutation")
			}
			checkFile(t, []byte(tc.input), 2)
		})
	}
	for _, field := range []string{"request", "result", "reason"} {
		input := strings.Replace(valid, `"format":1`, `"format":1,"`+field+`":"evidence"`, 1)
		checkFile(t, []byte(input), 0)
	}
}
func TestStructuralInputKindsCLI(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   injectcheck.Kind
		change func(*injectcheck.Pair)
	}{
		{"empty-original", injectcheck.InputOriginalEmpty, func(p *injectcheck.Pair) { p.Original = injectcheck.Instructions{} }},
		{"empty-certificate", injectcheck.InputCertificateEmpty, func(p *injectcheck.Pair) { p.Certificate.Original = []int{} }},
		{"length", injectcheck.InputCertificateLength, func(p *injectcheck.Pair) { p.Certificate.Original = []int{0} }},
		{"floor", injectcheck.InputStackFloor, func(p *injectcheck.Pair) { p.Premises.LowestOffset = 1 }},
		{"original-cfg", injectcheck.InputOriginalCFG, func(p *injectcheck.Pair) { p.Original[0] = asm.Ja.Label("missing") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := identityPair()
			tc.change(&p)
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			out, _ := checkFile(t, b, 2)
			var v injectcheck.Verdict
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatal(err)
			}
			if v.Kind != tc.kind {
				t.Fatalf("got %+v", v)
			}
		})
	}
}

// This corpus is the committed scope of the API/built-CLI agreement claim.
func TestPairCorpus(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "inject-check")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	files, err := filepath.Glob("testdata/pairs/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("empty corpus: %v", err)
	}
	// Keep all seven accepted configurations and eleven mutations in the run.
	wantNames := []string{
		"fixture-1-copy-readonly.json",
		"fixture-1-dispatch-any.json",
		"fixture-1-dispatch-static.json",
		"fixture-1-static-any.json",
		"fixture-1-typed-any.json",
		"fixture-1-typed-error.json",
		"fixture-1-typed-miss.json",
		"mutation-callee-saved-clobber.json",
		"mutation-drop-original.json",
		"mutation-forged-certificate.json",
		"mutation-helper-in-hook.json",
		"mutation-hook-store.json",
		"mutation-ldimm64-pseudo-kind.json",
		"mutation-map-fd-value-swap.json",
		"mutation-map-swap.json",
		"mutation-missing-restore.json",
		"mutation-wrong-jump.json",
		"mutation-wrong-spill.json",
	}
	names := make([]string, len(files))
	for i, file := range files {
		names[i] = filepath.Base(file)
	}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("corpus inventory: got %v, want %v", names, wantNames)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var p injectcheck.Pair
			if err := json.Unmarshal(b, &p); err != nil {
				t.Fatal(err)
			}
			var want struct {
				Accepted bool             `json:"accepted"`
				Kind     injectcheck.Kind `json:"kind"`
			}
			if err := json.Unmarshal(p.Result, &want); err != nil {
				t.Fatal(err)
			}
			api, apiErr := p.Validate()
			var input *injectcheck.InputError
			if errors.As(apiErr, &input) {
				t.Fatalf("corpus must reach semantic validation: %v", apiErr)
			}
			if api.Accepted != want.Accepted || api.Kind != want.Kind {
				t.Fatalf("API %+v want %+v", api, want)
			}
			command := exec.Command(binary, file)
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			err = command.Run()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			expected := 0
			if !want.Accepted {
				expected = 1
			}
			if code != expected {
				t.Fatalf("CLI exit=%d stderr=%s", code, stderr.String())
			}
			var cli injectcheck.Verdict
			if err := json.Unmarshal(stdout.Bytes(), &cli); err != nil {
				t.Fatal(err)
			}
			if cli != api {
				t.Fatalf("CLI %+v differs from API %+v", cli, api)
			}
		})
	}
}
func TestIndependentDependencies(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "../../pkg/injectcheck", ".")
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v: %s", err, out)
	}
	for _, dependency := range strings.Fields(string(out)) {
		if dependency == "github.com/takehaya/bpf-ninja/pkg/inject" {
			t.Fatalf("checker depends on transformer: %s", dependency)
		}
	}
}
