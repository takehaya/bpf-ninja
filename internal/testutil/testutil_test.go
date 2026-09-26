package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise Fatal and Skip in a subprocess, so a mistaken Skip cannot hide a
// compilation failure from the parent test.
func TestCompileBPFSourceFailureContract(t *testing.T) {
	if scenario := os.Getenv("BPF_NINJA_COMPILER_CHILD"); scenario != "" {
		source := "int test(void) { return 0; }"
		if scenario == "invalid-c" {
			source = "this is not C;"
		}
		CompileBPFSource(t, source)
		return
	}
	for _, scenario := range []string{"missing-local", "missing-ci", "exit42", "invalid-c"} {
		t.Run(scenario, func(t *testing.T) {
			bin := t.TempDir()
			ci := ""
			if scenario == "missing-ci" {
				ci = "true"
			}
			if scenario == "exit42" {
				if err := os.WriteFile(filepath.Join(bin, "clang"), []byte("#!/bin/sh\necho injected compiler failure >&2\nexit 42\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "invalid-c" {
				clang, err := exec.LookPath("clang")
				if err != nil {
					if os.Getenv("CI") == "true" || os.Getenv("CI") == "1" {
						t.Fatal(err)
					}
					t.Skip("real clang not installed")
				}
				if err := os.Symlink(clang, filepath.Join(bin, "clang")); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCompileBPFSourceFailureContract$", "-test.v")
			cmd.Env = append(os.Environ(), "BPF_NINJA_COMPILER_CHILD="+scenario, "PATH="+bin, "CI="+ci)
			out, err := cmd.CombinedOutput()
			skipped := strings.Contains(string(out), "--- SKIP:")
			if scenario == "missing-local" {
				if err != nil || !skipped {
					t.Fatalf("missing optional compiler: err=%v\n%s", err, out)
				}
			} else if err == nil || skipped {
				t.Fatalf("compiler error must fail, not skip: err=%v\n%s", err, out)
			}
		})
	}
}
