//go:build linux && amd64

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestKernelFrameRounding(t *testing.T) {
	for _, tc := range []struct {
		release, jit string
		readErr      error
		want         int
	}{
		{"6.9.0", "1\n", nil, 16},
		{"7.0.0-rc1", "2\n", nil, 16},
		{"6.8.12", "1\n", nil, 32},
		{"6.12.0", "0\n", nil, 32},
		{"unknown", "1\n", nil, 32},
		{"7.0.0", "", errors.New("denied"), 32},
	} {
		if got := kernelFrameRounding(tc.release, tc.jit, tc.readErr); got != tc.want {
			t.Errorf("release=%q jit=%q err=%v: got %d want %d", tc.release, tc.jit, tc.readErr, got, tc.want)
		}
	}
}

func TestInjectRunCommand(t *testing.T) {
	t.Setenv("BPF_NINJA_INJECT_CONFIG", `[{"program":"p","map":"sessions","hook":"lookup_hook","stack_lowest_offset":-8}]`)
	// The shell's flag and script must belong to the child, and its exit code
	// must reach main's ExitCoder path rather than being collapsed to status 1.
	app := newRootCommand()
	app.ExitErrHandler = func(context.Context, *cli.Command, error) {}
	err := app.Run(context.Background(), []string{"bpf-ninja", "inject-run", "--", "/bin/sh", "-c", "exit 37"})
	var exit cli.ExitCoder
	if !errors.As(err, &exit) || exit.ExitCode() != 37 {
		t.Fatalf("exit status: %v", err)
	}
	// The hooks file exists before the target runs, empty when nothing loaded.
	hooks := filepath.Join(t.TempDir(), "hooks.json")
	if err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--hooks-json", hooks, "--", "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(hooks); err != nil || string(data) != "{\n  \"version\": 1,\n  \"programs\": []\n}\n" {
		t.Fatalf("hooks file %q: %v", data, err)
	}
	// An unwritable path refuses before launching.
	marker := filepath.Join(t.TempDir(), "ran")
	if err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--hooks-json", filepath.Join(marker, "missing", "hooks.json"), "--", "/bin/touch", marker}); err == nil {
		t.Fatal("accepted unwritable --hooks-json")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("target ran despite unwritable --hooks-json")
	}
	if err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--"}); err == nil {
		t.Fatal("accepted missing target")
	}
	// --lookups-json makes the rules optional and writes an empty document
	// when nothing loads; without rules or it, the command refuses.
	t.Setenv("BPF_NINJA_INJECT_CONFIG", "")
	lookups := filepath.Join(t.TempDir(), "lookups.json")
	if err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--lookups-json", lookups, "--", "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(lookups); err != nil || string(data) != "{\n  \"version\": 1,\n  \"programs\": []\n}\n" {
		t.Fatalf("lookups file %q: %v", data, err)
	}
	if err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--", "/bin/true"}); err == nil {
		t.Fatal("accepted no rules without --lookups-json")
	}
	t.Setenv("BPF_NINJA_INJECT_CONFIG", "[]")
	if err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--", "/bin/true"}); err == nil {
		t.Fatal("accepted empty config")
	}
}
