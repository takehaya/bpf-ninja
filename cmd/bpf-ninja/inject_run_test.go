//go:build linux && amd64

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/urfave/cli/v3"
)

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
	if err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--"}); err == nil {
		t.Fatal("accepted missing target")
	}
	t.Setenv("BPF_NINJA_INJECT_CONFIG", "[]")
	if err := newRootCommand().Run(context.Background(), []string{"bpf-ninja", "inject-run", "--", "/bin/true"}); err == nil {
		t.Fatal("accepted empty config")
	}
}
