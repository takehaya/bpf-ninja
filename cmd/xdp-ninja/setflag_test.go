package main

import (
	"context"
	"testing"

	"github.com/urfave/cli/v3"
)

// parseSetFlags runs the real root command (with its Action swapped for a
// capture) over the given args and returns the parsed --set slice.
func parseSetFlags(t *testing.T, args ...string) []string {
	t.Helper()
	app := newRootCommand()
	var got []string
	app.Action = func(_ context.Context, c *cli.Command) error {
		got = c.StringSlice("set")
		return nil
	}
	if err := app.Run(context.Background(), append([]string{"xdp-ninja"}, args...)); err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return got
}

// TestSetFlagNotCommaSplit guards the DisableSliceFlagSeparator wiring: a
// single --set value carrying a comma-bearing key(...) mapping must reach the
// action as one element, and repeated --set must still accumulate.
func TestSetFlagNotCommaSplit(t *testing.T) {
	if !newRootCommand().DisableSliceFlagSeparator {
		t.Fatal("root command must set DisableSliceFlagSeparator so --set key(...) is not comma-split")
	}

	const spec = "NAME=/sys/fs/bpf/flows,key(imsi=arg:subscriber,teid=arg:teid)"
	if got := parseSetFlags(t, "--set", spec); len(got) != 1 || got[0] != spec {
		t.Fatalf("--set with commas parsed as %q, want single element %q", got, spec)
	}

	if got := parseSetFlags(t, "--set", "A=/a", "--set", "B=/b"); len(got) != 2 {
		t.Fatalf("repeated --set gave %q, want 2 elements", got)
	}
}
