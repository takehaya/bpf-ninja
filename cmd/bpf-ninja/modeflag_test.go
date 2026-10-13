package main

import (
	"context"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

// TestModeFlagValidation pins the --mode family checks by running the
// real root command against an interface that does not exist: every
// case must fail on the named validation (or, for the negative case,
// on anything but it) before a target is ever looked up.
func TestModeFlagValidation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string // "" = must not be the --rx-hwts mode error
	}{
		{"rx-hwts passes with mode xdp", []string{"--mode", "xdp", "--rx-hwts"}, ""},
		{"rx-hwts needs mode xdp", []string{"--rx-hwts"}, "--rx-hwts requires --mode xdp"},
		{"unknown mode", []string{"--mode", "bogus"}, "invalid mode"},
		{"xdp not combinable", []string{"--mode", "xdp", "--mode", "exit"}, "cannot be combined"},
		{"duplicate mode", []string{"--mode", "entry", "--mode", "entry"}, "at most once"},
		{"three modes", []string{"--mode", "entry", "--mode", "exit", "--mode", "entry"}, "at most once"},
		{"one filter for two modes", []string{"--mode", "entry", "icmp", "--mode", "exit"}, "one quoted filter after each"},
		{"arg-echo single mode", []string{"--mode", "entry", "--mode", "exit", "--arg-echo"}, "--arg-echo takes a single --mode"},
		{"split-by-tag single mode", []string{"--mode", "entry", "--mode", "exit", "--split-by-tag", "-w", "x.pcap"}, "--split-by-tag takes a single --mode"},
		{"emit needs two modes", []string{"--emit", "entry"}, "--emit only applies"},
		{"emit value", []string{"--mode", "entry", "--mode", "exit", "--emit", "bogus"}, "invalid --emit"},
		{"dump-asm single mode", []string{"--mode", "entry", "--mode", "exit", "--dump-asm", "full"}, "--dump-asm renders one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv := append([]string{"bpf-ninja", "-i", "nonexist0"}, tc.args...)
			err := newRootCommand().Run(context.Background(), argv)
			if err == nil {
				t.Fatalf("run %v: no error", tc.args)
			}
			if tc.wantErr == "" {
				if strings.Contains(err.Error(), "--rx-hwts requires") {
					t.Fatalf("run %v: rejected on the mode check: %v", tc.args, err)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("run %v: error %q, want it to contain %q", tc.args, err, tc.wantErr)
			}
		})
	}
}

// TestNewRootCommandFreshFlagState pins that every newRootCommand() gets
// its own command and flag objects, subcommands included: urfave keeps
// IsSet across Run calls on a shared flag, which made the package
// order-dependent and fail at -count=2.
func TestNewRootCommandFreshFlagState(t *testing.T) {
	emitIsSet := func(args ...string) bool {
		app := newRootCommand()
		var set bool
		app.Action = func(_ context.Context, c *cli.Command) error {
			set = c.IsSet("emit")
			return nil
		}
		if err := app.Run(context.Background(), append([]string{"bpf-ninja"}, args...)); err != nil {
			t.Fatalf("run %v: %v", args, err)
		}
		return set
	}
	if !emitIsSet("--emit", "entry") {
		t.Fatal("IsSet(emit) is false right after --emit")
	}
	if emitIsSet() {
		t.Fatal("IsSet(emit) leaked into a fresh newRootCommand()")
	}

	// A subcommand's flags must not leak either.
	maxEntriesIsSet := func(args ...string) bool {
		app := newRootCommand()
		var set bool
		app.Command("set").Command("create").Action = func(_ context.Context, c *cli.Command) error {
			set = c.IsSet("max-entries")
			return nil
		}
		if err := app.Run(context.Background(), append([]string{"bpf-ninja", "set", "create", "--key", "a:u8"}, args...)); err != nil {
			t.Fatalf("run set create %v: %v", args, err)
		}
		return set
	}
	if !maxEntriesIsSet("--max-entries", "8", "/sys/fs/bpf/x") {
		t.Fatal("IsSet(max-entries) is false right after --max-entries")
	}
	if maxEntriesIsSet("/sys/fs/bpf/x") {
		t.Fatal("IsSet(max-entries) leaked into a fresh newRootCommand()")
	}

	// Every command and flag, subcommands included, must be its own
	// object per newRootCommand().
	var walk func(a, b *cli.Command)
	walk = func(a, b *cli.Command) {
		if a == b {
			t.Errorf("command %q is shared between two newRootCommand()", a.Name)
		}
		for i := range a.Flags {
			if a.Flags[i] == b.Flags[i] {
				t.Errorf("flag %v of %q is shared between two newRootCommand()", a.Flags[i].Names(), a.Name)
			}
		}
		for i := range a.Commands {
			walk(a.Commands[i], b.Commands[i])
		}
	}
	walk(newRootCommand(), newRootCommand())
}
