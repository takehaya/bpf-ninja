package main

import (
	"context"
	"strings"
	"testing"
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
