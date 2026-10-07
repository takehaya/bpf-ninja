package main

import (
	"context"
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/program"
)

// TestTCVlanReinsertFlag runs the real root command against an interface
// that does not exist: --tc-vlan-reinsert must reach
// program.TCVlanReinsert before the target lookup fails, and is refused
// with --cbpf.
func TestTCVlanReinsertFlag(t *testing.T) {
	prev := program.TCVlanReinsert
	t.Cleanup(func() { program.TCVlanReinsert = prev })

	for _, tc := range []struct {
		args    []string
		want    bool
		wantErr string
	}{
		{nil, false, ""},
		{[]string{"--tc-vlan-reinsert"}, true, ""},
		{[]string{"--tc-vlan-reinsert", "--cbpf"}, false, "--tc-vlan-reinsert applies to DSL filters"},
	} {
		program.TCVlanReinsert = false
		argv := append([]string{"bpf-ninja", "-i", "nonexist0"}, tc.args...)
		err := newRootCommand().Run(context.Background(), argv)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("run %v: error %v, want it to contain %q", tc.args, err, tc.wantErr)
			}
			continue
		}
		if program.TCVlanReinsert != tc.want {
			t.Fatalf("run %v: TCVlanReinsert = %v, want %v (err %v)", tc.args, program.TCVlanReinsert, tc.want, err)
		}
	}
}
