package main

import (
	"context"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/urfave/cli/v3"
)

func TestImplicitEntryParamFlags(t *testing.T) {
	integerEntry := attach.Target{
		ProgID: 42, FuncName: "replacement", Type: ebpf.Extension,
		Params: []attach.FuncParamInfo{{Name: "orig_ret", Index: 1, Size: 4, Signed: true}},
	}
	ctxEntry := attach.Target{ProgID: 43, FuncName: "entry", Type: ebpf.XDP}
	ctxExtension := attach.Target{ProgID: 44, FuncName: "ctx_replacement", Type: ebpf.Extension}
	for _, flag := range []string{"--arg-filter", "--list-params", "--arg-echo"} {
		for _, tc := range []struct {
			name     string
			targets  []attach.Target
			explicit bool
			wantErr  bool
		}{
			{"integer EXT entry", []attach.Target{integerEntry}, false, false},
			{"ordinary entry", []attach.Target{ctxEntry}, false, true},
			{"ctx-only EXT entry", []attach.Target{ctxExtension}, false, true},
			{"mixed targets", []attach.Target{integerEntry, ctxEntry}, false, true},
			{"explicit function", []attach.Target{ctxEntry}, true, false},
		} {
			t.Run(flag+"/"+tc.name, func(t *testing.T) {
				cmd := newRootCommand()
				// Inject resolved targets: actual resolution requires live BPF programs.
				cmd.Action = func(_ context.Context, c *cli.Command) error {
					return validateImplicitEntryParams(c, tc.targets)
				}
				args := []string{"bpf-ninja", "-p", "42", flag}
				if flag == "--arg-filter" {
					args = append(args, "orig_ret=2")
				}
				if tc.explicit {
					args = append(args, "--func", "entry")
				}
				err := cmd.Run(context.Background(), args)
				if tc.wantErr {
					if err == nil || !strings.Contains(err.Error(), flag+" requires --func or an entry function with filterable integer parameters") || !strings.Contains(err.Error(), "has none") {
						t.Fatalf("unexpected validation error: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	if err := validateImplicitEntryParams(newRootCommand(), []attach.Target{ctxEntry}); err != nil {
		t.Fatalf("capture without argument options: %v", err)
	}
}
