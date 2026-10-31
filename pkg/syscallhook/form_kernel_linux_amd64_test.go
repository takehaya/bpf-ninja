//go:build linux && amd64 && integration

package syscallhook

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"golang.org/x/sys/unix"
)

func TestBpfAutoStatic(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	t.Setenv("SYSCALLHOOK_INTEGRATION_CHILD", "hook-rdonly")
	for _, tc := range []struct {
		name            string
		dispatch, retry bool
	}{
		{"typed", false, false}, {"dispatch", true, false}, {"inconclusive-probe", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := testRule()
			rule.Auto, rule.Map, rule.Dispatch = true, "", tc.dispatch
			var logs bytes.Buffer
			count := 0
			var links []link.Link
			var programs []*ebpf.Program
			defer func() {
				for _, l := range links {
					_ = l.Close()
				}
				for _, p := range programs {
					_ = p.Close()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			probeCalls := 0
			probe := func() error {
				probeCalls++
				if tc.retry {
					return unix.EPERM
				}
				return probeGlobalUntrusted()
			}
			code, err := run(ctx, []string{os.Args[0], "-test.run=^TestIntegrationLoader$", "-test.v"}, Options{
				Rules: []Rule{rule}, FailClosed: true, Log: &logs,
				OnInject: func(inj Injection) {
					count++
					t.Logf("form=%s reason=%s hooks=%+v", inj.HookForm.Form, inj.HookForm.Reason, inj.Hooks)
					if want := os.Getenv("BPF_NINJA_EXPECT_HOOK_FORM"); want != "" && inj.HookForm.Form != want {
						t.Errorf("form=%s, want %s", inj.HookForm.Form, want)
					}
					wantReason := "probe_arg_untrusted_supported"
					if inj.HookForm.Form == "static" {
						wantReason = "probe_arg_untrusted_unsupported"
					}
					if tc.retry {
						wantReason = "probe_inconclusive"
						if inj.HookForm.Form == "static" {
							wantReason = "retry_arg_untrusted_rejected"
						}
					}
					if inj.HookForm.Reason != wantReason {
						t.Errorf("unexpected reason %+v", inj.HookForm)
					}
					if len(inj.Hooks) != 1 || inj.Hooks[0].Static != (inj.HookForm.Form == "static") {
						t.Errorf("unexpected hooks %+v", inj.Hooks)
						return
					}
					target, e := ebpf.NewProgramFromID(ebpf.ProgramID(inj.ProgID))
					if e != nil {
						t.Error(e)
						return
					}
					defer func() { _ = target.Close() }()
					observer, e := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTarget: target, AttachTo: inj.Hooks[0].Name, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
					if e != nil {
						t.Errorf("observer load: %+v", e)
						return
					}
					programs = append(programs, observer)
					l, e := link.AttachTracing(link.TracingOptions{Program: observer})
					if e != nil {
						t.Errorf("observer attach: %v", e)
						return
					}
					links = append(links, l)
				},
			}, probe)
			if probeCalls != 1 {
				t.Errorf("feature probe ran %d times", probeCalls)
			}
			t.Logf("supervisor:\n%s", &logs)
			if err != nil || code != 0 || count != 1 || len(links) != 1 {
				t.Fatalf("code=%d err=%v injections=%d attaches=%d", code, err, count, len(links))
			}
		})
	}
}
