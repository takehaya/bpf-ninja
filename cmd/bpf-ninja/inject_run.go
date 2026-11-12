//go:build linux && amd64

package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/takehaya/bpf-ninja/internal/follow"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
	"github.com/urfave/cli/v3"
)

// announceInjections returns an OnInject that announces the load to captures
// before running next (nil for none). It returns when they have confirmed
// their observers or the hold deadline has passed; a capture that fails or is
// late reports that itself, and the load continues either way.
func announceInjections(next func(syscallhook.Injection), server *follow.Server, logf func(string, ...any)) func(syscallhook.Injection) {
	return func(inj syscallhook.Injection) {
		if inj.ProgID != 0 {
			names := make([]string, len(inj.Hooks))
			for i, h := range inj.Hooks {
				names[i] = h.Name
			}
			start := time.Now()
			if notified, held := server.Announce(inj.ProgID, names); notified > 0 {
				logf("program %q (id=%d): held the load %s for %d of %d following captures", inj.Program, inj.ProgID, time.Since(start).Round(time.Millisecond), held, notified)
			}
		}
		if next != nil {
			next(inj)
		}
	}
}

func newInjectRunCommand() *cli.Command {
	return &cli.Command{
		Name:      "inject-run",
		Usage:     "run an unmodified BPF loader under the experimental ptrace injector",
		ArgsUsage: "-- <target> [args...]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Usage: "JSON injection rules file (otherwise BPF_NINJA_INJECT_CONFIG contains JSON)"},
			&cli.BoolFlag{Name: "fail-closed", Usage: "refuse matched loads when injection fails; default retries the original load"},
			&cli.StringFlag{Name: "hooks-json", Usage: "write the injected programs' hooks and skipped sites as JSON to this file, rewritten after each injected load"},
			&cli.BoolFlag{Name: "stop-every-syscall", Usage: "stop the target at every syscall, not only at program and BTF loads; the default falls back to this where its seccomp filter cannot be used"},
			&cli.StringFlag{Name: "lookups-json", Usage: "write every loaded XDP, tc, cgroup_skb and netfilter program's lookups and maps, with a rule to edit, as JSON to this file; rules become optional"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			var input io.Reader = strings.NewReader(os.Getenv("BPF_NINJA_INJECT_CONFIG"))
			if path := cmd.String("config"); path != "" {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				input = f
			} else if os.Getenv("BPF_NINJA_INJECT_CONFIG") == "" {
				input = nil
				if cmd.String("lookups-json") == "" {
					return fmt.Errorf("--config or BPF_NINJA_INJECT_CONFIG is required")
				}
			}
			var rules []syscallhook.Rule
			if input != nil {
				var err error
				if rules, err = syscallhook.ParseConfig(input); err != nil {
					return err
				}
			}
			ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer cancel()
			opts := syscallhook.Options{Rules: rules, FailClosed: cmd.Bool("fail-closed"), EverySyscall: cmd.Bool("stop-every-syscall"), FrameRounding: inject.RunningKernelFrameRounding()}
			// The target owns stdout, so the hooks go to a file. It exists,
			// empty, before the target starts.
			var hooksErr, lookupsErr error
			if path := cmd.String("hooks-json"); path != "" {
				hooks, err := newHooksWriter(path)
				if err != nil {
					return fmt.Errorf("--hooks-json: %w", err)
				}
				opts.OnInject = func(inj syscallhook.Injection) {
					if err := hooks.add(inj); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "inject-run: --hooks-json: %v\n", err)
						hooksErr = cmp.Or(hooksErr, err)
						return
					}
					for _, site := range hooks.lastDead {
						_, _ = fmt.Fprintf(os.Stderr, "inject-run: site pc %d (map %s) is dead in this load: %s\n", site.PC, site.Map, site.DeadCause)
					}
				}
			}
			// Captures that follow a hook subscribe to this run's loads. Each
			// injected load is announced before the hooks file is written,
			// and the loader stays stopped until both steps finish.
			logf := func(format string, args ...any) {
				_, _ = fmt.Fprintf(os.Stderr, "inject-run: "+format+"\n", args...)
			}
			if server, err := follow.Listen(follow.Options{Logf: logf}); err != nil {
				logf("captures cannot follow this run's loads: %v", err)
			} else {
				defer func() { _ = server.Close() }()
				opts.OnInject = announceInjections(opts.OnInject, server, logf)
			}
			if path := cmd.String("lookups-json"); path != "" {
				lookups, err := newLookupsWriter(path)
				if err != nil {
					return fmt.Errorf("--lookups-json: %w", err)
				}
				opts.OnDiscover = func(d syscallhook.Discovery) {
					if err := lookups.add(d); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "inject-run: --lookups-json: %v\n", err)
						lookupsErr = cmp.Or(lookupsErr, err)
					}
				}
			}
			code, err := syscallhook.Run(ctx, cmd.Args().Slice(), opts)
			if err != nil {
				return err
			}
			if code != 0 {
				return cli.Exit(fmt.Sprintf("target exited with status %d", code), code)
			}
			if hooksErr != nil {
				return fmt.Errorf("--hooks-json: %w", hooksErr)
			}
			if lookupsErr != nil {
				return fmt.Errorf("--lookups-json: %w", lookupsErr)
			}
			return nil
		},
	}
}
