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

	"github.com/takehaya/bpf-ninja/pkg/syscallhook"
	"github.com/urfave/cli/v3"
)

func newInjectRunCommand() *cli.Command {
	return &cli.Command{
		Name:      "inject-run",
		Usage:     "run an unmodified BPF loader under the experimental ptrace injector",
		ArgsUsage: "-- <target> [args...]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Usage: "JSON injection rules file (otherwise BPF_NINJA_INJECT_CONFIG contains JSON)"},
			&cli.BoolFlag{Name: "fail-closed", Usage: "refuse matched loads when injection fails; default retries the original load"},
			&cli.StringFlag{Name: "hooks-json", Usage: "write the injected programs' hooks and skipped sites as JSON to this file, rewritten after each injected load"},
			&cli.StringFlag{Name: "lookups-json", Usage: "write every loaded XDP and tc program's lookups and maps, with a rule to edit, as JSON to this file; rules become optional"},
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
			opts := syscallhook.Options{Rules: rules, FailClosed: cmd.Bool("fail-closed")}
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
					}
				}
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
