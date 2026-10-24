//go:build linux && amd64

package main

import (
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
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			var input io.Reader = strings.NewReader(os.Getenv("BPF_NINJA_INJECT_CONFIG"))
			if path := cmd.String("config"); path != "" {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()
				input = f
			} else if os.Getenv("BPF_NINJA_INJECT_CONFIG") == "" {
				return fmt.Errorf("--config or BPF_NINJA_INJECT_CONFIG is required")
			}
			rules, err := syscallhook.ParseConfig(input)
			if err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer cancel()
			code, err := syscallhook.Run(ctx, cmd.Args().Slice(), syscallhook.Options{Rules: rules, FailClosed: cmd.Bool("fail-closed")})
			if err != nil {
				return err
			}
			if code != 0 {
				return cli.Exit(fmt.Sprintf("target exited with status %d", code), code)
			}
			return nil
		},
	}
}
