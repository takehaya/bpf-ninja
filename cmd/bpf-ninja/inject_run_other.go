//go:build !linux || !amd64

package main

import (
	"context"
	"fmt"
	"github.com/urfave/cli/v3"
)

func newInjectRunCommand() *cli.Command {
	return &cli.Command{Name: "inject-run", Usage: "experimental ptrace injector (Linux x86-64 only)", Action: func(context.Context, *cli.Command) error { return fmt.Errorf("inject-run requires Linux x86-64") }}
}
