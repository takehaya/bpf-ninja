//go:build !enable_libpcap

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/program"
)

func TestCBPFUnavailableBeforeTargetLookup(t *testing.T) {
	for _, args := range [][]string{
		{"bpf-ninja", "--cbpf"},
		{"bpf-ninja", "--cbpf", "-i", "nonexistent", "tcp port 80"},
		{"bpf-ninja", "--cbpf", "--mode", "xdp", "tcp port 80"},
		{"bpf-ninja", "--cbpf", "--dump-asm", "filter", "tcp port 80"},
		{"bpf-ninja", "--cbpf", "--dump-asm", "full", "tcp port 80"},
	} {
		_, _, err := captureStdio(t, func() error {
			return newRootCommand().Run(context.Background(), args)
		})
		if !errors.Is(err, program.ErrCBPFUnavailable) {
			t.Errorf("%v: got %v, want ErrCBPFUnavailable", args, err)
		}
	}
}
