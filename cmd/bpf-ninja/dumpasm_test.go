package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/program"
)

// captureStdio runs fn with os.Stdout / os.Stderr swapped for pipes and
// returns what fn wrote to each. It mutates process globals, so callers
// must not use t.Parallel.
func captureStdio(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	outR, outW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	errR, errW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	prevOut, prevErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	// Closing the write ends also on a panic or t.FailNow inside fn
	// lets the readers below finish instead of blocking forever.
	defer func() {
		_ = outW.Close()
		_ = errW.Close()
		os.Stdout, os.Stderr = prevOut, prevErr
	}()

	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&outBuf, outR); _ = outR.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(&errBuf, errR); _ = errR.Close() }()
	err = fn()
	_ = outW.Close()
	_ = errW.Close()
	wg.Wait()
	return outBuf.String(), errBuf.String(), err
}

// TestDumpAsmStreams pins the CLI wiring of --dump-asm: the asm goes to
// stdout and resolver warnings to stderr, each byte-identical to what
// program.DumpAsm writes to its two writers. Needs no root: --dump-asm
// returns before any target lookup.
func TestDumpAsmStreams(t *testing.T) {
	const expr = "eth/ipv4/(tcp|tcp)"
	var wantOut, wantErr bytes.Buffer
	if err := program.DumpAsm(&wantOut, &wantErr, program.DumpScopeFilter, expr, true, "entry", hook.KindXDP); err != nil {
		t.Fatal(err)
	}
	if wantErr.Len() == 0 {
		t.Fatalf("fixture %q must produce a warning", expr)
	}
	if !strings.Contains(wantOut.String(), "===") {
		t.Fatalf("DumpAsm wrote no asm for %q:\n%s", expr, wantOut.String())
	}
	stdout, stderr, err := captureStdio(t, func() error {
		return newRootCommand().Run(context.Background(),
			[]string{"bpf-ninja", "--dump-asm", "filter", expr})
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stdout != wantOut.String() {
		t.Errorf("stdout differs from the DumpAsm asm:\n%s", stdout)
	}
	if stderr != wantErr.String() {
		t.Errorf("stderr = %q, want %q", stderr, wantErr.String())
	}
}
