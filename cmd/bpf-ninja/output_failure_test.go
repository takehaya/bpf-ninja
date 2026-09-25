package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/urfave/cli/v3"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// Use a real queued ringbuf record: errors must wake both the polling and the
// signal-only coordinator, and Close failures must escape the CLI action.
func TestBpfOutputFailureStopsCapture(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	mode := os.Getenv("BPF_NINJA_OUTPUT_FAILURE_CHILD")
	if mode == "" {
		for _, mode := range []string{"write", "close", "raw", "malformed", "flush"} {
			for _, fast := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/fast=%v", mode, fast), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBpfOutputFailureStopsCapture$", "-test.v")
					cmd.Env = append(os.Environ(), "BPF_NINJA_OUTPUT_FAILURE_CHILD="+mode, "BPF_NINJA_OUTPUT_FAST="+strconv.FormatBool(fast))
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("capture failed or hung: %v\n%s", err, out)
					}
				})
			}
		}
		return
	}
	capture.DisableCPUAffinity = true
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	caplen := int64(4)
	if mode == "malformed" {
		caplen = 100
	}
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{
		asm.LoadMapPtr(asm.R1, m.FD()), asm.Mov.Imm(asm.R2, 32), asm.Mov.Imm(asm.R3, 0), asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R2, 0), asm.StoreMem(asm.R0, 0, asm.R2, asm.DWord), asm.StoreMem(asm.R0, 8, asm.R2, asm.DWord), asm.StoreMem(asm.R0, 16, asm.R2, asm.DWord), asm.StoreMem(asm.R0, 24, asm.R2, asm.DWord),
		asm.StoreImm(asm.R0, 14, caplen, asm.Half),
		asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Imm(asm.R2, 0), asm.FnRingbufSubmit.Call(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("exit"), asm.Return(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	if _, err := p.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "out.pcap")
	path := base + ".cpu0"
	if mode == "flush" {
		path = output.TagShardPath(base, 0, 0)
	}
	if mode == "raw" {
		path = fmt.Sprintf("%s.W%d.cpu0.raw", base, capture.WallOffsetNs)
	}
	if err := func() error {
		if mode == "malformed" {
			return nil
		}
		return os.Symlink("/dev/full", path)
	}(); err != nil {
		t.Fatal(err)
	}
	ctl := &captureControl{}
	app := newRootCommand()
	app.Action = func(_ context.Context, c *cli.Command) error {
		if mode == "write" {
			return pumpShards(c, []*ebpf.Map{m}, "test", func(int, []capture.Packet) error { return syscall.ENOSPC }, nil, nil, nil)
		}
		return captureLoopSharded(c, []*ebpf.Map{m}, output.Config{}, "test", nil, nil, ctl)
	}
	args := []string{"bpf-ninja", "--fast-reader=" + os.Getenv("BPF_NINJA_OUTPUT_FAST"), "-w", base}
	if mode != "write" && mode != "flush" {
		args = append(args, "-c", "1")
	}
	if mode == "flush" {
		args = append(args, "--split-by-tag")
	}
	if mode == "raw" {
		args = append(args, "--raw-dump")
	}
	err = app.Run(context.Background(), args)
	if mode == "malformed" {
		if err == nil || !strings.Contains(err.Error(), "caplen") || ctl.stats.Malformed.Load() != 1 {
			t.Fatalf("malformed capture: %v stats=%+v", err, ctl.stats)
		}
	} else if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("CLI action error = %v, want ENOSPC", err)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatalf("unexpected ack file: %v", err)
	}
}
