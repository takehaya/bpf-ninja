package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/urfave/cli/v3"
)

func TestBpfRawAccountingOnSignal(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	mode := os.Getenv("BPF_NINJA_RAW_COUNT_CHILD")
	if mode == "" {
		for _, mode := range []string{"false", "true"} {
			t.Run("fast="+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBpfRawAccountingOnSignal$", "-test.v")
				cmd.Env = append(os.Environ(), "BPF_NINJA_RAW_COUNT_CHILD="+mode)
				pipe, err := cmd.StderrPipe()
				if err != nil {
					t.Fatal(err)
				}
				var out, stderr bytes.Buffer
				cmd.Stdout = &out
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				scanner := bufio.NewScanner(pipe)
				ready := false
				for scanner.Scan() {
					line := scanner.Text()
					stderr.WriteString(line + "\n")
					if strings.Contains(line, "capturing (") {
						ready = true
						if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
							t.Error(err)
						}
					}
				}
				if err := cmd.Wait(); err != nil {
					t.Fatalf("child: %v\n%s\n%s", err, out.String(), stderr.String())
				}
				if !ready {
					t.Fatal("no readiness")
				}
			})
		}
		return
	}
	capture.DisableCPUAffinity = true
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 65536})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{
		asm.LoadMapPtr(asm.R1, m.FD()), asm.Mov.Imm(asm.R2, 32), asm.Mov.Imm(asm.R3, 0), asm.FnRingbufReserve.Call(), asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R2, 0), asm.StoreMem(asm.R0, 0, asm.R2, asm.DWord), asm.StoreMem(asm.R0, 8, asm.R2, asm.DWord), asm.StoreMem(asm.R0, 16, asm.R2, asm.DWord), asm.StoreMem(asm.R0, 24, asm.R2, asm.DWord), asm.StoreImm(asm.R0, 14, 4, asm.Half),
		asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Imm(asm.R2, 0), asm.FnRingbufSubmit.Call(), asm.Mov.Imm(asm.R0, 2).WithSymbol("exit"), asm.Return(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	for range 7 {
		if _, err := p.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
			t.Fatal(err)
		}
	}
	ctl := &captureControl{}
	base := filepath.Join(t.TempDir(), "capture")
	app := newRootCommand()
	app.Action = func(_ context.Context, c *cli.Command) error {
		return captureLoopShardedRaw(c, []*ebpf.Map{m}, "test", base, ctl)
	}
	if err := app.Run(context.Background(), []string{"bpf-ninja", "--fast-reader=" + mode}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(fmt.Sprintf("%s.W%d.cpu0.raw", base, capture.WallOffsetNs))
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(output.RawDumpHeaderSize + 7*32); st.Size() != want {
		t.Fatalf("raw file size=%d want=%d", st.Size(), want)
	}
	if ctl.stats.Consumed.Load() != 7 || ctl.written.Load() != 7 {
		t.Fatalf("consumed=%d written=%d", ctl.stats.Consumed.Load(), ctl.written.Load())
	}
}
