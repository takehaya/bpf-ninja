package program

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/google/gopacket/pcapgo"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestBpfRunCLITagCompletion(t *testing.T) {
	for _, mode := range []string{"percpu", "ctx"} {
		for _, removed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/removed=%v", mode, removed), func(t *testing.T) {
				coll, old, _ := runFixtureCapture(t, "run_stress_slow_xdp", mode, 0)
				if e := old.Close(); e != nil {
					t.Fatal(e)
				}
				pin := fmt.Sprintf("/sys/fs/bpf/run_cli_%d", os.Getpid())
				if e := setmap.Create(pin, "src:u64", "", 16); e != nil {
					t.Fatal(e)
				}
				defer func() { _ = os.Remove(pin) }()
				set, e := setmap.OpenSet(setmap.SpecRef{Name: "macs", Path: pin})
				if e != nil {
					t.Fatal(e)
				}
				defer set.Def.Close()
				limit := uint64(1)
				if removed {
					limit = 0
				}
				if e := set.Def.Add(map[string]string{"src": "00:00:00:00:00:00"}, setmap.EntryValue{Tag: 7, MaxBytes: limit}); e != nil {
					t.Fatal(e)
				}
				prog := coll.Programs["run_stress_slow_xdp"]
				info, e := prog.Info()
				if e != nil {
					t.Fatal(e)
				}
				id, _ := info.ID()
				dir := os.Getenv("BPF_NINJA_HOOK_TEST_DIR")
				if dir == "" {
					dir = t.TempDir()
				}
				path := filepath.Join(dir, fmt.Sprintf("tag-%s-removed-%v.pcapng", mode, removed))
				args := []string{"-p", fmt.Sprint(id), "--hook-pcapng", "--run-tracking", mode, "--func", "run_begin_xdp", "--func", "run_hook_xdp", "--set", "macs=" + pin, "--split-by-tag", "--ringbuf-size", "4", "--fast-reader", "--no-cpu-affinity", "-w", path, "eth[src in @macs]"}
				if removed {
					args = append(args, "--finalize-on-del")
				} else {
					args = append(args, "--exit-when-capped")
				}
				binaryPath := os.Getenv("BPF_NINJA_HOOK_TEST_BINARY")
				if binaryPath == "" {
					binaryPath = filepath.Join(t.TempDir(), "bpf-ninja")
					build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/bpf-ninja")
					if out, e := build.CombinedOutput(); e != nil {
						t.Fatalf("build CLI: %v\n%s", e, out)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binaryPath, args...)
				pipe, e := cmd.StderrPipe()
				if e != nil {
					t.Fatal(e)
				}
				if e = cmd.Start(); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if cmd.ProcessState == nil {
						_ = cmd.Process.Kill()
						_ = cmd.Wait()
					}
				}()
				ready, capped, finalized, scanned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
				var readyOnce, capOnce, finOnce sync.Once
				var log bytes.Buffer
				go func() {
					defer close(scanned)
					scanner := bufio.NewScanner(pipe)
					for scanner.Scan() {
						line := scanner.Text()
						fmt.Fprintln(&log, line)
						if strings.HasPrefix(line, "capturing (") {
							readyOnce.Do(func() { close(ready) })
						}
						if strings.Contains(line, "tag 7 capped") {
							capOnce.Do(func() { close(capped) })
						}
						if strings.Contains(line, "tag 7 finalized") {
							finOnce.Do(func() { close(finalized) })
						}
					}
				}()
				wait := func(ch <-chan struct{}) {
					t.Helper()
					select {
					case <-ch:
					case <-ctx.Done():
						t.Fatal("CLI event timeout")
					}
				}
				wait(ready)
				done := make(chan error, 1)
				go func() { _, _, e := prog.Test(make([]byte, 64)); done <- e }()
				if removed {
					deadline := time.Now().Add(3 * time.Second)
					for {
						var key uint64
						_ = coll.Maps["seen"].Lookup(uint32(0), &key)
						if key != 0 {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("root did not enter")
						}
						runtime.Gosched()
					}
					if e := set.Def.Delete(map[string]string{"src": "00:00:00:00:00:00"}); e != nil {
						t.Fatal(e)
					}
				} else {
					wait(capped)
				}
				select {
				case e := <-done:
					t.Fatalf("root ended before admission stopped: %v", e)
				default:
				}
				if e := <-done; e != nil {
					t.Fatal(e)
				}
				wait(finalized)
				if removed {
					if e := cmd.Process.Signal(syscall.SIGINT); e != nil {
						t.Fatal(e)
					}
				}
				e = cmd.Wait()
				<-scanned
				if err := os.WriteFile(path+".stderr", log.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
				if e != nil || !strings.Contains(log.String(), "capture status=complete") || !strings.Contains(log.String(), "run tracking: "+mode) {
					t.Fatalf("CLI=%v\n%s", e, log.String())
				}
				f, e := os.Open(output.TagMergedPath(path, 7))
				if e != nil {
					t.Fatal(e)
				}
				defer func() { _ = f.Close() }()
				rd, e := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
				if e != nil {
					t.Fatal(e)
				}
				n := 0
				for {
					_, _, e := rd.ReadPacketData()
					if e == io.EOF {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
					n++
				}
				if n != 2 {
					t.Fatalf("completed tag records=%d want2", n)
				}
				t.Logf("mode=%s removed=%v in-flight run completed: 2/2 records, clean CLI and finalized file", mode, removed)
			})
		}
	}
}
