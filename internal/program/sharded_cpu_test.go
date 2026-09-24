package program

import (
	"encoding/binary"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfShardsUnderRestrictedAffinity(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	if os.Getenv("BPF_NINJA_PRODUCER_RUN") == "1" {
		prog, err := ebpf.NewProgramFromFD(3)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = prog.Close() }()
		if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("BPF_NINJA_CPU_CHILD") == "" {
		var allowed unix.CPUSet
		if err := unix.SchedGetaffinity(0, &allowed); err != nil {
			t.Fatal(err)
		}
		cpu := -1
		for i := 1; i < len(allowed)*64; i++ {
			if allowed.IsSet(i) {
				cpu = i
				break
			}
		}
		if cpu < 0 {
			t.Skip("requires an allowed nonzero CPU")
		}
		cmd := exec.Command("taskset", "-c", strconv.Itoa(cpu), os.Args[0], "-test.run=^TestBpfShardsUnderRestrictedAffinity$", "-test.v")
		other := cpu
		for i := 0; i < len(allowed)*64; i++ {
			if i != cpu && allowed.IsSet(i) {
				other = i
				break
			}
		}
		cmd.Env = append(os.Environ(), "BPF_NINJA_CPU_CHILD="+strconv.Itoa(cpu), "BPF_NINJA_PRODUCER_CPU="+strconv.Itoa(other))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("restricted observer: %v\n%s", err, out)
		}
		t.Logf("CPU %d: %s", cpu, out)
		return
	}
	cpu, err := strconv.Atoi(os.Getenv("BPF_NINJA_CPU_CHILD"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.NumCPU() != 1 {
		t.Fatalf("observer sees %d CPUs, want 1", runtime.NumCPU())
	}
	outer, inners, err := createShardedRingbuf("cpuid")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outer.Close() }()
	for _, m := range inners {
		defer func() { _ = m.Close() }()
	}
	if cpu >= len(inners) {
		t.Fatalf("CPU ID %d has no shard: observer has %d usable CPU, map has %d entries", cpu, runtime.NumCPU(), len(inners))
	}
	insns := asm.Instructions{asm.FnGetSmpProcessorId.Call(), asm.StoreMem(asm.R10, -16, asm.R0, asm.Word)}
	insns = append(insns, emitShardedRBReserve(outer.FD(), 8)...)
	insns = append(insns, asm.LoadMem(asm.R1, asm.R10, -16, asm.Word), asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord), asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Imm(asm.R2, 0), asm.FnRingbufSubmit.Call(), asm.Mov.Imm(asm.R0, 2).WithSymbol("exit"), asm.Return())
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "cpu_shard_test", Type: ebpf.XDP, License: "GPL", Instructions: insns})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prog.Close() }()
	other, err := strconv.Atoi(os.Getenv("BPF_NINJA_PRODUCER_CPU"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fast := range []bool{false, true} {
		t.Run(strconv.FormatBool(fast), func(t *testing.T) {
			capture.SplitCoreRX = cpu
			defer func() { capture.SplitCoreRX = 0 }()
			records := make(chan int, 8)
			sink := func(shard int, rec []byte) error {
				if len(rec) != 8 || binary.NativeEndian.Uint64(rec) != uint64(shard) {
					t.Errorf("shard %d: CPU record %x", shard, rec)
				}
				records <- shard
				return nil
			}
			var stop func()
			if fast {
				reader, err := capture.NewFastShardedReader(inners)
				if err != nil {
					t.Fatal(err)
				}
				stop, err = reader.RunRawShardsFast(sink)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				reader, err := capture.NewShardedReader(inners)
				if err != nil {
					t.Fatal(err)
				}
				stop, err = reader.RunRawShards(sink)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer stop()
			for _, producer := range []int{cpu, other} {
				fd, err := unix.Dup(prog.FD())
				if err != nil {
					t.Fatal(err)
				}
				file := os.NewFile(uintptr(fd), "producer-program")
				cmd := exec.Command("taskset", "-c", strconv.Itoa(producer), os.Args[0], "-test.run=^TestBpfShardsUnderRestrictedAffinity$")
				cmd.Env = append(os.Environ(), "BPF_NINJA_PRODUCER_RUN=1")
				cmd.ExtraFiles = []*os.File{file}
				out, err := cmd.CombinedOutput()
				_ = file.Close()
				if err != nil {
					t.Fatalf("producer CPU %d: %v\n%s", producer, err, out)
				}
				select {
				case got := <-records:
					if got != producer {
						t.Fatalf("record from CPU %d, want %d", got, producer)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("observer CPU %d did not drain producer CPU %d", cpu, producer)
				}
			}
		})
	}

}
