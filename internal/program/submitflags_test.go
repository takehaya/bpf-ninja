package program

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// Every capture emitter must pass ringbufSubmitFlag() to bpf_ringbuf_submit,
// so --no-wakeup reaches each site; the XDP-native and gated sites have no
// privileged test of their own. Without --no-wakeup the flag comes from the
// two ring queries emitWakeFlag runs before the reserve.
func TestSubmitFlagsFollowNoWakeup(t *testing.T) {
	t.Cleanup(func() { capture.NoWakeup = false })
	id := asm.Instructions{asm.Mov.Imm(asm.R0, 0)}
	for _, noWakeup := range []bool{false, true} {
		capture.NoWakeup = noWakeup
		want, queries := asm.LoadMem(asm.R2, asm.R10, wakeFlagSlot, asm.DWord), 2
		if noWakeup {
			want, queries = asm.Mov.Imm(asm.R2, int32(BPF_RB_NO_WAKEUP)), 0
		}
		for name, insns := range map[string]asm.Instructions{
			"xdp-native": captureXDPNative(3, 64, 4),
			"record":     captureWithRecord(3, 4, false, 64, id, origLenFromR8, nil, 0, nil),
			"gated":      captureFromHold(3, 4, 64, id),
		} {
			submits, seen := 0, 0
			for i, ins := range insns {
				if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnRingbufQuery {
					seen++
				}
				if !ins.IsBuiltinCall() || asm.BuiltinFunc(ins.Constant) != asm.FnRingbufSubmit {
					continue
				}
				submits++
				if prev := insns[i-1]; fmt.Sprint(prev) != fmt.Sprint(want) {
					t.Errorf("%s NoWakeup=%v: before submit %v, want %v", name, noWakeup, prev, want)
				}
			}
			if submits == 0 {
				t.Errorf("%s: no bpf_ringbuf_submit", name)
			}
			if seen != queries {
				t.Errorf("%s NoWakeup=%v: %d bpf_ringbuf_query calls, want %d", name, noWakeup, seen, queries)
			}
		}
		// The discard after a failed copy takes the same flag, never 0.
		discards := 0
		for i, ins := range emitExportTerminals(4) {
			if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnRingbufDiscard {
				discards++
				if prev := emitExportTerminals(4)[i-1]; fmt.Sprint(prev) != fmt.Sprint(want) {
					t.Errorf("NoWakeup=%v: before discard %v, want %v", noWakeup, prev, want)
				}
			}
		}
		if discards != 1 {
			t.Errorf("NoWakeup=%v: %d bpf_ringbuf_discard calls, want 1", noWakeup, discards)
		}
	}
}

// TestBpfSubmitWakesAtThreshold runs the shared reserve and submit on one
// 64 KiB shard and watches it with an edge-triggered epoll, which reports
// the kernel's reader wakeups rather than data: one each time the backlog
// crosses a multiple of a quarter ring, and none under --no-wakeup.
func TestBpfSubmitWakesAtThreshold(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	size := RingbufSize
	RingbufSize = 1 << 16 // each shard gets the 64 KiB floor
	t.Cleanup(func() { RingbufSize = size; capture.NoWakeup = false })
	// The ring takes an 8-byte header, then the sample rounded up to 8.
	const reserve, recLen = 36, 48
	for _, noWakeup := range []bool{false, true} {
		t.Run(fmt.Sprintf("no-wakeup=%v", noWakeup), func(t *testing.T) {
			// A subtest has its own goroutine, so pin here: every record must
			// land on this CPU's shard.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var allowed, one unix.CPUSet
			if err := unix.SchedGetaffinity(0, &allowed); err != nil {
				t.Fatal(err)
			}
			cpu := 0
			for !allowed.IsSet(cpu) {
				cpu++
			}
			one.Set(cpu)
			if err := unix.SchedSetaffinity(0, &one); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.SchedSetaffinity(0, &allowed) }()
			capture.NoWakeup = noWakeup
			outer, inners, err := createShardedRingbuf("wake")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = outer.Close() }()
			for _, m := range inners {
				defer func() { _ = m.Close() }()
			}
			insns := asm.Instructions{asm.FnGetSmpProcessorId.Call(), asm.StoreMem(asm.R10, -16, asm.R0, asm.Word)}
			insns = append(insns, emitShardedRBReserve(outer.FD(), 0, reserve)...)
			insns = append(insns, asm.Mov.Reg(asm.R1, asm.R0), ringbufSubmitFlag(), asm.FnRingbufSubmit.Call(),
				asm.Mov.Imm(asm.R0, 2).WithSymbol("exit"), asm.Return())
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: insns})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = prog.Close() }()
			ring := inners[cpu]
			epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(epfd) }()
			ev := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLET, Fd: int32(ring.FD())}
			if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, ring.FD(), &ev); err != nil {
				t.Fatal(err)
			}
			woke := func(ms int) bool {
				events := make([]unix.EpollEvent, 1)
				for {
					n, err := unix.EpollWait(epfd, events, ms)
					if errors.Is(err, unix.EINTR) {
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					return n > 0
				}
			}
			threshold, n := int(ring.MaxEntries())/4, int(ring.MaxEntries())/recLen-1
			var got, want []int
			for i := range n {
				if ret, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil || ret != 2 {
					t.Fatalf("record %d: ret=%d err=%v", i, ret, err)
				}
				if woke(0) {
					got = append(got, i)
				}
				if !noWakeup && i*recLen/threshold != (i+1)*recLen/threshold {
					want = append(want, i)
				}
			}
			if woke(100) {
				got = append(got, n) // a late wakeup
			}
			c, err := fastrb.NewCursor(ring.FD())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if p := c.Produced(); p != uint64(n*recLen) {
				t.Fatalf("shard %d produced %d bytes, want %d", cpu, p, n*recLen)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("woken after records %v, want %v (%d records of %d B, threshold %d B)", got, want, n, recLen, threshold)
			}
		})
	}
}

// wakeFlagFlow checks, in program order, that the submit flag at
// wakeFlagSlot survives from the emitWakeFlag block to its use: at every
// bpf_ringbuf_submit and every jump to the discard, the last write to the
// slot must be a block's final flag store. A write is a store into
// [-24, -16), directly or through a frame-pointer copy, or a helper or
// kfunc that writes memory through such a pointer. Capture programs only
// jump forward, so program order covers every path that reaches the use.
func wakeFlagFlow(insns asm.Instructions) error {
	flag := asm.StoreMem(asm.R10, wakeFlagSlot, asm.R2, asm.DWord)
	fp, imm := map[asm.Register]int64{asm.R10: 0}, map[asm.Register]int64{}
	hits := func(r asm.Register, off, size int64) bool {
		base, ok := fp[r]
		return ok && base+off < wakeFlagSlot+8 && base+off+size > wakeFlagSlot
	}
	size := func(r asm.Register) int64 {
		if v, ok := imm[r]; ok {
			return v
		}
		return 512 // unknown: assume it may reach the slot
	}
	lastFlag, lastOther := -1, -1
	for i, ins := range insns {
		op := ins.OpCode
		writes := false
		switch {
		case op.Class().IsStore():
			writes = hits(ins.Dst, int64(ins.Offset), int64(op.Size().Sizeof()))
		case ins.IsKfuncCall():
			for r := asm.R1; r <= asm.R5; r++ {
				writes = writes || hits(r, 0, 8)
			}
		case ins.IsBuiltinCall():
			switch asm.BuiltinFunc(ins.Constant) {
			case asm.FnProbeRead, asm.FnProbeReadKernel, asm.FnProbeReadUser, asm.FnProbeReadStr,
				asm.FnProbeReadKernelStr, asm.FnProbeReadUserStr:
				writes = hits(asm.R1, 0, size(asm.R2))
			case asm.FnXdpLoadBytes, asm.FnSkbLoadBytes, asm.FnSkbLoadBytesRelative:
				writes = hits(asm.R3, 0, size(asm.R4))
			}
		}
		switch {
		case ins.OpCode == flag.OpCode && ins.Dst == flag.Dst && ins.Src == flag.Src && ins.Offset == flag.Offset:
			lastFlag = i
		case writes:
			lastOther = i
		}
		use := ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnRingbufSubmit ||
			op.Class().IsJump() && ins.Reference() == "rb_copy_fail"
		if use && (lastFlag < 0 || lastOther > lastFlag) {
			return fmt.Errorf("insn %d (%v): the submit flag at fp%d was last written by insn %d (%v), not by an emitWakeFlag block",
				i, ins, wakeFlagSlot, lastOther, insns[max(lastOther, 0)])
		}
		// Track frame-pointer copies and constants, in program order.
		if ins.IsBuiltinCall() || ins.IsKfuncCall() || ins.IsFunctionCall() {
			for r := asm.R0; r <= asm.R5; r++ {
				delete(fp, r)
				delete(imm, r)
			}
			continue
		}
		if !op.Class().IsALU() && !op.Class().IsLoad() || ins.Dst == asm.R10 {
			continue
		}
		base, isFP := fp[ins.Dst]
		switch {
		case op.Class().IsALU() && op.ALUOp() == asm.Mov && op.Source() == asm.RegSource:
			delete(imm, ins.Dst)
			if v, ok := fp[ins.Src]; ok {
				fp[ins.Dst] = v
			} else {
				delete(fp, ins.Dst)
			}
		case op.Class().IsALU() && op.ALUOp() == asm.Mov:
			delete(fp, ins.Dst)
			imm[ins.Dst] = ins.Constant
		case isFP && op.Class().IsALU() && op.ALUOp() == asm.Add && op.Source() == asm.ImmSource:
			fp[ins.Dst] = base + ins.Constant
		case isFP && op.Class().IsALU() && op.ALUOp() == asm.Sub && op.Source() == asm.ImmSource:
			fp[ins.Dst] = base - ins.Constant
		default:
			delete(fp, ins.Dst)
			delete(imm, ins.Dst)
		}
	}
	return nil
}

// The XDP-native program keeps the flag from its block to the submit, with
// and without the hardware timestamp kfunc; TestOrigLenFlow runs the same
// check over the tracing, --record and gated builders.
func TestXDPNativeWakeFlagFlow(t *testing.T) {
	t.Cleanup(func() { HWTimestampKfuncID = 0 })
	for _, kfunc := range []uint32{0, 7} {
		HWTimestampKfuncID = kfunc
		for _, expr := range []string{"", "eth/ipv4/tcp"} {
			out := codegen.Output{}
			if expr != "" {
				var err error
				if out, err = compileFilter(expr, true, false, ebpf.XDP); err != nil {
					t.Fatal(err)
				}
			}
			if err := wakeFlagFlow(buildXDPNativeInsns(out, 3, nil, 0, 4)); err != nil {
				t.Errorf("kfunc=%d %q: %v", kfunc, expr, err)
			}
		}
	}
}
