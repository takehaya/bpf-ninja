package program

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

// Every capture emitter must pass ringbufSubmitFlags() to bpf_ringbuf_submit,
// so --no-wakeup reaches each site; the XDP-native and gated sites have no
// privileged test of their own.
func TestSubmitFlagsFollowNoWakeup(t *testing.T) {
	t.Cleanup(func() { capture.NoWakeup = false })
	id := asm.Instructions{asm.Mov.Imm(asm.R0, 0)}
	for _, noWakeup := range []bool{false, true} {
		capture.NoWakeup = noWakeup
		want := int64(0)
		if noWakeup {
			want = int64(BPF_RB_NO_WAKEUP)
		}
		for name, insns := range map[string]asm.Instructions{
			"xdp-native": captureXDPNative(3, 64, 4),
			"record":     captureWithRecord(3, 4, false, 64, id, origLenFromR8, nil, 0, nil),
			"gated":      captureFromHold(3, 4, 64, id),
		} {
			submits := 0
			for i, ins := range insns {
				if !ins.IsBuiltinCall() || asm.BuiltinFunc(ins.Constant) != asm.FnRingbufSubmit {
					continue
				}
				submits++
				prev := insns[i-1]
				if prev.OpCode != asm.Mov.Op(asm.ImmSource) || prev.Dst != asm.R2 || prev.Constant != want {
					t.Errorf("%s NoWakeup=%v: before submit %v, want r2 = %d", name, noWakeup, prev, want)
				}
			}
			if submits == 0 {
				t.Errorf("%s: no bpf_ringbuf_submit", name)
			}
		}
	}
}
