package program

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfArgMemberReadFailure(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, argMemberSource))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	target := coll.Programs["member_target"]
	params, err := attach.GetFuncParams(target, "sdf_classify")
	if err != nil {
		t.Fatal(err)
	}
	for _, exit := range []bool{false, true} {
		for _, name := range []string{"control", "null_filter", "fault_filter", "fault_echo"} {
			t.Run(fmt.Sprintf("exit=%v/%s", exit, name), func(t *testing.T) {
				// Echo only the integer n so echo cannot mask a failed filter.
				selected := []string{"n"}
				exprs := []string{"q->imsi!=2"}
				if name == "fault_echo" {
					selected, exprs = []string{"q->imsi"}, nil
				}
				echo, err := attach.ResolveEchoArgs(selected, params)
				if err != nil {
					t.Fatal(err)
				}
				fs, err := filter.ParseAndValidateFilters(exprs, params)
				if err != nil {
					t.Fatal(err)
				}
				ring, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: EchoRingSize})
				if err != nil {
					t.Fatal(err)
				}
				probe := &Probe{maps: []*ebpf.Map{ring}}
				defer func() { _ = probe.Close() }()
				insns := buildArgEchoInsns(ring.FD(), fs, echo)
				if name == "fault_filter" || name == "fault_echo" {
					injected := false
					for i, in := range insns {
						if in == asm.FnProbeReadKernel.Call() {
							// Force -EFAULT with a non-NULL unreadable address,
							// after the generated NULL check has already passed.
							insns = append(insns[:i], append(asm.Instructions{asm.Mov.Imm(asm.R3, 1)}, insns[i:]...)...)
							injected = true
							break
						}
					}
					if !injected {
						t.Fatal("missing member read")
					}
				}
				_, at := tracingLabel(exit)
				if err := attachTracingProbe(probe, target, "member_fault", "sdf_classify", at, insns, false, attach.FuncAvailability{}); err != nil {
					t.Fatal(err)
				}
				rd, err := fastrb.New(ring.FD(), EchoRingSize)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rd.Close() }()
				data := make([]byte, 64)
				if name == "null_filter" {
					data[0] = 1
				}
				if _, err := target.Run(&ebpf.RunOptions{Data: data}); err != nil {
					t.Fatal(err)
				}
				count := 0
				rd.ReadBatch(func(rec []byte) {
					count++
					if len(rec) != 8 || binary.NativeEndian.Uint64(rec) != 7 {
						t.Errorf("integer echo: %x", rec)
					}
				})
				want := 0
				if name == "control" {
					want = 1
				}
				if count != want {
					t.Fatalf("records=%d, want %d", count, want)
				}
			})
		}
	}
}
