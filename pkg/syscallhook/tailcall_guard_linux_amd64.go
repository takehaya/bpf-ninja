//go:build linux && amd64

package syscallhook

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

var errTailCallReachability = errors.New("native BPF_PROG_TEST_RUN fell through after a tail call from a subprogram")

func tailCallProbeFunc(name string, linkage btf.FuncLinkage) *btf.Func {
	return &btf.Func{Name: name, Linkage: linkage, Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24}}}},
	}}
}

// tailCallReachabilityProbeSpec has the native shape the guard detects. It is
// only executed with BPF_PROG_TEST_RUN and is never attached.
func tailCallReachabilityProbeSpec() *ebpf.CollectionSpec {
	entry := btf.WithFuncMetadata(asm.Call.Label("tail_sub").WithSymbol("probe_entry"), tailCallProbeFunc("probe_entry", btf.GlobalFunc))
	sub := tailCallProbeFunc("tail_sub", btf.StaticFunc)
	leaf := tailCallProbeFunc("fallthrough", btf.StaticFunc)
	insns := asm.Instructions{
		entry, asm.Return(),
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("tail_sub"), sub),
		asm.Mov.Reg(asm.R1, asm.R6), asm.LoadMapPtr(asm.R2, 0).WithReference("jmp"), asm.Mov.Imm(asm.R3, 0), asm.FnTailCall.Call(),
		asm.Mov.Reg(asm.R1, asm.R6), asm.Call.Label("fallthrough"), asm.Mov.Imm(asm.R0, 2), asm.Return(),
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("fallthrough"), leaf), asm.Return(),
	}
	target := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 3).WithSymbol("probe_target"), tailCallProbeFunc("probe_target", btf.GlobalFunc)),
		asm.Return(),
	}
	return &ebpf.CollectionSpec{ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{"jmp": {Name: "tail_probe_jmp", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1,
			Contents: []ebpf.MapKV{{Key: uint32(0), Value: "target"}}}},
		Programs: map[string]*ebpf.ProgramSpec{
			"caller": {Name: "tail_probe", Type: ebpf.XDP, License: "GPL", Instructions: insns},
			"target": {Name: "tail_target", Type: ebpf.XDP, License: "GPL", Instructions: target},
		},
	}
}

func probeTailCallReachability() error {
	coll, err := ebpf.NewCollection(tailCallReachabilityProbeSpec())
	if err != nil {
		return fmt.Errorf("load native tail-call reachability probe: %w", err)
	}
	defer coll.Close()
	action, err := coll.Programs["caller"].Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1})
	if err != nil {
		return fmt.Errorf("run native tail-call reachability probe: %w", err)
	}
	switch action {
	case 3:
		return nil
	case 2:
		return errTailCallReachability
	default:
		return fmt.Errorf("native tail-call reachability probe returned unexpected action %d", action)
	}
}
