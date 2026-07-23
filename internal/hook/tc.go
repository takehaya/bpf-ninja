package hook

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	tchost "github.com/takehaya/bpf-ninja/pkg/kunai/host/tc"
)

var tcHook = &Hook{
	Kind:           KindTC,
	ProgTypes:      []ebpf.ProgramType{ebpf.SchedCLS, ebpf.SchedACT},
	PacketPrologue: skbPacketPrologue,
	// The tc host carries VlanInMetadata in both entry and fexit caps,
	// because the kernel strips the outer VLAN tag into skb metadata
	// before either attach point runs.
	EntryCaps: tchost.EntryCapabilities,
	FexitCaps: tchost.FexitCapabilities,
}

// skbPacketPrologue reads the packet window from a kernel
// struct sk_buff * (the kernel struct, NOT the BPF-rewritten __sk_buff
// view — that rewrite does not fire in tracing context). Member offsets
// drift across kernel versions, so they are resolved from kernel BTF at
// runtime. sk_buff has no data_end member; it is computed as data + len.
func skbPacketPrologue() (asm.Instructions, error) {
	dataOff, lenOff, err := skBuffPacketOffsets()
	if err != nil {
		return nil, fmt.Errorf("resolving struct sk_buff offsets via BTF: %w", err)
	}
	return append(tracingPrelude(),
		asm.LoadMem(asm.R7, asm.R6, int16(dataOff), asm.DWord), // R7 = skb->data
		asm.LoadMem(asm.R9, asm.R6, int16(lenOff), asm.Word),   // R9 = skb->len
		asm.Mov.Reg(asm.R8, asm.R7),
		asm.Add.Reg(asm.R8, asm.R9), // R8 = data + len
	), nil
}
