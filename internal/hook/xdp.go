package hook

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	xdphost "github.com/takehaya/bpf-ninja/pkg/kunai/host/xdp"
)

var xdpHook = &Hook{
	Kind:           KindXDP,
	ProgTypes:      []ebpf.ProgramType{ebpf.XDP},
	PacketPrologue: xdpPacketPrologue,
	// XDP entry keeps zero caps: no action value yet, and VLAN is
	// in-band at XDP so no layout flags apply either.
	EntryCaps: func() codegen.Capabilities { return codegen.Capabilities{} },
	FexitCaps: xdphost.FexitCapabilities,
	Identity:  xdpIdentity,
	// Interface names predate the registry ("xdp:DROP", not
	// "xdp:XDP_DROP") — kept for pcap-consumer compatibility.
	Actions: []ActionName{
		{Value: 0, Name: "xdp:ABORTED"},
		{Value: 1, Name: "xdp:DROP"},
		{Value: 2, Name: "xdp:PASS"},
		{Value: 3, Name: "xdp:TX"},
		{Value: 4, Name: "xdp:REDIRECT"},
	},
	LinkType: layers.LinkTypeEthernet,
}

// xdpIdentity loads xdp_buff->data_hard_start (offset 24: data,
// data_end, data_meta, data_hard_start — ABI-stable). It is the start
// of the frame buffer, invariant across bpf_xdp_adjust_head/tail, and
// for native XDP_PASS it becomes skb->head of the resulting skb.
func xdpIdentity(dst asm.Register) (asm.Instructions, error) {
	return asm.Instructions{asm.LoadMem(dst, asm.R6, 24, asm.DWord)}, nil
}

// xdpPacketPrologue reads the packet window from a kernel
// struct xdp_buff *: data @ +0, data_end @ +8 (both 8B pointers,
// ABI-stable so the offsets are hardcoded).
func xdpPacketPrologue() (asm.Instructions, error) {
	return append(tracingPrelude(),
		asm.LoadMem(asm.R7, asm.R6, 0, asm.DWord),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),
		asm.Mov.Reg(asm.R9, asm.R8),
		asm.Sub.Reg(asm.R9, asm.R7),
	), nil
}
