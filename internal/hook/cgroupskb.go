package hook

import (
	"github.com/cilium/ebpf"
	"github.com/google/gopacket/layers"
	cgskbhost "github.com/takehaya/bpf-ninja/pkg/kunai/host/cgroupskb"
)

var cgroupSKBHook = &Hook{
	Kind:      KindCgroupSKB,
	ProgTypes: []ebpf.ProgramType{ebpf.CGroupSKB},
	// fentry/fexit on a cgroup-skb program sees the same kernel
	// struct sk_buff * at args[0] as tc, so the skb prologue is shared.
	// The packet window differs though: skb->data points at the
	// network (L3) header — no Ethernet framing — hence LinkTypeRaw
	// and the L3-start host capabilities.
	PacketPrologue: skbPacketPrologue,
	EntryCaps:      cgskbhost.EntryCapabilities,
	FexitCaps:      cgskbhost.FexitCapabilities,
	// Mirrors cgskbhost.Actions; consistency is asserted by
	// TestHookActionsMatchHostVocab. Egress verdicts 2/3 (drop with
	// congestion notification) have no uapi symbol and land on the
	// lazily-added UNKNOWN interface.
	Actions: []ActionName{
		{Value: 0, Name: "cgroup-skb:SK_DROP"},
		{Value: 1, Name: "cgroup-skb:SK_PASS"},
	},
	LinkType: layers.LinkTypeRaw,
}
