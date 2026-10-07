package hook

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/google/gopacket/layers"
	tchost "github.com/takehaya/bpf-ninja/pkg/kunai/host/tc"
)

var tcHook = &Hook{
	Kind:           KindTC,
	ProgTypes:      []ebpf.ProgramType{ebpf.SchedCLS, ebpf.SchedACT},
	PacketPrologue: skbPacketPrologue,
	OuterVlanTag:   skbOuterVlanTag,
	Identity:       skbIdentity,
	// The kernel strips the outer VLAN tag into skb metadata before
	// either attach point runs; OuterVlanTag puts it back into the
	// filter's copy, so the filter parses the wire frame.
	EntryCaps: tchost.WireEntryCapabilities,
	FexitCaps: tchost.WireFexitCapabilities,
	// Mirrors tchost.Actions (uapi/linux/pkt_cls.h); consistency is
	// asserted by TestHookActionsMatchHostVocab.
	Actions: []ActionName{
		{Value: uint32(0xffffffff), Name: "tc:TC_ACT_UNSPEC"}, // -1
		{Value: 0, Name: "tc:TC_ACT_OK"},
		{Value: 1, Name: "tc:TC_ACT_RECLASSIFY"},
		{Value: 2, Name: "tc:TC_ACT_SHOT"},
		{Value: 3, Name: "tc:TC_ACT_PIPE"},
		{Value: 4, Name: "tc:TC_ACT_STOLEN"},
		{Value: 5, Name: "tc:TC_ACT_QUEUED"},
		{Value: 6, Name: "tc:TC_ACT_REPEAT"},
		{Value: 7, Name: "tc:TC_ACT_REDIRECT"},
		{Value: 8, Name: "tc:TC_ACT_TRAP"},
	},
	LinkType: layers.LinkTypeEthernet,
}

// skbIdentity uses the sk_buff pointer itself (R6 = ctx): the object
// is not replaced while the program runs, so it pairs the entry and
// exit records of one invocation. (skb->head is not used here because
// bpf_skb_adjust_room and friends can reallocate it mid-program.)
func skbIdentity(dst asm.Register) (asm.Instructions, error) {
	return asm.Instructions{asm.Mov.Reg(dst, asm.R6)}, nil
}

// skbPacketPrologue reads the packet window from a kernel
// struct sk_buff * (the kernel struct, NOT the BPF-rewritten __sk_buff
// view — that rewrite does not fire in tracing context). Member offsets
// drift across kernel versions, so they are resolved from kernel BTF at
// runtime. sk_buff has no data_end member; it is computed as data plus
// the LINEAR head length `len - data_len` (skb_headlen()), not the
// total `len`: a GRO/GSO or fragmented skb keeps `data_len` bytes in
// frags, and a flat probe_read from `data` past the head would copy
// unrelated kernel memory into the capture. The window (and therefore
// caplen) is clamped to the head; frag bytes are not captured.
func skbPacketPrologue() (asm.Instructions, error) {
	dataOff, lenOff, dataLenOff, err := skBuffPacketOffsets()
	if err != nil {
		return nil, fmt.Errorf("resolving struct sk_buff offsets via BTF: %w", err)
	}
	return append(tracingPrelude(),
		asm.LoadMem(asm.R7, asm.R6, int16(dataOff), asm.DWord),   // R7 = skb->data
		asm.LoadMem(asm.R9, asm.R6, int16(lenOff), asm.Word),     // R9 = skb->len
		asm.LoadMem(asm.R8, asm.R6, int16(dataLenOff), asm.Word), // R8 = skb->data_len
		asm.Sub.Reg(asm.R9, asm.R8),                              // R9 = linear head length
		asm.Mov.Reg(asm.R8, asm.R7),
		asm.Add.Reg(asm.R8, asm.R9), // R8 = data + headlen
	), nil
}

// skbOuterVlanTag loads the outer VLAN tag from struct sk_buff (R6):
// R2 = vlan_proto as stored (network order), R3 = vlan_tci. A kernel
// with the vlan_present bit reports no tag (R2 = 0) when it is clear,
// because proto and tci may then be stale.
func skbOuterVlanTag() (asm.Instructions, error) {
	v, err := skBuffVlanOffsets()
	if err != nil {
		return nil, fmt.Errorf("resolving struct sk_buff VLAN members via BTF: %w", err)
	}
	insns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R6, int16(v.proto), asm.Half),
		asm.LoadMem(asm.R3, asm.R6, int16(v.tci), asm.Half),
	}
	if v.hasPresent {
		insns = append(insns,
			asm.LoadMem(asm.R1, asm.R6, int16(v.presentByte), asm.Byte),
			asm.JSet.Imm(asm.R1, int32(1)<<v.presentBit, "vlan_tag_present"),
			asm.Mov.Imm(asm.R2, 0),
			asm.Mov.Reg(asm.R1, asm.R1).WithSymbol("vlan_tag_present"),
		)
	}
	return insns, nil
}
