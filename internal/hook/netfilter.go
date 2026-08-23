package hook

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/google/gopacket/layers"
	nfhost "github.com/takehaya/bpf-ninja/pkg/kunai/host/netfilter"
)

var netfilterHook = &Hook{
	Kind:      KindNetfilter,
	ProgTypes: []ebpf.ProgramType{ebpf.Netfilter},
	// A netfilter program (kernel 6.4+) receives `struct bpf_nf_ctx *`
	// at args[0] — not the sk_buff itself — so the prologue derefs
	// ctx->skb first and then reuses the shared sk_buff window loads.
	// The hook sits at the IP layer: skb->data points at the network
	// (L3) header, hence LinkTypeRaw and the L3-start capabilities.
	PacketPrologue: nfPacketPrologue,
	EntryCaps:      nfhost.EntryCapabilities,
	FexitCaps:      nfhost.FexitCapabilities,
	// Mirrors nfhost.Actions; consistency is asserted by
	// TestHookActionsMatchHostVocab. The verifier caps netfilter BPF
	// returns to NF_DROP/NF_ACCEPT, so the table is complete.
	Actions: []ActionName{
		{Value: 0, Name: "netfilter:NF_DROP"},
		{Value: 1, Name: "netfilter:NF_ACCEPT"},
	},
	LinkType: layers.LinkTypeRaw,
}

// nfPacketPrologue reads the packet window from a netfilter program's
// `struct bpf_nf_ctx` context: one extra pointer hop (ctx->skb, offset
// resolved from kernel BTF) in front of the same sk_buff window loads
// the tc and cgroup-skb hooks use. Like skbPacketPrologue the window
// is clamped to the linear head `len - data_len`; see that function
// for why. R6 keeps the original ctx per the PacketPrologue contract;
// R7 is the skb scratch (len and data_len are read before R7 is
// overwritten with skb->data).
func nfPacketPrologue() (asm.Instructions, error) {
	skbOff, err := nfCtxSkbOffset()
	if err != nil {
		return nil, fmt.Errorf("resolving struct bpf_nf_ctx offsets via BTF: %w", err)
	}
	dataOff, lenOff, dataLenOff, err := skBuffPacketOffsets()
	if err != nil {
		return nil, fmt.Errorf("resolving struct sk_buff offsets via BTF: %w", err)
	}
	return append(tracingPrelude(),
		asm.LoadMem(asm.R7, asm.R6, int16(skbOff), asm.DWord),    // R7 = ctx->skb
		asm.LoadMem(asm.R9, asm.R7, int16(lenOff), asm.Word),     // R9 = skb->len
		asm.LoadMem(asm.R8, asm.R7, int16(dataLenOff), asm.Word), // R8 = skb->data_len
		asm.Sub.Reg(asm.R9, asm.R8),                              // R9 = linear head length
		asm.LoadMem(asm.R7, asm.R7, int16(dataOff), asm.DWord),   // R7 = skb->data
		asm.Mov.Reg(asm.R8, asm.R7),
		asm.Add.Reg(asm.R8, asm.R9), // R8 = data + headlen
	), nil
}

// nfCtxSkbOffset returns the kernel BTF byte offset of
// `struct bpf_nf_ctx`'s `skb` member. The struct is two pointers today
// (state, skb) but the offset is resolved from BTF like the sk_buff
// members, so a future member insertion cannot silently skew the read.
// Cached at first call, same rationale as skBuffPacketOffsets.
func nfCtxSkbOffset() (uint32, error) {
	nfCtxOnce.Do(func() {
		spec, err := btf.LoadKernelSpec()
		if err != nil {
			nfCtxErr = fmt.Errorf("loading kernel BTF: %w", err)
			return
		}
		var ctx *btf.Struct
		if err := spec.TypeByName("bpf_nf_ctx", &ctx); err != nil {
			nfCtxErr = fmt.Errorf("BTF type bpf_nf_ctx not found (netfilter BPF needs kernel 6.4+): %w", err)
			return
		}
		for _, m := range ctx.Members {
			if m.Name == "skb" {
				nfCtxSkbOff = m.Offset.Bytes()
				return
			}
		}
		nfCtxErr = fmt.Errorf("BTF struct bpf_nf_ctx has no skb member")
	})
	return nfCtxSkbOff, nfCtxErr
}

var (
	nfCtxOnce   sync.Once
	nfCtxSkbOff uint32
	nfCtxErr    error
)
