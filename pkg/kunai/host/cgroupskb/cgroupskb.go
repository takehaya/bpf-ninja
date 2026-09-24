// Package cgroupskb provides kunai host adapters for hosts attached as
// fentry / fexit on a cgroup-skb (BPF_PROG_TYPE_CGROUP_SKB) program.
// Importing this package is the canonical way to enable cgroup-skb
// specific DSL atoms (currently `where action == SK_DROP/SK_PASS`) in a
// kunai filter; the kunai core itself holds no cgroup knowledge — see
// pkg/kunai/codegen/caps.go for the Capabilities contract this package
// conforms to.
//
// A cgroup-skb program sees skb->data pointing at the NETWORK (L3)
// header — there is no Ethernet header in the packet window — so both
// capability sets carry HostLayout.PacketStartsAtL3 and DSL chains
// should root at ipv4/ipv6.
package cgroupskb

import (
	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// Actions matches the cgroup-skb filter verdicts (kernel SK_DROP /
// SK_PASS, include/linux/bpf.h). Egress programs may additionally
// return 2 or 3 (drop with congestion notification); those have no
// uapi symbol, so they are intentionally absent here and surface as
// unknown verdicts downstream.
var Actions = map[string]int32{
	"SK_DROP": 0,
	"SK_PASS": 1,
}

// FexitFetcher is the default adapter for a single-context-parameter entry
// function: the wrapper saves args at fp-48 and the return sits at args+8.
// Wrappers for arbitrary subfunctions must supply an ActionFetcher matching
// their target ABI. bpf-ninja overrides this with a canonical saved-return slot
// populated from each target's BTF prototype, so mixed arities can share filters.
func FexitFetcher() codegen.ActionFetcher { return fexitFetcher{} }

type fexitFetcher struct{}

func (fexitFetcher) EmitFetch(dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(dst, asm.R10, -48, asm.DWord),
		asm.LoadMem(dst, dst, 8, asm.Word),
	}
}

// FexitCapabilities returns the standard codegen.Capabilities for hosts
// attached as fexit on a cgroup-skb program. The Lang group carries the
// SK_* action atoms (parser label reservation is derived from
// Lang.Action by kunai.Compile). Host sets PacketStartsAtL3 (no
// Ethernet header in the window) and VlanInMetadata (with no L2 header
// there are no in-band VLAN tags to parse either).
func FexitCapabilities() codegen.Capabilities {
	return codegen.Capabilities{
		Lang: codegen.LangCaps{
			Action:        Actions,
			ActionFetcher: FexitFetcher(),
		},
		Host: hostLayout(),
	}
}

// EntryCapabilities returns the codegen.Capabilities for hosts attached
// as fentry on a cgroup-skb program. fentry has no verdict yet, so the
// Lang group stays empty; the packet-layout facts hold at both attach
// points.
func EntryCapabilities() codegen.Capabilities {
	return codegen.Capabilities{Host: hostLayout()}
}

func hostLayout() codegen.HostLayout {
	return codegen.HostLayout{
		VlanInMetadata:   true,
		PacketStartsAtL3: true,
	}
}
