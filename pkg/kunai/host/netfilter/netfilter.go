// Package netfilter provides kunai host adapters for hosts attached as
// fentry / fexit on a netfilter (BPF_PROG_TYPE_NETFILTER, kernel 6.4+)
// program. Importing this package is the canonical way to enable
// netfilter specific DSL atoms (currently `where action == NF_DROP`
// and `where action == NF_ACCEPT`) in a kunai filter; the kunai core itself holds no
// netfilter knowledge — see pkg/kunai/codegen/caps.go for the
// Capabilities contract this package conforms to.
//
// A netfilter program hooks the IP layer (NF_INET_* hook points), so
// the packet window starts at the NETWORK (L3) header — there is no
// Ethernet header — and both capability sets carry
// HostLayout.PacketStartsAtL3. DSL chains should root at ipv4/ipv6.
package netfilter

import (
	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// Actions matches the verdicts a netfilter BPF program may return.
// The kernel verifier restricts the return value to NF_DROP (0) and
// NF_ACCEPT (1) (net/netfilter/nf_bpf_link.c); the other classic
// NF_* verdicts (STOLEN / QUEUE / REPEAT) are rejected at load time
// and therefore never observable, so they are intentionally absent.
var Actions = map[string]int32{
	"NF_DROP":   0,
	"NF_ACCEPT": 1,
}

// FexitFetcher returns a codegen.ActionFetcher for hosts attached as
// fexit on a netfilter program. It assumes the host wrapper saved the
// BPF tracing args pointer at stack[-48] at program entry and that
// args[1] is the verdict slot — the same tracing-args ABI as the xdp,
// tc, and cgroup-skb fetchers, met by the bpf-ninja host program (see
// internal/program/program.go).
//
// Different host wrappers with a different stack ABI should provide
// their own fetcher rather than reusing this one.
func FexitFetcher() codegen.ActionFetcher { return fexitFetcher{} }

type fexitFetcher struct{}

func (fexitFetcher) EmitFetch(dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(dst, asm.R10, -48, asm.DWord),
		asm.LoadMem(dst, dst, 8, asm.Word),
	}
}

// FexitCapabilities returns the standard codegen.Capabilities for hosts
// attached as fexit on a netfilter program. The Lang group carries the
// NF_* action atoms; Host sets PacketStartsAtL3 (no Ethernet header in
// the window) and VlanInMetadata (with no L2 header there are no
// in-band VLAN tags to parse either).
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
// as fentry on a netfilter program. fentry has no verdict yet, so the
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
