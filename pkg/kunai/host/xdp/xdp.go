// Package xdp provides kunai host adapters for hosts attached as
// fentry / fexit on an XDP program. Importing this package is the
// canonical way to enable XDP-specific DSL atoms (currently
// `where action == XDP_*`) in a kunai filter; the kunai core itself
// holds no XDP knowledge — see pkg/kunai/codegen/caps.go for the
// Capabilities contract this package conforms to.
//
// Future XDP-specific helpers (e.g. packet-resize hooks for
// bpf_xdp_adjust_head / bpf_xdp_adjust_tail) belong here as well so
// the kunai compiler stays target-agnostic and host knowledge stays
// concentrated in one place.
package xdp

import (
	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

// Actions matches the XDP return values defined in
// uapi/linux/bpf.h. It is the symbolic-name → integer map a host
// passes to kunai so DSL expressions like `where action == XDP_DROP`
// resolve correctly.
var Actions = map[string]int32{
	"XDP_ABORTED":  0,
	"XDP_DROP":     1,
	"XDP_PASS":     2,
	"XDP_TX":       3,
	"XDP_REDIRECT": 4,
}

// FexitFetcher returns a codegen.ActionFetcher for hosts attached as
// fexit on an XDP program. It assumes the host wrapper saved the BPF
// tracing args pointer at stack[-48] at program entry and that
// args[1] is the XDP retval slot — both invariants are met by the
// xdp-ninja host program (see internal/program/program.go).
//
// Different host wrappers with a different stack ABI should provide
// their own fetcher rather than reusing this one.
func FexitFetcher() codegen.ActionFetcher { return fexitFetcher{} }

type fexitFetcher struct{}

func (fexitFetcher) EmitFetch(dst asm.Register) asm.Instructions {
	return asm.Instructions{
		// Saved tracing args pointer (host wrapper stashed it at
		// stack[-48] at program entry).
		asm.LoadMem(dst, asm.R10, -48, asm.DWord),
		// args[1] is the XDP return value (u32 sitting at args+8 in
		// the BPF tracing args ABI).
		asm.LoadMem(dst, dst, 8, asm.Word),
	}
}

// FexitCapabilities returns the standard codegen.Capabilities for
// hosts attached as fexit on an XDP program. Only the Lang group is
// populated; the parser-side reservation of "XDP_*" labels is derived
// automatically from Lang.Action by kunai.Compile, and XDP keeps VLAN
// in-band so Host stays zero.
func FexitCapabilities() codegen.Capabilities {
	return codegen.Capabilities{
		Lang: codegen.LangCaps{
			Action:        Actions,
			ActionFetcher: FexitFetcher(),
		},
	}
}
