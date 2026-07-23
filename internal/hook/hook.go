// Package hook is the registry of BPF attach-target kinds bpf-ninja can
// trace. Each supported kind (XDP, tc clsact, ...) is described once by a
// Hook value: which ebpf.ProgramType(s) it covers, how the tracing
// prologue reads the packet window out of the target's context, and which
// kunai host capabilities apply at fentry/fexit. Callers look hooks up by
// program type (auto-detection from a target program) or by name, instead
// of switching on ebpf.ProgramType at every site.
package hook

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// Kind names a hook in CLI/docs-facing contexts.
type Kind string

const (
	KindXDP Kind = "xdp"
	KindTC  Kind = "tc"
)

// Hook describes one attach-target kind.
type Hook struct {
	Kind Kind

	// ProgTypes is the set of ebpf.ProgramType values this hook covers
	// (tc clsact spans SchedCLS and SchedACT).
	ProgTypes []ebpf.ProgramType

	// PacketPrologue emits the tracing-program prelude that loads the
	// packet window from the target's context. Contract on exit:
	// R6=ctx, R7=data, R8=data_end, R9=pkt_len, stack[-48]=args ptr.
	PacketPrologue func() (asm.Instructions, error)

	// EntryCaps / FexitCaps are the kunai host capabilities for fentry
	// and fexit compiles respectively (action atoms, packet layout).
	EntryCaps func() codegen.Capabilities
	FexitCaps func() codegen.Capabilities
}

// registry lists all supported hooks. Order defines the wording of
// SupportedLabel (and therefore user-facing error messages).
var registry = []*Hook{xdpHook, tcHook}

// ByProgramType finds the hook covering pt. The single lookup replaces
// the per-site `pt == XDP || pt == SchedCLS || ...` supported-type checks.
func ByProgramType(pt ebpf.ProgramType) (*Hook, bool) {
	for _, h := range registry {
		for _, t := range h.ProgTypes {
			if t == pt {
				return h, true
			}
		}
	}
	return nil, false
}

// ByName finds a hook by its Kind name.
func ByName(name Kind) (*Hook, bool) {
	for _, h := range registry {
		if h.Kind == name {
			return h, true
		}
	}
	return nil, false
}

// SupportedLabel renders the supported program types for error messages,
// e.g. "XDP, SchedCLS, or SchedACT".
func SupportedLabel() string {
	var names []string
	for _, h := range registry {
		for _, t := range h.ProgTypes {
			names = append(names, t.String())
		}
	}
	if len(names) <= 1 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + ", or " + names[len(names)-1]
}

// UnsupportedTypeError is the shared error shape for a target program
// whose type no hook covers.
func UnsupportedTypeError(pt ebpf.ProgramType) error {
	return fmt.Errorf("target program type %s is not supported (need %s)", pt, SupportedLabel())
}

// tracingPrelude is the hook-independent head of every PacketPrologue:
// save the tracing args pointer at stack[-48] (fexit action lookup, arg
// filters) and load args[0] — the host-specific packet ctx — into R6.
func tracingPrelude() asm.Instructions {
	return asm.Instructions{
		asm.StoreMem(asm.R10, -48, asm.R1, asm.DWord),
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
	}
}
