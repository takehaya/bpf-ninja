package program

import (
	"fmt"
	"io"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/xdp-ninja/internal/filter"
	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

// DumpScope selects how much of the eBPF program DumpAsm renders.
type DumpScope string

const (
	// DumpScopeFilter renders just the kunai/cbpfc filter output —
	// Main + Callbacks + CaptureInfo. Useful for hand-testing a DSL
	// or tcpdump expression in isolation; nothing about the surrounding
	// xdp-ninja wrapper is shown.
	DumpScopeFilter DumpScope = "filter"

	// DumpScopeFull renders the full tracing program that loadProbe
	// would have built (loadPacketPointers + filter + bpf_xdp_output
	// + Return), with map FDs left at 0 since nothing is loaded.
	DumpScopeFull DumpScope = "full"
)

// DumpAsm compiles a filter expression and writes the resulting eBPF
// instructions to w in human-readable form. Nothing is loaded.
//
// scope picks between filter-only ("filter") and the wrapped program
// ("full"). mode picks the wrapper shape: "entry"/"exit" for the
// fentry/fexit tracing wrapper, "xdp" for the XDP-native wrapper.
// Mode is ignored when scope == DumpScopeFilter except that it
// drives the Capabilities passed to the kunai compile (exit enables
// the action atom).
func DumpAsm(w io.Writer, scope DumpScope, expr string, useDSL bool, mode string) error {
	if expr == "" {
		return fmt.Errorf("--dump-asm requires a filter expression")
	}

	isFexit := mode == "exit"
	isXDPNative := mode == "xdp"

	// xdp-native uses zero Capabilities (no observed action atom),
	// same shape as fentry — compileFilter(_, _, false) covers both.
	out, err := compileFilter(expr, useDSL, isFexit, ebpf.XDP)
	if err != nil {
		return err
	}

	var buf strings.Builder
	switch scope {
	case DumpScopeFilter, "":
		renderFilter(&buf, out, useDSL, mode)
	case DumpScopeFull:
		if err := renderFull(&buf, out, mode, isFexit, isXDPNative); err != nil {
			return err
		}
	default:
		return fmt.Errorf("--dump-asm: unknown scope %q (expected: filter | full)", scope)
	}

	_, err = io.WriteString(w, buf.String())
	return err
}

func renderFilter(buf *strings.Builder, out codegen.Output, useDSL bool, mode string) {
	syntax := "tcpdump → cBPF → eBPF (cbpfc)"
	if useDSL {
		syntax = "DSL → eBPF (kunai)"
	}

	fmt.Fprintf(buf, "=== Filter (%s, mode=%s) ===\n\n", syntax, mode)

	buf.WriteString("=== Main (R0=pkt_start, R1=pkt_end → R2=accept/reject @ filter_result) ===\n")
	if len(out.Main) == 0 {
		buf.WriteString("  (empty)\n")
	} else {
		fmt.Fprintln(buf, out.Main)
	}

	buf.WriteString("=== Callbacks (bpf2bpf subprograms for bpf_loop) ===\n")
	if len(out.Callbacks) == 0 {
		buf.WriteString("  (none)\n")
	} else {
		fmt.Fprintln(buf, out.Callbacks)
	}

	buf.WriteString("=== CaptureInfo ===\n")
	if out.Capture.MaxCapLen == 0 {
		fmt.Fprintf(buf, "  MaxCapLen: 0 (caller default — typically %d)\n", defaultCapLen)
	} else {
		fmt.Fprintf(buf, "  MaxCapLen: %d\n", out.Capture.MaxCapLen)
	}
}

func renderFull(buf *strings.Builder, out codegen.Output, mode string, isFexit, isXDPNative bool) error {
	var (
		insns asm.Instructions
		shape string
	)
	if isXDPNative {
		insns = buildXDPNativeInsns(out, 0, nil)
		shape = "XDP-native program"
	} else {
		var err error
		insns, err = buildTracingInsns(out, filter.TargetFilters{}, 0, 0, isFexit, ebpf.XDP, nil, nil)
		if err != nil {
			return err
		}
		shape = "tracing program"
	}

	fmt.Fprintf(buf, "=== Full %s (mode=%s, target=<not-resolved>, map FDs=0 placeholder) ===\n\n", shape, mode)
	fmt.Fprintln(buf, insns)
	return nil
}
