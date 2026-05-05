// Package program — XDP-native attach path.
//
// Unlike the fentry/fexit modes (LoadEntry / LoadExit), this attach
// type makes xdp-ninja itself the XDP program on the netdev. Used
// when no XDP is already there and the user just wants packet capture
// without piggybacking on someone else's program.
//
// Key differences vs the tracing path:
//   - context is `struct xdp_md *` directly (R1), so packet pointers
//     come straight from ctx->data / ctx->data_end without the
//     scratch-buffer + bpf_probe_read_kernel detour the verifier
//     forces on tracing programs.
//   - we always return XDP_PASS; capture is the only side effect.
//     Drop / firewall mode is a future flag (out of scope for v1).
//   - no args[1] action atom (the program decides the action, it
//     doesn't observe one), so we pass codegen.Capabilities{}.
package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

const (
	// xdpModeNative is the metadata `mode` byte emitted by --mode xdp.
	// 0 = entry (fentry), 1 = exit (fexit), 2 = xdp-native.
	xdpModeNative uint8 = 2

	// xdpPass is the action value xdp-native always returns.
	xdpPass int32 = 2
)

// LoadXDPNative builds and attaches xdp-ninja as a native XDP program
// on the named interface. Matched packets are captured (always
// XDP_PASS); other packets pass through untouched. Empty filterExpr
// captures every packet.
//
// Caller is responsible for ensuring no XDP program is already
// attached (see attach.InspectInterface) before calling.
func LoadXDPNative(state *attach.InterfaceState, filterExpr string, useDSL bool) (*Probe, error) {
	// isFexit=false so kunai gets zero Capabilities — XDP-native has
	// no observed action atom (the program decides the action, doesn't
	// read one), same shape fentry uses.
	out, err := compileFilter(filterExpr, useDSL, false, ebpf.XDP)
	if err != nil {
		return nil, err
	}

	eventsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "ninja_xdp_pe", Type: ebpf.PerfEventArray,
	})
	if err != nil {
		return nil, fmt.Errorf("creating perf map: %w", err)
	}

	probe := &Probe{
		EventsMap: eventsMap,
		maps:      []*ebpf.Map{eventsMap},
	}

	insns := buildXDPNativeInsns(out, eventsMap.FD())
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "xdp_ninja_native",
		Type:         ebpf.XDP,
		Instructions: insns,
		License:      "GPL",
	})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("loading XDP program: %w", err)
	}
	probe.prog = prog

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: state.IfIndex,
	})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("attaching XDP: %w", err)
	}
	probe.link = l

	return probe, nil
}

// buildXDPNativeInsns assembles the XDP program: load packet pointers
// from xdp_md ctx, run the filter directly on packet memory, capture
// matched packets, return XDP_PASS.
//
// Stack layout (R10 negative offsets):
//
//	-8:  metadata: u32 action (= XDP_PASS)
//	-4:  metadata: u8 mode (= 2 = xdp-native)
//	-3:  metadata: u8 _pad
//	-2:  metadata: u16 _pad
//	[-56..-160-8N]: kunai-internal (arith spill, bpf_loop ctx, layer entry)
//
// Register usage (callee-saved across the program):
//
//	R6 = xdp_md ctx (saved for bpf_xdp_output)
//	R7 = data       (set in prologue, reused as packet start)
//	R8 = data_end
//	R9 = pkt_len
//
// Filter ABI inputs (host sets before each filter run):
//
//	R0 = packet start (= R7)
//	R1 = packet end   (= R8)
//	R9 = pkt_len      (set in prologue)
//
// The filter output lands at "filter_result" with R2 = 1 (match) or 0.
func buildXDPNativeInsns(filterOut codegen.Output, eventsFD int) asm.Instructions {
	var insns asm.Instructions
	insns = append(insns, loadXDPPacketPointers()...)
	insns = append(insns, runFilterDirect(filterOut.Main)...)
	insns = append(insns, captureXDPNative(eventsFD, filterOut.Capture.MaxCapLen)...)
	insns = append(insns,
		asm.Mov.Imm(asm.R0, xdpPass).WithSymbol("exit"),
		asm.Return(),
	)
	if len(filterOut.Callbacks) > 0 {
		insns[0] = btf.WithFuncMetadata(insns[0], codegen.MainFilterFuncBTF("xdp_ninja_filter"))
		insns = append(insns, filterOut.Callbacks...)
	}
	return insns
}

// loadXDPPacketPointers sets up R6=ctx, R7=data, R8=data_end, R9=pkt_len.
// xdp_md->data and ->data_end are u32 fields the verifier specially
// recognises — loaded as 4-byte values, treated as PTR_TO_PACKET.
func loadXDPPacketPointers() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),               // R6 = ctx (xdp_md *)
		asm.LoadMem(asm.R7, asm.R6, 0, asm.Word),  // R7 = ctx->data
		asm.LoadMem(asm.R8, asm.R6, 4, asm.Word),  // R8 = ctx->data_end
		asm.Mov.Reg(asm.R9, asm.R8),               // R9 = pkt_len
		asm.Sub.Reg(asm.R9, asm.R7),
	}
}

// runFilterDirect is the XDP-native counterpart of runFilter. The
// verifier accepts ctx->data / ctx->data_end as packet pointers, so we
// don't need the scratch-map detour the tracing path uses. The filter
// runs directly on packet memory.
func runFilterDirect(filter asm.Instructions) asm.Instructions {
	if len(filter) == 0 {
		return nil
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R0, asm.R7), // R0 = packet start
		asm.Mov.Reg(asm.R1, asm.R8), // R1 = packet end
	}
	insns = append(insns, filter...)
	insns = append(insns, asm.JEq.Imm(asm.R2, 0, "exit").WithSymbol("filter_result"))
	return insns
}

// captureXDPNative emits bpf_xdp_output(ctx, &events_map, ...) for the
// matched packet. Metadata is built on the stack; action is hardcoded
// to XDP_PASS (we always pass), mode is xdpModeNative.
func captureXDPNative(eventsFD int, maxCapLen int) asm.Instructions {
	if maxCapLen <= 0 {
		maxCapLen = defaultCapLen
	}

	insns := asm.Instructions{
		// metadata: action = XDP_PASS (=2), mode = 2 (xdp-native), pad = 0
		asm.StoreImm(asm.R10, -8, int64(xdpPass), asm.Word),
		asm.StoreImm(asm.R10, -4, int64(xdpModeNative), asm.Byte),
		asm.StoreImm(asm.R10, -3, 0, asm.Byte),
		asm.StoreImm(asm.R10, -2, 0, asm.Half),

		// bpf_xdp_output(ctx, &events_map, flags, &metadata, sizeof(metadata))
		asm.Mov.Reg(asm.R1, asm.R6),      // R1 = xdp_md ctx
		asm.LoadMapPtr(asm.R2, eventsFD), // R2 = perf event map

		// R3 = (cap_len << 32) | BPF_F_CURRENT_CPU
		asm.Mov.Reg(asm.R3, asm.R9), // R3 = pkt_len
		asm.JLE.Imm(asm.R3, int32(maxCapLen), "xdp_native_cap_ok"),
		asm.Mov.Imm(asm.R3, int32(maxCapLen)),
		asm.LSh.Imm(asm.R3, 32).WithSymbol("xdp_native_cap_ok"),
		asm.LoadImm(asm.R0, bpfFCurrentCPU, asm.DWord),
		asm.Or.Reg(asm.R3, asm.R0),

		asm.Mov.Reg(asm.R4, asm.R10),
		asm.Add.Imm(asm.R4, -int32(metadataSize)),
		asm.Mov.Imm(asm.R5, int32(metadataSize)),

		// bpf_perf_event_output for XDP context. The high 32 bits of
		// the flags arg (BPF_F_CTXLEN_MASK) tell the kernel to append
		// that many bytes of the packet (read from xdp_md->data) after
		// the user metadata. Same flag layout as bpf_xdp_output, but
		// FnPerfEventOutput is what the verifier permits for
		// BPF_PROG_TYPE_XDP.
		asm.FnPerfEventOutput.Call(),
	}
	return insns
}

