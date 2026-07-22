// Package program — XDP-native attach path.
//
// Unlike the fentry/fexit modes (LoadEntry / LoadExit), this attach
// type makes bpf-ninja itself the XDP program on the netdev. Used
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
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// XDPNativeBenchDrop toggles the --mode xdp action: when true, captured
// packets return XDP_DROP instead of XDP_PASS, bypassing the kernel
// skb-create / IP-layer-drop path. Useful for benchmarks where that
// path becomes the dominant per-packet cost (microburst stress).
// Production deployments should leave this false.
var XDPNativeBenchDrop bool

const (
	// xdpModeNative is the metadata `mode` byte emitted by --mode xdp.
	// 0 = entry (fentry), 1 = exit (fexit), 2 = xdp-native.
	xdpModeNative uint8 = 2

	// xdpPass is the action value xdp-native returns for captured packets
	// in production mode. Override via XDPNativeBenchDrop for benchmark
	// scenarios where the kernel-side netif drop path (skb create + IP
	// layer drop) becomes the bottleneck.
	xdpPass int32 = 2
	xdpDrop int32 = 1
)

// LoadXDPNative builds and attaches bpf-ninja as a native XDP program
// on the named interface. Matched packets are captured (always
// XDP_PASS); other packets pass through untouched. Empty filterExpr
// captures every packet.
//
// Caller is responsible for ensuring no XDP program is already
// attached (see attach.InspectInterface) before calling.
func LoadXDPNative(state *attach.InterfaceState, filterExpr string, useDSL bool, sets []*setmap.Set) (*Probe, error) {
	// isFexit=false so kunai gets zero Capabilities — XDP-native has
	// no observed action atom (the program decides the action, doesn't
	// read one), same shape fentry uses.
	var slots *pktSetSlots
	if len(sets) > 0 {
		slots = newPktSetSlots(sets)
	}
	out, err := compileFilterWithSlots(filterExpr, useDSL, false, ebpf.XDP, slots)
	if slots != nil && slots.allocErr() != nil {
		return nil, slots.allocErr()
	}
	if err != nil {
		return nil, err
	}
	if SnaplenOverride > 0 {
		out.Capture.MaxCapLen = SnaplenOverride
	}

	outerMap, innerMaps, err := createShardedRingbuf("xdp")
	if err != nil {
		return nil, err
	}
	probe := &Probe{
		Warnings:  out.Warnings,
		EventsMap: outerMap,
		InnerMaps: innerMaps,
		maps:      append([]*ebpf.Map{outerMap}, innerMaps...),
	}

	insns := buildXDPNativeInsns(out, outerMap.FD(), slots)
	spec := &ebpf.ProgramSpec{
		Name:         "bpf_ninja_native",
		Type:         ebpf.XDP,
		Instructions: insns,
		License:      "GPL",
	}
	if HWTimestampKfuncID != 0 {
		// xdp_metadata kfuncs require the program to be device-bound:
		// the verifier needs to know which driver implements the
		// metadata ops. BPF_F_XDP_DEV_BOUND_ONLY (= 1<<6) binds the
		// program to state.IfIndex without auto-attaching as XDP.
		spec.Ifindex = uint32(state.IfIndex)
		spec.Flags |= 1 << 6
	}
	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("loading XDP program: %w", err)
	}
	probe.progs = append(probe.progs, prog)

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: state.IfIndex,
	})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("attaching XDP: %w", err)
	}
	probe.links = append(probe.links, l)

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
func buildXDPNativeInsns(filterOut codegen.Output, eventsFD int, slots *pktSetSlots) asm.Instructions {
	var insns asm.Instructions
	insns = append(insns, loadXDPPacketPointers()...)
	// Default the tag to 0 before any set lookup can overwrite it, so a
	// captured packet that matched no set (or a set-less filter) reports 0.
	insns = append(insns, emitTagSlotZero()...)
	// DSL `field in @set`: zero the key buffer, let the filter extract the
	// packet fields into it, then look each referenced set up (miss →
	// skip capture). ANDs with the kunai verdict runFilterDirect produced.
	refs := referencedSets(filterOut.Extractions)
	if slots != nil {
		insns = append(insns, slots.emitPktSetKeyZeroing(refs)...)
	}
	insns = append(insns, runFilterDirect(filterOut.Main)...)
	if slots != nil {
		insns = append(insns, slots.emitPktSetLookups(refs)...)
	}
	insns = append(insns, captureXDPNative(eventsFD, filterOut.Capture.MaxCapLen)...)
	finalAction := xdpPass
	if XDPNativeBenchDrop {
		finalAction = xdpDrop
	}
	insns = append(insns,
		asm.Mov.Imm(asm.R0, finalAction).WithSymbol("exit"),
		asm.Return(),
	)
	if len(filterOut.Callbacks) > 0 {
		insns[0] = btf.WithFuncMetadata(insns[0], codegen.MainFilterFuncBTF("bpf_ninja_filter"))
		insns = append(insns, filterOut.Callbacks...)
	}
	return insns
}

// loadXDPPacketPointers sets up R6=ctx, R7=data, R8=data_end, R9=pkt_len.
// xdp_md->data and ->data_end are u32 fields the verifier specially
// recognises — loaded as 4-byte values, treated as PTR_TO_PACKET.
func loadXDPPacketPointers() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),              // R6 = ctx (xdp_md *)
		asm.LoadMem(asm.R7, asm.R6, 0, asm.Word), // R7 = ctx->data
		asm.LoadMem(asm.R8, asm.R6, 4, asm.Word), // R8 = ctx->data_end
		asm.Mov.Reg(asm.R9, asm.R8),              // R9 = pkt_len
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

// captureXDPNative is the XDP-native capture epilogue, mirror of
// captureWithRingbuf (tracing): bpf_ringbuf_reserve a fixed-size slot,
// write metadata + bounded packet copy directly into the slot, then
// bpf_ringbuf_submit. No staging map.
//
// On-wire RawSample is the full reservation
// (metadataSize + maxCapLen bytes); the metadata's u16 caplen field
// tells userspace how many of the trailing payload bytes are real.
// XDP-native always reports action = XDP_PASS (= 2) and mode = 2.
//
// Metadata layout matches capture.MetadataSize (20 B) — see
// internal/capture/capture.go for the wire format.
//
// Local stack slots used here (R10 negative offsets):
//
//	-8:  u64 tag slot (low 32 bits = set-map value, 0 if none)
//	-16: u32 cpu_id (scratch for outer-map lookup)
//	-32: reserved-slot ptr (PTR_TO_MEM, mem_size = metadataSize + maxCapLen)
//	-40: u32 saved copy_size
//	-48: u64 kernel_ts_ns (saved bpf_ktime_get_ns return)
func captureXDPNative(eventsFD int, maxCapLen int) asm.Instructions {
	if maxCapLen <= 0 {
		maxCapLen = defaultCapLen
	}
	reserveSize := int32(metadataSize + maxCapLen)

	var insns asm.Instructions
	// Timestamp prologue: hardware (NIC PHC via kfunc) if enabled and
	// available, otherwise software bpf_ktime_get_ns(). Both branches
	// leave the timestamp at stack[-48]; the smp_processor_id epilogue
	// is shared.
	if HWTimestampKfuncID != 0 {
		insns = append(insns,
			// bpf_xdp_metadata_rx_timestamp(ctx=R6, &stack[-48])
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -48),
			emitKfuncCall(HWTimestampKfuncID),
			// R0 == 0 means the kfunc wrote a valid HW ts to
			// stack[-48]; non-zero (typically -EOPNOTSUPP) falls
			// through to software ktime.
			asm.JEq.Imm(asm.R0, 0, "ts_ok"),
			asm.FnKtimeGetNs.Call(),
			asm.StoreMem(asm.R10, -48, asm.R0, asm.DWord),
			asm.FnGetSmpProcessorId.Call().WithSymbol("ts_ok"),
			asm.StoreMem(asm.R10, -16, asm.R0, asm.Word),
		)
	} else {
		insns = append(insns,
			asm.FnKtimeGetNs.Call(),
			asm.StoreMem(asm.R10, -48, asm.R0, asm.DWord),
			asm.FnGetSmpProcessorId.Call(),
			asm.StoreMem(asm.R10, -16, asm.R0, asm.Word),
		)
	}
	insns = append(insns, emitShardedRBReserve(eventsFD, reserveSize)...)
	insns = append(insns, asm.Instructions{

		// --- Write kernel_ts_ns into slot[0..8] ---
		asm.LoadMem(asm.R1, asm.R10, -48, asm.DWord),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),

		// --- Write action/mode/pad into slot[8..14] (caplen 14, tag 16 later) ---
		asm.StoreImm(asm.R0, 8, int64(xdpPass), asm.Word),
		asm.StoreImm(asm.R0, 12, int64(xdpModeNative), asm.Byte),
		asm.StoreImm(asm.R0, 13, 0, asm.Byte),
	}...)

	insns = append(insns, asm.Instructions{
		// --- copy_size = min(pkt_len, maxCapLen) → metadata caplen ---
		// pkt_len here is the LINEAR-region length (R9 = data_end -
		// data); multi-buff frag total is not accessible without a
		// working bpf_xdp_get_buff_len kfunc invocation, deferred as
		// future work.
		asm.Mov.Reg(asm.R3, asm.R9),
		asm.JLE.Imm(asm.R3, int32(maxCapLen), "xn_cap_ok"),
		asm.Mov.Imm(asm.R3, int32(maxCapLen)),
		asm.StoreMem(asm.R0, 14, asm.R3, asm.Half).WithSymbol("xn_cap_ok"),

		// --- Write tag metadata into slot[16..20] (0 unless a set matched) ---
		// Before the copy-skip guard below so a zero-length packet still
		// carries its tag. tagSlot is 8 bytes; the low 32 go into the field.
		asm.LoadMem(asm.R1, asm.R10, tagSlot, asm.DWord),
		asm.StoreMem(asm.R0, 16, asm.R1, asm.Word),

		// --- bpf_xdp_load_bytes(ctx, 0, R0+20, copy_size) ---
		// XDP-aware bounded read; dst = slot + metadataSize (= 20).
		// Helper requires Linux 5.18+, which our verifier matrix
		// (6.1+) satisfies.
		//
		// Verifier-friendly ordering (verified on 6.1 / 6.6 / 6.12
		// / 6.18): the JLT < 1 guard runs first so the umin=1
		// constraint applies to R3 directly; R4 is then mov'd from
		// R3 BEFORE R3 is clobbered to become the dst pointer. A
		// stack roundtrip would drop umin=1 across the reload,
		// which 6.1 / 6.6 reject as "R4 invalid zero-sized read".
		asm.JLT.Imm(asm.R3, 1, "xn_skip_load"),
		asm.Mov.Reg(asm.R1, asm.R6),                                           // ctx
		asm.Mov.Imm(asm.R2, 0),                                                // offset
		asm.Mov.Reg(asm.R4, asm.R3),                                           // copy_size (umin=1)
		asm.Mov.Reg(asm.R3, asm.R0), asm.Add.Imm(asm.R3, int32(metadataSize)), // dst = slot+20
		asm.FnXdpLoadBytes.Call(),

		// --- bpf_ringbuf_submit(reservation_ptr, flags) ---
		asm.LoadMem(asm.R1, asm.R10, -32, asm.DWord).WithSymbol("xn_skip_load"),
		asm.Mov.Imm(asm.R2, int32(RingbufSubmitFlags)),
		asm.FnRingbufSubmit.Call(),
	}...)
	return insns
}
