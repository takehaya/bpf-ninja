package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// Gated (entry + exit) capture.
//
// With two stages a packet is captured only if it matches the entry
// filter as the program received it AND the exit filter (packet as the
// program left it, plus the verdict). The entry bytes must therefore be
// kept until the verdict is known: the fentry program copies them into a
// per-CPU "hold" slot instead of emitting them, and the fexit program
// decides. Nothing is written into the packet.
//
// Why a plain per-CPU slot is enough (no id, no lock): on a non-RT
// kernel a driver's NAPI poll runs the XDP program for one packet to
// completion — fentry(N), program, fexit(N) — with bottom halves off,
// BPF programs cannot sleep, and the trampoline runs both probes on the
// same CPU. So whatever fexit(N) finds in this CPU's slot was written by
// fentry(N), unless fentry(N) did not match and the slot still holds an
// older packet. That is why fexit always clears `valid` first (consume),
// and additionally checks that the slot's frame identity equals the
// current invocation's. PREEMPT_RT with CONFIG_PREEMPT_RT_NEEDS_BH_LOCK
// off is out of scope (a higher-priority NAPI thread can interleave).
//
// Hold slot layout (per-CPU array, one entry):
//
//	 0  u64 ts_ns    entry timestamp (becomes the entry record's timestamp)
//	 8  u64 frame    hook identity at entry (sanity-checked at exit)
//	16  u32 pkt_len
//	20  u16 caplen   bytes actually copied
//	22  u16 valid    1 = written by the fentry of an invocation whose fexit
//	                 has not consumed it yet
//	24  u32 tag      set-map value
//	28  u32 _pad
//	32  u8  bytes[maxCapLen]  (only when the entry image is emitted)

// Emit selects which records a gated (entry + exit) capture emits for a
// packet that matched both stages.
type Emit uint8

const (
	// EmitBoth emits the entry image and the exit image, both stamped
	// with the verdict and the same frame identity.
	EmitBoth Emit = iota
	// EmitEntry emits only the entry image (as the program received the
	// packet), selected by the exit verdict.
	EmitEntry
	// EmitExit emits only the exit image; the entry stage then only
	// records that the packet matched (no copy), which is the cheapest
	// gated form.
	EmitExit
)

// ParseEmit maps the --emit value.
func ParseEmit(s string) (Emit, error) {
	switch s {
	case "both":
		return EmitBoth, nil
	case "entry":
		return EmitEntry, nil
	case "exit":
		return EmitExit, nil
	}
	return 0, fmt.Errorf("invalid --emit %q: must be both, entry, or exit", s)
}

func (e Emit) String() string {
	switch e {
	case EmitEntry:
		return "entry"
	case EmitExit:
		return "exit"
	}
	return "both"
}

const (
	holdTs     = 0
	holdFrame  = 8
	holdPktLen = 16
	holdCapLen = 20
	holdValid  = 22
	holdTag    = 24
	holdHdr    = 32
)

// holdValueSize is the per-CPU hold slot size for an entry snaplen.
func holdValueSize(emit Emit, entryCapLen int) int {
	if emit == EmitExit {
		return holdHdr
	}
	return holdHdr + entryCapLen
}

// emitHoldLookup loads the per-CPU hold slot pointer into R0 (jumping to
// "exit" if the lookup fails, which cannot happen for an array with one
// entry but the verifier needs the check). Uses stack[-16] as the key.
func emitHoldLookup(holdFD int) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.R10, -16, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, holdFD),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
	}
}

// buildGatedEntryInsns is the fentry half: filter gate, then on match
// write the hold slot (and the entry bytes unless only the exit image is
// wanted). Never emits to the ring.
func buildGatedEntryInsns(filterOut codegen.Output, tf filter.TargetFilters, holdFD, scratchFD int, progType ebpf.ProgramType, slots *pktSetSlots, pktRefs []string, emit Emit, entryCapLen int) (asm.Instructions, error) {
	h, ok := hook.ByProgramType(progType)
	if !ok {
		return nil, hook.UnsupportedTypeError(progType)
	}
	insns, err := buildFilterGate(filterOut, tf, scratchFD, progType, slots, pktRefs)
	if err != nil {
		return nil, err
	}
	identity, err := h.Identity(asm.R1)
	if err != nil {
		return nil, err
	}

	insns = append(insns, emitHoldLookup(holdFD)...)
	insns = append(insns,
		// R8 (data_end) is dead after the filter; keep the hold pointer
		// there across helper calls (callee-saved).
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R8, holdTs, asm.R0, asm.DWord),
	)
	insns = append(insns, identity...)
	insns = append(insns,
		asm.StoreMem(asm.R8, holdFrame, asm.R1, asm.DWord),
		asm.StoreMem(asm.R8, holdPktLen, asm.R9, asm.Word),
		// caplen = min(pkt_len, entryCapLen)
		asm.Mov.Reg(asm.R3, asm.R9),
		asm.JLE.Imm(asm.R3, int32(entryCapLen), "gh_cap_ok"),
		asm.Mov.Imm(asm.R3, int32(entryCapLen)),
		asm.StoreMem(asm.R8, holdCapLen, asm.R3, asm.Half).WithSymbol("gh_cap_ok"),
		asm.StoreImm(asm.R8, holdValid, 1, asm.Half),
		asm.LoadMem(asm.R1, asm.R10, tagSlot, asm.DWord),
		asm.StoreMem(asm.R8, holdTag, asm.R1, asm.Word),
	)
	if emit != EmitExit {
		insns = append(insns,
			// bpf_probe_read_kernel(hold + 32, caplen, data)
			asm.Mov.Reg(asm.R1, asm.R8), asm.Add.Imm(asm.R1, holdHdr),
			asm.Mov.Reg(asm.R2, asm.R3),
			asm.Mov.Reg(asm.R3, asm.R7),
			asm.FnProbeReadKernel.Call(),
		)
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	if len(filterOut.Callbacks) > 0 {
		insns[0] = btf.WithFuncMetadata(insns[0], codegen.MainFilterFuncBTF("bpf_ninja_filter"))
		insns = append(insns, filterOut.Callbacks...)
	}
	return insns, nil
}

// buildGatedExitInsns is the fexit half: consume the hold slot (bail out
// cheaply when the entry stage did not match), run the exit filter, and
// on match emit the entry image from the hold and/or the exit image.
func buildGatedExitInsns(filterOut codegen.Output, tf filter.TargetFilters, eventsFD, holdFD, scratchFD int, progType ebpf.ProgramType, slots *pktSetSlots, pktRefs []string, emit Emit, entryCapLen int) (asm.Instructions, error) {
	h, ok := hook.ByProgramType(progType)
	if !ok {
		return nil, hook.UnsupportedTypeError(progType)
	}
	identity, err := h.Identity(asm.R1)
	if err != nil {
		return nil, err
	}
	insns, err := loadPacketPointers(progType)
	if err != nil {
		return nil, err
	}

	// --- consume the hold before any filter work ---
	insns = append(insns, emitHoldLookup(holdFD)...)
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R0, holdValid, asm.Half),
		asm.JEq.Imm(asm.R2, 0, "exit"),               // entry stage did not match: nothing to do
		asm.StoreImm(asm.R0, holdValid, 0, asm.Half), // consume, whatever happens below
		asm.LoadMem(asm.R2, asm.R0, holdFrame, asm.DWord),
	)
	insns = append(insns, identity...)
	insns = append(insns,
		asm.JNE.Reg(asm.R1, asm.R2, "exit"), // stale slot (missed fentry, RT interleave): drop it
	)

	gate, err := buildFilterBody(filterOut, tf, scratchFD, slots, pktRefs)
	if err != nil {
		return nil, err
	}
	insns = append(insns, gate...)

	if emit != EmitExit {
		insns = append(insns, captureFromHold(eventsFD, holdFD, entryCapLen)...)
	}
	if emit != EmitEntry {
		insns = append(insns, captureWithRingbuf(eventsFD, true, filterOut.Capture.MaxCapLen, identity)...)
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	if len(filterOut.Callbacks) > 0 {
		insns[0] = btf.WithFuncMetadata(insns[0], codegen.MainFilterFuncBTF("bpf_ninja_filter"))
		insns = append(insns, filterOut.Callbacks...)
	}
	return insns, nil
}

// captureFromHold emits the entry image kept in the hold slot as a
// mode-0 record stamped with the exit verdict (args[1]) and the hold's
// timestamp, tag and frame identity. Same ring/stack conventions as
// captureWithRingbuf (stack[-16] cpu key, stack[-32] reserved slot).
func captureFromHold(eventsFD, holdFD int, entryCapLen int) asm.Instructions {
	reserveSize := int32(metadataSize + entryCapLen)
	insns := emitHoldLookup(holdFD)
	insns = append(insns,
		asm.Mov.Reg(asm.R8, asm.R0), // hold pointer, callee-saved across helpers
		asm.FnGetSmpProcessorId.Call(),
		asm.StoreMem(asm.R10, -16, asm.R0, asm.Word),
	)
	insns = append(insns, emitShardedRBReserve(eventsFD, reserveSize)...)
	insns = append(insns,
		// ts = hold.ts
		asm.LoadMem(asm.R1, asm.R8, holdTs, asm.DWord),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		// action = args[1] (the verdict this fexit sees), mode = 0 (entry image)
		asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord),
		asm.LoadMem(asm.R2, asm.R2, 8, asm.DWord),
		asm.StoreMem(asm.R0, 8, asm.R2, asm.Word),
		asm.StoreImm(asm.R0, 12, 0, asm.Byte),
		asm.StoreImm(asm.R0, 13, 0, asm.Byte),
		// caplen = min(hold.caplen, entryCapLen) (the clamp keeps the
		// verifier's copy-size bound; hold.caplen never exceeds it)
		asm.LoadMem(asm.R3, asm.R8, holdCapLen, asm.Half),
		asm.JLE.Imm(asm.R3, int32(entryCapLen), "gx_cap_ok"),
		asm.Mov.Imm(asm.R3, int32(entryCapLen)),
		asm.StoreMem(asm.R0, 14, asm.R3, asm.Half).WithSymbol("gx_cap_ok"),
		// tag, frame
		asm.LoadMem(asm.R1, asm.R8, holdTag, asm.Word),
		asm.StoreMem(asm.R0, 16, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R8, holdFrame, asm.DWord),
		asm.StoreMem(asm.R0, 20, asm.R1, asm.DWord),
		// bpf_probe_read_kernel(slot + 28, caplen, hold + 32)
		asm.Mov.Reg(asm.R1, asm.R0), asm.Add.Imm(asm.R1, int32(metadataSize)),
		asm.Mov.Reg(asm.R2, asm.R3),
		asm.Mov.Reg(asm.R3, asm.R8), asm.Add.Imm(asm.R3, holdHdr),
		asm.FnProbeReadKernel.Call(),
		// submit
		asm.LoadMem(asm.R1, asm.R10, -32, asm.DWord),
		asm.Mov.Imm(asm.R2, int32(RingbufSubmitFlags)),
		asm.FnRingbufSubmit.Call(),
	)
	return insns
}
