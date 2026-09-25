package program

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

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
// kernel a driver's NAPI poll runs the program for one packet to
// completion — fentry(N), program, fexit(N) — with bottom halves off,
// BPF programs cannot sleep, and the trampoline runs both probes on the
// same CPU. So whatever fexit(N) finds in this CPU's slot was written by
// fentry(N), unless fentry(N) did not match and the slot still holds an
// older packet. That is why fexit always clears `valid` first (consume),
// and additionally checks that the slot's frame identity equals the
// current invocation's. PREEMPT_RT with CONFIG_PREEMPT_RT_NEEDS_BH_LOCK
// off is out of scope (a higher-priority NAPI thread can interleave).
//
// A tail call in the target does not skip its fexit: the tail-called
// program returns into the caller's trampoline (the return address
// survives the jump; the kernel keeps tail_call_cnt across it with
// BPF_TRAMP_F_TAIL_CALL_CTX), so the hold is consumed with the verdict
// of the whole chain. Attaching to a tail-call *target* fires neither
// probe (its prologue is skipped), so no hold is written there either.
//
// Both programs keep the hold pointer in R8 for their whole body: the
// prologue's data_end is never read on the tracing path (see
// hook.PacketPrologue), and R8 is callee-saved across helper calls.
//
// Hold slot layout (per-CPU array, one entry):
//
//	 0  u64 ts_ns    entry timestamp (becomes the entry record's timestamp)
//	 8  u64 frame    hook identity at entry (sanity-checked at exit)
//	16  u16 caplen   bytes actually copied
//	18  u16 valid    1 = written by the fentry of an invocation whose fexit
//	                 has not consumed it yet
//	20  u32 tag      set-map value
//	24  u64 seq      per-CPU count of matched entries; (cpu << 48 | seq) is
//	                 the opaque packet id both records carry
//	32  u8  bytes[entryCapLen]  (absent when only the exit image is emitted)

// Emit selects which records a gated (entry + exit) capture emits for a
// packet that matched both stages.
type Emit uint8

const (
	// EmitBoth emits the entry image and the exit image, both stamped
	// with the verdict and the same packet id.
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

const (
	holdTs     = 0
	holdFrame  = 8
	holdCapLen = 16
	holdValid  = 18
	holdTag    = 20
	holdSeq    = 24
	holdHdr    = 32
)

// emitHoldLookup loads the per-CPU hold slot pointer into R8 (jumping to
// "exit" if the lookup fails, which cannot happen for an array with one
// entry but the verifier needs the check). Uses stack[-16] as the key.
func emitHoldLookup(holdFD int) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.R10, -16, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, holdFD),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Reg(asm.R8, asm.R0),
	}
}

// buildGatedEntryInsns is the fentry half: filter gate, then on match
// write the hold slot (and the entry bytes unless only the exit image is
// wanted). Never emits to the ring.
func buildGatedEntryInsns(h *hook.Hook, filterOut codegen.Output, tf filter.TargetFilters, holdFD, scratchFD int, slots *pktSetSlots, pktRefs []string, emit Emit, entryCapLen int, gateFD int) (asm.Instructions, error) {
	insns, err := buildFilterGate(h, filterOut, tf, scratchFD, slots, pktRefs, false, 0)
	if err != nil {
		return nil, err
	}
	insns = append(insns, emitTagBarrier(gateFD)...)
	identity, err := h.Identity(asm.R1)
	if err != nil {
		return nil, err
	}
	insns = append(insns, emitHoldLookup(holdFD)...)
	insns = append(insns,
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R8, holdTs, asm.R0, asm.DWord),
	)
	insns = append(insns, identity...)
	insns = append(insns,
		asm.StoreMem(asm.R8, holdFrame, asm.R1, asm.DWord),
		// caplen = min(pkt_len, entryCapLen)
		asm.Mov.Reg(asm.R3, asm.R9),
		asm.JLE.Imm(asm.R3, int32(entryCapLen), "gh_cap_ok"),
		asm.Mov.Imm(asm.R3, int32(entryCapLen)),
		asm.StoreMem(asm.R8, holdCapLen, asm.R3, asm.Half).WithSymbol("gh_cap_ok"),
		asm.StoreImm(asm.R8, holdValid, 1, asm.Half),
		asm.LoadMem(asm.R1, asm.R10, tagSlot, asm.DWord),
		asm.StoreMem(asm.R8, holdTag, asm.R1, asm.Word),
		// seq++ : the opaque per-CPU packet id of this invocation
		asm.LoadMem(asm.R1, asm.R8, holdSeq, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R8, holdSeq, asm.R1, asm.DWord),
	)
	if emit != EmitExit {
		insns = append(insns,
			// bpf_probe_read_kernel(hold + holdHdr, caplen, data)
			asm.Mov.Reg(asm.R1, asm.R8), asm.Add.Imm(asm.R1, holdHdr),
			asm.Mov.Reg(asm.R2, asm.R3),
			asm.Mov.Reg(asm.R3, asm.R7),
			asm.FnProbeReadKernel.Call(),
		)
	}
	return finishProgram(insns, filterOut, 0), nil
}

// buildGatedExitInsns is the fexit half: consume the hold slot (bail out
// cheaply when the entry stage did not match), run the exit filter, and
// on match emit the entry image from the hold and/or the exit image.
func buildGatedExitInsns(h *hook.Hook, filterOut codegen.Output, tf filter.TargetFilters, eventsFD, holdFD, statsFD, scratchFD int, slots *pktSetSlots, pktRefs []string, emit Emit, entryCapLen int, returnOffset int16, gateFD int) (asm.Instructions, error) {
	identity, err := h.Identity(asm.R1)
	if err != nil {
		return nil, err
	}
	insns, err := h.PacketPrologue()
	if err != nil {
		return nil, err
	}

	insns = append(insns, loadSavedReturn(returnOffset)...)
	// --- consume the hold before any filter work ---
	insns = append(insns, emitHoldLookup(holdFD)...)
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R8, holdValid, asm.Half),
		asm.JEq.Imm(asm.R2, 0, "exit"),               // entry stage did not match: nothing to do
		asm.StoreImm(asm.R8, holdValid, 0, asm.Half), // consume, whatever happens below
		asm.LoadMem(asm.R2, asm.R8, holdFrame, asm.DWord),
	)
	insns = append(insns, identity...)
	insns = append(insns,
		asm.JNE.Reg(asm.R1, asm.R2, "exit"), // stale slot (missed fentry, RT interleave): drop it
	)

	body, err := buildFilterBody(filterOut, tf, scratchFD, slots, pktRefs)
	if err != nil {
		return nil, err
	}
	insns = append(insns, body...)
	insns = append(insns, emitTagBarrier(gateFD)...)
	if gateFD > 0 {
		// The entry image may carry a different set tag from the exit image.
		// A tombstone for either image prevents later export of that tag.
		insns = append(insns, asm.LoadMem(asm.R1, asm.R8, holdTag, asm.Word), asm.StoreMem(asm.R10, -16, asm.R1, asm.Word), asm.LoadMapPtr(asm.R1, gateFD), asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16), asm.FnMapLookupElem.Call(), asm.JNE.Imm(asm.R0, 0, "exit"))
	}

	// --- packet id for both records: cpu << 48 | hold.seq, parked in
	// R6 (ctx is not read again after the filter) ---
	insns = append(insns,
		asm.FnGetSmpProcessorId.Call(),
		asm.LSh.Imm(asm.R0, 48),
		asm.LoadMem(asm.R6, asm.R8, holdSeq, asm.DWord),
		asm.Or.Reg(asm.R6, asm.R0),
	)
	packetID := asm.Instructions{asm.Mov.Reg(asm.R1, asm.R6)}

	if emit != EmitExit {
		insns = append(insns, captureFromHold(eventsFD, statsFD, entryCapLen, packetID)...)
		if emit == EmitBoth && statsFD > 0 {
			count := emitExportCounter(statsFD, statSubmitted, "hold_submitted")
			insns = append(insns, count[:len(count)-1]...)
		}
	}
	if emit != EmitEntry {
		// ponytail: a failed reserve here leaves the entry record just
		// submitted without its exit twin; reserve both slots before
		// submitting either if pairs must be atomic under ring pressure.
		insns = append(insns, captureWithRingbuf(eventsFD, statsFD, true, filterOut.Capture.MaxCapLen, packetID)...)
	}
	return finishProgram(append(insns, emitExportTerminals(statsFD)...), filterOut, 0), nil
}

// captureFromHold emits the entry image kept in the hold slot (R8) as a
// mode-0 record stamped with the exit verdict (args[1]), the hold's
// timestamp and tag, and the packet id loaded by packetID (→ R1; must
// not clobber R0/R6..R9). Same ring/stack conventions as
// captureWithRingbuf (stack[-16] cpu key, stack[-32] reserved slot).
func captureFromHold(eventsFD, statsFD, entryCapLen int, packetID asm.Instructions) asm.Instructions {
	reserveSize := int32(metadataSize + entryCapLen)
	insns := asm.Instructions{
		asm.FnGetSmpProcessorId.Call(),
		asm.StoreMem(asm.R10, -16, asm.R0, asm.Word),
	}
	insns = append(insns, emitShardedRBReserve(eventsFD, statsFD, reserveSize)...)
	insns = append(insns,
		// ts = hold.ts
		asm.LoadMem(asm.R1, asm.R8, holdTs, asm.DWord),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		// action = args[1] (the verdict this fexit sees), mode = 0 (entry image)
		asm.LoadMem(asm.R2, asm.R10, savedReturnSlot, asm.Word),
		asm.StoreMem(asm.R0, 8, asm.R2, asm.Word),
		asm.StoreImm(asm.R0, 12, 0, asm.Byte),
		asm.StoreImm(asm.R0, 13, 0, asm.Byte),
		// caplen = min(hold.caplen, entryCapLen) (the clamp keeps the
		// verifier's copy-size bound; hold.caplen never exceeds it)
		asm.LoadMem(asm.R3, asm.R8, holdCapLen, asm.Half),
		asm.JLE.Imm(asm.R3, int32(entryCapLen), "gx_cap_ok"),
		asm.Mov.Imm(asm.R3, int32(entryCapLen)),
		asm.StoreMem(asm.R0, 14, asm.R3, asm.Half).WithSymbol("gx_cap_ok"),
		// tag
		asm.LoadMem(asm.R1, asm.R8, holdTag, asm.Word),
		asm.StoreMem(asm.R0, 16, asm.R1, asm.Word),
	)
	insns = append(insns, packetID...)
	insns = append(insns,
		asm.StoreMem(asm.R0, 20, asm.R1, asm.DWord),
		// bpf_probe_read_kernel(slot + metadataSize, caplen, hold + holdHdr)
		asm.Mov.Reg(asm.R1, asm.R0), asm.Add.Imm(asm.R1, int32(metadataSize)),
		asm.Mov.Reg(asm.R2, asm.R3),
		asm.Mov.Reg(asm.R3, asm.R8), asm.Add.Imm(asm.R3, holdHdr),
		asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, "rb_copy_fail"),
		// submit
		asm.LoadMem(asm.R1, asm.R10, -32, asm.DWord),
		asm.Mov.Imm(asm.R2, int32(RingbufSubmitFlags)),
		asm.FnRingbufSubmit.Call(),
	)
	return insns
}
