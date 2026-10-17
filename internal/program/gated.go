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
// The one exception on a non-RT kernel is synchronous re-entry: the
// target calls bpf_clone_redirect, whose dev_queue_xmit runs the same
// program again (attached at the egress) before the outer invocation
// returns. Nesting on one CPU is strictly LIFO, so the hold is one slot
// per depth: every fentry takes the next depth before its filter runs,
// and its fexit gives it back, so each invocation finds its own slot.
// An invocation deeper than holdSlots is counted (statHoldOverflow), not
// held. A probe skipped because another attach rewrote the trampoline
// mid-invocation can still leave a slot or the depth stale. Every fentry
// numbers its invocation and a hold carries the number of the one that
// wrote it, so a fexit never pairs a hold left by another invocation,
// even when that invocation's frame address has been recycled. The next
// fentry restarts a stale depth (statHoldResync), and the counters
// (statHoldOverwrite, statHoldUnpaired, and holds still valid at the
// end, added by ExportStats) report the loss.
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
// Hold slot layout (per-CPU array, holdSlots entries, index = depth):
//
//	 0  u64 ts_ns    entry timestamp (becomes the entry record's timestamp)
//	 8  u64 frame    hook identity at entry (sanity-checked at exit)
//	16  u16 caplen   bytes actually copied
//	18  u16 valid    1 = written by the fentry of an invocation whose fexit
//	                 has not consumed it yet
//	20  u32 tag      set-map value
//	24  u64 seq      this invocation's packet sequence; (cpu << 48 | seq)
//	                 is the opaque packet id both records carry
//	32  u32 copy_error  entry snapshot error, checked after exit selection
//	36  u32 padding
//	40  u64 inv      number of the invocation whose fentry wrote the hold
//	48  u32 depth    slot 0 only: invocations on this CPU between their
//	                 fentry and fexit
//	56  u64 next_seq slot 0 only: per-CPU count of matched entries
//	64  u64 next_inv slot 0 only: per-CPU count of fentries
//	72  u64 enter_j[maxHoldSlots]    slot 0 only: jiffies at each depth's fentry
//	152 u64 enter_inv[maxHoldSlots]  slot 0 only: invocation number at each depth
//	232 u8  bytes[entryCapLen]  (absent when only the exit image is emitted)

// packetIDCPUShift places the CPU id above the per-CPU sequence in a
// gated record's packet id: cpu << packetIDCPUShift | seq.
const packetIDCPUShift = 48

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
	holdTs      = 0
	holdFrame   = 8
	holdCapLen  = 16
	holdValid   = 18
	holdTag     = 20
	holdSeq     = 24
	holdCopyErr = 32
	holdInv     = 40                          // invocation number of the fentry that wrote the hold
	holdDepth   = 48                          // slot 0 only
	holdNextSeq = 56                          // slot 0 only
	holdNextInv = 64                          // slot 0 only
	holdEnterJ  = 72                          // slot 0 only: u64 jiffies at each depth's fentry
	holdEnterI  = holdEnterJ + 8*maxHoldSlots // slot 0 only: u64 invocation number at each depth
	holdHdr     = holdEnterI + 8*maxHoldSlots
)

// maxHoldSlots bounds holdSlots (the slot-0 header has one entry time
// per depth).
const maxHoldSlots = 10

// holdSlots is the number of per-CPU hold slots, one per nesting depth of
// the target on one CPU. Synchronous re-entry goes through a BPF
// transmit (bpf_clone_redirect -> dev_queue_xmit), which the kernel
// refuses once the per-CPU xmit recursion count passes
// XMIT_RECURSION_LIMIT (8): at most 9 nested invocations below the
// outer one (TestBpfGatedReentry pins this). A var so tests can make
// the cap reachable.
var holdSlots = maxHoldSlots

// emitHoldBase loads hold slot 0 (it carries the per-CPU depth and the
// sequence counter) into R0, jumping to "exit" if the lookup fails,
// which cannot happen for an array but the verifier needs the check.
// Uses stack[-16] as the key; clobbers R1-R5.
func emitHoldBase(holdFD int) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.R10, -16, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, holdFD),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
	}
}

// emitHoldSlot loads the hold slot whose index is in stack[-16] into R0
// (jumping to "exit" on a miss). Clobbers R1-R5.
func emitHoldSlot(holdFD int) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R1, holdFD),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
	}
}

// buildGatedEntryInsns is the fentry half: filter gate, then on match
// write the hold slot (and the entry bytes unless only the exit image is
// wanted). Never emits to the ring.
func buildGatedEntryInsns(h *hook.Hook, filterOut codegen.Output, tf filter.TargetFilters, holdFD, holdStopFD, statsFD, scratchFD int, slots *pktSetSlots, pktRefs []string, emit Emit, entryCapLen int, gateFD int) (asm.Instructions, error) {
	// Every invocation, matched or not, takes the next depth on this CPU
	// before the filter runs; its fexit gives it back. A skipped fexit
	// (another attach rewrote the trampoline mid-invocation) would leave
	// the depth raised for good, so the depth is resynchronised: a nest
	// finishes within a few microseconds, so if the innermost open depth
	// was entered more than one jiffy ago it is stale and the depth
	// restarts from 0 (counted; the stale holds it overwrites are counted
	// as hold_overwrite). R7 and R8 are free until the prologue.
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	insns = append(insns, emitHoldBase(holdFD)...)
	insns = append(insns,
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.FnJiffies64.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.LoadMem(asm.R2, asm.R8, holdDepth, asm.Word),
		asm.JEq.Imm(asm.R2, 0, "gd_take"),
		asm.Mov.Reg(asm.R3, asm.R2),
		asm.Sub.Imm(asm.R3, 1),
		// past the slots, the deepest recorded entry time stands in
		asm.JLT.Imm(asm.R3, int32(holdSlots), "gd_age"),
		asm.Mov.Imm(asm.R3, int32(holdSlots-1)),
		asm.LSh.Imm(asm.R3, 3).WithSymbol("gd_age"),
		asm.Mov.Reg(asm.R5, asm.R8),
		asm.Add.Reg(asm.R5, asm.R3),
		asm.LoadMem(asm.R5, asm.R5, holdEnterJ, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Sub.Reg(asm.R4, asm.R5),
		asm.JLE.Imm(asm.R4, 1, "gd_take"),
		asm.StoreImm(asm.R8, holdDepth, 0, asm.Word),
	)
	insns = append(insns, emitCounterInc(statsFD, statHoldResync, "gd_reload")...)
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R8, holdDepth, asm.Word).WithSymbol("gd_reload"),
		asm.JGE.Imm(asm.R2, int32(holdSlots), "gd_inc").WithSymbol("gd_take"),
		asm.Mov.Reg(asm.R3, asm.R2),
		asm.LSh.Imm(asm.R3, 3),
		asm.Mov.Reg(asm.R5, asm.R8),
		asm.Add.Reg(asm.R5, asm.R3),
		asm.StoreMem(asm.R5, holdEnterJ, asm.R7, asm.DWord),
		// number this invocation; its fexit accepts only a hold with it
		asm.LoadMem(asm.R4, asm.R8, holdNextInv, asm.DWord),
		asm.Add.Imm(asm.R4, 1),
		asm.StoreMem(asm.R8, holdNextInv, asm.R4, asm.DWord),
		asm.StoreMem(asm.R5, holdEnterI, asm.R4, asm.DWord),
		asm.Add.Imm(asm.R2, 1).WithSymbol("gd_inc"),
		asm.StoreMem(asm.R8, holdDepth, asm.R2, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
	)
	gate, err := buildFilterGate(h, filterOut, tf, scratchFD, slots, pktRefs, false, 0)
	if err != nil {
		return nil, err
	}
	insns = append(insns, gate...)
	insns = append(insns, emitTagBarrier(gateFD)...)
	identity, err := h.Identity(asm.R1)
	if err != nil {
		return nil, err
	}
	if holdStopFD > 0 {
		// Quiesce sets the stop flag before detaching (see Probe.Quiesce).
		insns = append(insns,
			asm.StoreImm(asm.R10, -16, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, holdStopFD),
			asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
			asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
			asm.JNE.Imm(asm.R1, 0, "exit"),
		)
	}
	// This invocation's slot is its depth (taken above, and nothing nested
	// can run in between). Past the last slot it is counted, not held.
	insns = append(insns, emitHoldBase(holdFD)...)
	insns = append(insns,
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.LoadMem(asm.R2, asm.R8, holdDepth, asm.Word),
		asm.Sub.Imm(asm.R2, 1),
		asm.JLT.Imm(asm.R2, int32(holdSlots), "gh_slot_ok"),
	)
	insns = append(insns, emitExportCounter(statsFD, statHoldOverflow, "gh_overflow")...)
	insns = append(insns,
		asm.StoreMem(asm.R10, -16, asm.R2, asm.Word).WithSymbol("gh_slot_ok"),
		// seq++ (slot 0 keeps the counter): the opaque per-CPU packet id
		asm.LoadMem(asm.R1, asm.R8, holdNextSeq, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R8, holdNextSeq, asm.R1, asm.DWord),
	)
	insns = append(insns, emitHoldSlot(holdFD)...)
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R10, -16, asm.Word),
		asm.JGE.Imm(asm.R2, int32(holdSlots), "exit"), // bound for the verifier
		asm.LSh.Imm(asm.R2, 3),
		asm.Add.Reg(asm.R2, asm.R8),
		asm.LoadMem(asm.R3, asm.R2, holdEnterI, asm.DWord),
		asm.StoreMem(asm.R0, holdInv, asm.R3, asm.DWord),
		asm.LoadMem(asm.R1, asm.R8, holdNextSeq, asm.DWord),
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.StoreMem(asm.R8, holdSeq, asm.R1, asm.DWord),
	)
	// With a slot per depth a hold is still valid here only after a probe
	// was skipped (another attach rewrote the trampoline mid-invocation).
	// Count the earlier invocation as lost before overwriting its hold.
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R8, holdValid, asm.Half),
		asm.JEq.Imm(asm.R2, 0, "gh_fresh"),
	)
	insns = append(insns, emitCounterInc(statsFD, statHoldOverwrite, "gh_fresh")...)
	insns = append(insns,
		asm.FnKtimeGetNs.Call().WithSymbol("gh_fresh"),
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
		asm.StoreImm(asm.R8, holdCopyErr, 0, asm.Word),
		asm.LoadMem(asm.R1, asm.R10, tagSlot, asm.DWord),
		asm.StoreMem(asm.R8, holdTag, asm.R1, asm.Word),
	)
	if emit != EmitExit {
		insns = append(insns,
			// bpf_probe_read_kernel(hold + holdHdr, caplen, data)
			asm.Mov.Reg(asm.R1, asm.R8), asm.Add.Imm(asm.R1, holdHdr),
			asm.Mov.Reg(asm.R2, asm.R3),
			asm.Mov.Reg(asm.R3, asm.R7),
			asm.FnProbeReadKernel.Call(),
			asm.StoreMem(asm.R8, holdCopyErr, asm.R0, asm.Word),
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
	// --- give the depth back and consume this depth's hold before any
	// filter work. Depth 0 here means the fentry did not run (the fexit
	// was attached first); a depth past the slots was counted at entry. ---
	insns = append(insns, emitHoldBase(holdFD)...)
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R0, holdDepth, asm.Word),
		asm.JEq.Imm(asm.R2, 0, "exit"),
		asm.Sub.Imm(asm.R2, 1),
		asm.StoreMem(asm.R0, holdDepth, asm.R2, asm.Word),
		asm.JGE.Imm(asm.R2, int32(holdSlots), "exit"),
		asm.StoreMem(asm.R10, -16, asm.R2, asm.Word),
		// this invocation's number, parked in the filter's scratch-pointer
		// slot, which the filter only writes later
		asm.LSh.Imm(asm.R2, 3),
		asm.Add.Reg(asm.R2, asm.R0),
		asm.LoadMem(asm.R3, asm.R2, holdEnterI, asm.DWord),
		asm.StoreMem(asm.R10, -24, asm.R3, asm.DWord),
	)
	insns = append(insns, emitHoldSlot(holdFD)...)
	insns = append(insns,
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.LoadMem(asm.R2, asm.R8, holdValid, asm.Half),
		asm.JEq.Imm(asm.R2, 0, "exit"),               // entry stage did not match: nothing to do
		asm.StoreImm(asm.R8, holdValid, 0, asm.Half), // consume, whatever happens below
		// A hold another invocation left at this depth (its fexit was
		// skipped, or the depth was resynchronised) never pairs, even if
		// its frame address was recycled for this invocation.
		asm.LoadMem(asm.R2, asm.R8, holdInv, asm.DWord),
		asm.LoadMem(asm.R3, asm.R10, -24, asm.DWord),
		asm.JNE.Reg(asm.R2, asm.R3, "hold_unpaired"),
		asm.LoadMem(asm.R2, asm.R8, holdFrame, asm.DWord),
	)
	insns = append(insns, identity...)
	insns = append(insns,
		asm.JNE.Reg(asm.R1, asm.R2, "hold_unpaired"), // written by another invocation: count and drop it
	)

	body, err := buildFilterBody(h, filterOut, tf, scratchFD, slots, pktRefs)
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

	if emit != EmitExit {
		// Count a failed entry snapshot only after both filters selected this
		// invocation. No ring record has been reserved, so skip the discard path.
		insns = append(insns, asm.LoadMem(asm.R1, asm.R8, holdCopyErr, asm.Word), asm.JNE.Imm(asm.R1, 0, "rb_copy_count"))
	}

	// --- packet id for both records: cpu << packetIDCPUShift | hold.seq, parked in
	// R6 (ctx is not read again after the filter) ---
	insns = append(insns,
		asm.FnGetSmpProcessorId.Call(),
		asm.LSh.Imm(asm.R0, packetIDCPUShift),
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
	insns = append(insns, emitExportTerminals(statsFD)...)
	insns = append(insns, emitExportCounter(statsFD, statHoldUnpaired, "hold_unpaired")...)
	return finishProgram(insns, filterOut, 0), nil
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
