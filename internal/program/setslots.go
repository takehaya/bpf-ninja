// Package program — packet-field set matching (DSL `gtp[teid in @NAME]`).
//
// This is the host half of architecture B (see the plan / kunai
// codegen.SetSlotResolver). kunai extracts the packet field into a
// host-owned stack slot during the filter body; the host then looks the
// pinned set map up against those bytes after the filter returns. kunai
// never sees a map — only the R10 offset this resolver hands it.
package program

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/internal/setmap"
	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

// The packet-field key buffer lives in the host stack region [-40, -24),
// which is free — during the filter and until the set lookup completes —
// in BOTH attach paths:
//
//   - tracing: the host slots are -8/-12/-16/-24/-48; -32 and -40 are
//     unused (the arg-based emitSetFilters key buffer sits at -57..-120,
//     below KunaiStackTop, reused strictly before runFilter).
//   - XDP-native: captureXDPNative reuses -32/-40 as scratch, but only
//     AFTER the lookup has consumed the key buffer.
//
// kunai owns [-56, ...) (KunaiStackTop = -56), so the buffer stays above
// it. That bounds the total key width to 16 bytes — enough for a TEID (4),
// an IMSI (8), or a TEID+IMSI composite (12); wider keys are rejected.
const (
	pktSetKeyTop   int16 = -24 // exclusive upper bound (closest to 0)
	pktSetKeyFloor int16 = -40 // inclusive lower bound
)

// pktSetSlots implements codegen.SetSlotResolver over the opened --set
// definitions. Slots are allocated lazily on first SlotFor call, so only
// the sets the DSL actually extracts fields from consume the 16-byte
// budget (arg-filter-only sets, matched separately, cost nothing here).
type pktSetSlots struct {
	sets   map[string]*setSlot
	cursor int16 // next free offset, allocated downward from pktSetKeyTop
	err    error // first over-budget allocation, surfaced by allocErr()
}

type setSlot struct {
	def       *setmap.Definition
	base      int16 // R10 offset of the key buffer; 0 until allocated
	allocated bool
}

// newPktSetSlots wraps the opened sets in a resolver; nothing is allocated
// until codegen queries a set via SlotFor.
func newPktSetSlots(sets []*setmap.Set) *pktSetSlots {
	p := &pktSetSlots{sets: make(map[string]*setSlot, len(sets)), cursor: pktSetKeyTop}
	for _, s := range sets {
		p.sets[s.Name] = &setSlot{def: s.Def}
	}
	return p
}

// allocErr returns the first over-budget error hit during compile-time
// SlotFor calls (SlotFor itself can only signal ok=false), so the loader
// can surface a clear message instead of a downstream codegen error.
func (p *pktSetSlots) allocErr() error { return p.err }

// keyAlign is the alignment a key buffer needs so every field's store is
// naturally aligned: the widest field width, capped at 8. The cap matters
// for a 16-byte field (an IPv6 SID), which kunai stores as two aligned
// DWords — those need only 8-alignment, and pktSetKeyFloor (-40) is
// 8-aligned but not 16-aligned, so aligning the base to 16 would push it
// below the floor and spuriously overflow the 16-byte budget.
func keyAlign(def *setmap.Definition) int16 {
	align := int16(1)
	for _, f := range def.Fields {
		w := int16(f.Size)
		if w > 8 {
			w = 8
		}
		if w > align {
			align = w
		}
	}
	return align
}

// HasSet reports whether name was declared with --set.
func (p *pktSetSlots) HasSet(name string) bool {
	_, ok := p.sets[name]
	return ok
}

// SlotFor returns the R10 slot and width for one key field of a set,
// allocating the set's key buffer on first use.
func (p *pktSetSlots) SlotFor(setName, fieldName string) (off int16, size int, ok bool) {
	s, ok := p.sets[setName]
	if !ok {
		return 0, 0, false
	}
	f, ok := s.def.Field(fieldName)
	if !ok {
		return 0, 0, false
	}
	if !s.allocated {
		// A key field is laid out at a natural offset within its key, so
		// aligning the base down to the key's widest field width keeps
		// every extracted-field StoreMem naturally aligned (an unaligned
		// DWord store would be verifier-rejected) while packing tighter
		// than rounding the whole key up to 8.
		align := keyAlign(s.def)
		base := (p.cursor - int16(s.def.KeySize)) &^ (align - 1)
		if base < pktSetKeyFloor {
			if p.err == nil {
				p.err = fmt.Errorf("set @%s: combined packet-key width exceeds the %d-byte budget", setName, int(pktSetKeyTop-pktSetKeyFloor))
			}
			return 0, 0, false
		}
		s.base, s.allocated, p.cursor = base, true, base
	}
	return s.base + int16(f.Off), int(f.Size), true
}

// referencedSets returns the distinct set names the compiled filter
// extracted fields for, in first-seen order — the sets whose maps the
// host must look up after the filter runs.
func referencedSets(extractions []codegen.ExtractSlot) []string {
	var order []string
	seen := map[string]bool{}
	for _, ex := range extractions {
		if !seen[ex.SetName] {
			seen[ex.SetName] = true
			order = append(order, ex.SetName)
		}
	}
	return order
}

// emitPktSetKeyZeroing zeroes the allocated key-buffer span before the
// filter runs, so padding bytes a field store does not cover stay zero
// (hash maps hash every key byte; setmap.BuildKey zero-pads to match).
// Only the dwords covering the sets actually used are emitted (a single
// u32/u64 key touches one dword, not the whole 16-byte region). No-op
// when nothing references a set.
func (p *pktSetSlots) emitPktSetKeyZeroing(referenced []string) asm.Instructions {
	lowest := pktSetKeyTop
	for _, name := range referenced {
		if s := p.sets[name]; s != nil && s.allocated && s.base < lowest {
			lowest = s.base
		}
	}
	if lowest >= pktSetKeyTop {
		return nil // nothing allocated
	}
	// The region [-40,-24) is two 8-aligned dwords: [-40,-32) and
	// [-32,-24). Stores must be dword-aligned and inside the region (a
	// base may not be 8-aligned, so a store from `lowest` directly could
	// overrun -24). The upper dword [-32,-24) is always in use: the
	// topmost buffer always ends exactly at -24 (KeySize is a multiple of
	// its alignment and -24 is aligned, so base = -24 - KeySize), so we
	// always emit it; the lower dword only when the span reaches it.
	insns := asm.Instructions{asm.Mov.Imm(asm.R3, 0)}
	if lowest < pktSetKeyFloor+8 { // spans into the lower dword
		insns = append(insns, asm.StoreMem(asm.R10, pktSetKeyFloor, asm.R3, asm.DWord))
	}
	insns = append(insns, asm.StoreMem(asm.R10, pktSetKeyFloor+8, asm.R3, asm.DWord))
	return insns
}

// emitPktSetLookups emits one pinned-map membership check per referenced
// set, against the key buffer kunai populated during the filter. A miss
// jumps to "exit" (skip capture); all sets AND together, and AND with the
// kunai verdict that already ran.
func (p *pktSetSlots) emitPktSetLookups(referenced []string) asm.Instructions {
	var insns asm.Instructions
	for _, name := range referenced {
		s := p.sets[name]
		insns = append(insns, emitSetLookup(s.def.Map.FD(), s.base)...)
	}
	return insns
}
