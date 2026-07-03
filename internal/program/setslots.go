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
// definitions, allocating each referenced set a key buffer in the shared
// [-40, -24) region.
type pktSetSlots struct {
	defs map[string]*setmap.Definition
	base map[string]int16 // set name → R10 offset of its key buffer
}

// newPktSetSlots allocates a key-buffer slot for every provided set and
// returns the resolver, or an error if the combined key width exceeds the
// 16-byte packet-extraction budget.
func newPktSetSlots(sets []*setmap.Set) (*pktSetSlots, error) {
	p := &pktSetSlots{
		defs: make(map[string]*setmap.Definition, len(sets)),
		base: make(map[string]int16, len(sets)),
	}
	cursor := pktSetKeyTop
	for _, s := range sets {
		cursor -= int16(s.Def.KeySize)
		if cursor < pktSetKeyFloor {
			return nil, fmt.Errorf("set @%s: combined key width exceeds the %d-byte packet-extraction budget", s.Name, int(pktSetKeyTop-pktSetKeyFloor))
		}
		p.defs[s.Name] = s.Def
		p.base[s.Name] = cursor
	}
	return p, nil
}

// HasSet reports whether name was declared with --set.
func (p *pktSetSlots) HasSet(name string) bool {
	_, ok := p.defs[name]
	return ok
}

// SlotFor returns the R10 slot and width for one key field of a set.
func (p *pktSetSlots) SlotFor(setName, fieldName string) (off int16, size int, ok bool) {
	def, ok := p.defs[setName]
	if !ok {
		return 0, 0, false
	}
	f, ok := def.Field(fieldName)
	if !ok {
		return 0, 0, false
	}
	return p.base[setName] + int16(f.Off), int(f.Size), true
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

// emitPktSetKeyZeroing zeroes the whole [-40, -24) key-buffer region
// before the filter runs, so padding bytes a field store does not cover
// stay zero (hash maps hash every key byte; setmap.BuildKey zero-pads to
// match). Two dword stores cover the 16-byte region. No-op when nothing
// references a set.
func emitPktSetKeyZeroing(referenced []string) asm.Instructions {
	if len(referenced) == 0 {
		return nil
	}
	return asm.Instructions{
		asm.Mov.Imm(asm.R3, 0),
		asm.StoreMem(asm.R10, pktSetKeyFloor, asm.R3, asm.DWord),   // [-40,-32)
		asm.StoreMem(asm.R10, pktSetKeyFloor+8, asm.R3, asm.DWord), // [-32,-24)
	}
}

// emitPktSetLookups emits one pinned-map membership check per referenced
// set, against the key buffer kunai populated during the filter. A miss
// jumps to "exit" (skip capture); all sets AND together, and AND with the
// kunai verdict that already ran. Reload of R-registers is unnecessary:
// this runs after the filter body, before capture.
func (p *pktSetSlots) emitPktSetLookups(referenced []string) asm.Instructions {
	var insns asm.Instructions
	for _, name := range referenced {
		def := p.defs[name]
		insns = append(insns,
			asm.LoadMapPtr(asm.R1, def.Map.FD()),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, int32(p.base[name])),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
		)
	}
	return insns
}
