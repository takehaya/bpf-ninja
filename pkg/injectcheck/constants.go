package injectcheck

import "github.com/cilium/ebpf/asm"

const (
	stackBottom           = -512
	slotContext           = -8  // Also the u32 region's R0 save.
	slotKey               = -16 // Also the u32 region's R2 save.
	slotResult            = -24 // Also update/push flags, reloaded before saving R0.
	slotMap               = -32 // Also update value when no map slot is needed.
	slotValue             = -40
	postludeBudget        = 4096
	idUndefined           = 0
	idOpaque              = -1
	idFrame               = 11
	idContext             = 100
	idResult              = 200
	resultRegs     uint16 = 1 << asm.R0
	argRegs        uint16 = 1<<asm.R1 | 1<<asm.R2 | 1<<asm.R3 | 1<<asm.R4 | 1<<asm.R5
	callerSaved           = resultRegs | argRegs
	u32Clobbers    uint16 = 1<<asm.R1 | 1<<asm.R3 | 1<<asm.R4 | 1<<asm.R5
	allRegs        uint16 = (1 << (asm.RFP + 1)) - 1
)
