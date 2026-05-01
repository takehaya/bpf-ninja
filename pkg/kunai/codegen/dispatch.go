package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// genNoCheckDispatch emits nothing: when a vocab declares
// <SELF>_<PARENT>_NO_CHECK = true the child is trusted to follow the
// parent without a boundary marker (e.g. EoMPLS payload, inner
// Ethernet of a pseudowire). The bounds check in genLayer still
// protects scratch-buffer reads.
func genNoCheckDispatch(current *ir.LayerInstance) (asm.Instructions, error) {
	if !current.Dispatch.Const.Bool {
		return nil, fmt.Errorf("codegen: NO_CHECK const %q must be true to be emitted", current.Dispatch.Const.Name)
	}
	return nil, nil
}

// genSanityDispatch emits a check that the current layer's start byte
// satisfies a sanity constraint declared by the protocol. MVP only
// supports the NIBBLE type: "IPv4 under MPLS has the first nibble of
// its header equal to 4". Future sanity types (MAGIC / LENGTH /
// RANGE) are rejected with ErrNotImplemented so vocab authors get a
// uniform error if they use them prematurely.
//
// NIBBLE codegen reads one byte at the layer's start, shifts the
// upper nibble into the low four bits, and compares against the
// declared value. failLabel receives control when the check fails
// (dslReject for a mandatory layer, a skip marker for `?`).
func genSanityDispatch(current *ir.LayerInstance, failLabel string) (asm.Instructions, error) {
	c := current.Dispatch.Const
	switch c.SanityType {
	case "NIBBLE":
		if c.Value > 0xF {
			return nil, fmt.Errorf("codegen: NIBBLE sanity value %d does not fit in 4 bits", c.Value)
		}
		insns := loadFromOffset(0, asm.Byte)
		insns = append(insns,
			asm.RSh.Imm(asm.R3, 4),
			asm.JNE.Imm(asm.R3, int32(c.Value), failLabel),
		)
		return insns, nil
	}
	return nil, fmt.Errorf("%w: sanity type %q (only NIBBLE is implemented)", ErrNotImplemented, c.SanityType)
}
