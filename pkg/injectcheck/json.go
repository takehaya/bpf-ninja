package injectcheck

import (
	"bytes"
	"encoding/json"

	"github.com/cilium/ebpf/asm"
)

func unassociated(is asm.Instructions) error {
	for i, ins := range is {
		if ins.Map() != nil {
			return reject(AssociatedMap, "instruction %d: associated maps are unsupported; check before map association", i)
		}
	}
	return nil
}

// Instructions is the JSON representation used by inject-check. Unlike direct
// encoding of asm.Instructions, it preserves symbols/references and refuses
// associated maps before encoding can silently discard their identity.
// Symbol names and numeric FDs refer to a single, unchanged external binding
// table shared by both streams; this format does not serialize live maps.
type Instructions asm.Instructions

type wireInstruction struct {
	OpCode            asm.OpCode
	Dst, Src          asm.Register
	Offset            int16
	Constant          int64
	Symbol, Reference string
}

func (is Instructions) MarshalJSON() ([]byte, error) {
	if err := unassociated(asm.Instructions(is)); err != nil {
		return nil, err
	}
	wire := make([]wireInstruction, len(is))
	for i, ins := range is {
		wire[i] = wireInstruction{OpCode: ins.OpCode, Dst: ins.Dst, Src: ins.Src,
			Offset: ins.Offset, Constant: ins.Constant, Symbol: ins.Symbol(), Reference: ins.Reference()}
	}
	return json.Marshal(wire)
}

func (is *Instructions) UnmarshalJSON(data []byte) error {
	var wire []wireInstruction
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&wire); err != nil {
		return err
	}
	out := make(Instructions, len(wire))
	for i, ins := range wire {
		out[i] = asm.Instruction{OpCode: ins.OpCode, Dst: ins.Dst, Src: ins.Src,
			Offset: ins.Offset, Constant: ins.Constant}.WithSymbol(ins.Symbol).WithReference(ins.Reference)
	}
	*is = out
	return nil
}
