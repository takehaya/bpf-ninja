package injectcheck

import (
	"encoding/json"
	"fmt"

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
	OpCode    asm.OpCode   `json:"opcode"`
	Dst       asm.Register `json:"dst"`
	Src       asm.Register `json:"src"`
	Offset    int16        `json:"offset"`
	Constant  int64        `json:"constant"`
	Symbol    string       `json:"symbol"`
	Reference string       `json:"reference"`
}

func (is Instructions) MarshalJSON() ([]byte, error) {
	if err := unassociated(asm.Instructions(is)); err != nil {
		return nil, err
	}
	wire := make([]wireInstruction, len(is))
	for i, ins := range is {
		if err := noLoadMetadata(ins); err != nil {
			return nil, fmt.Errorf("instruction %d: %w", i, err)
		}
		wire[i] = wireInstruction{OpCode: ins.OpCode, Dst: ins.Dst, Src: ins.Src,
			Offset: ins.Offset, Constant: ins.Constant, Symbol: ins.Symbol(), Reference: ins.Reference()}
	}
	return json.Marshal(wire)
}

func (is *Instructions) UnmarshalJSON(data []byte) error {
	var wire []wireInstruction
	if err := strictJSON(data, &wire); err != nil {
		return err
	}
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return inputError(InputJSON, "%v", err)
	}
	for i, value := range values {
		if string(value) == "null" {
			return inputError(InputJSON, "instruction %d is null", i)
		}
	}

	out := make(Instructions, len(wire))
	for i, ins := range wire {
		out[i] = asm.Instruction{OpCode: ins.OpCode, Dst: ins.Dst, Src: ins.Src,
			Offset: ins.Offset, Constant: ins.Constant}.WithSymbol(ins.Symbol).WithReference(ins.Reference)
	}
	*is = out
	return nil
}
