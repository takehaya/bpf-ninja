package codegen

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

func TestRequiredMaskUses32BitCompare(t *testing.T) {
	spec := newSpec("parent", "parent_h",
		vocab.Field{Name: "tag", Bits: 8},
		vocab.Field{Name: "flags", Bits: 32},
	)
	req := &vocab.DispatchFieldMask{FieldName: "flags", Mask: 0x80}

	fixed, err := emitRequiredMaskCheck(spec, req, 5, asm.R3, nil, "fail")
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := emitRequiredMaskCheckBounded(spec, req, asm.R4, asm.R5, asm.R3, -5, "fail")
	if err != nil {
		t.Fatal(err)
	}
	for name, insns := range map[string]asm.Instructions{"fixed": fixed, "bounded": bounded} {
		if got := insns[len(insns)-1].OpCode.Class(); got != asm.Jump32Class {
			t.Errorf("%s requirement compare class = %v, want %v", name, got, asm.Jump32Class)
		}
	}
}
