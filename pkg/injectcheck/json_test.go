package injectcheck

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestJSONMapPolicy(t *testing.T) {
	a := asm.LoadMapPtr(asm.R1, 0)
	if err := a.AssociateMap(rrFD(100)); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"same-map", "swapped-map", "original-only", "transformed-only", "non-map-opcode"} {
		t.Run(kind, func(t *testing.T) {
			in, out := asm.Instructions{a, asm.Return()}, asm.Instructions{a, asm.Return()}
			switch kind {
			case "swapped-map":
				if err := out[0].AssociateMap(rrFD(101)); err != nil {
					t.Fatal(err)
				}
			case "original-only":
				out[0] = asm.LoadMapPtr(asm.R1, 0)
			case "transformed-only":
				in[0] = asm.LoadMapPtr(asm.R1, 0)
			case "non-map-opcode":
				in[0].OpCode = asm.Mov.Imm(asm.R0, 0).OpCode
				out[0] = in[0]
			}
			if _, err := Check(in, out, Certificate{Original: []int{0, 1}}); err == nil || !strings.Contains(err.Error(), "associated maps") {
				t.Fatalf("associated input: %v", err)
			}
			for _, is := range []asm.Instructions{in, out} {
				if is[0].Map() == nil {
					continue
				}
				if _, err := json.Marshal(Instructions(is)); err == nil {
					t.Fatal("serialization silently discarded map identity")
				}
			}
		})
	}
	in := Instructions{asm.LoadMapPtr(asm.R1, 0).WithReference("map_a").WithSymbol("entry"), asm.LoadMapValue(asm.R2, 100, 24), asm.Return()}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Instructions
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	for i := range in {
		if !same(in[i], out[i]) || in[i].Reference() != out[i].Reference() || in[i].Symbol() != out[i].Symbol() {
			t.Fatalf("map operands lost in JSON: %s", b)
		}
	}
	for _, b := range []string{`[{"Map":{"FD":100}}]`, `[{"Metadata":{"Map":100}}]`} {
		if err := json.Unmarshal([]byte(b), &out); err == nil {
			t.Fatalf("accepted unsupported map metadata: %s", b)
		}
	}
}

func TestMapOperandMutations(t *testing.T) {
	for _, load := range []asm.Instruction{asm.LoadMapPtr(asm.R1, 100), asm.LoadMapValue(asm.R1, 100, 24)} {
		in := asm.Instructions{load, asm.Mov.Imm(asm.R0, 2), asm.Return()}
		c := Certificate{Original: []int{0, 1, 2}}
		if _, err := Check(in, in, c); err != nil {
			t.Fatal(err)
		}
		for _, mutation := range []string{"fd", "pseudo-kind", "value-offset"} {
			out := append(asm.Instructions(nil), in...)
			switch mutation {
			case "fd":
				out[0].Constant ^= 1
			case "pseudo-kind":
				out[0].Src ^= asm.PseudoMapFD ^ asm.PseudoMapValue
			case "value-offset":
				out[0].Constant ^= 1 << 32
			}
			if _, err := Check(in, out, c); err == nil {
				t.Fatalf("accepted %s for %v", mutation, load)
			}
		}
	}
}
