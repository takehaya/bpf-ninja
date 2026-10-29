package injectcheck

import (
	"encoding/json"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestLoadTimeMetadataIdentity(t *testing.T) {
	// Rebuild with: clang -target bpf -O2 -g -fdebug-compilation-dir=. -c
	// testdata/metadata.c -o testdata/metadata.elf
	first, err := ebpf.LoadCollectionSpec("testdata/metadata.elf")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ebpf.LoadCollectionSpec("testdata/metadata.elf")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ program, key string }{
		{"core", "github.com/cilium/ebpf/btf.coreRelocationMeta"},
		{"config", "github.com/cilium/ebpf.kconfigMetaKey"},
		{"function", "github.com/cilium/ebpf.kfuncMetaKey"},
		{"symbol", "github.com/cilium/ebpf.ksymMetaKey"},
	} {
		t.Run(tc.program, func(t *testing.T) {
			in := first.Programs[tc.program].Instructions
			other := second.Programs[tc.program].Instructions
			var at = -1
			for i, ins := range in {
				ids, err := loadMetadata(ins)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := ids[tc.key]; ok {
					at = i
					break
				}
			}
			if at < 0 {
				t.Fatalf("fixture is missing metadata %s", tc.key)
			}
			c := Certificate{Original: make([]int, len(in))}
			for i := range in {
				c.Original[i] = i
			}
			if _, err := Check(in, in, c, Premises{}); err != nil {
				t.Fatalf("identity: %v", err)
			}
			for _, name := range []string{"drop", "swap"} {
				out := clone(in)
				if name == "drop" {
					out[at].Metadata = asm.Metadata{}
					out[at] = out[at].WithSymbol(in[at].Symbol()).WithReference(in[at].Reference())
				} else {
					out[at] = other[at]
				}
				_, err := Check(in, out, c, Premises{})
				assertKind(t, err, MetadataChanged)
			}
			out := append(asm.Instructions{in[at]}, in...)
			for i := range c.Original {
				c.Original[i]++
			}
			_, err := Check(in, out, c, Premises{})
			assertKind(t, err, MetadataUnsupported)
			_, err = json.Marshal(Instructions(in))
			assertKind(t, err, MetadataUnsupported)
		})
	}
}

func TestInvalidOriginalRegister(t *testing.T) {
	in, out, c := p6Pair(asm.Instructions{asm.Mov.Imm(asm.R1, 0), asm.Mov.Reg(asm.R0, asm.R3), asm.Return()})
	in[2].Dst = 12
	out[c.Original[2]] = in[2]
	_, err := checkFixture(in, out, c)
	assertInputKind(t, err, InputRegister)
}
