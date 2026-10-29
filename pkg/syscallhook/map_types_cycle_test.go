package syscallhook

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

func TestMapTypesCyclicELF(t *testing.T) {
	timer := time.AfterFunc(5*time.Second, func() { panic("cyclic ELF supplementation did not terminate") })
	defer timer.Stop()
	// Minimal ELF64-BPF: legacy sessions hash map (4/8 byte key/value), u32,
	// and review_record { pointer -> Const -> ordinary TypeTag -> same Const }.
	const path = "testdata/maptypes/cycle.elf"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	typ, err := spec.Types.AnyTypeByName("review_record")
	if err != nil {
		t.Fatal(err)
	}
	target := typ.(*btf.Struct).Members[0].Type.(*btf.Pointer).Target.(*btf.Const)
	if target.Type.(*btf.TypeTag).Type != target {
		t.Fatal("ELF did not retain the qualified cycle")
	}
	p := inject.RawProgram{Maps: map[int32]inject.RawMap{7: {Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 8}}}
	rule := Rule{Map: "sessions", MapBTF: &MapBTF{ELF: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), KeyType: "u32", ValueType: "review_record"}}
	if err := supplyMapTypes(&p, rule); err == nil || !strings.Contains(err.Error(), "map types ELF: map value type: cyclic pointer pointee") {
		t.Fatalf("expected cyclic ELF refusal, got %v", err)
	}
	if p.Maps[7].Key != nil || p.Maps[7].Value != nil {
		t.Fatal("partially supplied types on cycle refusal")
	}
}
