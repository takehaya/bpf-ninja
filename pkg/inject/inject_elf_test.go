package inject

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// This compiler-backed check covers the exported ELF entry point without BPF
// privileges. The standalone kernel test uses asm and never invokes clang.
func TestTransformThroughELF(t *testing.T) {
	obj := testutil.CompileBPFSource(t, `
#define SEC(name) __attribute__((section(name), used))
struct xdp_md { unsigned int data, data_end; };
SEC("xdp") int ingress(struct xdp_md *ctx) {
    asm volatile("*(u32 *)(r10 - 4) = 7\n"
                 "r0 = r10\n"
                 "r0 += -4\n"
                 "r2 = *(u32 *)(r0 + 0)\n"
                 "r1 = 0\n" ::: "r0", "r1", "r2", "memory");
    return 2;
}
char _license[] SEC("license") = "GPL";
`)
	elf, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(elf)
	src, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		t.Fatal(err)
	}
	prog := src.Programs["ingress"]
	var site uint32
	found := 0
	it := prog.Instructions.Iterate()
	for it.Next() {
		if sameInstr(*it.Ins, asm.LoadMem(asm.R2, asm.R0, 0, asm.Word)) {
			site, found = uint32(it.Offset), found+1
		}
	}
	if found != 1 {
		t.Fatalf("fixture load count %d, want one", found)
	}
	sum := sha256.Sum256(elf)
	req := Request{ELFSHA256: strings.ToUpper(hex.EncodeToString(sum[:])), ProgramName: "ingress", SitePC: site,
		HookName: "observe_u32", Load: LoadShape{PtrReg: asm.R0}, Stack: StackAudit{LowestOffset: -8}}
	res, err := Transform(elf, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Spec.Programs["ingress"].Instructions.Size() != prog.Instructions.Size()+72 || res.AddedBytes != 72 {
		t.Fatal("unexpected transformed instruction growth")
	}
	want, err := checksum(prog.Instructions, src.ByteOrder)
	if err != nil || res.SourceChecksum != want {
		t.Fatalf("source checksum %q, want %q (%v)", res.SourceChecksum, want, err)
	}
	if !bytes.Equal(elf, before) {
		t.Fatal("ELF input mutated")
	}
}
