package inject_test

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// Example_cooperativeLoader shows a cooperative loader: it reads the pinned ELF
// bytes the operator audited, applies the typed observation transform, and only
// then builds the collection. If the transform refuses, the loader stops — it
// never falls back to loading the unmodified ELF.
func Example_cooperativeLoader() {
	// The operator audits a specific build and records its SHA-256, the program
	// and raw-slot site, the load shape, and the stack low-water mark. These are
	// synthetic placeholders; use the values from your own audited build.
	const auditedELF = "/run/pinned/target.elf.audited"
	const auditedSHA = "0000000000000000000000000000000000000000000000000000000000000000"

	elf, err := os.ReadFile(auditedELF)
	if err != nil {
		return // handle I/O error in real code
	}

	// Transform hashes exactly these bytes; there is no second read of the path,
	// so the audit cannot be invalidated between check and use.
	res, err := inject.Transform(elf, inject.Request{
		ELFSHA256:   auditedSHA,
		ProgramName: "ingress_prog",
		SitePC:      1234,
		HookName:    "obs_point",
		Load:        inject.LoadShape{PtrReg: asm.R0, Offset: 0},
		Stack:       inject.StackAudit{LowestOffset: -128},
	})
	if err != nil {
		// A refusal is terminal: do NOT load the unmodified ELF as a fallback.
		fmt.Println("transform refused:", err)
		return
	}

	// res.Spec is an independent clone; the parsed source was left untouched.
	// Pin res.TransformedChecksum alongside res.SourceChecksum to audit output.
	coll, err := ebpf.NewCollectionWithOptions(res.Spec, ebpf.CollectionOptions{})
	if err != nil {
		return // verifier / permission error
	}
	defer coll.Close()

	// Attach an fentry program to res.HookName to observe (site, value).
	_ = coll
}
