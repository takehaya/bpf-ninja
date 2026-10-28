//go:build enable_libpcap

package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
	"golang.org/x/net/bpf"
)

// CBPFEnabled reports whether legacy tcpdump filter compilation is built in.
const CBPFEnabled = true

func compileCBPF(expr string, progType ebpf.ProgramType) (codegen.Output, error) {
	// Compile against the hook's link type: on an L3-start hook
	// (LinkTypeRaw) libpcap then resolves `ip` / `tcp port 80` at the
	// right offsets and rejects L2 atoms like `ether host` on its own.
	linkType := layers.LinkTypeEthernet
	if h, ok := hook.ByProgramType(progType); ok {
		linkType = h.LinkType
	}
	if linkType == layers.LinkTypeRaw {
		// libpcap needs the platform DLT_RAW, not the capture-file LINKTYPE_RAW (101).
		linkType = layers.LinkType(pcap.DatalinkNameToVal("RAW"))
	}
	rawInsns, err := pcap.CompileBPFFilter(linkType, 65535, expr)
	if err != nil {
		return codegen.Output{}, fmt.Errorf("compiling filter %q: %w", expr, err)
	}

	bpfInsns := make([]bpf.Instruction, len(rawInsns))
	for i, insn := range rawInsns {
		bpfInsns[i] = bpf.RawInstruction{Op: insn.Code, Jt: insn.Jt, Jf: insn.Jf, K: insn.K}.Disassemble()
	}

	cbpfcInsns, err := cbpfc.ToEBPF(bpfInsns, cbpfc.EBPFOpts{
		PacketStart: asm.R0, PacketEnd: asm.R1, Result: asm.R2,
		ResultLabel: "filter_result",
		Working:     [4]asm.Register{asm.R2, asm.R3, asm.R4, asm.R5},
		LabelPrefix: "filter",
	})
	if err != nil {
		return codegen.Output{}, err
	}
	return codegen.Output{Main: cbpfcInsns}, nil
}
