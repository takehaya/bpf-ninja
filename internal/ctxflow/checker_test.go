package ctxflow_test

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/ctxflow"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// helperPassPair builds, by hand, an entry that sets R1-R5 and calls leaf,
// whose first instruction calls helper and which then deletes key 0 from a
// map. The transformed stream passes the context to leaf in the register
// ctxflow picks; a hook observes the delete.
func helperPassPair(t *testing.T, helper asm.BuiltinFunc) (in, out asm.Instructions, cert injectcheck.Certificate, premises injectcheck.Premises) {
	t.Helper()
	format := [16]byte{}
	copy(format[:], "%d %d %d\n")
	for i := 0; i < 4; i++ {
		in = append(in, asm.StoreImm(asm.RFP, int16(-16+4*i), int64(int32(binary.LittleEndian.Uint32(format[4*i:]))), asm.Word))
	}
	in = append(in, asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16), asm.Mov.Imm(asm.R2, 10), asm.Mov.Imm(asm.R3, 11), asm.Mov.Imm(asm.R4, 22), asm.Mov.Imm(asm.R5, 33))
	call := len(in)
	in = append(in, asm.Call.Label("leaf"), asm.Return())
	leaf := len(in)
	in = append(in, helper.Call().WithSymbol("leaf"), asm.StoreImm(asm.RFP, -8, 0, asm.DWord), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.LoadMapPtr(asm.R1, 0).WithReference("map"))
	site := len(in)
	in = append(in, asm.FnMapDeleteElem.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return())

	reads, err := ctxflow.ArgReads(in, leaf)
	if err != nil {
		t.Fatal(err)
	}
	reg := ctxflow.FreeArg(reads)
	if reg == 0 {
		t.Fatalf("%v: ctxflow finds no free register (reads %06b)", helper, reads)
	}
	out = asm.Instructions{asm.StoreMem(asm.RFP, -24, asm.R1, asm.DWord)}
	cert = injectcheck.Certificate{Original: make([]int, len(in))}
	for i, ins := range in {
		switch i {
		case call:
			out = append(out, asm.LoadMem(reg, asm.RFP, -24, asm.DWord))
		case leaf:
			out = append(out, asm.StoreMem(asm.RFP, -24, reg, asm.DWord).WithSymbol("leaf"))
			ins = ins.WithSymbol("")
		case site:
			out = append(out, asm.StoreMem(asm.RFP, -32, asm.R2, asm.DWord))
		}
		cert.Original[i] = len(out)
		out = append(out, ins)
		if i == site {
			out = append(out, asm.StoreMem(asm.RFP, -40, asm.R0, asm.DWord), asm.LoadMem(asm.R1, asm.RFP, -24, asm.DWord), asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -40, asm.DWord))
		}
	}
	hook := len(out)
	out = append(out, asm.Mov.Imm(asm.R0, 0).WithSymbol("hook"), asm.Return())
	cert.Hooks = []injectcheck.Span{{Start: hook, End: len(out)}}
	premises = injectcheck.Premises{LowestOffset: -16, Targets: []injectcheck.SiteTarget{{Site: site, When: injectcheck.TargetAny, Hook: hook,
		Ctx: &injectcheck.CtxSource{Pass: []injectcheck.PassFrame{{Start: leaf, Reg: int(reg)}}}}}}
	return in, out, cert, premises
}

// The checker does not take read-before-write from the transformer's helper
// table. With bpf_trace_printk planted back to three arguments, ctxflow passes
// the context in R5, which the helper prints; the checker must refuse it.
func TestCheckerOwnsHelperReads(t *testing.T) {
	// A helper that really reads R1-R3 leaves R5 free, and the pair is accepted.
	in, out, cert, premises := helperPassPair(t, asm.FnProbeRead)
	if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != 1 {
		t.Fatalf("probe_read: counts=%+v err=%v", counts, err)
	}
	defer ctxflow.SetHelperArgs(int(asm.FnTracePrintk), 3)()
	in, out, cert, premises = helperPassPair(t, asm.FnTracePrintk)
	if reg := premises.Targets[0].Ctx.Pass[0].Reg; reg != int(asm.R5) {
		t.Fatalf("the planted table gives r%d, want r5", reg)
	}
	_, err := injectcheck.Check(in, out, cert, premises)
	var rejection *injectcheck.Rejection
	if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance || !strings.Contains(err.Error(), "reads r5 before writing it") {
		t.Fatalf("err = %v, want a rejection: trace_printk reads r5", err)
	}
}
