// Package program — --arg-echo diagnostic path.
//
// arg-echo answers "what value does this function actually receive in a
// given integer argument?" — the question that comes up when an
// --arg-filter never matches because the caller encodes the value
// differently than expected (e.g. an IMSI carried as TBCD rather than a
// plain decimal). Instead of the packet-capture pipeline, the probe emits
// just the target function's integer args to a dedicated ringbuf, and the
// CLI prints them; --arg-filter (if given) still gates which calls echo.
package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"

	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/filter"
)

// EchoRingSize is the byte capacity of the arg-echo ringbuf. 64 KiB is a
// power of two and a page multiple (a valid BPF ringbuf size) — ample for
// a low-rate diagnostic that emits len(params)*8 bytes per matched call.
// Exported so the CLI reader (fastrb) can mmap the ring with the right
// size.
const EchoRingSize = 64 * 1024

// LoadArgEcho builds and attaches an echo-only probe: it stores the tracing
// args pointer, applies any argFilters as a gate, then emits the selected
// integer args (echoParams, in order) as consecutive u64s to a dedicated
// ringbuf. It deliberately skips the sharded packet ringbuf, scratch map
// and packet filter used by the capture path.
func LoadArgEcho(
	targetProg *ebpf.Program,
	funcName string,
	argFilters []filter.ArgFilter,
	echoParams []attach.FuncParamInfo,
	isFexit bool,
) (*Probe, error) {
	if len(echoParams) == 0 {
		return nil, fmt.Errorf("--arg-echo requires at least one filterable integer parameter (see --list-params)")
	}

	info, err := targetProg.Info()
	if err != nil {
		return nil, fmt.Errorf("reading target program info: %w", err)
	}
	if pt := info.Type; pt != ebpf.XDP && pt != ebpf.SchedCLS && pt != ebpf.SchedACT {
		return nil, fmt.Errorf("target program type %s is not supported (need XDP, SchedCLS, or SchedACT)", pt)
	}

	label := "entry"
	attachType := ebpf.AttachTraceFEntry
	if isFexit {
		label = "exit"
		attachType = ebpf.AttachTraceFExit
	}

	ring, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: fmt.Sprintf("ninja_%s_echo", label), Type: ebpf.RingBuf, MaxEntries: EchoRingSize,
	})
	if err != nil {
		return nil, fmt.Errorf("creating arg-echo ringbuf: %w", err)
	}

	probe := &Probe{
		IsFexit:    isFexit,
		EchoRing:   ring,
		EchoParams: echoParams,
		maps:       []*ebpf.Map{ring},
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: fmt.Sprintf("xdp_ninja_%s_e", label), Type: ebpf.Tracing, AttachType: attachType,
		AttachTo: funcName, AttachTarget: targetProg,
		Instructions: buildArgEchoInsns(ring.FD(), argFilters, echoParams), License: "GPL",
	})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("loading %s arg-echo program: %w", label, err)
	}
	probe.prog = prog

	l, err := link.AttachTracing(link.TracingOptions{Program: prog, AttachType: attachType})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("attaching %s arg-echo: %w", label, err)
	}
	probe.link = l

	return probe, nil
}

// buildArgEchoInsns emits: save args ptr -> (arg filter gate) -> reserve a
// len(params)*8 byte ringbuf record -> store each arg as a u64 -> submit.
// The record layout is one native-endian u64 per param, in echoParams
// order, matching program.RecordEchoArgs on the reader side.
func buildArgEchoInsns(echoRingFD int, argFilters []filter.ArgFilter, params []attach.FuncParamInfo) asm.Instructions {
	insns := asm.Instructions{
		// stack[-48] = tracing args ptr (buildArgFilter and the arg
		// loads below both read it from here).
		asm.StoreMem(asm.R10, -48, asm.R1, asm.DWord),
	}
	// Optional gate: jumps to "exit" when the arg predicate doesn't match.
	insns = append(insns, buildArgFilter(argFilters)...)

	// reserve(echoRing, len*8, 0); R0 = slot ptr (0 on failure).
	insns = append(insns,
		asm.LoadMapPtr(asm.R1, echoRingFD),
		asm.Mov.Imm(asm.R2, int32(len(params)*8)),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
	)

	// R1 = args ptr; copy each arg into slot[i*8].
	insns = append(insns, asm.LoadMem(asm.R1, asm.R10, -48, asm.DWord))
	for i, p := range params {
		var ls asm.Size
		switch p.Size {
		case 1:
			ls = asm.Byte
		case 2:
			ls = asm.Half
		case 4:
			ls = asm.Word
		default:
			ls = asm.DWord
		}
		insns = append(insns, asm.LoadMem(asm.R3, asm.R1, int16(p.Index*8), ls))
		if p.Signed && p.Size < 8 {
			// sign-extend to 64-bit so the reader can render it as int64.
			shift := int32((8 - p.Size) * 8)
			insns = append(insns, asm.LSh.Imm(asm.R3, shift), asm.ArSh.Imm(asm.R3, shift))
		}
		insns = append(insns, asm.StoreMem(asm.R0, int16(i*8), asm.R3, asm.DWord))
	}

	// submit(slot, 0); then exit.
	insns = append(insns,
		asm.Mov.Reg(asm.R1, asm.R0),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return insns
}
