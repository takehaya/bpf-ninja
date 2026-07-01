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
	// One record is len(params)*8 bytes; it must fit in the ring (with head
	// room for the 8-byte record header) or bpf_ringbuf_reserve always
	// fails and nothing prints. In practice params is tiny; guard anyway.
	if recordSize := len(echoParams) * 8; recordSize >= EchoRingSize {
		return nil, fmt.Errorf("--arg-echo: %d params (%d B/record) exceed the %d B echo ring", len(echoParams), recordSize, EchoRingSize)
	}

	if _, err := validateTracingTarget(targetProg); err != nil {
		return nil, err
	}
	label, attachType := tracingLabel(isFexit)

	// Keep names within the 15-char BPF object-name limit so bpftool shows
	// them intact: "nj_entry_echo" (13) / "nj_exit_echo" (12).
	ring, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: fmt.Sprintf("nj_%s_echo", label), Type: ebpf.RingBuf, MaxEntries: EchoRingSize,
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

	// "njecho_entry" (12) / "njecho_exit" (11): distinct from the capture
	// probe's "xdp_ninja_entry"/"xdp_ninja_exit" and within the 15-char
	// BPF name limit (so the distinguishing name isn't truncated away).
	insns := buildArgEchoInsns(ring.FD(), argFilters, echoParams)
	if err := attachTracingProbe(probe, targetProg, fmt.Sprintf("njecho_%s", label), funcName, attachType, insns); err != nil {
		return nil, err
	}
	return probe, nil
}

// buildArgEchoInsns emits: save args ptr -> (arg filter gate) -> reserve a
// len(params)*8 byte ringbuf record -> store each arg as a u64 -> submit.
// The record layout is one native-endian u64 per param, in echoParams
// order, matching the CLI reader (formatEchoArgs) which decodes each u64.
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

	// R1 = args ptr; copy each arg into slot[i*8]. emitArgLoad (shared with
	// the arg-filter gate) owns the size/sign-extend logic.
	insns = append(insns, asm.LoadMem(asm.R1, asm.R10, -48, asm.DWord))
	for i, p := range params {
		insns = append(insns, emitArgLoad(asm.R3, asm.R1, int16(p.Index*8), p.Size, p.Signed)...)
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
