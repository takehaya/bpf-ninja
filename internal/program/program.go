// Package program dynamically builds and attaches a single fentry or fexit tracing program.
// When a filter is specified, a cbpfc-compiled eBPF filter is embedded.
package program

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cloudflare/cbpfc"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// Probe は fentry または fexit の1つのトレーシングポイント。
type Probe struct {
	EventsMap *ebpf.Map
	IsFexit   bool
	maps      []*ebpf.Map
	prog      *ebpf.Program
	link      link.Link
}

func (p *Probe) Close() error {
	var errs []error
	if p.link != nil {
		if err := p.link.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.prog != nil {
		if err := p.prog.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, m := range p.maps {
		if err := m.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// LoadEntry は fentry (前段) probe を作成してアタッチする。
func LoadEntry(targetProg *ebpf.Program, funcName string, filterExpr string) (*Probe, error) {
	return loadProbe(targetProg, funcName, filterExpr, false)
}

// LoadExit は fexit (後段) probe を作成してアタッチする。
func LoadExit(targetProg *ebpf.Program, funcName string, filterExpr string) (*Probe, error) {
	return loadProbe(targetProg, funcName, filterExpr, true)
}

func loadProbe(targetProg *ebpf.Program, funcName string, filterExpr string, isFexit bool) (*Probe, error) {
	var filterInsns asm.Instructions
	if filterExpr != "" {
		fi, err := compileFilter(filterExpr)
		if err != nil {
			return nil, err
		}
		filterInsns = fi
	}

	label := "entry"
	attachType := ebpf.AttachTraceFEntry
	if isFexit {
		label = "exit"
		attachType = ebpf.AttachTraceFExit
	}

	eventsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: fmt.Sprintf("ninja_%s_pe", label), Type: ebpf.PerfEventArray,
	})
	if err != nil {
		return nil, fmt.Errorf("creating perf map: %w", err)
	}

	probe := &Probe{
		EventsMap: eventsMap, IsFexit: isFexit,
		maps: []*ebpf.Map{eventsMap},
	}

	// フィルタがある場合のみ scratch buffer を作成
	// (verifier が xdp->data 経由のメモリアクセスを scalar として拒否するため、
	//  PTR_TO_MAP_VALUE にコピーしてからフィルタを実行する)
	scratchFD := 0
	if len(filterInsns) > 0 {
		scratchMap, err := ebpf.NewMap(&ebpf.MapSpec{
			Name: fmt.Sprintf("ninja_%s_sc", label), Type: ebpf.PerCPUArray,
			KeySize: 4, ValueSize: scratchBufSize, MaxEntries: 1,
		})
		if err != nil {
			_ = probe.Close()
			return nil, fmt.Errorf("creating scratch map: %w", err)
		}
		probe.maps = append(probe.maps, scratchMap)
		scratchFD = scratchMap.FD()
	}

	insns := buildTracingInsns(filterInsns, eventsMap.FD(), scratchFD, isFexit)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: fmt.Sprintf("xdp_ninja_%s", label), Type: ebpf.Tracing, AttachType: attachType,
		AttachTo: funcName, AttachTarget: targetProg,
		Instructions: insns, License: "GPL",
	})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("loading %s program: %w", label, err)
	}
	probe.prog = prog

	l, err := link.AttachTracing(link.TracingOptions{Program: prog, AttachType: attachType})
	if err != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("attaching %s: %w", label, err)
	}
	probe.link = l

	return probe, nil
}

// --- Filter compilation (tcpdump expr → cBPF → eBPF) ---

func compileFilter(expr string) (asm.Instructions, error) {
	rawInsns, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, expr)
	if err != nil {
		return nil, fmt.Errorf("compiling filter %q: %w", expr, err)
	}

	bpfInsns := make([]bpf.Instruction, len(rawInsns))
	for i, insn := range rawInsns {
		bpfInsns[i] = bpf.RawInstruction{Op: insn.Code, Jt: insn.Jt, Jf: insn.Jf, K: insn.K}.Disassemble()
	}

	return cbpfc.ToEBPF(bpfInsns, cbpfc.EBPFOpts{
		PacketStart: asm.R0, PacketEnd: asm.R1, Result: asm.R2,
		ResultLabel: "filter_result",
		Working:     [4]asm.Register{asm.R2, asm.R3, asm.R4, asm.R5},
		LabelPrefix: "filter",
	})
}

// --- eBPF program generation ---
//
// レジスタ割り当て (callee-saved):
//   R6 = xdp_buff ポインタ (trusted, bpf_xdp_output に渡す)
//   R7 = xdp->data (パケット先頭)
//   R8 = xdp->data_end (パケット末尾)
//   R9 = パケット長
//
// スタックレイアウト (R10 からの負オフセット):
//   -8:  metadata: u32 action
//   -12: metadata: u8 mode + u8 _pad[3]
//   -16: map lookup の key
//   -24: scratch buffer ポインタ (フィルタ時のみ)
//   -48: tracing args ポインタの退避
//
// bpf_xdp_output を使うことで:
//   - パケットデータはカーネルが xdp_buff から直接コピー (bpf_probe_read_kernel 不要)
//   - per-CPU event buffer map が不要
//   - メタデータ (action, mode) だけスタック上に構築
//
// perf event のデータフォーマット (ユーザーランドで受け取る):
//   [metadata (8B)] [パケットデータ (カーネルが自動付加)]
//   metadata: u32 action + u8 mode + u8 _pad[3]

const (
	scratchBufSize = 256
	maxCapLen      = 1500
	metadataSize   = 8 // action(4) + mode(1) + pad(3)
)

const bpfFCurrentCPU int64 = 0xFFFFFFFF

func buildTracingInsns(filter asm.Instructions, eventsFD, scratchFD int, isFexit bool) asm.Instructions {
	var insns asm.Instructions
	insns = append(insns, loadPacketPointers()...)
	insns = append(insns, runFilter(filter, scratchFD)...)
	insns = append(insns, captureWithXdpOutput(eventsFD, isFexit)...)
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	return insns
}

// loadPacketPointers は tracing args から xdp_buff のフィールドを直接読む。
// xdp_buff は trusted pointer (BTF型付き) なので直接フィールドアクセスが可能。
//
// 終了時: R6=xdp_buff, R7=data, R8=data_end, R9=pkt_len, stack[-48]=args
func loadPacketPointers() asm.Instructions {
	return asm.Instructions{
		asm.StoreMem(asm.R10, -48, asm.R1, asm.DWord), // args ポインタを退避
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),     // R6 = args[0] = xdp_buff *

		// xdp_buff の構造体フィールドを直接読む (trusted pointer)
		asm.LoadMem(asm.R7, asm.R6, 0, asm.DWord),     // R7 = xdp_buff->data
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),     // R8 = xdp_buff->data_end

		asm.Mov.Reg(asm.R9, asm.R8),                    // R9 = pkt_len
		asm.Sub.Reg(asm.R9, asm.R7),
	}
}

// runFilter は scratch buffer にヘッダをコピーして cbpfc フィルタを実行する。
func runFilter(filter asm.Instructions, scratchFD int) asm.Instructions {
	if len(filter) == 0 {
		return nil
	}

	insns := asm.Instructions{
		// scratch buffer を取得
		asm.LoadMapPtr(asm.R1, scratchFD),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.StoreMem(asm.R10, -24, asm.R0, asm.DWord),

		// ヘッダコピー: bpf_probe_read_kernel(scratch, 256, data)
		asm.Mov.Reg(asm.R1, asm.R0),
		asm.Mov.Imm(asm.R2, int32(scratchBufSize)),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.FnProbeReadKernel.Call(),

		// R0 = scratch 先頭, R1 = scratch + min(pkt_len, 256)
		asm.LoadMem(asm.R0, asm.R10, -24, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.JLE.Imm(asm.R1, int32(scratchBufSize), "len_ok"),
		asm.Mov.Imm(asm.R1, int32(scratchBufSize)),
		asm.Add.Reg(asm.R1, asm.R0).WithSymbol("len_ok"),
	}
	insns = append(insns, filter...)
	insns = append(insns, asm.JEq.Imm(asm.R2, 0, "exit").WithSymbol("filter_result"))
	return insns
}

// captureWithXdpOutput は bpf_xdp_output でパケットを perf buffer に送出する。
//
// bpf_xdp_output(xdp_buff, perf_map, (pkt_len << 32) | BPF_F_CURRENT_CPU, &metadata, sizeof(metadata))
//
// カーネルが xdp_buff->data から pkt_len バイトを自動的にコピーして
// perf event に付加してくれるので、bpf_probe_read_kernel でのパケットコピーが不要。
//
// ユーザーランドで受け取る RawSample のフォーマット:
//   [metadata (8B)] [パケットデータ (pkt_len バイト)]
func captureWithXdpOutput(eventsFD int, isFexit bool) asm.Instructions {
	insns := asm.Instructions{}

	// --- メタデータをスタック上に構築 ---
	if isFexit {
		// action = args[1]
		insns = append(insns,
			asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord), // saved args ptr
			asm.LoadMem(asm.R2, asm.R2, 8, asm.DWord),    // args[1] = XDP action
			asm.StoreMem(asm.R10, -8, asm.R2, asm.Word),   // stack[-8] = action (u32)
			asm.StoreImm(asm.R10, -4, 1, asm.Byte),        // stack[-4] = mode=1 (exit)
		)
	} else {
		insns = append(insns,
			asm.StoreImm(asm.R10, -8, 0, asm.Word),        // stack[-8] = action=0
			asm.StoreImm(asm.R10, -4, 0, asm.Byte),        // stack[-4] = mode=0 (entry)
		)
	}

	// padding
	insns = append(insns,
		asm.StoreImm(asm.R10, -3, 0, asm.Byte),
		asm.StoreImm(asm.R10, -2, 0, asm.Half),
	)

	// --- bpf_xdp_output ---
	// R1 = xdp_buff (カーネルがここからパケットデータを読む)
	// R2 = perf event map
	// R3 = (cap_len << 32) | BPF_F_CURRENT_CPU
	// R4 = &metadata (スタック上)
	// R5 = sizeof(metadata)
	insns = append(insns,
		asm.Mov.Reg(asm.R1, asm.R6),                      // R1 = xdp_buff
		asm.LoadMapPtr(asm.R2, eventsFD),                  // R2 = perf map

		// R3 = flags: (cap_len << 32) | BPF_F_CURRENT_CPU
		// cap_len = min(pkt_len, 1500)
		asm.Mov.Reg(asm.R3, asm.R9),                      // R3 = pkt_len
		asm.JLE.Imm(asm.R3, maxCapLen, "xdp_out_cap_ok"),
		asm.Mov.Imm(asm.R3, maxCapLen),
		asm.LSh.Imm(asm.R3, 32).WithSymbol("xdp_out_cap_ok"), // R3 = cap_len << 32
		asm.LoadImm(asm.R0, bpfFCurrentCPU, asm.DWord),   // R0 = BPF_F_CURRENT_CPU
		asm.Or.Reg(asm.R3, asm.R0),                        // R3 = (cap_len << 32) | BPF_F_CURRENT_CPU

		asm.Mov.Reg(asm.R4, asm.R10),                     // R4 = &metadata
		asm.Add.Imm(asm.R4, -int32(metadataSize)),
		asm.Mov.Imm(asm.R5, int32(metadataSize)),         // R5 = 8

		asm.FnXdpOutput.Call(),
	)

	return insns
}
