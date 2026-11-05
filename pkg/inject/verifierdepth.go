package inject

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// KernelInfo contains the kernel identity needed by stack-depth accounting.
type KernelInfo struct {
	Release      string
	Major, Minor int
}

// FrameFloor records the two independently observed depths for one function.
type FrameFloor struct {
	Name              string      `json:"name"`
	Start             int         `json:"-"`
	VerifiedDepth     int         `json:"verified_depth"`
	TextDepth         int         `json:"text_depth"`
	TextExact         bool        `json:"text_exact"`
	Floor             int16       `json:"floor"`
	Source            string      `json:"source"`
	Dead              bool        `json:"dead,omitempty"`
	SkipReason        string      `json:"skip_reason,omitempty"`
	Note              string      `json:"note,omitempty"`
	Slots             *FrameSlots `json:"slots,omitempty"`
	DeepestTextAccess *TextAccess `json:"deepest_text_access,omitempty"`
}

// TextAccess identifies the deepest direct RFP access when one is present.
type TextAccess struct {
	PC     int    `json:"pc"`
	File   string `json:"file,omitempty"`
	Line   uint32 `json:"line,omitempty"`
	Offset int16  `json:"offset"`
}

type FrameSlots struct {
	Context int `json:"ctx"`
	Key     int `json:"key"`
	Result  int `json:"result"`
	Map     int `json:"map"`
	Value   int `json:"value"`
}

// StackReport is the verifier-backed stack accounting for one trial load.
type StackReport struct {
	Source           string            `json:"source"`
	Kernel           string            `json:"kernel,omitempty"`
	FrameRounding    int               `json:"frame_rounding,omitempty"`
	Functions        []FrameFloor      `json:"functions"`
	SkippedFunctions []SkippedFunction `json:"skipped_functions,omitempty"`
	Error            string            `json:"error,omitempty"`
}

type SkippedFunction struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Frames returns the usable per-function floors. Dead and unsafe old-kernel
// functions are omitted so callers cannot accidentally instrument them.
func (r StackReport) Frames() map[string]int16 {
	out := make(map[string]int16)
	for _, f := range r.Functions {
		if !f.Dead && f.SkipReason == "" {
			out[f.Name] = f.Floor
		}
	}
	return out
}

// ParseStackDepths parses the numeric prefix of the verifier's stats line.
// Kernel and distribution suffixes after the number list are ignored.
func ParseStackDepths(log string) ([]int, error) {
	const marker = "stack depth "
	for _, line := range strings.Split(log, "\n") {
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		s := line[i+len(marker):]
		var out []int
		for {
			end := 0
			for end < len(s) && s[end] >= '0' && s[end] <= '9' {
				end++
			}
			if end == 0 {
				break
			}
			n, err := strconv.Atoi(s[:end])
			if err != nil {
				return nil, fmt.Errorf("stack depth: %w", err)
			}
			out = append(out, n)
			if end == len(s) || s[end] != '+' {
				break
			}
			s = s[end+1:]
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("stack depth line has no depths")
		}
		return out, nil
	}
	return nil, fmt.Errorf("verifier log has no stack depth line")
}

type functionRange struct {
	name       string
	start, end int
}

func instructionFunctions(insns asm.Instructions) ([]functionRange, error) {
	var out []functionRange
	for i := range insns {
		fn := btf.FuncMetadata(&insns[i])
		if i != 0 && fn == nil {
			continue
		}
		name := insns[i].Symbol()
		if fn != nil {
			name = fn.Name
		}
		if name == "" {
			return nil, fmt.Errorf("function at instruction %d has no name", i)
		}
		if len(out) > 0 {
			out[len(out)-1].end = i
		}
		out = append(out, functionRange{name: name, start: i})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("program has no functions")
	}
	out[len(out)-1].end = len(insns)
	return out, nil
}

// FrameFloors combines a successful trial load's verifier depths with direct
// instruction accesses. The latter keeps fastcall spill removal from making a
// floor shallower than the original bytecode.
func FrameFloors(depths []int, loadedFuncs []string, insns asm.Instructions, kernel KernelInfo) (StackReport, error) {
	report := StackReport{Source: "verifier", Kernel: kernel.Release, Functions: []FrameFloor{}}
	if len(depths) != len(loadedFuncs) {
		return report, fmt.Errorf("verifier reported %d stack depths for %d loaded functions", len(depths), len(loadedFuncs))
	}
	loaded := make(map[string]int, len(loadedFuncs))
	for i, name := range loadedFuncs {
		if _, exists := loaded[name]; exists {
			return report, fmt.Errorf("loaded function name %q is ambiguous", name)
		}
		if depths[i] < 0 || depths[i] > 512 {
			return report, fmt.Errorf("function %q has invalid verifier stack depth %d", name, depths[i])
		}
		loaded[name] = depths[i]
	}
	ranges, err := instructionFunctions(insns)
	if err != nil {
		return report, err
	}
	seen := make(map[string]bool, len(ranges))
	for _, fn := range ranges {
		if seen[fn.name] {
			return report, fmt.Errorf("function name %q is ambiguous", fn.name)
		}
		seen[fn.name] = true
		verified, live := loaded[fn.name]
		floor := FrameFloor{Name: fn.name, Start: fn.start, VerifiedDepth: verified}
		floor.DeepestTextAccess = deepestTextAccess(insns, fn)
		if !live {
			floor.TextDepth, floor.TextExact = stackFrameDepthExact(insns[fn.start:fn.end], 0)
			floor.Floor = int16(-floor.TextDepth)
			floor.Dead, floor.Source = true, "dead"
			report.Functions = append(report.Functions, floor)
			continue
		}
		text, exact := stackFrameDepthExact(insns[fn.start:fn.end], int16(-verified))
		floor.TextDepth, floor.TextExact = text, exact
		depth := max(verified, text)
		floor.Floor = int16(-depth)
		floor.Source = "verifier"
		if text > verified {
			floor.Source = "text"
		} else if verified > text {
			floor.Note = "the verifier counted more than the deepest direct access (aliases, callee writes through a caller pointer, or verifier-added stack use)"
		}
		slots := lookupSlots(floor.Floor)
		floor.Slots = &FrameSlots{Context: slots.ctx, Key: slots.key, Result: slots.result, Map: slots.mapSlot, Value: slots.updateValue(true)}
		if kernel.Major < 6 || kernel.Major == 6 && kernel.Minor < 8 {
			if !exact {
				floor.SkipReason = "kernel before 6.8 does not count variable-offset stack accesses and the text scan is not exact"
				report.SkippedFunctions = append(report.SkippedFunctions, SkippedFunction{Name: fn.name, Reason: floor.SkipReason})
			}
		}
		report.Functions = append(report.Functions, floor)
	}
	for _, name := range loadedFuncs {
		if !seen[name] {
			return report, fmt.Errorf("loaded function %q is absent from the original instruction metadata", name)
		}
	}
	return report, nil
}

// FrameFloorsRaw restores function and line metadata from a syscall load
// before computing floors. Raw instruction bytes don't carry either one.
func FrameFloorsRaw(depths []int, loadedFuncs []string, program RawProgram, kernel KernelInfo) (StackReport, error) {
	insns, _, _, err := prepareRawLookup(program)
	if err != nil {
		return StackReport{}, err
	}
	return FrameFloors(depths, loadedFuncs, insns, kernel)
}

func deepestTextAccess(insns asm.Instructions, fn functionRange) *TextAccess {
	var deepest *TextAccess
	var file string
	var line uint32
	prefixSlots := 0
	if fn.start != 0 {
		prefixSlots = int(insns[:fn.start].Size() / 8)
	}
	it := insns[fn.start:fn.end].Iterate()
	for it.Next() {
		ins := it.Ins
		if src, ok := ins.Source().(*btf.Line); ok {
			file, line = src.FileName(), src.LineNumber()
		}
		class := ins.OpCode.Class()
		direct := class == asm.LdXClass && ins.Src == asm.RFP ||
			(class == asm.StClass || class == asm.StXClass) && ins.Dst == asm.RFP
		if !direct || ins.Offset >= 0 || deepest != nil && ins.Offset >= deepest.Offset {
			continue
		}
		deepest = &TextAccess{PC: prefixSlots + int(it.Offset), File: file, Line: line, Offset: ins.Offset}
	}
	return deepest
}
