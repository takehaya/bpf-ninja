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
	Name          string `json:"name"`
	Start         int    `json:"-"`
	VerifiedDepth int    `json:"verified_depth"`
	TextDepth     int    `json:"text_depth"`
	TextExact     bool   `json:"text_exact"`
	Floor         int16  `json:"floor"`
	Source        string `json:"source"`
	Dead          bool   `json:"dead,omitempty"`
	SkipReason    string `json:"skip_reason,omitempty"`
}

// StackReport is the verifier-backed stack accounting for one trial load.
type StackReport struct {
	Source        string       `json:"source"`
	Kernel        string       `json:"kernel,omitempty"`
	FrameRounding int          `json:"frame_rounding,omitempty"`
	Functions     []FrameFloor `json:"functions"`
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
		if !live {
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
		}
		if kernel.Major < 6 || kernel.Major == 6 && kernel.Minor < 8 {
			if !exact {
				floor.SkipReason = "kernel before 6.8 does not count variable-offset stack accesses and the text scan is not exact"
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
