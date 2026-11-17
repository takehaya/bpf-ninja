package inject

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// rawEntryPoints runs every raw entry point on raw and returns their errors.
func rawEntryPoints(raw RawProgram) []error {
	mapCalls, err1 := DiscoverMapCallsRaw(raw)
	_, err2 := DiscoverCallSitesRaw(raw, mapCalls)
	_, err3 := DiscoverLookupsRaw(raw)
	_, err4 := TransformLookupRaw(raw, LookupRequestRaw{Calls: []string{"bpf_ktime_get_ns"}, Entry: true, HookName: "h", Stack: StackAudit{LowestOffset: -8}})
	_, err5 := TransformLookupRaw(raw, LookupRequestRaw{Auto: true, HookName: "h", Stack: StackAudit{LowestOffset: -8}})
	_, err6 := FrameFloorsRaw([]int{8}, []string{"p"}, raw, KernelInfo{})
	return []error{err1, err2, err3, err4, err5, err6}
}

// A register field past r10, which the kernel checks only on the paths it
// visits, is refused by every raw entry point instead of indexing the
// per-register state.
func TestRawRegisterFieldRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*asm.Instruction)
	}{
		{"mov dst", func(ins *asm.Instruction) { *ins = asm.Mov.Imm(13, 5) }},
		{"mov src", func(ins *asm.Instruction) { *ins = asm.Mov.Reg(asm.R0, 11) }},
		{"atomic src", func(ins *asm.Instruction) { *ins = asm.StoreXAdd(asm.RFP, 12, asm.DWord) }},
		{"load dst", func(ins *asm.Instruction) { *ins = asm.LoadMem(14, asm.RFP, -8, asm.DWord) }},
		{"load src", func(ins *asm.Instruction) { *ins = asm.LoadMem(asm.R0, 15, 0, asm.DWord) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := calleesRaw(t, 7, 8)
			tc.edit(&raw.Instructions[6]) // the r0 = 0 before bpf_ktime_get_ns
			for i, err := range rawEntryPoints(raw) {
				if !errors.Is(err, ErrRefused) {
					t.Errorf("entry point %d: %v", i, err)
				}
			}
		})
	}
}

// FuzzRawRegisterFields sets the register byte of one instruction: no raw
// entry point may panic, and a field past r10 is refused.
func FuzzRawRegisterFields(f *testing.F) {
	for r := byte(11); r <= 15; r++ {
		f.Add(uint8(6), r)    // dst 11..15
		f.Add(uint8(6), r<<4) // src 11..15
	}
	f.Add(uint8(2), uint8(0xa2))
	f.Fuzz(func(t *testing.T, index, regs uint8) {
		raw := calleesRaw(t, 7, 8)
		ins := &raw.Instructions[int(index)%len(raw.Instructions)]
		ins.Dst, ins.Src = asm.Register(regs&0xf), asm.Register(regs>>4)
		errs := rawEntryPoints(raw)
		if ins.Dst > asm.R10 || ins.Src > asm.R10 {
			for i, err := range errs {
				if !errors.Is(err, ErrRefused) {
					t.Errorf("entry point %d: %v", i, err)
				}
			}
		}
	})
}
