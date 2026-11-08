package interp_test

import (
	"strings"
	"testing"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
	"github.com/takehaya/bpf-ninja/tools/regionval/interp"
)

// The register fields are 4 bits wide, so a raw instruction can name r11 to
// r15. The interpreter must refuse it with an error instead of indexing past
// the register file. (core.Allowed already keeps such instructions out of
// every window Check validates.)
func TestRegisterFieldAboveR10(t *testing.T) {
	for _, x := range []core.Insn{
		{Op: 0xbf, Dst: 11, Src: 1},           // dst = src
		{Op: 0xbf, Dst: 1, Src: 15},           // dst = src
		{Op: 0x07, Dst: 12},                   // dst += imm
		{Op: 0x79, Dst: 13, Src: 10, Off: -8}, // dst = *(u64 *)(src + off)
		{Op: 0x79, Dst: 1, Src: 14, Off: -8},  // dst = *(u64 *)(src + off)
		{Op: 0x7b, Dst: 11, Src: 1, Off: -8},  // *(u64 *)(dst + off) = src
		{Op: 0x7b, Dst: 10, Src: 15, Off: -8}, // *(u64 *)(dst + off) = src
		{Op: 0x15, Dst: 11, Off: 0},           // if dst == imm
		{Op: 0x5d, Dst: 1, Src: 12, Off: 0},   // if dst != src
		{Op: 0xbc, Dst: 15, Src: 1},           // wdst = wsrc
	} {
		w := core.Window{Kind: core.KindEntry, Insns: []core.Insn{x}, Center: -1, Floor: -8, HasFloor: true}
		_, err := runNoPanic(t, w)
		if err == nil || !strings.Contains(err.Error(), "register") {
			t.Errorf("%v: err = %v, want a register error", x, err)
		}
	}
}

func runNoPanic(t *testing.T, w core.Window) (out interp.Output, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%v: panic: %v", w.Insns[0], r)
		}
	}()
	return interp.Run(w, interp.Input{Oracle: func(int) uint64 { return 0 }})
}
