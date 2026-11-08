// Package core is regionval's trusted core: the wire decoder, the
// allowlist, the symbolic execution of one window and its obligations. Rows
// of the allowlist are cited by their IDs (README.md, Allowed instructions).
package core

import (
	"encoding/binary"
	"fmt"
)

// Instruction classes (RFC 9669 §3.3).
const (
	ClassLD    = 0
	ClassLDX   = 1
	ClassST    = 2
	ClassSTX   = 3
	ClassALU   = 4
	ClassJMP   = 5
	ClassJMP32 = 6
	ClassALU64 = 7
)

const (
	OpLdImm64 = 0x18 // {IMM, DW, LD}, two slots (RFC 9669 §5.4)
	OpCall    = 0x85 // {CALL, K, JMP}
	OpExit    = 0x95 // {EXIT, K, JMP}
	codeJA    = 0x00
	codeCall  = 0x80
	codeExit  = 0x90
)

// Insn is one decoded instruction (RFC 9669 §3.1). Idx-independent: Raw is the slot
// offset of its first slot; jump offsets, func_info and call imm count slots.
type Insn struct {
	Op    uint8
	Dst   uint8
	Src   uint8
	Off   int16
	Imm   int32
	Imm64 int64 // wide instructions only: next_imm<<32 | uint32(imm)
	Raw   int
}

func (x Insn) Class() uint8 { return x.Op & 7 }

// Slots is 2 for the wide instruction, 1 otherwise; the second slot has only imm set.
func (x Insn) Slots() int {
	if x.Op == OpLdImm64 {
		return 2
	}
	return 1
}

// IsJump reports a JMP/JMP32 instruction that is neither call nor exit.
func (x Insn) IsJump() bool {
	c := x.Class()
	return (c == ClassJMP || c == ClassJMP32) && x.Op&0xf0 != codeCall && x.Op&0xf0 != codeExit
}

// JumpTarget is the raw target of a jump, raw + 1 + off: JMP32 JA uses imm.
func (x Insn) JumpTarget() int {
	if x.Class() == ClassJMP32 && x.Op&0xf0 == codeJA {
		return x.Raw + 1 + int(x.Imm)
	}
	return x.Raw + 1 + int(x.Off)
}

func (x Insn) IsHelperCall() bool { return x.Op == OpCall && x.Src == 0 }
func (x Insn) IsPseudoCall() bool { return x.Op == OpCall && x.Src == 1 }
func (x Insn) IsFuncRef() bool    { return x.Op == OpLdImm64 && x.Src == 4 } // RFC §5.4 Table 12 src 0x4

// CallTarget is the raw target of a pseudo call or function reference, raw + 1 + imm.
func (x Insn) CallTarget() int { return x.Raw + 1 + int(x.Imm) }

// Same compares every encoded field.
func (x Insn) Same(y Insn) bool {
	return x.Op == y.Op && x.Dst == y.Dst && x.Src == y.Src && x.Off == y.Off && x.Imm == y.Imm && x.Imm64 == y.Imm64
}

func (x Insn) String() string {
	return fmt.Sprintf("{op 0x%02x dst r%d src r%d off %d imm %d}", x.Op, x.Dst, x.Src, x.Off, x.Imm)
}

// Decode reads a little-endian instruction stream.
func Decode(b []byte) ([]Insn, error) {
	if len(b)%8 != 0 {
		return nil, fmt.Errorf("stream length %d is not a multiple of 8", len(b))
	}
	le := binary.LittleEndian
	n := len(b) / 8
	var out []Insn
	for raw := 0; raw < n; {
		s := b[raw*8 : raw*8+8]
		x := Insn{Op: s[0], Dst: s[1] & 0xf, Src: s[1] >> 4, Off: int16(le.Uint16(s[2:])), Imm: int32(le.Uint32(s[4:])), Raw: raw}
		if x.Op == OpLdImm64 {
			if raw+1 >= n {
				return nil, fmt.Errorf("raw %d: wide instruction without its second slot", raw)
			}
			t := b[raw*8+8 : raw*8+16]
			if t[0] != 0 || t[1] != 0 || t[2] != 0 || t[3] != 0 {
				return nil, fmt.Errorf("raw %d: second slot of wide instruction has nonzero opcode/regs/offset", raw)
			}
			x.Imm64 = int64(uint64(le.Uint32(t[4:]))<<32 | uint64(uint32(x.Imm)))
		}
		out = append(out, x)
		raw += x.Slots()
	}
	return out, nil
}
