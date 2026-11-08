package core

import "fmt"

// Fields that a row requires to be zero (RFC 9669 §3.1: unused fields are zero).
const (
	zDst = 1 << iota
	zSrc
	zOff
	zImm
)

// Row is one allowed instruction (README.md, Allowed instructions).
// Anything without a row is not modelled and makes its window not
// validated.
type Row struct {
	ID        string
	Op        uint8
	CallSrc   int8  // for 0x85: the required src (0 helper, 1 pseudo call); -1 otherwise
	Zero      uint8 // zDst|zSrc|zOff|zImm
	WritesDst bool  // dst = r10 is refused (the frame pointer is read-only)
	Shift     int32 // shift rows: imm must be in [0, Shift)
}

var table = []Row{
	// ALU64
	{ID: "A64-1", Op: 0xb7, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true},
	{ID: "A64-2", Op: 0xbf, CallSrc: -1, Zero: zOff | zImm, WritesDst: true},
	{ID: "A64-3", Op: 0x07, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true},
	{ID: "A64-4", Op: 0x57, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true},
	{ID: "A64-5", Op: 0x5f, CallSrc: -1, Zero: zOff | zImm, WritesDst: true},
	{ID: "A64-6", Op: 0x47, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true},
	{ID: "A64-7", Op: 0x4f, CallSrc: -1, Zero: zOff | zImm, WritesDst: true},
	{ID: "A64-8", Op: 0x67, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true, Shift: 64},
	// ALU32
	{ID: "A32-1", Op: 0xb4, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true},
	{ID: "A32-2", Op: 0xbc, CallSrc: -1, Zero: zOff | zImm, WritesDst: true},
	{ID: "A32-3", Op: 0x04, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true},
	{ID: "A32-4", Op: 0x54, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true},
	{ID: "A32-5", Op: 0x5c, CallSrc: -1, Zero: zOff | zImm, WritesDst: true},
	{ID: "A32-6", Op: 0x44, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true},
	{ID: "A32-7", Op: 0x4c, CallSrc: -1, Zero: zOff | zImm, WritesDst: true},
	{ID: "A32-8", Op: 0x64, CallSrc: -1, Zero: zSrc | zOff, WritesDst: true, Shift: 32},
	// LDX
	{ID: "LDX-1", Op: 0x61, CallSrc: -1, Zero: zImm, WritesDst: true},
	{ID: "LDX-2", Op: 0x69, CallSrc: -1, Zero: zImm, WritesDst: true},
	{ID: "LDX-3", Op: 0x71, CallSrc: -1, Zero: zImm, WritesDst: true},
	{ID: "LDX-4", Op: 0x79, CallSrc: -1, Zero: zImm, WritesDst: true},
	// STX
	{ID: "STX-1", Op: 0x63, CallSrc: -1, Zero: zImm},
	{ID: "STX-2", Op: 0x6b, CallSrc: -1, Zero: zImm},
	{ID: "STX-3", Op: 0x73, CallSrc: -1, Zero: zImm},
	{ID: "STX-4", Op: 0x7b, CallSrc: -1, Zero: zImm},
	// JMP / JMP32
	{ID: "J-1", Op: 0x05, CallSrc: -1, Zero: zDst | zSrc | zImm},
	{ID: "J-2", Op: 0x15, CallSrc: -1, Zero: zSrc},
	{ID: "J-3", Op: 0x55, CallSrc: -1, Zero: zSrc},
	{ID: "J-4", Op: 0x76, CallSrc: -1, Zero: zSrc},
	// CALL, EXIT
	{ID: "C-1", Op: OpCall, CallSrc: 0, Zero: zDst | zOff},
	{ID: "C-2", Op: OpCall, CallSrc: 1, Zero: zDst | zOff},
	{ID: "E-1", Op: OpExit, CallSrc: -1, Zero: zDst | zSrc | zOff | zImm},
}

// Allowed returns the row modelling x, or a reason why x is not modelled.
// It is the only way an instruction enters the symbolic step.
func Allowed(x Insn) (Row, string) {
	if x.Dst > 10 || x.Src > 10 {
		return Row{}, fmt.Sprintf("%v: register number above r10", x)
	}
	for _, r := range table {
		if r.Op != x.Op || (r.CallSrc >= 0 && int8(x.Src) != r.CallSrc) {
			continue
		}
		switch {
		case r.Zero&zDst != 0 && x.Dst != 0, r.Zero&zSrc != 0 && x.Src != 0,
			r.Zero&zOff != 0 && x.Off != 0, r.Zero&zImm != 0 && x.Imm != 0:
			return Row{}, fmt.Sprintf("%v: %s with a nonzero reserved field", x, r.ID)
		case r.WritesDst && x.Dst == 10:
			return Row{}, fmt.Sprintf("%v: %s writes r10", x, r.ID)
		case r.Shift != 0 && (x.Imm < 0 || x.Imm >= r.Shift):
			return Row{}, fmt.Sprintf("%v: %s shift amount out of range", x, r.ID)
		}
		return r, ""
	}
	return Row{}, fmt.Sprintf("%v: opcode 0x%02x (src %d) not in the allowlist", x, x.Op, x.Src)
}
