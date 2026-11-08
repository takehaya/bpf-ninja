// Package interp is the reference concrete interpreter for regionval's
// allowlisted subset. It is written from RFC 9669 independently of the symbolic stepper (core/sym.go): it
// decodes class, code and source bits instead of matching whole opcodes,
// computes on uint64 values, and keeps each frame as 512 concrete bytes at
// a concrete address. It shares only the decoded instruction type and the
// window description (data) with the core. It is not part of the trusted
// core and Check never calls it.
package interp

import (
	"encoding/binary"
	"fmt"

	"github.com/takehaya/bpf-ninja/tools/regionval/core"
)

// Concrete frame bases (r10 of the window frame and of the wrapper frame).
// They are far from the special register values the tests draw.
const (
	Base0 uint64 = 0xffffc90000a00000
	Base1 uint64 = Base0 - 0x10000
)

// Input is a concrete entry state plus the oracle. Every value the window
// cannot compute (a helper result, havocked registers, bytes a helper
// writes, a load from memory other than a frame) is the next oracle value,
// in this order: a load from other memory takes one value (truncated to
// its width); a helper call takes r0, r1-r5, then each byte of the window
// frame's [f,0) in ascending order ([-512,0) without a floor); a hook call
// takes r0-r5; a call to the wrapper takes the callee's r0 and r6-r9; the
// return from the wrapper takes the caller's r1-r5.
type Input struct {
	Regs   [10]uint64
	Stack  [2][512]byte // entry bytes of frame 0 and frame 1, index offset+512
	Oracle func(i int) uint64
}

// Output is the window frame when the window ends, the positions executed,
// and the number of oracle values used.
type Output struct {
	Locs  []core.Loc
	Regs  [11]uint64
	Stack [512]byte
	Used  int
	Exit  bool
}

type frame struct {
	code []core.Insn
	hook map[int]bool
	pc   int
	r    [11]uint64
}

type machine struct {
	w     core.Window
	in    Input
	fr    []frame
	mem   [2][512]byte
	used  int
	out   Output
	floor int
}

func (m *machine) draw() uint64 {
	v := m.in.Oracle(m.used)
	m.used++
	return v
}

// addr maps a concrete address range to (frame, index) if it lies inside a
// live frame.
func (m *machine) addr(a uint64, n int) (int, int, bool) {
	for f := range m.fr {
		base := [2]uint64{Base0, Base1}[f]
		if a >= base-512 && a <= base-uint64(n) {
			return f, int(a - (base - 512)), true
		}
	}
	return 0, 0, false
}

const maxSteps = 1 << 16

// Run executes w on in. An error means the window leaves what the
// interpreter models (a store outside a frame, a call to an unknown
// function, a jump outside the code, running out of steps).
func Run(w core.Window, in Input) (Output, error) {
	m := &machine{w: w, in: in, mem: in.Stack, floor: -512}
	if w.HasFloor {
		m.floor = int(w.Floor)
	}
	top := frame{code: w.Insns, hook: w.Hook}
	copy(top.r[:10], in.Regs[:])
	top.r[10] = Base0
	m.fr = []frame{top}
	for steps := 0; ; steps++ {
		if steps == maxSteps {
			return m.out, fmt.Errorf("step limit")
		}
		done, err := m.step()
		if err != nil {
			return m.out, err
		}
		if done {
			m.out.Regs, m.out.Stack, m.out.Used = m.fr[0].r, m.mem[0], m.used
			return m.out, nil
		}
	}
}

func (m *machine) step() (bool, error) {
	d := len(m.fr) - 1
	f := &m.fr[d]
	body := d > 0 || m.w.Kind == core.KindHook
	if f.pc == len(f.code) {
		if body {
			return false, fmt.Errorf("fell off a function body")
		}
		return true, nil
	}
	x := f.code[f.pc]
	if x.Dst > 10 || x.Src > 10 { // 4-bit fields; the register file is r0-r10
		return false, fmt.Errorf("%v: register number above r10", x)
	}
	m.out.Locs = append(m.out.Locs, core.Loc{Depth: d, PC: f.pc})
	r := &f.r
	class, code, useReg := x.Op&7, x.Op&0xf0, x.Op&0x08 != 0
	f.pc++
	switch class {
	case 4, 7: // ALU, ALU64 (RFC §4.1)
		var b uint64
		switch {
		case useReg:
			b = r[x.Src]
		case class == 7:
			b = uint64(int64(x.Imm))
		default:
			b = uint64(uint32(x.Imm))
		}
		a := r[x.Dst]
		if class == 4 {
			a, b = uint64(uint32(a)), uint64(uint32(b))
		}
		var v uint64
		switch code {
		case 0x00:
			v = a + b
		case 0x40:
			v = a | b
		case 0x50:
			v = a & b
		case 0x60:
			if class == 4 {
				v = a << (b & 31)
			} else {
				v = a << (b & 63)
			}
		case 0xb0:
			v = b
		default:
			return false, fmt.Errorf("%v: ALU code %#x not modelled", x, code)
		}
		if class == 4 {
			v = uint64(uint32(v))
		}
		r[x.Dst] = v
	case 1, 3: // LDX, STX MEM (RFC §5.1)
		if x.Op&0xe0 != 0x60 {
			return false, fmt.Errorf("%v: mode not modelled", x)
		}
		n := map[uint8]int{0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}[x.Op&0x18]
		var buf [8]byte
		if class == 1 {
			a := r[x.Src] + uint64(int64(x.Off))
			if fi, i, ok := m.addr(a, n); ok {
				copy(buf[:n], m.mem[fi][i:i+n])
			} else {
				binary.LittleEndian.PutUint64(buf[:], m.draw())
				clear(buf[n:])
			}
			r[x.Dst] = binary.LittleEndian.Uint64(buf[:])
		} else {
			a := r[x.Dst] + uint64(int64(x.Off))
			fi, i, ok := m.addr(a, n)
			if !ok {
				return false, fmt.Errorf("%v: store to %#x outside every frame", x, a)
			}
			binary.LittleEndian.PutUint64(buf[:], r[x.Src])
			copy(m.mem[fi][i:i+n], buf[:n])
		}
	case 5, 6: // JMP, JMP32 (RFC §4.3)
		switch code {
		case 0x80:
			return false, m.call(x, d)
		case 0x90:
			return m.exit(d, body)
		}
		taken := true
		if code != 0x00 {
			a, b := r[x.Dst], uint64(int64(x.Imm))
			if useReg {
				b = r[x.Src]
			}
			if class == 6 {
				a, b = uint64(uint32(a)), uint64(uint32(b))
			}
			switch {
			case code == 0x10:
				taken = a == b
			case code == 0x50:
				taken = a != b
			case code == 0x70 && class == 6:
				taken = int32(uint32(a)) >= int32(uint32(b))
			case code == 0x70:
				taken = int64(a) >= int64(b)
			default:
				return false, fmt.Errorf("%v: jump code %#x not modelled", x, code)
			}
		} else if class == 6 {
			return false, fmt.Errorf("%v: JMP32 JA not modelled", x)
		}
		if taken {
			t := f.pc + int(x.Off)
			if t < 0 || t > len(f.code) || (body && t == len(f.code)) {
				return false, fmt.Errorf("%v: jump target %d outside the code", x, t)
			}
			f.pc = t
		}
	default:
		return false, fmt.Errorf("%v: class %d not modelled", x, class)
	}
	return false, nil
}

func (m *machine) call(x core.Insn, d int) error {
	f := &m.fr[d]
	at := f.pc - 1
	switch {
	case x.Src == 0: // helper: r0, r1-r5, then the window frame's bytes [f,0)
		for k := 0; k <= 5; k++ {
			f.r[k] = m.draw()
		}
		for o := m.floor; o < 0; o++ {
			m.mem[0][o+512] = byte(m.draw())
		}
	case x.Src == 1 && d == 0 && at == m.w.Center && m.w.Callee != nil: // wrapper
		c := frame{code: m.w.Callee, hook: m.w.CalleeHook}
		c.r[1], c.r[2], c.r[3], c.r[4], c.r[5] = f.r[1], f.r[2], f.r[3], f.r[4], f.r[5]
		c.r[0] = m.draw()
		for k := 6; k <= 9; k++ {
			c.r[k] = m.draw()
		}
		c.r[10] = Base1
		m.fr = append(m.fr, c)
	case x.Src == 1 && f.hook[at]: // hook: r0-r5 unknown, the rest kept (trusted calling convention)
		for k := 0; k <= 5; k++ {
			f.r[k] = m.draw()
		}
	default:
		return fmt.Errorf("%v: call target not modelled", x)
	}
	return nil
}

func (m *machine) exit(d int, body bool) (bool, error) {
	if d == 1 {
		r0 := m.fr[1].r[0]
		m.fr = m.fr[:1]
		m.fr[0].r[0] = r0
		for k := 1; k <= 5; k++ {
			m.fr[0].r[k] = m.draw()
		}
		return false, nil
	}
	if !body {
		return false, fmt.Errorf("exit outside a function body")
	}
	m.out.Exit = true
	return true, nil
}
