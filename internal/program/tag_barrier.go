package program

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Tombstones belong to this capture, so an external set add cannot reopen a
// tag after finalization has begun. Exhaustion is an error, never eviction.
func (p *Probe) initTagBarrier() (int, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ninja_closed", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 65536})
	if err != nil {
		return 0, err
	}
	p.closedTags = m
	p.maps = append(p.maps, m)
	return m.FD(), nil
}

// BlockTag stops future exports and waits for every invocation that might
// have passed the old gate, including a reserved but uncommitted ring record.
// Call the reader watermark only AFTER this returns successfully.
func (p *Probe) BlockTag(tag uint32) error {
	if tag == 0 || p.closedTags == nil {
		return fmt.Errorf("tag barrier unavailable for tag %d", tag)
	}
	if err := p.closedTags.Update(tag, uint32(1), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("blocking tag %d: %w", tag, err)
	}
	return p.Barrier()
}
func emitTagBarrier(fd int) asm.Instructions {
	if fd <= 0 {
		return nil
	}
	return asm.Instructions{
		asm.LoadMem(asm.R1, asm.R10, tagSlot, asm.DWord),
		asm.StoreMem(asm.R10, -16, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, fd),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(), asm.JNE.Imm(asm.R0, 0, "exit"),
	}
}
