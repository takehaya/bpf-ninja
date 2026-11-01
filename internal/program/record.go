package program

import (
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/record"
)

// recordValidSlot accumulates the entry block's valid bits. The filter
// gate's users of this range (kunai below KunaiStackTop, the set key
// buffer) are dead once the filter has matched.
const recordValidSlot = -64

// reservedSlot holds the ring reservation from emitShardedRBReserve.
const reservedSlot = -32

// fieldSnap tees each filter-compared value into a per-CPU array so the
// filter block records exactly what the condition tested, not a re-read
// that another CPU could have changed while the packet filter ran. Slot i
// of the field layout is at 8*i in the map value.
type fieldSnap struct {
	fd     int
	key    int // per-target slot, so a preempting target cannot overwrite it
	layout *record.Layout
}

// off is the snapshot slot of a filter argument or set key field, or -1.
func (s *fieldSnap) off(paramIndex int, deref, pointer bool, offset, size uint32, signed bool) int16 {
	if s == nil {
		return -1
	}
	i := s.layout.FieldIndex(paramIndex, deref, pointer, offset, size, signed)
	if i < 0 {
		return -1
	}
	return int16(8 * i)
}

// emitSnapStore writes R3 into snapshot slot off, preserving R3 and R6-R9
// and restoring R2 to the tracing args pointer. A per-CPU array[0] lookup
// never misses, so the guard jumps to exit only defensively.
func emitSnapStore(fd, key int, off int16) asm.Instructions {
	return asm.Instructions{
		asm.StoreMem(asm.R10, argMemberTmp, asm.R3, asm.DWord),
		asm.StoreImm(asm.R10, -16, int64(key), asm.Word),
		asm.LoadMapPtr(asm.R1, fd),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMem(asm.R3, asm.R10, argMemberTmp, asm.DWord),
		asm.StoreMem(asm.R0, off, asm.R3, asm.DWord),
		asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord),
	}
}

// emitSnapLoad loads snapshot slot off into R3 and restores R2 to the
// tracing args pointer, so a later read of the same field reuses its single
// read. A per-CPU array[0..n] lookup never misses; the guard is defensive.
func emitSnapLoad(fd, key int, off int16) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.R10, -16, int64(key), asm.Word),
		asm.LoadMapPtr(asm.R1, fd),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadMem(asm.R3, asm.R0, off, asm.DWord),
		asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord),
	}
}

// emitRecordBlock writes l's block at metadataSize in the reservation.
// It expects R0 = the reservation (also saved at reservedSlot) and leaves
// R0 = the reservation; R6-R9 are preserved. A filter block copies the
// values the gate snapshotted (snap), so every field is valid once the
// gate matched. An entry block reads site, status, key and value through
// the member filter's path, clearing a field's valid bit on a failed read.
func emitRecordBlock(l *record.Layout, snap *fieldSnap) asm.Instructions {
	base := int16(metadataSize)
	insns := asm.Instructions{
		asm.StoreImm(asm.R0, base+record.OffLen, int64(l.Size()), asm.Half),
		asm.StoreImm(asm.R0, base+record.OffVersion, record.BlockVersion, asm.Byte),
		asm.StoreImm(asm.R0, base+record.OffKind, int64(l.Kind()), asm.Byte),
	}
	if l.Mode == record.ModeFilter {
		// -16 (post-reserve) holds the array key, -40 the snapshot pointer.
		insns = append(insns,
			asm.StoreImm(asm.R10, -16, int64(snap.key), asm.Word),
			asm.LoadMapPtr(asm.R1, snap.fd),
			asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -16),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "rb_copy_fail"),
			asm.StoreMem(asm.R10, -40, asm.R0, asm.DWord),
		)
		for i := range l.Fields {
			insns = append(insns,
				asm.LoadMem(asm.R1, asm.R10, -40, asm.DWord),
				asm.LoadMem(asm.R1, asm.R1, int16(8*i), asm.DWord),
				asm.LoadMem(asm.R0, asm.R10, reservedSlot, asm.DWord),
				asm.StoreMem(asm.R0, base+record.HeaderSize+int16(8*i), asm.R1, asm.DWord),
			)
		}
		mask := int32(uint32(uint64(1)<<len(l.Fields) - 1))
		return append(insns,
			asm.LoadMem(asm.R0, asm.R10, reservedSlot, asm.DWord),
			asm.Mov.Imm(asm.R1, mask),
			asm.StoreMem(asm.R0, base+record.OffValid, asm.R1, asm.Word),
		)
	}
	insns = append(insns, asm.Mov.Imm(asm.R1, 0), asm.StoreMem(asm.R10, recordValidSlot, asm.R1, asm.DWord))
	zero := func(off int16, size int) {
		for ; size >= 4; off, size = off+4, size-4 {
			insns = append(insns, asm.StoreImm(asm.R0, off, 0, asm.Word))
		}
		for ; size > 0; off, size = off+1, size-1 {
			insns = append(insns, asm.StoreImm(asm.R0, off, 0, asm.Byte))
		}
	}
	zero(base+record.EntryOffSite, 4)
	zero(base+record.EntryOffStatus, 8)
	insns = append(insns,
		asm.StoreImm(asm.R0, base+record.EntryOffKeyLen, int64(l.Key.Len), asm.Half),
		asm.StoreImm(asm.R0, base+record.EntryOffValueLen, int64(l.Value.Len), asm.Half),
	)
	if s := l.Site; s.Present() {
		insns = append(insns, emitRecordScalar(s.ParamIndex, 4, base+record.EntryOffSite, record.ValidSite)...)
	}
	if s := l.Status; s.Present() {
		insns = append(insns, emitRecordScalar(s.ParamIndex, 8, base+record.EntryOffStatus, record.ValidStatus)...)
	}
	off := base + record.EntryOffBytes
	insns = append(insns, emitRecordBytes(l.Key, off, record.ValidKey, "rec_key")...)
	insns = append(insns, emitRecordBytes(l.Value, off+int16(l.Key.Len), record.ValidValue, "rec_value")...)
	return append(insns,
		asm.LoadMem(asm.R1, asm.R10, recordValidSlot, asm.DWord),
		asm.LoadMem(asm.R0, asm.R10, reservedSlot, asm.DWord),
		asm.StoreMem(asm.R0, base+record.OffValid, asm.R1, asm.Word),
	)
}

// emitRecordValid ORs bit into the valid accumulator.
func emitRecordValid(bit uint32) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R1, asm.R10, recordValidSlot, asm.DWord),
		asm.Or.Imm(asm.R1, int32(bit)),
		asm.StoreMem(asm.R10, recordValidSlot, asm.R1, asm.DWord),
	}
}

// emitRecordScalar stores the low size bytes of an integer argument.
func emitRecordScalar(index int, size uint32, off int16, bit uint32) asm.Instructions {
	insns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord),
		asm.LoadMem(asm.R3, asm.R2, int16(index*8), asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, reservedSlot, asm.DWord),
		asm.StoreMem(asm.R1, off, asm.R3, asmSizeFor(size)),
	}
	return append(insns, emitRecordValid(bit)...)
}

// emitRecordBytes copies a key or value into the block. A pointer is read
// with bpf_probe_read_kernel, which also zeroes the destination when the
// pointer is NULL or the read faults; an integer argument stores its bytes.
func emitRecordBytes(b record.Bytes, off int16, bit uint32, label string) asm.Instructions {
	if !b.Present() || b.Len == 0 {
		return nil
	}
	if !b.Pointer {
		return emitRecordScalar(b.ParamIndex, b.Len, off, bit)
	}
	null, read, done := label+"_null", label+"_read", label+"_done"
	insns := emitArgPointerLoad(b.ParamIndex, null)
	return append(insns,
		asm.Ja.Label(read),
		asm.Mov.Imm(asm.R3, 0).WithSymbol(null),
		asm.LoadMem(asm.R1, asm.R10, reservedSlot, asm.DWord).WithSymbol(read),
		asm.Add.Imm(asm.R1, int32(off)),
		asm.Mov.Imm(asm.R2, int32(b.Len)),
		asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, done),
		asm.LoadMem(asm.R1, asm.R10, recordValidSlot, asm.DWord),
		asm.Or.Imm(asm.R1, int32(bit)),
		asm.StoreMem(asm.R10, recordValidSlot, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, 0).WithSymbol(done),
	)
}

// recordMode is the metadata mode byte of a record that carries a block.
func recordMode(mode uint8) int64 { return int64(mode | capture.ModeRecordFlag) }
