package syscallhook

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Linux UAPI offsets, independent of Go struct padding. The launcher supports
// native x86-64 only; compat and x32 syscall ABIs are never rewritten.
const (
	maxBuffer    = 16 << 20
	maxAttr      = 4096
	progAttrSize = 108 // through line_info_cnt
)

var wire = binary.LittleEndian

func u32(b []byte, off int) uint32      { return wire.Uint32(b[off:]) }
func u64(b []byte, off int) uint64      { return wire.Uint64(b[off:]) }
func put32(b []byte, off int, v uint32) { wire.PutUint32(b[off:], v) }
func put64(b []byte, off int, v uint64) { wire.PutUint64(b[off:], v) }
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func parseProgAttr(b []byte) error {
	if len(b) < progAttrSize {
		return fmt.Errorf("BPF_PROG_LOAD attr is %d bytes; need at least %d for BTF metadata", len(b), progAttrSize)
	}
	if u32(b, 4) == 0 || uint64(u32(b, 4))*8 > maxBuffer {
		return fmt.Errorf("invalid or oversized instruction count")
	}
	if u32(b, 72) == 0 || u32(b, 88) == 0 {
		return fmt.Errorf("program BTF and func_info are required")
	}
	for _, f := range []struct{ size, count, want int }{{76, 88, 8}, {92, 104, 16}} {
		if u32(b, f.count) == 0 {
			continue
		}
		if u32(b, f.size) != uint32(f.want) {
			return fmt.Errorf("unsupported metadata record size %d (need %d)", u32(b, f.size), f.want)
		}
		if uint64(u32(b, f.count))*uint64(f.want) > maxBuffer {
			return fmt.Errorf("metadata exceeds %d bytes", maxBuffer)
		}
	}
	// These inputs contain instruction offsets, a token, or a signature over the
	// original instructions. Zero-valued extension fields are OK. fd_array (120)
	// and fd_array_cnt (148) pass through unchanged: the rewrite adds no map or
	// kfunc call, so every index into the array keeps its meaning, and every load
	// runs in the tracee, where the array's fds are valid. Map loads by index are
	// refused separately (fdArrayMapIndex).
	for _, f := range []struct{ off, size int }{{116, 4}, {128, 8}, {136, 4}, {144, 4}, {152, 8}, {160, 4}, {164, 4}} {
		if len(b) > f.off {
			end := min(len(b), f.off+f.size)
			for _, v := range b[f.off:end] {
				if v != 0 {
					return fmt.Errorf("unsupported PROG_LOAD extension at offset %d", f.off)
				}
			}
		}
	}
	if len(b) > 168 {
		for _, v := range b[168:] {
			if v != 0 {
				return fmt.Errorf("unknown nonzero PROG_LOAD extension")
			}
		}
	}
	return nil
}

// fdArrayMapIndex refuses a map load that names its map by an fd_array index
// (BPF_PSEUDO_MAP_IDX, BPF_PSEUDO_MAP_IDX_VALUE): the raw path resolves maps by
// the fd in the instruction only, so it would not know which map is loaded.
// shortcut: refuses every such load, resolve the index through the array when a
// loader that emits these must be hooked.
func fdArrayMapIndex(insns []byte) error {
	for i := 0; i+8 <= len(insns); i += 8 {
		if src := insns[i+1] >> 4; insns[i] == 0x18 && (src == 5 || src == 6) {
			return fmt.Errorf("map load by fd_array index at instruction %d is unsupported", i/8)
		}
	}
	return nil
}
