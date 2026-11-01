// Package record describes the decision-state block a capture at an
// injected hook writes into each ring record before the packet bytes.
//
// The block layout is fixed when the probe is loaded. Every multi-byte
// field is in the capturing host's byte order (little-endian on the
// supported hosts):
//
//	off  size  field
//	0    u16   len      total block bytes, header included
//	2    u8    version  BlockVersion
//	3    u8    kind     KindFilter or KindEntry
//	4    u32   valid    bit i is set when field i was read
//
// KindFilter: one u64 per field from offset 8, in Layout.Fields order. An
// integer is sign- or zero-extended to 64 bits; a NULL test records the
// pointer it tested, and the comment shows only null or !=null, so the
// address never reaches the capture file.
//
// KindEntry (valid bits: ValidSite, ValidStatus, ValidKey, ValidValue):
//
//	8    u32   site       the hook's site argument, or the low half of info
//	12   u16   key_len    key bytes recorded
//	14   u16   value_len  value bytes recorded
//	16   u64   status     the hook's status (or info) argument, 0 if none
//	24   key_len bytes of the key, then value_len bytes of the value
//
// A field that could not be read is zero and has its valid bit clear.
package record

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// Mode selects what a capture at a hook records with each packet.
type Mode string

const (
	ModeNone   Mode = "none"
	ModeFilter Mode = "filter"
	ModeEntry  Mode = "entry"
)

// ParseMode accepts none, filter and entry.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case ModeNone, ModeFilter, ModeEntry:
		return m, nil
	}
	return "", fmt.Errorf("invalid --record %q: must be none, filter or entry", s)
}

// Block header and entry body offsets.
const (
	BlockVersion = 1
	HeaderSize   = 8

	OffLen     = 0
	OffVersion = 2
	OffKind    = 3
	OffValid   = 4

	EntryOffSite     = 8
	EntryOffKeyLen   = 12
	EntryOffValueLen = 14
	EntryOffStatus   = 16
	EntryOffBytes    = 24
)

// Block kinds.
const (
	KindFilter = 1
	KindEntry  = 2
)

// Entry valid bits.
const (
	ValidSite = 1 << iota
	ValidStatus
	ValidKey
	ValidValue
)

// DefaultMaxBytes caps the recorded key and value bytes by default.
const DefaultMaxBytes = 256

// MaxBytesLimit is the largest accepted --record-max.
const MaxBytesLimit = 4096

// MaxFields is the number of filter fields the valid bitmap can describe.
const MaxFields = 32

// MaxCommentBytes is the largest comment a pcapng opt_comment can hold.
const MaxCommentBytes = 65535

// Field is one hook argument or member the filter block records.
type Field struct {
	Name       string // expression as written in --arg-filter, e.g. value->action
	ParamIndex int
	Size       uint32
	Signed     bool
	Deref      bool // read through the pointer argument (member or [0])
	Pointer    bool // record whether the pointer argument is NULL
	Offset     uint32
}

// Scalar is an integer hook argument the entry block records.
type Scalar struct {
	Name       string
	ParamIndex int // -1 when the hook has no such argument
	Size       uint32
}

// Present reports whether the hook has the argument.
func (s Scalar) Present() bool { return s.ParamIndex >= 0 }

// Bytes is the key or value of the map entry the hook received.
type Bytes struct {
	Name       string
	ParamIndex int    // -1 when the hook has no such argument
	Pointer    bool   // read the pointee; otherwise the integer argument's own bytes
	Size       uint32 // full size from BTF; 0 when the pointee is untyped
	Len        uint32 // recorded bytes: min(Size, cap)
	Type       btf.Type
}

// Present reports whether the hook has the argument.
func (b Bytes) Present() bool { return b.ParamIndex >= 0 }

// Layout is the fixed block one capture site writes.
type Layout struct {
	Mode   Mode
	Fields []Field // ModeFilter

	Site, Status Scalar // ModeEntry
	Key, Value   Bytes  // ModeEntry
}

// FieldIndex returns the filter field matching a filter argument or set key
// field, or -1. The key is the dedup key buildFilter uses (every field but
// the name), so a snapshot taken at filter time lands in the right slot.
func (l *Layout) FieldIndex(paramIndex int, deref, pointer bool, offset, size uint32, signed bool) int {
	for i, f := range l.Fields {
		if f.ParamIndex == paramIndex && f.Deref == deref && f.Pointer == pointer &&
			f.Offset == offset && f.Size == size && f.Signed == signed {
			return i
		}
	}
	return -1
}

// Size is the block length in bytes.
func (l *Layout) Size() int {
	if l.Mode == ModeFilter {
		return HeaderSize + 8*len(l.Fields)
	}
	return EntryOffBytes + int(l.Key.Len) + int(l.Value.Len)
}

// Kind is the block's kind byte.
func (l *Layout) Kind() uint8 {
	if l.Mode == ModeFilter {
		return KindFilter
	}
	return KindEntry
}
