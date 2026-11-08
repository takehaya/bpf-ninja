package regionval

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// FuncRec is one func_info record (uapi bpf.h struct bpf_func_info, little-endian).
type FuncRec struct {
	InsnOff uint32 // raw offset
	TypeID  uint32
}

// ParseFuncInfo reads 8-byte bpf_func_info records. insn_off is a raw slot offset, 0 first, then strictly increasing.
func ParseFuncInfo(b []byte) ([]FuncRec, error) {
	if len(b)%8 != 0 {
		return nil, fmt.Errorf("func_info length %d is not a multiple of 8", len(b))
	}
	le := binary.LittleEndian
	var rs []FuncRec
	for i := 0; i < len(b); i += 8 {
		r := FuncRec{InsnOff: le.Uint32(b[i:]), TypeID: le.Uint32(b[i+4:])}
		if (i == 0 && r.InsnOff != 0) || (i > 0 && r.InsnOff <= rs[len(rs)-1].InsnOff) {
			return nil, fmt.Errorf("func_info record %d: insn_off %d not 0 / not increasing", i/8, r.InsnOff)
		}
		rs = append(rs, r)
	}
	return rs, nil
}

const (
	btfKindFunc      = 12
	btfKindFuncProto = 13
)

// BTFFunc is a FUNC type: its name and the names of its FUNC_PROTO's
// parameters (nil if its type is not a FUNC_PROTO).
type BTFFunc struct {
	Name   string
	Params []string
}

// ParseBTFFuncs returns the FUNC types of a BTF blob by type id (uapi
// btf.h: struct btf_header, struct btf_type, struct btf_param, BTF_KIND_*).
// Any malformed or unknown construct is an error.
func ParseBTFFuncs(b []byte) (map[uint32]BTFFunc, error) {
	le := binary.LittleEndian
	if len(b) < 24 || le.Uint16(b) != 0xeb9f || b[2] != 1 {
		return nil, fmt.Errorf("btf: bad header")
	}
	hdr := le.Uint32(b[4:])
	typeOff, typeLen, strOff, strLen := le.Uint32(b[8:]), le.Uint32(b[12:]), le.Uint32(b[16:]), le.Uint32(b[20:])
	end := func(off, n uint32) (uint64, bool) {
		e := uint64(hdr) + uint64(off) + uint64(n)
		return e, e <= uint64(len(b))
	}
	if _, ok := end(typeOff, typeLen); !ok || hdr < 24 {
		return nil, fmt.Errorf("btf: type section out of range")
	}
	if _, ok := end(strOff, strLen); !ok {
		return nil, fmt.Errorf("btf: string section out of range")
	}
	types := b[hdr+typeOff : hdr+typeOff+typeLen]
	strs := b[hdr+strOff : hdr+strOff+strLen]
	name := func(off uint32) (string, error) {
		if off >= uint32(len(strs)) {
			return "", fmt.Errorf("btf: name offset %d out of range", off)
		}
		n := bytes.IndexByte(strs[off:], 0)
		if n < 0 {
			return "", fmt.Errorf("btf: unterminated name at %d", off)
		}
		return string(strs[off : off+uint32(n)]), nil
	}
	funcs := map[uint32]BTFFunc{}
	protoOf := map[uint32]uint32{}  // FUNC id -> its type
	params := map[uint32][]string{} // FUNC_PROTO id -> parameter names
	for id, p := uint32(1), 0; p < len(types); id++ {
		if p+12 > len(types) {
			return nil, fmt.Errorf("btf: truncated type %d", id)
		}
		nameOff, info := le.Uint32(types[p:]), le.Uint32(types[p+4:])
		kind, vlen := (info>>24)&0x1f, int(info&0xffff)
		var extra int
		switch kind {
		case 2, 7, 8, 9, 10, 11, 12, 16, 18: // PTR FWD TYPEDEF VOLATILE CONST RESTRICT FUNC FLOAT TYPE_TAG
		case 1, 14, 17: // INT VAR DECL_TAG
			extra = 4
		case 3: // ARRAY
			extra = 12
		case 4, 5, 15, 19: // STRUCT UNION DATASEC ENUM64
			extra = 12 * vlen
		case 6, 13: // ENUM FUNC_PROTO
			extra = 8 * vlen
		default:
			return nil, fmt.Errorf("btf: type %d has unknown kind %d", id, kind)
		}
		if p+12+extra > len(types) {
			return nil, fmt.Errorf("btf: truncated type %d", id)
		}
		switch kind {
		case btfKindFunc:
			n, err := name(nameOff)
			if err != nil {
				return nil, err
			}
			funcs[id] = BTFFunc{Name: n}
			protoOf[id] = le.Uint32(types[p+8:])
		case btfKindFuncProto:
			ps := make([]string, vlen)
			for j := range ps {
				n, err := name(le.Uint32(types[p+12+8*j:]))
				if err != nil {
					return nil, err
				}
				ps[j] = n
			}
			params[id] = ps
		}
		p += 12 + extra
	}
	for id, f := range funcs {
		f.Params = params[protoOf[id]]
		funcs[id] = f
	}
	return funcs, nil
}
