package attach

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

const (
	DefaultMembersDepth = 3
	MaxMembersDepth     = 32
	maxMemberRows       = 4096
)

// ArgMemberInfo describes a physical member, including promoted anonymous
// members. Offset is in bytes from the argument's pointee; BitOffset is the
// remaining 0..7 bits. Size is the type's storage size, nil if BTF cannot size it.
type ArgMemberInfo struct {
	Expression string          `json:"expression"`
	Type       string          `json:"type"`
	Offset     uint64          `json:"offset"`
	BitOffset  uint64          `json:"bit_offset,omitempty"`
	Size       *int            `json:"size"`
	Signed     *bool           `json:"signed,omitempty"`
	Bitfield   uint32          `json:"bitfield_size,omitempty"`
	Filterable bool            `json:"filterable"`
	Reason     string          `json:"reason,omitempty"`
	Members    []ArgMemberInfo `json:"members,omitempty"`
	Truncated  string          `json:"members_truncated,omitempty"`
}

// ListArgMembers lists a pointer parameter's members in BTF declaration order.
// Depth counts named member levels; anonymous containers promote their children
// without consuming a level. The second result explains omitted root members.
func ListArgMembers(p FuncParamInfo, depth int) ([]ArgMemberInfo, string) {
	ptr, ok := btf.UnderlyingType(p.Type).(*btf.Pointer)
	if !ok {
		return nil, ""
	}
	if resolved, err := ResolveArg(p.Name+"[0]", []FuncParamInfo{p}); err == nil {
		size := int(resolved.Size)
		return []ArgMemberInfo{{Expression: p.Name + "[0]", Type: ArgTypeName(ptr.Target), Size: &size, Signed: &resolved.Signed, Filterable: true}}, ""
	}
	depth = min(max(depth, 1), MaxMembersDepth)
	remaining := maxMemberRows
	active := make(map[btf.Type]bool)
	var walk func(btf.Type, string, uint64, int) ([]ArgMemberInfo, string)
	walk = func(typ btf.Type, prefix string, offset uint64, level int) ([]ArgMemberInfo, string) {
		typ = btf.UnderlyingType(typ)
		members, ok := aggregateMembers(typ)
		if !ok || len(members) == 0 {
			return []ArgMemberInfo{}, ""
		}
		if active[typ] {
			return nil, "cycle"
		}
		if level > depth {
			return nil, "depth limit"
		}
		active[typ] = true
		defer delete(active, typ)
		out := []ArgMemberInfo{}
		limited := false
		truncated := walkPromotedMembers(members, 0, func(m argMember) bool {
			if remaining == 0 {
				limited = true
				return false
			}
			remaining--
			at := offset + m.offset
			n := ArgMemberInfo{
				Expression: prefix + m.Name, Type: ArgTypeName(m.Type),
				Offset: at / 8, BitOffset: at % 8, Bitfield: uint32(m.BitfieldSize),
			}
			if size, err := btf.Sizeof(m.Type); err == nil {
				n.Size = &size
			}
			switch t := btf.UnderlyingType(m.Type).(type) {
			case *btf.Int:
				signed := t.Encoding&btf.Signed != 0
				n.Signed = &signed
			case *btf.Enum:
				signed := t.Signed
				n.Signed = &signed
			}
			_, err := ResolveArg(n.Expression, []FuncParamInfo{p})
			n.Filterable = err == nil
			if err != nil {
				n.Reason = strings.TrimPrefix(err.Error(), fmt.Sprintf("%q: ", n.Expression))
			}
			n.Members, n.Truncated = walk(m.Type, n.Expression+".", at, level+1)
			out = append(out, n)
			return true
		})
		if limited {
			truncated = fmt.Sprintf("member limit (%d)", maxMemberRows)
		}
		return out, truncated
	}
	return walk(ptr.Target, p.Name+"->", 0, 1)
}

// ArgTypeName retains typedef names instead of flattening them for display.
func ArgTypeName(typ btf.Type) string {
	return argTypeName(typ, 0)
}

func argTypeName(typ btf.Type, depth int) string {
	if depth > MaxMembersDepth {
		return "..."
	}
	child := func(t btf.Type) string { return argTypeName(t, depth+1) }
	name := typ.TypeName()
	if name == "" {
		name = "(anonymous)"
	}
	switch t := typ.(type) {
	case *btf.Typedef, *btf.Int, *btf.Float:
		return name
	case *btf.Struct:
		return "struct " + name
	case *btf.Union:
		return "union " + name
	case *btf.Enum:
		return "enum " + name
	case *btf.Pointer:
		return child(t.Target) + " *"
	case *btf.Array:
		dimensions := ""
		elem := typ
		for {
			array, ok := elem.(*btf.Array)
			if !ok || depth > MaxMembersDepth {
				return argTypeName(elem, depth) + dimensions
			}
			dimensions += fmt.Sprintf("[%d]", array.Nelems)
			elem = array.Type
			depth++
		}
	case *btf.Const:
		return "const " + child(t.Type)
	case *btf.Volatile:
		return "volatile " + child(t.Type)
	case *btf.Restrict:
		return "restrict " + child(t.Type)
	case *btf.TypeTag:
		return child(t.Type)
	case *btf.Void:
		return "void"
	default:
		return fmt.Sprintf("%T", typ)
	}
}
