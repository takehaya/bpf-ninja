package attach

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/cilium/ebpf/btf"
)

var argExpression = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*(?:->[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*|\[0\])?$`)

// ResolveArg resolves an integer argument or pointer-member expression using
// the target function's BTF. It never follows a second pointer.
func ResolveArg(expr string, params []FuncParamInfo) (FuncParamInfo, error) {
	if !argExpression.MatchString(expr) {
		return FuncParamInfo{}, fmt.Errorf("invalid argument expression %q (expected param, param->member.member, or param[0])", expr)
	}
	name, path, deref := strings.Cut(expr, "->")
	scalar := strings.HasSuffix(expr, "[0]")
	if scalar {
		name, deref = strings.TrimSuffix(expr, "[0]"), true
	}
	var available []string
	for _, p := range params {
		available = append(available, p.Name)
		if p.Name != name {
			continue
		}
		if !deref {
			if p.Kind != "" {
				return FuncParamInfo{}, fmt.Errorf("parameter %q is a pointer; select an integer member with %s->member or %s[0], or compare it with null", name, name, name)
			}
			return p, nil
		}
		ptr, ok := btf.UnderlyingType(p.Type).(*btf.Pointer)
		if !ok {
			return FuncParamInfo{}, fmt.Errorf("parameter %q must be a pointer to a struct/union", name)
		}
		typ := btf.UnderlyingType(ptr.Target)
		var offset uint64
		var membersPath []string
		if !scalar {
			membersPath = strings.Split(path, ".")
		}
		for _, member := range membersPath {
			members, ok := aggregateMembers(typ)
			if !ok {
				return FuncParamInfo{}, fmt.Errorf("%q: cannot select member %q from %T; expected struct/union", expr, member, typ)
			}
			matches, names := findMembers(members, member, 0)
			if len(matches) == 0 {
				return FuncParamInfo{}, fmt.Errorf("%q: member %q not found; available members: %v", expr, member, names)
			}
			if len(matches) != 1 {
				return FuncParamInfo{}, fmt.Errorf("%q: ambiguous anonymous member %q", expr, member)
			}
			m := matches[0]
			if m.BitfieldSize != 0 {
				return FuncParamInfo{}, fmt.Errorf("%q: bitfield member %q is not supported", expr, member)
			}
			if m.offset%8 != 0 {
				return FuncParamInfo{}, fmt.Errorf("%q: member %q is not byte-aligned", expr, member)
			}
			offset += m.offset / 8
			typ = btf.UnderlyingType(m.Type)
		}
		switch t := typ.(type) {
		case *btf.Int:
			p.Size, p.Signed = t.Size, t.Encoding&btf.Signed != 0
		case *btf.Enum:
			p.Size, p.Signed = t.Size, t.Signed
		default:
			return FuncParamInfo{}, fmt.Errorf("%q: final member must be an integer or enum, got %s", expr, memberKind(typ))
		}
		if p.Size != 1 && p.Size != 2 && p.Size != 4 && p.Size != 8 {
			return FuncParamInfo{}, fmt.Errorf("%q: unsupported member size %d (expected 1, 2, 4, or 8)", expr, p.Size)
		}
		if offset > math.MaxInt32 {
			return FuncParamInfo{}, fmt.Errorf("%q: member offset %d exceeds supported range", expr, offset)
		}
		p.Name, p.Kind, p.TypeName = expr, "", ""
		p.Deref, p.Offset = true, uint32(offset)
		return p, nil
	}
	return FuncParamInfo{}, fmt.Errorf("parameter %q not found; available parameters: %v", name, available)
}

// memberKind names a non-integer member type for error messages.
func memberKind(typ btf.Type) string {
	switch typ.(type) {
	case *btf.Struct:
		return "struct (select one of its members)"
	case *btf.Union:
		return "union (select one of its members)"
	case *btf.Array:
		return "array"
	case *btf.Pointer:
		return "pointer (only one dereference is supported)"
	case *btf.Float:
		return "float"
	}
	return fmt.Sprintf("%T", typ)
}

func aggregateMembers(typ btf.Type) ([]btf.Member, bool) {
	switch t := btf.UnderlyingType(typ).(type) {
	case *btf.Struct:
		return t.Members, true
	case *btf.Union:
		return t.Members, true
	}
	return nil, false
}

type argMember struct {
	btf.Member
	offset uint64 // Bits, widened so anonymous nesting cannot wrap BTF's uint32 offset.
}

// Anonymous struct/union members expose their children at the enclosing level.
func findMembers(members []btf.Member, name string, depth int) (matches []argMember, names []string) {
	walkPromotedMembers(members, depth, func(m argMember) bool {
		names = append(names, m.Name)
		if m.Name == name {
			matches = append(matches, m)
		}
		return true
	})
	return matches, names
}

// walkPromotedMembers shares anonymous-member promotion between resolution and
// discovery. Returning false from visit stops traversal (the listing's row cap).
func walkPromotedMembers(members []btf.Member, depth int, visit func(argMember) bool) string {
	active := make(map[btf.Type]bool)
	truncated := ""
	var walk func([]btf.Member, int, uint64, btf.Bits) bool
	walk = func(members []btf.Member, depth int, offset uint64, bits btf.Bits) bool {
		if depth > 32 {
			truncated = "anonymous depth limit (32)"
			return true
		}
		for _, m := range members {
			if bits != 0 {
				m.BitfieldSize = bits
			}
			at := offset + uint64(m.Offset)
			if m.Name != "" {
				if !visit(argMember{m, at}) {
					return false
				}
				continue
			}
			typ := btf.UnderlyingType(m.Type)
			if children, ok := aggregateMembers(typ); ok {
				if active[typ] {
					truncated = "anonymous cycle"
					continue
				}
				active[typ] = true
				more := walk(children, depth+1, at, m.BitfieldSize)
				delete(active, typ)
				if !more {
					return false
				}
			}
		}
		return true
	}
	walk(members, depth, 0, 0)
	return truncated
}

// ResolveEchoArgs keeps bare --arg-echo limited to integer parameters, while
// explicit expressions may select pointer members using the same resolver.
func ResolveEchoArgs(exprs []string, params []FuncParamInfo) ([]FuncParamInfo, error) {
	var out []FuncParamInfo
	if len(exprs) == 0 {
		for _, p := range params {
			if p.Kind == "" {
				out = append(out, p)
			}
		}
		return out, nil
	}
	for _, expr := range exprs {
		p, err := ResolveArg(expr, params)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ResolvePointerArg accepts a bare pointer parameter for an explicit NULL test.
func ResolvePointerArg(expr string, params []FuncParamInfo) (FuncParamInfo, error) {
	for _, p := range params {
		if p.Name == expr {
			if _, ok := btf.UnderlyingType(p.Type).(*btf.Pointer); ok {
				p.Size, p.Signed = 8, false
				return p, nil
			}
		}
	}
	return FuncParamInfo{}, fmt.Errorf("%q: null comparison requires a pointer parameter (see --list-params)", expr)
}
