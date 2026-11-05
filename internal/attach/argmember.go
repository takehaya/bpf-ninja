package attach

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
)

// ArgExpressionPattern is the syntax of an argument expression: param,
// param->member[N].member, param[0][N].member or param.field. Brackets take
// any text that cannot end the step, so that ResolveArg can say why an index
// is refused.
const ArgExpressionPattern = `[a-zA-Z_][a-zA-Z0-9_]*(?:->` + argMemberStep + `(?:\.` + argMemberStep + `)*|(?:` + argIndex + `)+(?:\.` + argMemberStep + `)*|\.[a-zA-Z_][a-zA-Z0-9_]*)?`

const (
	argIndex      = `\[[^\].>]*\]`
	argMemberStep = `[a-zA-Z_][a-zA-Z0-9_]*(?:` + argIndex + `)*`
)

var argExpression = regexp.MustCompile(`^` + ArgExpressionPattern + `$`)

// ResolveArg resolves an integer argument, status field or pointer-member
// expression using the target function's BTF. It never follows a second pointer.
func ResolveArg(expr string, params []FuncParamInfo) (FuncParamInfo, error) {
	if !argExpression.MatchString(expr) {
		return FuncParamInfo{}, fmt.Errorf("invalid argument expression %q (expected param, param->member[N].member, param[0][N].member, or status.ret/status.flags)", expr)
	}
	name, path, deref := strings.Cut(expr, "->")
	var rootIndexes []string
	if base, rest, ok := strings.Cut(name, "["); ok {
		indexes, members, _ := strings.Cut(rest, "].")
		name, rootIndexes, path, deref = base, splitIndexes(indexes), members, true
	}
	name, field, isField := strings.Cut(name, ".")
	var available []string
	for _, p := range params {
		available = append(available, p.Name)
		if p.Name != name {
			continue
		}
		if isField {
			return resolveStatusField(expr, field, p)
		}
		if !deref {
			if p.Kind != "" {
				return FuncParamInfo{}, fmt.Errorf("parameter %q is a pointer; select an integer member with %s->member or %s[0], or compare it with null", name, name, name)
			}
			return p, nil
		}
		ptr, ok := btf.UnderlyingType(p.Type).(*btf.Pointer)
		if !ok {
			if p.StatusWord {
				return FuncParamInfo{}, fmt.Errorf("%q: status is not a pointer; use %s.ret or %s.flags", expr, name, name)
			}
			return FuncParamInfo{}, fmt.Errorf("parameter %q must be a pointer to a struct/union", name)
		}
		typ := btf.UnderlyingType(ptr.Target)
		if _, void := typ.(*btf.Void); void && p.VoidSize > 0 {
			// A sized untyped key or value reads as the struct { u8 bytes[N]; }
			// a static hook declares for a map without BTF.
			bytes := &btf.Array{Index: &btf.Int{Name: "u32", Size: 4}, Type: &btf.Int{Name: "u8", Size: 1}, Nelems: p.VoidSize}
			typ = &btf.Struct{Size: p.VoidSize, Members: []btf.Member{{Name: "bytes", Type: bytes}}}
		}
		var offset uint64
		if rootIndexes != nil {
			if rootIndexes[0] != "0" {
				return FuncParamInfo{}, fmt.Errorf("%q: a pointer argument takes only [0] before any array index, got [%s]", expr, rootIndexes[0])
			}
			var err error
			if typ, offset, err = indexArray(expr, typ, rootIndexes[1:]); err != nil {
				return FuncParamInfo{}, err
			}
		}
		var membersPath []string
		if path != "" {
			membersPath = strings.Split(path, ".")
		}
		through := false
		for _, step := range membersPath {
			member, rest, indexed := strings.Cut(step, "[")
			if s, ok := typ.(*btf.Struct); ok && hookabi.Opaque(s) {
				through = true
			}
			members, ok := aggregateMembers(typ)
			if !ok {
				return FuncParamInfo{}, fmt.Errorf("%q: cannot select member %q from %s; expected struct/union", expr, member, memberKind(typ))
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
			through = through || m.opaque
			if indexed {
				elem, at, err := indexArray(expr, typ, splitIndexes(rest))
				if err != nil {
					return FuncParamInfo{}, err
				}
				typ, offset = elem, offset+at
			}
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
		p.Deref, p.Offset, p.ThroughOpaque = true, uint32(offset), through
		return p, nil
	}
	return FuncParamInfo{}, fmt.Errorf("parameter %q not found; available parameters: %v", name, available)
}

// splitIndexes splits "1][2]", the text after a step's first bracket.
func splitIndexes(s string) []string {
	return strings.Split(strings.TrimSuffix(s, "]"), "][")
}

// indexArray applies constant indexes to typ, returning the element type and
// its byte offset from typ.
func indexArray(expr string, typ btf.Type, indexes []string) (btf.Type, uint64, error) {
	var offset uint64
	for _, s := range indexes {
		n, err := strconv.ParseUint(s, 10, 64)
		// A leading zero is refused because C would read it as octal.
		if err != nil || len(s) > 1 && s[0] == '0' {
			return nil, 0, fmt.Errorf("%q: array index [%s] must be a non-negative decimal constant", expr, s)
		}
		array, ok := typ.(*btf.Array)
		if !ok {
			return nil, 0, fmt.Errorf("%q: cannot apply [%d] to %s; expected a fixed-length array", expr, n, memberKind(typ))
		}
		if n >= uint64(array.Nelems) {
			return nil, 0, fmt.Errorf("%q: index %d is out of range for an array of %d elements", expr, n, array.Nelems)
		}
		typ = btf.UnderlyingType(array.Type)
		size, err := btf.Sizeof(typ)
		if err != nil {
			return nil, 0, fmt.Errorf("%q: sizing the array element: %w", expr, err)
		}
		offset += n * uint64(size)
	}
	return typ, offset, nil
}

// resolveStatusField resolves a half of a generated hook's status word,
// (u32)ret | flags << 32. Offset is the half's byte offset in the argument.
func resolveStatusField(expr, field string, p FuncParamInfo) (FuncParamInfo, error) {
	if p.Kind != "" {
		return FuncParamInfo{}, fmt.Errorf("%q: parameter %q is a pointer; select a member with %s->%s", expr, p.Name, p.Name, field)
	}
	if !p.StatusWord {
		return FuncParamInfo{}, fmt.Errorf("%q: only the status argument of a generated hook has .ret and .flags", expr)
	}
	switch field {
	case "ret":
		p.Signed = true
	case "flags":
		p.Signed, p.Offset = false, 4
	default:
		return FuncParamInfo{}, fmt.Errorf("%q: status has the fields ret and flags, not %q", expr, field)
	}
	p.Name, p.Size = expr, 4
	return p, nil
}

// StatusFields lists the fields ResolveArg accepts on p, none unless p is a
// generated hook's status word.
func StatusFields(p FuncParamInfo) []FuncParamInfo {
	if !p.StatusWord {
		return nil
	}
	var out []FuncParamInfo
	for _, field := range []string{"ret", "flags"} {
		f, _ := resolveStatusField(p.Name+"."+field, field, p) // both names resolve on a status word
		out = append(out, f)
	}
	return out
}

// memberKind names a non-integer member type for error messages.
func memberKind(typ btf.Type) string {
	switch t := typ.(type) {
	case *btf.Struct:
		return "struct (select one of its members)"
	case *btf.Union:
		return "union (select one of its members)"
	case *btf.Array:
		if t.Nelems == 0 {
			return "zero-length array"
		}
		return "array (select an element with [N])"
	case *btf.Pointer:
		return "pointer (only one dereference is supported)"
	case *btf.Float:
		return "float"
	case *btf.Void:
		return "void"
	case *btf.Int:
		return "integer"
	case *btf.Enum:
		return "enum"
	}
	return "unsupported type"
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
	opaque bool   // promoted through an anonymous hookabi.Opaque struct
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
	var walk func([]btf.Member, int, uint64, btf.Bits, bool) bool
	walk = func(members []btf.Member, depth int, offset uint64, bits btf.Bits, opaque bool) bool {
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
				if !visit(argMember{m, at, opaque}) {
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
				s, isStruct := typ.(*btf.Struct)
				more := walk(children, depth+1, at, m.BitfieldSize, opaque || isStruct && hookabi.Opaque(s))
				delete(active, typ)
				if !more {
					return false
				}
			}
		}
		return true
	}
	walk(members, depth, 0, 0, false)
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
