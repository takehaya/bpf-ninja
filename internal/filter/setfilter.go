// Set filters: `--arg-filter "@NAME"` references a named pinned-map set
// (see internal/setmap) and passes when the composite key built from the
// target function's arguments exists in the map. Resolution is per attach
// target because the same param name can sit at a different arg index in
// different functions — the same reason plain arg-filters resolve per
// target.
package filter

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/setmap"
)

// SetKeyField binds one key-struct member to a fentry arg of one target
// function.
type SetKeyField struct {
	FieldName   string // BTF member name in the key struct
	FieldOff    uint32 // byte offset within the key
	FieldSize   uint32 // 1/2/4/8
	ParamName   string
	ParamIdx    int // per-target arg index
	ParamSize   uint32
	ParamSigned bool // sign-extend a narrow signed arg into the key field
}

// SetFilter is one "@NAME" reference resolved against one target's
// params. Map is borrowed from the setmap.Set (the CLI owns its
// lifetime); it must stay open until the tracing program is loaded.
type SetFilter struct {
	SetName string
	Map     *ebpf.Map
	KeySize uint32
	Fields  []SetKeyField
}

// TargetFilters is everything --arg-filter produced for one attach
// target: plain scalar compares plus set lookups, all ANDed.
type TargetFilters struct {
	Args []ArgFilter
	Sets []SetFilter
}

// Empty reports whether the target has no filters at all.
func (tf TargetFilters) Empty() bool {
	return len(tf.Args) == 0 && len(tf.Sets) == 0
}

// SplitFilterExprs partitions --arg-filter values into set references
// ("@name") and plain filter expressions.
func SplitFilterExprs(exprs []string) (refs, plain []string) {
	for _, e := range exprs {
		if name, ok := strings.CutPrefix(e, "@"); ok {
			refs = append(refs, name)
		} else {
			plain = append(plain, e)
		}
	}
	return refs, plain
}

// ResolveSetFilters binds each referenced set's key fields to the
// target's function params. Every key field must resolve (full-key rule):
// through the set's explicit key(...) mapping when given, else implicitly
// by field name.
func ResolveSetFilters(sets []*setmap.Set, refs []string, params []attach.FuncParamInfo) ([]SetFilter, error) {
	byName := map[string]*setmap.Set{}
	for _, s := range sets {
		byName[s.Name] = s
	}
	paramByName := map[string]attach.FuncParamInfo{}
	for _, p := range params {
		paramByName[p.Name] = p
	}

	var out []SetFilter
	for _, ref := range refs {
		s, ok := byName[ref]
		if !ok {
			return nil, fmt.Errorf("@%s: no such set (define it with --set %q)", ref, ref+"=/sys/fs/bpf/...")
		}

		// source per key field: explicit mapping wins, else field name.
		// (OpenSet has already reconciled a scalar key's synthetic name
		// with the mapping's field name, so field lookups are uniform.)
		srcFor := map[string]string{}
		for _, m := range s.Mapping {
			if _, ok := s.Def.Field(m.Field); !ok {
				return nil, fmt.Errorf("@%s: key(...) names field %q but the map key has: %s", ref, m.Field, keyFieldList(s.Def))
			}
			srcFor[m.Field] = m.Source
		}

		sf := SetFilter{SetName: s.Name, Map: s.Def.Map, KeySize: s.Def.KeySize}
		for _, f := range s.Def.Fields {
			src, ok := srcFor[f.Name]
			if !ok {
				src = "arg:" + f.Name // implicit match by name
			}
			paramName := strings.TrimPrefix(src, "arg:")
			p, ok := paramByName[paramName]
			if !ok {
				return nil, fmt.Errorf("@%s: key field %s needs arg %q, which the target function does not have (see --list-params); map it with key(%s=arg:<param>)", ref, f.Name, paramName, f.Name)
			}
			if p.Size > f.Size {
				return nil, fmt.Errorf("@%s: arg %s (u%d) is wider than key field %s (u%d) — truncation is not supported", ref, paramName, p.Size*8, f.Name, f.Size*8)
			}
			sf.Fields = append(sf.Fields, SetKeyField{
				FieldName: f.Name, FieldOff: f.Off, FieldSize: f.Size,
				ParamName: paramName, ParamIdx: p.Index, ParamSize: p.Size, ParamSigned: p.Signed,
			})
		}
		out = append(out, sf)
	}
	return out, nil
}

func keyFieldList(d *setmap.Definition) string {
	names := make([]string, len(d.Fields))
	for i, f := range d.Fields {
		names[i] = f.Name
	}
	return strings.Join(names, ", ")
}
