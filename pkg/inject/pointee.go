package inject

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// walkPointee resolves the wrapper chain while retaining its first special tag.
// qualifiedTags enables tags behind typedefs and qualifiers for supplied BTF;
// kernel BTF keeps specialField's direct-tag semantics.
func walkPointee(typ btf.Type, qualifiedTags bool) (btf.Type, string, error) {
	const maxDepth = 32 // Match cilium/ebpf's maxResolveDepth.
	seen := make(map[btf.Type]bool)
	var field string
	inspectTags := true
	for depth := 0; depth <= maxDepth; depth++ {
		if seen[typ] {
			return nil, "", fmt.Errorf("cyclic pointer pointee type chain")
		}
		seen[typ] = true
		var next btf.Type
		switch t := typ.(type) {
		case *btf.TypeTag:
			if inspectTags && field == "" {
				switch t.Value {
				case "kptr", "kptr_untrusted", "kptr_ref", "percpu_kptr", "uptr":
					field = t.Value
				}
			}
			next = t.Type
		case *btf.Typedef:
			next = t.Type
		case *btf.Const:
			next = t.Type
		case *btf.Volatile:
			next = t.Type
		case *btf.Restrict:
			next = t.Type
		default:
			return typ, field, nil
		}
		if _, tag := typ.(*btf.TypeTag); !tag {
			inspectTags = qualifiedTags
		}
		typ = next
	}
	return nil, "", fmt.Errorf("pointer pointee type chain exceeds depth %d", maxDepth)
}
