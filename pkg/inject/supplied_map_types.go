package inject

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// CheckSuppliedMapTypes checks operator-supplied types for a BTF-less lookup
// map. Supervisors call this before supplementation; TransformLookupRaw must
// still accept kernel-validated types containing special fields.
func CheckSuppliedMapTypes(m RawMap) error {
	for _, side := range []struct {
		name string
		typ  btf.Type
	}{{"key", m.Key}, {"value", m.Value}} {
		seen := make(map[btf.Type]bool)
		var check func(btf.Type) error
		check = func(typ btf.Type) error {
			typ = btf.UnderlyingType(typ)
			if seen[typ] {
				return nil
			}
			seen[typ] = true
			if field := specialField(typ); field != "" {
				return fmt.Errorf("map %s type contains special field %q; a map without BTF cannot have special fields", side.name, field)
			}
			var members []btf.Member
			switch t := typ.(type) {
			case *btf.Int, *btf.Enum, *btf.Float:
				return nil
			case *btf.Pointer:
				// As preserves tags while traversing pointee typedefs and qualifiers.
				for target := t.Target; ; {
					tag, ok := btf.As[*btf.TypeTag](target)
					if !ok {
						break
					}
					switch tag.Value {
					case "kptr", "kptr_untrusted", "kptr_ref", "percpu_kptr", "uptr":
						return fmt.Errorf("map %s type contains special field %q; a map without BTF cannot have special fields", side.name, tag.Value)
					}
					target = tag.Type
				}
				switch target := btf.UnderlyingType(t.Target); target.(type) {
				case *btf.Void, *btf.Fwd:
					return nil
				default:
					return check(target)
				}
			case *btf.Struct:
				members = t.Members
			case *btf.Union:
				members = t.Members
			case *btf.Array:
				return check(t.Type)
			default:
				return fmt.Errorf("map %s type %T is not a data kind", side.name, typ)
			}
			for _, member := range members {
				if err := check(member.Type); err != nil {
					return err
				}
			}
			return nil
		}
		if err := check(side.typ); err != nil {
			return err
		}
	}
	if reason := checkLookupMap(&m); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	return nil
}
