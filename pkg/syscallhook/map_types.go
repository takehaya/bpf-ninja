package syscallhook

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// supplyMapTypes supplies hook metadata only; it never changes a live map.
func supplyMapTypes(p *inject.RawProgram, rule Rule) error {
	if rule.MapTypesELF == "" {
		return nil
	}
	data, err := os.ReadFile(rule.MapTypesELF)
	if err != nil {
		return fmt.Errorf("map types ELF: %w", err)
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256(data)); !strings.EqualFold(sum, rule.MapTypesSHA256) {
		return fmt.Errorf("map types ELF SHA-256 %s does not match %s", sum, rule.MapTypesSHA256)
	}
	// Parse the same bytes that were hashed, so replacing the file cannot change the source.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("map types ELF: %w", err)
	}
	if spec.ByteOrder != wire {
		return fmt.Errorf("map types ELF: byte order does not match live program")
	}
	return supplyMapTypesFromSpec(p, rule, spec)
}

func supplyMapTypesFromSpec(p *inject.RawProgram, rule Rule, spec *ebpf.CollectionSpec) error {
	name := rule.Map
	var schema *ebpf.MapSpec
	for _, m := range spec.Maps {
		kernelName := m.Name
		if len(kernelName) > 15 {
			kernelName = kernelName[:15]
		}
		if kernelName != name {
			continue
		}
		if schema != nil {
			return fmt.Errorf("map types ELF: ambiguous kernel map name %q", name)
		}
		schema = m
	}
	if schema == nil {
		return fmt.Errorf("map types ELF: map %q missing", name)
	}
	var live inject.RawMap
	var liveFD int32
	found := false
	for fd, m := range p.Maps {
		if m.Name != name {
			continue
		}
		if found {
			return fmt.Errorf("map types ELF: ambiguous live map name %q", name)
		}
		live, liveFD, found = m, fd, true
	}
	if !found {
		return fmt.Errorf("map types ELF: live map %q missing", name)
	}
	if live.BTFID != 0 || live.Key != nil || live.Value != nil {
		return fmt.Errorf("map types ELF: live map %q already has BTF; refusing to replace its types", name)
	}
	if live.Type != schema.Type {
		return fmt.Errorf("map types ELF: map %q type mismatch: live %s, ELF %s", name, live.Type, schema.Type)
	}
	if live.KeySize != schema.KeySize || live.ValueSize != schema.ValueSize {
		return fmt.Errorf("map types ELF: map %q sizes mismatch: live %d/%d, ELF %d/%d", name, live.KeySize, live.ValueSize, schema.KeySize, schema.ValueSize)
	}
	if live.Flags != schema.Flags {
		return fmt.Errorf("map types ELF: map %q flags mismatch: live %#x, ELF %#x", name, live.Flags, schema.Flags)
	}
	key, err := mapType(spec.Types, rule.MapKeyType, schema.Key, live.KeySize, "key")
	if err != nil {
		return err
	}
	value, err := mapType(spec.Types, rule.MapValueType, schema.Value, live.ValueSize, "value")
	if err != nil {
		return err
	}
	// Commit both sides together only after all checks succeed.
	live.Key, live.Value = btf.Copy(key), btf.Copy(value)
	p.Maps[liveFD] = live
	return nil
}

func mapType(types *btf.Spec, name string, fallback btf.Type, size uint32, side string) (btf.Type, error) {
	typ := fallback
	if name != "" {
		if types == nil {
			return nil, fmt.Errorf("map types ELF: no BTF for %s type %q", side, name)
		}
		matches, err := types.AnyTypesByName(name)
		// Check exact names ourselves: ebpf-go v0.22.0 can leave non-exact flavors.
		var exact []btf.Type
		for _, candidate := range matches {
			if candidate.TypeName() == name {
				exact = append(exact, candidate)
			}
		}
		matches = exact
		if err != nil || len(matches) == 0 {
			return nil, fmt.Errorf("map types ELF: %s type %q missing", side, name)
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("map types ELF: ambiguous %s type %q (%d matches)", side, name, len(matches))
		}
		typ = matches[0]
	}
	if typ == nil {
		return nil, fmt.Errorf("map types ELF: map lacks %s BTF; select an existing type with map_%s_type", side, side)
	}
	n, err := btf.Sizeof(typ)
	if err != nil || n != int(size) {
		return nil, fmt.Errorf("map types ELF: %s BTF size mismatch: want %d, got %d (%v)", side, size, n, err)
	}
	return typ, nil
}
