package syscallhook

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// maxMapTypesELFSize bounds the per-load read while the tracee is stopped.
const maxMapTypesELFSize = 64 << 20 // 64 MiB

// supplyMapTypes supplies hook metadata only; it never changes a live map.
func supplyMapTypes(p *inject.RawProgram, rule Rule) error {
	if rule.MapTypesELF == "" {
		return nil
	}
	if _, _, err := mapTypesLive(p, rule.Map); err != nil {
		return err
	}
	// O_NONBLOCK lets us open a FIFO without waiting for a writer, then reject
	// it using the opened descriptor rather than a racy path-only check.
	f, err := os.OpenFile(rule.MapTypesELF, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("map types ELF: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("map types ELF: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("map types ELF: source must be a regular file")
	}
	if info.Size() > maxMapTypesELFSize {
		return fmt.Errorf("map types ELF: source exceeds 64 MiB limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxMapTypesELFSize+1))
	if err != nil {
		return fmt.Errorf("map types ELF: %w", err)
	}
	if len(data) > maxMapTypesELFSize {
		return fmt.Errorf("map types ELF: source exceeds 64 MiB limit")
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256(data)); !strings.EqualFold(sum, rule.MapTypesSHA256) {
		return fmt.Errorf("map types ELF: SHA-256 %s does not match %s", sum, rule.MapTypesSHA256)
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
		if inject.KernelObjName(m.Name) != name {
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
	liveFD, live, err := mapTypesLive(p, name)
	if err != nil {
		return err
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
	live.Key, live.Value = key, value
	if err := inject.CheckSuppliedMapTypes(live); err != nil {
		return fmt.Errorf("map types ELF: %w", err)
	}
	// Commit both sides together, detached from the source spec.
	live.Key, live.Value = btf.Copy(key), btf.Copy(value)
	p.Maps[liveFD] = live
	return nil
}

func mapTypesLive(p *inject.RawProgram, name string) (int32, inject.RawMap, error) {
	var live inject.RawMap
	var liveFD int32
	found := false
	for fd, m := range p.Maps {
		if m.Name != name {
			continue
		}
		if found {
			return 0, live, fmt.Errorf("map types ELF: ambiguous live map name %q", name)
		}
		live, liveFD, found = m, fd, true
	}
	if !found {
		return 0, live, fmt.Errorf("map types ELF: live map %q missing", name)
	}
	if live.BTFID != 0 || live.Key != nil || live.Value != nil {
		return 0, live, fmt.Errorf("map types ELF: live map %q already has BTF; refusing to replace its types", name)
	}
	return liveFD, live, nil
}

func mapType(types *btf.Spec, name string, fallback btf.Type, size uint32, side string) (btf.Type, error) {
	typ := fallback
	if name != "" {
		if types == nil {
			return nil, fmt.Errorf("map types ELF: no BTF for %s type %q", side, name)
		}
		matches, err := types.AnyTypesByName(name)
		if err != nil && !errors.Is(err, btf.ErrNotFound) {
			return nil, fmt.Errorf("map types ELF: %s type %q: %w", side, name, err)
		}
		// cilium/ebpf v0.22.0 AnyTypesByName can leave non-exact candidates, so filter them ourselves.
		var exact []btf.Type
		for _, candidate := range matches {
			if candidate.TypeName() != name {
				continue
			}
			if n, err := btf.Sizeof(candidate); err != nil || n <= 0 {
				continue // Forward declarations and other unsized entries are not layouts.
			}
			duplicate := false
			for _, previous := range exact {
				if reflect.DeepEqual(btf.UnderlyingType(candidate), btf.UnderlyingType(previous)) {
					duplicate = true
					break
				}
			}
			if !duplicate {
				exact = append(exact, candidate)
			}
		}
		matches = exact
		if len(matches) == 0 {
			return nil, fmt.Errorf("map types ELF: %s type %q missing or has no sized layout", side, name)
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("map types ELF: ambiguous %s type %q (%d distinct layouts)", side, name, len(matches))
		}
		typ = matches[0]
		if fallback != nil {
			if btf.UnderlyingType(typ) != btf.UnderlyingType(fallback) {
				return nil, fmt.Errorf("map types ELF: %s type %q would replace the ELF map's declared type %q", side, name, fallback.TypeName())
			}
			typ = fallback
		}
	}
	if typ == nil {
		return nil, fmt.Errorf("map types ELF: map lacks %s BTF; select an existing type with map_%s_type", side, side)
	}
	n, err := btf.Sizeof(typ)
	if err != nil {
		return nil, fmt.Errorf("map types ELF: %s BTF type has no size: %w", side, err)
	}
	if n <= 0 {
		return nil, fmt.Errorf("map types ELF: %s BTF type has no positive size", side)
	}
	if n != int(size) {
		return nil, fmt.Errorf("map types ELF: %s BTF size mismatch: want %d, got %d", side, size, n)
	}
	return typ, nil
}
