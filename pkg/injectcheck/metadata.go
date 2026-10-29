package injectcheck

import (
	"maps"
	"reflect"

	"github.com/cilium/ebpf/asm"
)

// cilium/ebpf v0.22 has no metadata iterator or public accessors for its
// kconfig/kfunc/ksym keys. Read their pointer identities without unsafe. The
// pinned layout is checked by metadata fixtures; a layout change fails closed.
func loadMetadata(ins asm.Instruction) (map[string]uintptr, error) {
	metadata := reflect.ValueOf(ins.Metadata)
	if metadata.Kind() != reflect.Struct {
		return nil, reject(MetadataUnsupported, "unsupported asm.Metadata layout")
	}
	head := metadata.FieldByName("head")
	if head.Kind() != reflect.Pointer || head.Type().Elem().Kind() != reflect.Struct {
		return nil, reject(MetadataUnsupported, "unsupported asm.Metadata layout")
	}
	identities := map[string]uintptr{}
	for e := head; !e.IsNil(); {
		entry := e.Elem()
		key, value, next := entry.FieldByName("key"), entry.FieldByName("value"), entry.FieldByName("next")
		if key.Kind() != reflect.Interface || value.Kind() != reflect.Interface || next.Kind() != reflect.Pointer || next.Type() != head.Type() {
			return nil, reject(MetadataUnsupported, "unsupported asm.Metadata layout")
		}
		e = next
		// A nil key is a legal annotation with no load-time meaning.
		if key.IsNil() {
			continue
		}
		keyType := key.Elem().Type()
		name := keyType.PkgPath() + "." + keyType.Name()
		switch name {
		case "github.com/cilium/ebpf/btf.coreRelocationMeta", "github.com/cilium/ebpf.kconfigMetaKey", "github.com/cilium/ebpf.kfuncMetaKey", "github.com/cilium/ebpf.ksymMetaKey":
			value = value.Elem()
			if value.Kind() != reflect.Pointer {
				return nil, reject(MetadataUnsupported, "unsupported load-time metadata %s", name)
			}
			identities[name] = value.Pointer()
		}
	}
	return identities, nil
}

func compareMetadata(a, b asm.Instruction) error {
	left, err := loadMetadata(a)
	if err != nil {
		return err
	}
	right, err := loadMetadata(b)
	if err != nil {
		return err
	}
	if !maps.Equal(left, right) {
		return reject(MetadataChanged, "load-time metadata identity changed (CO-RE/kconfig/kfunc/ksym)")
	}
	return nil
}
func noLoadMetadata(ins asm.Instruction) error {
	identities, err := loadMetadata(ins)
	if err != nil {
		return err
	}
	if len(identities) > 0 {
		return reject(MetadataUnsupported, "load-time metadata is unsupported in inserted instructions and serialized projections")
	}
	return nil
}
