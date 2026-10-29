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
	head := reflect.ValueOf(ins.Metadata).FieldByName("head")
	if !head.IsValid() || head.Kind() != reflect.Pointer {
		return nil, reject(MetadataUnsupported, "unsupported asm.Metadata layout")
	}
	identities := map[string]uintptr{}
	for e := head; !e.IsNil(); e = e.Elem().FieldByName("next") {
		key := e.Elem().FieldByName("key").Elem().Type()
		name := key.PkgPath() + "." + key.Name()
		switch name {
		case "github.com/cilium/ebpf/btf.coreRelocationMeta", "github.com/cilium/ebpf.kconfigMetaKey", "github.com/cilium/ebpf.kfuncMetaKey", "github.com/cilium/ebpf.ksymMetaKey":
			value := e.Elem().FieldByName("value").Elem()
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
