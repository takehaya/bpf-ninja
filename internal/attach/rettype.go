package attach

import (
	"os"
	"slices"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// Kernel BTF sources of RetPointee; tests replace them.
var (
	loadVmlinuxBTF = btf.LoadKernelSpec
	loadModuleBTF  = btf.LoadKernelModuleSpec
	moduleBTFNames = func() ([]string, error) {
		entries, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			return nil, err
		}
		var names []string
		for _, e := range entries {
			if e.Name() != "vmlinux" {
				names = append(names, e.Name())
			}
		}
		return names, nil
	}
)

var (
	retPointeeMu    sync.Mutex
	retPointeeCache = map[string]btf.Type{}
)

// RetPointee returns the kernel struct or union named name, the type a
// generated call hook's ret_type decl tag gives its const void *ret: from
// vmlinux BTF, else from the one module BTF that defines it (a provider
// such as nf_conntrack built as a module). nil when no kernel BTF at hand
// has it, or more than one module defines it; ret then stays untyped and
// can only be compared with null. It is the one place where the capture
// decides the type behind ret.
func RetPointee(name string) btf.Type {
	retPointeeMu.Lock()
	defer retPointeeMu.Unlock()
	if typ, ok := retPointeeCache[name]; ok {
		return typ
	}
	typ := findRetPointee(name)
	retPointeeCache[name] = typ
	return typ
}

func findRetPointee(name string) btf.Type {
	if spec, err := loadVmlinuxBTF(); err == nil {
		if typ := aggregateByName(spec, name); typ != nil {
			return typ
		}
	}
	modules, err := moduleBTFNames()
	if err != nil {
		return nil
	}
	slices.Sort(modules)
	var found btf.Type
	for _, module := range modules {
		spec, err := loadModuleBTF(module)
		if err != nil {
			continue
		}
		if typ := aggregateByName(spec, name); typ != nil {
			if found != nil && found != typ {
				return nil // ambiguous: two modules define it
			}
			found = typ
		}
	}
	return found
}

// aggregateByName is the one struct or union named name in spec, nil when
// spec has none or more than one.
func aggregateByName(spec *btf.Spec, name string) btf.Type {
	types, err := spec.AnyTypesByName(name)
	if err != nil {
		return nil
	}
	var found btf.Type
	for _, typ := range types {
		switch typ.(type) {
		case *btf.Struct, *btf.Union:
			if found != nil {
				return nil
			}
			found = typ
		}
	}
	return found
}
