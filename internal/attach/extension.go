package attach

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// extensionLink describes a live freplace edge, with BTF IDs local to the target.
type extensionLink struct {
	ProgramID uint32
	TargetID  uint32
	FuncID    btf.TypeID
}

func extensionLinks() ([]extensionLink, error) {
	it := new(link.Iterator)
	defer it.Close()
	var edges []extensionLink
	for it.Next() {
		// Link exposes FD but not the common header separately from detailed
		// Info. Read that header first so unrelated link implementations'
		// Info errors cannot prevent capture.
		fdLink, ok := it.Link.(interface{ FD() int })
		if !ok {
			return nil, fmt.Errorf("link %d does not expose an FD for freplace checks", it.ID)
		}
		var header struct{ Type, ID, Program uint32 }
		// The BPF ABI stores this pointer as a u64; keep its address stable
		// while the syscall wrapper runs, including Go stack growth.
		var pinned runtime.Pinner
		pinned.Pin(&header)
		attr := struct {
			FD, Len uint32
			Info    uint64
		}{uint32(fdLink.FD()), uint32(unsafe.Sizeof(header)), uint64(uintptr(unsafe.Pointer(&header)))}
		_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		pinned.Unpin()
		if errno == unix.ENOENT {
			continue
		}
		if errno != 0 {
			return nil, fmt.Errorf("reading link %d header for freplace checks: %w", it.ID, errno)
		}
		if link.Type(header.Type) != link.TracingType {
			continue
		}
		p, err := ebpf.NewProgramFromID(ebpf.ProgramID(header.Program))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		typ := p.Type()
		_ = p.Close()
		if typ != ebpf.Extension {
			continue
		}
		info, err := it.Link.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading link info: %w", err)
		}
		tr := info.Tracing()
		if tr == nil || tr.TargetObjectId == 0 {
			continue
		}
		edges = append(edges, extensionLink{uint32(info.Program), tr.TargetObjectId, btf.TypeID(tr.TargetBtfId)})
	}
	return edges, it.Err()
}

func selectHookType(id uint32, actual ebpf.ProgramType, edges []extensionLink, resolve func(uint32) (ebpf.ProgramType, error)) (ebpf.ProgramType, error) {
	if actual != ebpf.Extension {
		return actual, nil
	}
	var selected ebpf.ProgramType
	for _, edge := range edges {
		if edge.ProgramID != id {
			continue
		}
		typ, err := resolve(edge.TargetID)
		if err != nil {
			return 0, fmt.Errorf("resolving EXT target %d: %w", edge.TargetID, err)
		}
		// The kernel enforces saved_dst_prog_type on subsequent attaches.
		if selected != 0 && selected != typ {
			return 0, fmt.Errorf("EXT program (id=%d) has conflicting target hook types: %s and %s", id, selected, typ)
		}
		selected = typ
	}
	if selected == 0 {
		return 0, fmt.Errorf("EXT program (id=%d) is unattached: no freplace link found", id)
	}
	return selected, nil
}

// ProgramHookType resolves the packet adapter independently of the actual type.
func ProgramHookType(id uint32, actual ebpf.ProgramType) (ebpf.ProgramType, error) {
	if actual != ebpf.Extension {
		return actual, nil
	}
	edges, err := extensionLinks()
	if err != nil {
		return 0, fmt.Errorf("listing EXT links: %w", err)
	}
	return programHookType(id, actual, edges)
}

func programHookType(id uint32, actual ebpf.ProgramType, edges []extensionLink) (ebpf.ProgramType, error) {
	// saved_dst_prog_type is set at load time, but only live links expose
	// the replaced program to userspace; do not guess from ctx BTF.
	return selectHookType(id, actual, edges, func(id uint32) (ebpf.ProgramType, error) {
		p, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
		if err != nil {
			return 0, err
		}
		defer func() { _ = p.Close() }()
		info, err := p.Info()
		if err != nil {
			return 0, err
		}
		return info.Type, nil
	})
}

func checkReplacement(edges []extensionLink, id uint32, fid btf.TypeID, name string) error {
	for _, edge := range edges {
		if edge.TargetID == id && edge.FuncID == fid {
			return fmt.Errorf("program (id=%d) function %s is replaced by EXT program (id=%d); target -p %d instead", id, name, edge.ProgramID, edge.ProgramID)
		}
	}
	return nil
}

// ExtensionGuard shares a live-link snapshot and parsed BTF across one load.
// A new operation must create a new guard to avoid retaining stale link state.
type ExtensionGuard struct {
	edges    []extensionLink
	programs map[*ebpf.Program]*extensionProgram
}
type extensionProgram struct {
	id    uint32
	entry string
	spec  *btf.Spec
}

func NewExtensionGuard() (*ExtensionGuard, error) {
	edges, err := extensionLinks()
	if err != nil {
		return nil, fmt.Errorf("cannot check freplace safety: enumerating links: %w", err)
	}
	return &ExtensionGuard{edges: edges, programs: make(map[*ebpf.Program]*extensionProgram)}, nil
}

func (g *ExtensionGuard) Spec(prog *ebpf.Program) (*btf.Spec, error) {
	if p := g.programs[prog]; p != nil {
		return p.spec, nil
	}
	info, err := prog.Info()
	if err != nil {
		return nil, err
	}
	id, _ := info.ID()
	entry, spec, err := resolveEntryFunc(prog, uint32(id))
	if err != nil {
		return nil, err
	}
	g.programs[prog] = &extensionProgram{uint32(id), entry, spec}
	return spec, nil
}

func (g *ExtensionGuard) Check(prog *ebpf.Program, name string, allowSlot bool) error {
	spec, err := g.Spec(prog)
	if err != nil {
		return err
	}
	p := g.programs[prog]
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		return err
	}
	fid, err := spec.TypeID(fn)
	if err != nil {
		return err
	}
	if err := checkReplacement(g.edges, p.id, fid, name); err != nil {
		return err
	}
	if !allowSlot && name != p.entry && fn.Linkage == btf.GlobalFunc {
		for _, edge := range g.edges {
			if edge.TargetID == p.id {
				return fmt.Errorf("program (id=%d) function %s may be a freplace slot; attaching would make a later freplace fail with EBUSY; use --allow-dispatcher-slot to override", p.id, name)
			}
		}
	}
	return nil
}

// CheckReplacedFunc checks replacement and dispatcher slot safety.
func CheckReplacedFunc(prog *ebpf.Program, name string) error {
	g, err := NewExtensionGuard()
	if err != nil {
		return err
	}
	return g.Check(prog, name, false)
}

// ProgramHookType resolves an EXT adapter using this operation's link snapshot.
func (g *ExtensionGuard) ProgramHookType(prog *ebpf.Program) (ebpf.ProgramType, error) {
	info, err := prog.Info()
	if err != nil {
		return 0, err
	}
	id, _ := info.ID()
	return programHookType(uint32(id), info.Type, g.edges)
}
