package attach

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

const (
	FuncPresent     = "present"
	FuncAbsent      = "absent_from_loaded_func_info"
	FuncMissing     = "missing_btf_func"
	FuncNotInTarget = "not_in_target_program"
	FuncUnknown     = "unknown"
)

// FuncAvailability describes membership in this load, independently of BTF linkage.
type FuncAvailability struct {
	Reason         string     `json:"reason"`
	BTFFuncPresent bool       `json:"btf_func_present"`
	FuncTypeID     btf.TypeID `json:"func_type_id,omitempty"`
	Detail         string     `json:"detail,omitempty"`
}

// String is the compact reason used in warnings and listings.
func (a FuncAvailability) String() string {
	return a.Reason
}

// Explain provides context for target-resolution and tracing-load errors.
func (a FuncAvailability) Explain() string {
	switch a.Reason {
	case FuncAbsent:
		return a.Reason + ": BTF FUNC exists but is absent from this program's func_info. If it belongs to this program, the verifier removed the function as unreachable in this load (for example, a feature disabled by configuration), so nothing in it can run now. Loading the program again with that feature enabled makes it observable. Kernels without lazy verification of global subprogs keep these global functions. That mechanism first shipped in Linux v6.8 (commit 2afae08c9dcb8ac648414277cec70c2fe6a34d9e). Our tests on 6.1 kept them and on 7.0 removed them; retention depends on the kernel and backports. Shared BTF may instead describe a function whose body belongs to another program; target that program."
	case FuncMissing:
		return a.Reason + ": no exact BTF FUNC with this name exists in the target's BTF"
	case FuncNotInTarget:
		return a.Reason + ": this BTF FUNC is an external declaration without a body in the target program"
	default:
		if a.Reason == "" {
			a.Reason = FuncUnknown
		}
		message := a.Reason + ": cannot determine loaded func_info membership"
		if a.Detail != "" {
			message += ": " + a.Detail
		}
		return message
	}
}

func (a FuncAvailability) Unavailable() bool {
	return a.Reason == FuncAbsent || a.Reason == FuncMissing || a.Reason == FuncNotInTarget
}

// loadedFuncInfo matches exact type IDs in the cached BTF. FuncInfos() exposes
// names/pointers from another spec, not IDs; avoid translating identity by name.
type loadedFuncInfo struct {
	ids map[btf.TypeID]bool
	err error
}

func readLoadedFuncInfo(prog *ebpf.Program) loadedFuncInfo {
	if prog == nil {
		return loadedFuncInfo{err: errors.New("no loaded program handle")}
	}
	return queryLoadedFuncInfo(func(info *progFuncInfo) error {
		attr := struct {
			FD, Len uint32
			Info    uint64
		}{
			uint32(prog.FD()), uint32(unsafe.Sizeof(*info)), uint64(uintptr(unsafe.Pointer(info))),
		}
		_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		runtime.KeepAlive(prog)
		if errno != 0 {
			return fmt.Errorf("BPF_OBJ_GET_INFO_BY_FD: %w", errno)
		}
		return nil
	})
}

// Prefix of Linux struct bpf_prog_info through nr_func_info (uapi/linux/bpf.h).
type progFuncInfo struct {
	Header    [128]byte
	BTFID     uint32
	RecSize   uint32
	FuncInfo  uint64
	Count     uint32
	LineCount uint32
}

func queryLoadedFuncInfo(query func(*progFuncInfo) error) loadedFuncInfo {
	var info progFuncInfo
	var pinned runtime.Pinner
	defer pinned.Unpin()
	pinned.Pin(&info)
	if err := query(&info); err != nil {
		return loadedFuncInfo{err: err}
	}
	if err := validateFuncInfoHeader(info.Count, info.RecSize); err != nil {
		return loadedFuncInfo{err: err}
	}
	records := make([]funcInfoRecord, info.Count)
	pinned.Pin(&records[0])
	// Request only func_info on the second query, not the JIT/map lengths
	// returned by the first query without their corresponding buffers.
	info.Header = [128]byte{}
	info.BTFID = 0
	info.LineCount = 0
	info.FuncInfo = uint64(uintptr(unsafe.Pointer(&records[0])))
	if err := query(&info); err != nil {
		return loadedFuncInfo{err: err}
	}
	return decodeFuncInfo(info.Count, info.RecSize, records)
}

type funcInfoRecord struct {
	Offset uint32
	TypeID btf.TypeID
}

func validateFuncInfoHeader(count, recSize uint32) error {
	if count == 0 {
		return errors.New("func_info unavailable (count=0); the loader may not have supplied func_info, or the caller lacks CAP_BPF")
	}
	if recSize != 8 {
		return fmt.Errorf("unsupported func_info record size %d (want 8)", recSize)
	}
	return nil
}

func decodeFuncInfo(count, recSize uint32, records []funcInfoRecord) loadedFuncInfo {
	if err := validateFuncInfoHeader(count, recSize); err != nil {
		return loadedFuncInfo{err: err}
	}
	if count != uint32(len(records)) {
		return loadedFuncInfo{err: errors.New("incomplete func_info read")}
	}
	ids := make(map[btf.TypeID]bool, len(records))
	for _, r := range records {
		ids[r.TypeID] = true
	}
	return loadedFuncInfo{ids: ids}
}

func (loaded loadedFuncInfo) classify(spec *btf.Spec, name string) FuncAvailability {
	a := FuncAvailability{Reason: FuncUnknown}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			a.Reason = FuncMissing
		} else {
			a.Detail = err.Error()
		}
		return a
	}
	return loaded.classifyFunc(spec, fn)
}

func (loaded loadedFuncInfo) classifyFunc(spec *btf.Spec, fn *btf.Func) FuncAvailability {
	a := FuncAvailability{Reason: FuncUnknown, BTFFuncPresent: true}
	id, err := spec.TypeID(fn)
	if err != nil {
		a.Detail = err.Error()
		return a
	}
	a.FuncTypeID = id
	if loaded.err != nil {
		a.Detail = loaded.err.Error()
		return a
	}
	if loaded.ids[id] {
		a.Reason = FuncPresent
	} else if fn.Linkage == btf.ExternFunc {
		a.Reason = FuncNotInTarget
	} else {
		a.Reason = FuncAbsent
	}
	return a
}

// FuncAvailability caches one func_info read per ProgInfo, including read failures.
func (p *ProgInfo) FuncAvailability(name string) FuncAvailability {
	spec, err := p.BTFSpecCached()
	if err != nil {
		return FuncAvailability{Reason: FuncUnknown, Detail: err.Error()}
	}
	return p.funcInfoCached().classify(spec, name)
}

func (p *ProgInfo) funcInfoCached() *loadedFuncInfo {
	if p.loadedFuncs == nil {
		loaded := readLoadedFuncInfo(p.Program)
		p.loadedFuncs = &loaded
	}
	return p.loadedFuncs
}

// ListFuncs reads and caches loaded func_info, including read failures, once per ProgInfo.
// It includes every BTF FUNC, classified by exact type ID, even if absent from this load.
func (p *ProgInfo) ListFuncs() ([]FuncInfo, error) {
	spec, err := p.BTFSpecCached()
	if err != nil {
		return nil, err
	}
	loaded := p.funcInfoCached()
	var funcs []FuncInfo
	for typ, err := range spec.All() {
		if err != nil {
			return funcs, err
		}
		if fn, ok := typ.(*btf.Func); ok {
			funcs = append(funcs, FuncInfo{
				Name: fn.Name, Linkage: fn.Linkage.String(),
				Availability: loaded.classifyFunc(spec, fn),
			})
		}
	}
	return funcs, nil
}
