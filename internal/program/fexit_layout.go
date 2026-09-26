package program

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
)

// savedReturnSlot is a canonical u32 action shared by the compiled filter and
// the capture epilogue. It occupies fp-12..fp-9, between the u32 map lookup key
// at fp-16 and the eight-byte tag slot at fp-8.
const savedReturnSlot int16 = -12

type savedReturnFetcher struct{}

func (savedReturnFetcher) EmitFetch(dst asm.Register) asm.Instructions {
	return asm.Instructions{asm.LoadMem(dst, asm.R10, savedReturnSlot, asm.Word)}
}

func fexitReturnOffset(prog *ebpf.Program, name string) (int16, error) {
	spec, err := attach.BTFSpec(prog)
	if err != nil {
		return 0, err
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		return 0, err
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return 0, fmt.Errorf("function %q has no BTF prototype", name)
	}
	return fexitPrototypeOffset(proto)
}

// Each supported parameter occupies one u64 tracing slot. Aggregate arguments
// may occupy several slots; reject them instead of guessing from argument count.
// Capture metadata/actions are u32, so void/pointer/wider returns cannot be
// represented faithfully and are explicitly unsupported for packet exit capture.
func fexitPrototypeOffset(proto *btf.FuncProto) (int16, error) {
	if len(proto.Params) == 0 || len(proto.Params) > 5 {
		return 0, fmt.Errorf("fexit packet capture requires 1..5 scalar/pointer parameters")
	}
	if _, ok := btf.UnderlyingType(proto.Params[0].Type).(*btf.Pointer); !ok {
		return 0, fmt.Errorf("fexit packet capture requires a context pointer as the first parameter")
	}
	for _, p := range proto.Params {
		switch typ := btf.UnderlyingType(p.Type).(type) {
		case *btf.Pointer:
		case *btf.Int:
			if typ.Size == 0 || typ.Size > 8 {
				return 0, fmt.Errorf("unsupported fexit parameter %q: integer size %d", p.Name, typ.Size)
			}
		case *btf.Enum:
			if typ.Size == 0 || typ.Size > 8 {
				return 0, fmt.Errorf("unsupported fexit parameter %q: enum size %d", p.Name, typ.Size)
			}
		default:
			return 0, fmt.Errorf("unsupported fexit parameter %q of type %T", p.Name, typ)
		}
	}
	var size uint32
	switch ret := btf.UnderlyingType(proto.Return).(type) {
	case *btf.Int:
		size = ret.Size
	case *btf.Enum:
		size = ret.Size
	default:
		return 0, fmt.Errorf("unsupported fexit return type %T: packet actions require a 32-bit integer", ret)
	}
	if size != 4 {
		return 0, fmt.Errorf("unsupported fexit return size %d: packet actions require a 32-bit integer", size)
	}
	return int16(len(proto.Params) * 8), nil
}

func loadSavedReturn(offset int16) asm.Instructions {
	return asm.Instructions{asm.LoadMem(asm.R2, asm.R10, -48, asm.DWord), asm.LoadMem(asm.R2, asm.R2, offset, asm.Word), asm.StoreMem(asm.R10, savedReturnSlot, asm.R2, asm.Word)}
}
