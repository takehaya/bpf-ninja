package codegen

import (
	"fmt"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/ir"
)

// genNoCheckDispatch emits nothing: when a vocab declares
// KUNAI_<SELF>_<PARENT>_NO_CHECK = true the child is trusted to follow
// the parent without a boundary marker (e.g. EoMPLS payload, inner
// Ethernet of a pseudowire). The bounds check in genLayer still
// protects scratch-buffer reads.
func genNoCheckDispatch(current *ir.LayerInstance) (asm.Instructions, error) {
	if !current.Dispatch.Const.Bool {
		return nil, fmt.Errorf("codegen: NO_CHECK const %q must be true to be emitted", current.Dispatch.Const.Name)
	}
	return nil, nil
}
