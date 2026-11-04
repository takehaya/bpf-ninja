package program

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// This guards our tracing-program generators; it does not prove map or memory ownership.
func checkObserverHelpers(insns asm.Instructions) error {
	for i, ins := range insns {
		if !ins.OpCode.Class().IsJump() || ins.OpCode.JumpOp() != asm.Call {
			continue
		}
		if ins.IsFunctionCall() {
			continue // generated callback bodies are part of this same scan
		}
		if ins.IsBuiltinCall() {
			switch asm.BuiltinFunc(ins.Constant) {
			case asm.FnMapLookupElem, asm.FnProbeReadKernel,
				asm.FnKtimeGetNs, asm.FnGetSmpProcessorId, asm.FnJiffies64,
				asm.FnGetFuncArg, asm.FnGetFuncRet, asm.FnLoop,
				asm.FnRingbufReserve, asm.FnRingbufQuery, asm.FnRingbufSubmit, asm.FnRingbufDiscard:
				continue
			}
		}
		return fmt.Errorf("observer call at instruction %d is not allowed: %s", i, ins)
	}
	return nil
}
