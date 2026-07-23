package hook

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// skBuffPacketOffsets returns the kernel BTF byte offsets of
// `struct sk_buff`'s `data` (8B pointer) and `len` (4B u32) members.
// tc clsact fexit/fentry programs receive a `struct sk_buff *` (the
// kernel struct, NOT the BPF-rewritten `__sk_buff` view) at args[0],
// so the linear-region read needs the actual member offsets — which
// drift across kernel versions, hence runtime BTF resolution.
//
// Cached at first call: BTF spec load + walk is on the order of
// milliseconds, fine to amortise across all probes loaded in-process.
func skBuffPacketOffsets() (data uint32, length uint32, err error) {
	skBuffOnce.Do(func() {
		var spec *btf.Spec
		spec, skBuffErr = btf.LoadKernelSpec()
		if skBuffErr != nil {
			skBuffErr = fmt.Errorf("loading kernel BTF: %w", skBuffErr)
			return
		}
		var skb *btf.Struct
		if err := spec.TypeByName("sk_buff", &skb); err != nil {
			skBuffErr = fmt.Errorf("BTF type sk_buff not found: %w", err)
			return
		}
		var foundData, foundLen bool
		for _, m := range skb.Members {
			switch m.Name {
			case "data":
				skBuffDataOff = m.Offset.Bytes()
				foundData = true
			case "len":
				skBuffLenOff = m.Offset.Bytes()
				foundLen = true
			}
		}
		if !foundData || !foundLen {
			skBuffErr = fmt.Errorf("BTF struct sk_buff missing data or len member (data=%v len=%v)", foundData, foundLen)
			return
		}
	})
	return skBuffDataOff, skBuffLenOff, skBuffErr
}

var (
	skBuffOnce    sync.Once
	skBuffDataOff uint32
	skBuffLenOff  uint32
	skBuffErr     error
)
