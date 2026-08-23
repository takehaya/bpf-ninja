package hook

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// skBuffPacketOffsets returns the kernel BTF byte offsets of
// `struct sk_buff`'s `data` (8B pointer), `len` (4B u32), and
// `data_len` (4B u32) members. `len - data_len` is the linear head
// length (skb_headlen()); the prologues clamp the packet window to it
// because a GRO/GSO or fragmented skb keeps `data_len` bytes in frags
// that a flat read from `data` must not cross.
// tc clsact fexit/fentry programs receive a `struct sk_buff *` (the
// kernel struct, NOT the BPF-rewritten `__sk_buff` view) at args[0],
// so the linear-region read needs the actual member offsets — which
// drift across kernel versions, hence runtime BTF resolution.
//
// Cached at first call: BTF spec load + walk is on the order of
// milliseconds, fine to amortise across all probes loaded in-process.
func skBuffPacketOffsets() (data uint32, length uint32, dataLen uint32, err error) {
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
		var foundData, foundLen, foundDataLen bool
		for _, m := range skb.Members {
			switch m.Name {
			case "data":
				skBuffDataOff = m.Offset.Bytes()
				foundData = true
			case "len":
				skBuffLenOff = m.Offset.Bytes()
				foundLen = true
			case "data_len":
				skBuffDataLenOff = m.Offset.Bytes()
				foundDataLen = true
			}
		}
		if !foundData || !foundLen || !foundDataLen {
			skBuffErr = fmt.Errorf("BTF struct sk_buff missing data, len, or data_len member (data=%v len=%v data_len=%v)", foundData, foundLen, foundDataLen)
			return
		}
	})
	return skBuffDataOff, skBuffLenOff, skBuffDataLenOff, skBuffErr
}

var (
	skBuffOnce       sync.Once
	skBuffDataOff    uint32
	skBuffLenOff     uint32
	skBuffDataLenOff uint32
	skBuffErr        error
)
