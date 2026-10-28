//go:build !enable_libpcap

package program

import (
	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// CBPFEnabled reports whether legacy tcpdump filter compilation is built in.
const CBPFEnabled = false

func compileCBPF(_ string, _ ebpf.ProgramType) (codegen.Output, error) {
	return codegen.Output{}, ErrCBPFUnavailable
}
