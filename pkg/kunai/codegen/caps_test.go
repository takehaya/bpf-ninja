package codegen

import "github.com/cilium/ebpf/asm"

// Test-local stand-in for an action-atom-enabling Capabilities value.
// The codegen package cannot import its own host/xdp sub-package
// without an import cycle, so the inline fixture mirrors XDPFexit's
// shape: Action map, fetcher that loads from stack[-48] then args+8,
// and a reservation set covering the same symbols. Real callers
// import pkg/kunai/host/xdp.FexitCapabilities() instead.
var testActions = map[string]int32{
	"XDP_ABORTED":  0,
	"XDP_DROP":     1,
	"XDP_PASS":     2,
	"XDP_TX":       3,
	"XDP_REDIRECT": 4,
}

type testFexitFetcher struct{}

func (testFexitFetcher) EmitFetch(dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(dst, asm.R10, -48, asm.DWord),
		asm.LoadMem(dst, dst, 8, asm.Word),
	}
}

// xdpFexitCapsForTest returns a Capabilities equivalent to what
// host/xdp.FexitCapabilities() would produce.
func xdpFexitCapsForTest() Capabilities {
	reserved := make(map[string]bool, len(testActions))
	for k := range testActions {
		reserved[k] = true
	}
	return Capabilities{
		Lex:  LexCaps{ReservedLabels: reserved},
		Lang: LangCaps{Action: testActions, ActionFetcher: testFexitFetcher{}},
	}
}
