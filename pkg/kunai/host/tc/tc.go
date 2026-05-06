// Package tc provides kunai host adapters for hosts attached as
// fentry / fexit on a tc clsact (BPF_PROG_TYPE_SCHED_CLS) program.
// Importing this package is the canonical way to enable tc-specific
// DSL atoms (currently `where action == TC_ACT_*`) in a kunai filter;
// the kunai core itself holds no tc knowledge — see
// pkg/kunai/codegen/caps.go for the Capabilities contract this
// package conforms to.
package tc

import (
	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/codegen"
)

// Actions matches the TC action verdicts defined in
// uapi/linux/pkt_cls.h. It is the symbolic-name → integer map a host
// passes to kunai so DSL expressions like `where action == TC_ACT_SHOT`
// resolve correctly.
var Actions = map[string]int32{
	"TC_ACT_UNSPEC":     -1,
	"TC_ACT_OK":         0,
	"TC_ACT_RECLASSIFY": 1,
	"TC_ACT_SHOT":       2,
	"TC_ACT_PIPE":       3,
	"TC_ACT_STOLEN":     4,
	"TC_ACT_QUEUED":     5,
	"TC_ACT_REPEAT":     6,
	"TC_ACT_REDIRECT":   7,
	"TC_ACT_TRAP":       8,
}

// FexitFetcher returns a codegen.ActionFetcher for hosts attached as
// fexit on a tc clsact program. It assumes the host wrapper saved the
// BPF tracing args pointer at stack[-48] at program entry and that
// args[1] is the TC verdict slot — both invariants are met by the
// xdp-ninja host program (see internal/program/program.go).
//
// Different host wrappers with a different stack ABI should provide
// their own fetcher rather than reusing this one.
func FexitFetcher() codegen.ActionFetcher { return fexitFetcher{} }

type fexitFetcher struct{}

func (fexitFetcher) EmitFetch(dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(dst, asm.R10, -48, asm.DWord),
		asm.LoadMem(dst, dst, 8, asm.Word),
	}
}

// FexitCapabilities returns the standard codegen.Capabilities for
// hosts attached as fexit on a tc clsact program. The parser-side
// reservation of "TC_ACT_*" labels is derived automatically from
// Actions by kunai.Compile, so the returned struct only sets the two
// required fields.
func FexitCapabilities() codegen.Capabilities {
	return codegen.Capabilities{
		Action:        Actions,
		ActionFetcher: FexitFetcher(),
	}
}
