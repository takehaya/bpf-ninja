package program

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/record"
)

func TestObserverFormsUseAllowedHelpers(t *testing.T) {
	out, err := compileFilter("eth/mpls@m{1,8}/ipv4/tcp where m.label == 7", true, false, ebpf.XDP)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Callbacks) == 0 {
		t.Fatal("DSL fixture emitted no callback subprogram")
	}
	h, _ := hook.ByName(hook.KindXDP)
	build := func(insns asm.Instructions, err error) asm.Instructions {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return insns
	}
	entry := build(buildTracingInsnsForHook(h, out, filter.TargetFilters{}, 1, 2, 3, false, 0, nil, nil, 0))
	exit := build(buildTracingInsnsForHook(h, out, filter.TargetFilters{}, 1, 2, 3, true, 48, nil, nil, 0))
	gatedEntry := build(buildGatedEntryInsns(h, out, filter.TargetFilters{}, 4, 5, 3, 2, nil, nil, EmitBoth, 128, 0))
	gatedExit := build(buildGatedExitInsns(h, out, filter.TargetFilters{}, 1, 4, 3, 2, nil, nil, EmitBoth, 128, 48, 0, false))
	static := staticXDPHook(h, true)
	staticExit := build(buildGatedExitInsns(static, out, filter.TargetFilters{}, 1, 4, 3, 2, nil, nil, EmitBoth, 128, fexitReturnViaHelper, 0, true))
	layout := &record.Layout{Mode: record.ModeFilter, Fields: []record.Field{{Name: "site", ParamIndex: 1, Size: 4}}}
	recording := build(buildRecordingInsns(h, out, filter.TargetFilters{}, 1, 2, 3, false, 0, nil, nil, 0, layout, 1, &fieldSnap{fd: 6, layout: layout}))
	argEcho := buildArgEchoInsns(1, nil, []attach.FuncParamInfo{{Name: "value", Index: 1, Size: 4, Deref: true}})

	forms := map[string]asm.Instructions{
		"entry": entry, "exit": exit, "gated-entry": gatedEntry, "gated-exit": gatedExit,
		"static-exit": staticExit, "recording": recording, "arg-echo": argEcho,
	}
	seen := map[asm.BuiltinFunc]bool{}
	for name, insns := range forms {
		t.Run(name, func(t *testing.T) {
			if err := checkObserverHelpers(insns); err != nil {
				t.Fatal(err)
			}
			for _, ins := range insns {
				if ins.IsBuiltinCall() {
					seen[asm.BuiltinFunc(ins.Constant)] = true
				}
			}
		})
	}
	for _, helper := range []asm.BuiltinFunc{
		asm.FnMapLookupElem, asm.FnProbeReadKernel, asm.FnKtimeGetNs, asm.FnGetSmpProcessorId,
		asm.FnJiffies64, asm.FnGetFuncArg, asm.FnGetFuncRet, asm.FnLoop,
		asm.FnRingbufReserve, asm.FnRingbufQuery, asm.FnRingbufSubmit, asm.FnRingbufDiscard,
	} {
		if !seen[helper] {
			t.Errorf("current observer fixtures emitted no %s call", helper)
		}
	}
}

func TestObserverHelpersRejectStateChangingAndUnknownCalls(t *testing.T) {
	for _, ins := range []asm.Instruction{
		asm.FnMapUpdateElem.Call(), asm.FnMapDeleteElem.Call(), asm.FnTailCall.Call(),
		asm.FnRedirect.Call(), asm.FnOverrideReturn.Call(), asm.FnProbeWriteUser.Call(),
		asm.FnGetPrandomU32.Call(), asm.BuiltinFunc(9999).Call(),
		{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: 1},
	} {
		if err := checkObserverHelpers(asm.Instructions{ins}); err == nil {
			t.Fatalf("allowed %s", ins)
		}
	}
}
