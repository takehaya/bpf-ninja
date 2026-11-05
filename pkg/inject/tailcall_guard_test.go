package inject

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func tailGuardFunc(name string, linkage btf.FuncLinkage) *btf.Func {
	return &btf.Func{Name: name, Linkage: linkage, Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}}}
}

func tailGuardFixture(entry, sub, leaf asm.Instructions, linkage btf.FuncLinkage) asm.Instructions {
	entry[0] = btf.WithFuncMetadata(entry[0].WithSymbol("entry"), tailGuardFunc("entry", btf.GlobalFunc))
	sub[0] = btf.WithFuncMetadata(sub[0].WithSymbol("sub"), tailGuardFunc("sub", linkage))
	leaf[0] = btf.WithFuncMetadata(leaf[0].WithSymbol("leaf"), tailGuardFunc("leaf", btf.StaticFunc))
	return append(append(entry, sub...), leaf...)
}

func TestTailCallReachabilityLossPositions(t *testing.T) {
	tail := asm.Instructions{asm.FnTailCall.Call(), asm.Mov.Imm(asm.R0, 2), asm.Return()}
	leaf := asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
	cases := []struct {
		name    string
		entry   asm.Instructions
		sub     asm.Instructions
		linkage btf.FuncLinkage
		lost    bool
	}{
		{"before tail in static", asm.Instructions{asm.Call.Label("sub"), asm.Return()}, append(asm.Instructions{asm.Call.Label("leaf")}, tail...), btf.StaticFunc, true},
		{"after tail in static", asm.Instructions{asm.Call.Label("sub"), asm.Return()}, append(append(asm.Instructions{}, tail[:1]...), asm.Call.Label("leaf"), asm.Mov.Imm(asm.R0, 2), asm.Return()), btf.StaticFunc, true},
		{"caller before sub", asm.Instructions{asm.Call.Label("leaf"), asm.Call.Label("sub"), asm.Return()}, tail, btf.StaticFunc, false},
		{"caller after sub", asm.Instructions{asm.Call.Label("sub"), asm.Call.Label("leaf"), asm.Return()}, tail, btf.StaticFunc, false},
		{"nested callee", asm.Instructions{asm.Call.Label("sub"), asm.Return()}, append(append(asm.Instructions{}, tail[:1]...), asm.Call.Label("middle"), asm.Mov.Imm(asm.R0, 2), asm.Return(),
			btf.WithFuncMetadata(asm.Call.Label("leaf").WithSymbol("middle"), tailGuardFunc("middle", btf.StaticFunc)), asm.Return()), btf.StaticFunc, true},
		{"global subprogram", asm.Instructions{asm.Call.Label("sub"), asm.Return()}, append(append(asm.Instructions{}, tail[:1]...), asm.Call.Label("leaf"), asm.Mov.Imm(asm.R0, 2), asm.Return()), btf.GlobalFunc, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := losesTailCallReachability(tailGuardFixture(tc.entry, tc.sub, leaf, tc.linkage))
			if err != nil || got != tc.lost {
				t.Fatalf("lost=%v err=%v, want %v", got, err, tc.lost)
			}
		})
	}

	entryTail := tailGuardFixture(append(asm.Instructions{asm.Call.Label("leaf")}, tail...), asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}, leaf, btf.StaticFunc)
	if lost, err := losesTailCallReachability(entryTail); err != nil || lost {
		t.Fatalf("entry tail call lost=%v err=%v", lost, err)
	}
}

func TestTailCallReachabilityLossMustBeIntroduced(t *testing.T) {
	broken := tailGuardFixture(asm.Instructions{asm.Call.Label("sub"), asm.Return()},
		asm.Instructions{asm.FnTailCall.Call(), asm.Call.Label("leaf"), asm.Mov.Imm(asm.R0, 2), asm.Return()},
		asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}, btf.StaticFunc)
	introduced, err := introducesTailCallReachabilityLoss(broken, broken)
	if err != nil || introduced {
		t.Fatalf("native shape introduced=%v err=%v", introduced, err)
	}
}

func TestTailCallReachabilityGuard(t *testing.T) {
	probeErr := errors.New("native test_run fell through")
	t.Run("refuses subprogram lookup hook", func(t *testing.T) {
		work := subprogramTailLookupFixture()
		req := autoReq()
		req.Stack.LowestOffset = -16
		calls := 0
		plan, err := transformLookupGuarded(work, req, func() error { calls++; return probeErr })
		if calls != 1 || !errors.Is(err, ErrRefused) || len(plan.skipped) != 1 ||
			!strings.Contains(plan.skipped[0].Reason, probeErr.Error()) {
			t.Fatalf("calls=%d plan=%+v err=%v", calls, plan, err)
		}
	})

	t.Run("keeps entry and skips unsafe tail hook", func(t *testing.T) {
		work := subTailCallerFixture()
		calls := 0
		plan, err := transformLookupGuarded(work, LookupRequest{ProgramName: "caller", Entry: true, TailCalls: true,
			HookName: "obs", Stack: StackAudit{LowestOffset: 0}}, func() error { calls++; return probeErr })
		if err != nil || calls != 1 || len(plan.hooks) != 1 || plan.hooks[0].Kind != HookEntry || len(plan.skipped) != 1 ||
			plan.skipped[0].Op != HookTailCall || !strings.Contains(plan.skipped[0].Reason, probeErr.Error()) {
			t.Fatalf("calls=%d plan=%+v err=%v", calls, plan, err)
		}
	})

	t.Run("refuses when no site remains", func(t *testing.T) {
		work := subTailCallerFixture()
		_, err := transformLookupGuarded(work, LookupRequest{ProgramName: "caller", TailCalls: true,
			HookName: "obs", Stack: StackAudit{LowestOffset: 0}}, func() error { return probeErr })
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no hook site is safe") || !strings.Contains(err.Error(), probeErr.Error()) {
			t.Fatalf("refusal: %v", err)
		}
	})

	t.Run("does not probe unaffected rewrite", func(t *testing.T) {
		work := tailCallerFixture()
		calls := 0
		if _, err := transformLookupGuarded(work, LookupRequest{ProgramName: "caller", TailCalls: true,
			HookName: "obs", Stack: StackAudit{LowestOffset: 0}}, func() error { calls++; return probeErr }); err != nil || calls != 0 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})

	t.Run("does not probe native broken shape", func(t *testing.T) {
		work := subTailCallerWithFallthroughCallFixture()
		calls := 0
		if _, err := transformLookupGuarded(work, LookupRequest{ProgramName: "caller", TailCalls: true,
			HookName: "obs", Stack: StackAudit{LowestOffset: 0}}, func() error { calls++; return probeErr }); err != nil || calls != 0 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})

	t.Run("raw load path reports the skipped site", func(t *testing.T) {
		raw, _ := rawLookupFixtureBTF(t, subTailCallerFixture(), "caller", true)
		result, err := TransformLookupRawGuarded(raw, LookupRequestRaw{Entry: true, TailCalls: true,
			HookName: "obs", Stack: StackAudit{LowestOffset: 0}}, func() error { return probeErr })
		if err != nil || len(result.Hooks) != 1 || result.Hooks[0].Kind != HookEntry || len(result.Skipped) != 1 ||
			!strings.Contains(result.Skipped[0].Reason, probeErr.Error()) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
}
