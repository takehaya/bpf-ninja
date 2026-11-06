package inject

import (
	"errors"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/ctxflow"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// percpuDeepFixture is deepLookupFixture(-504) with a per-CPU lookup, which
// reads the CPU number in R3.
func percpuDeepFixture() *ebpf.CollectionSpec {
	spec := deepLookupFixture(-504)
	spec.Maps["sessions"].Type = ebpf.PerCPUHash
	insns := spec.Programs["p"].Instructions
	at := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.IsBuiltinCall() })
	insns[at] = asm.FnMapLookupPercpuElem.Call()
	insns = slices.Insert(insns, at, asm.Mov.Imm(asm.R3, 0))
	for i := range insns[:at] {
		if insns[i].OpCode.JumpOp() == asm.JGT {
			insns[i].Offset++ // the short-packet branch crosses the insertion
		}
	}
	spec.Programs["p"].Instructions = insns
	return spec
}

// cut removes out[j], an inserted instruction, and moves every index after it
// and every jump across it.
func cut(out asm.Instructions, cert *injectcheck.Certificate, premises *injectcheck.Premises, j int) asm.Instructions {
	out = slices.Clone(out)
	pcs := make([]int, len(out)+1)
	for i, ins := range out {
		pcs[i+1] = pcs[i] + int(ins.Size()/asm.InstructionSize)
	}
	size := int16(pcs[j+1] - pcs[j])
	for i, ins := range out {
		if !ins.OpCode.Class().IsJump() || ins.IsFunctionCall() || ins.OpCode.JumpOp() == asm.Exit || ins.Reference() != "" {
			continue
		}
		to := pcs[i] + 1 + int(ins.Offset)
		if i < j && to > pcs[j] {
			out[i].Offset -= size
		} else if i > j && to <= pcs[j] {
			out[i].Offset += size
		}
	}
	out = slices.Delete(out, j, j+1)
	for i := range cert.Original {
		if cert.Original[i] > j {
			cert.Original[i]--
		}
	}
	move := func(spans []injectcheck.Span) []injectcheck.Span {
		spans = slices.Clone(spans)
		for i := range spans {
			if spans[i].Start > j {
				spans[i].Start--
			}
			if spans[i].End > j {
				spans[i].End--
			}
		}
		return spans
	}
	cert.Hooks, cert.Wrappers = move(cert.Hooks), move(cert.Wrappers)
	premises.Targets = slices.Clone(premises.Targets)
	for i := range premises.Targets {
		if premises.Targets[i].Hook > j {
			premises.Targets[i].Hook--
		}
	}
	return out
}

func isMov(ins asm.Instruction, dst, src asm.Register) bool {
	mov := asm.Mov.Reg(dst, src)
	return ins.OpCode == mov.OpCode && ins.Dst == dst && ins.Src == src
}

func wantRejected(t *testing.T, err error) {
	t.Helper()
	var rejection *injectcheck.Rejection
	if !errors.As(err, &rejection) {
		t.Fatalf("checker accepted or failed without a rejection: %v", err)
	}
	t.Logf("rejected: %v", err)
}

// Each fault keeps the hook target and result arm but changes the arguments
// the hook gets, into another template the generator also emits. Only the ABI
// planned for the site tells them apart.
func TestCheckerBindsWrapperABI(t *testing.T) {
	t.Run("generic-hit-without-map", func(t *testing.T) {
		// r6=r4, r7=r2, r9=r1, helper, r8=r0, jeq, r1=r6, r2=site, r3=r7,
		// r4=r0, r5=r9, call, r0=r8, exit: drop r9=r1 and r5=r9, and the
		// rest is the typed hit template with a site argument.
		in, out, cert, premises := wrapperPair(t, mapInMapDeepFixture(), deepReq(-504, LookupHit))
		if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
			t.Fatalf("clean pair: %v", err)
		}
		w := cert.Wrappers[0].Start
		if !isMov(out[w+2], asm.R9, asm.R1) || !isMov(out[w+10], asm.R5, asm.R9) {
			t.Fatalf("unexpected wrapper: %v", out[w:cert.Wrappers[0].End])
		}
		out = cut(out, &cert, &premises, w+10)
		out = cut(out, &cert, &premises, w+2)
		_, err := injectcheck.Check(in, out, cert, premises)
		wantRejected(t, err)
	})
	t.Run("site-args-as-no-site-template", func(t *testing.T) {
		// r1=r6, r2=site, r3=r7, r4=r0 becomes r1=r6, r2=r7, r3=r0: the hook
		// planned with a site argument reads the key as the site and the
		// value as the key.
		in, out, cert, premises := wrapperPair(t, deepLookupFixture(-504), deepReq(-504, LookupHit))
		w := cert.Wrappers[0].Start
		if out[w+6].OpCode != asm.Mov.Imm32(asm.R2, 0).OpCode || out[w+6].Dst != asm.R2 {
			t.Fatalf("unexpected wrapper: %v", out[w:cert.Wrappers[0].End])
		}
		out = cut(out, &cert, &premises, w+8)
		out[w+6], out[w+7] = asm.Mov.Reg(asm.R2, asm.R7), asm.Mov.Reg(asm.R3, asm.R0)
		_, err := injectcheck.Check(in, out, cert, premises)
		wantRejected(t, err)
	})
	t.Run("wrong-site-immediate", func(t *testing.T) {
		in, out, cert, premises := wrapperPair(t, deepLookupFixture(-504), deepReq(-504, LookupAny))
		w := cert.Wrappers[0].Start
		found := false
		for j := w; j < cert.Wrappers[0].End; j++ {
			if out[j].OpCode == asm.Mov.Imm32(asm.R2, 0).OpCode && out[j].Dst == asm.R2 {
				out[j].Constant++
				found = true
				break
			}
		}
		if !found {
			t.Fatal("no site argument")
		}
		_, err := injectcheck.Check(in, out, cert, premises)
		wantRejected(t, err)
	})
	t.Run("percpu-ctx-in-r3", func(t *testing.T) {
		// R3 is the per-CPU lookup's CPU. A prelude that loads ctx into R3,
		// read by the wrapper from R3, would pass ctx as the CPU number.
		in, out, cert, premises := wrapperPair(t, percpuDeepFixture(), deepReq(-504, LookupHit))
		if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
			t.Fatalf("clean per-CPU pair: %v", err)
		}
		site := -1
		for i := range in {
			if in[i].IsBuiltinCall() {
				site = cert.Original[i]
			}
		}
		w := cert.Wrappers[0].Start
		prelude := out[site-1]
		if prelude.Dst != asm.R4 || out[w].Src != asm.R4 {
			t.Fatalf("unexpected prelude %v or wrapper head %v", prelude, out[w])
		}
		out = slices.Clone(out)
		out[site-1].Dst = asm.R3
		out[w].Src = asm.R3
		_, err := injectcheck.Check(in, out, cert, premises)
		wantRejected(t, err)
	})
}

// An unwrapped site's hook call is bound to the same planned ABI.
func TestCheckerBindsHookCallABI(t *testing.T) {
	// A frame with room for the slots: the postlude is r0 spill, jeq, r1 =
	// ctx, r2 = site, r3 = key, r4 = r0, call, r0 restore.
	postlude := func(t *testing.T, when LookupWhen) (asm.Instructions, asm.Instructions, injectcheck.Certificate, injectcheck.Premises, int) {
		in, out, cert, premises := lookupPair(t, deepLookupFixture(-480), deepReq(-480, when), false)
		if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
			t.Fatalf("clean pair: %v", err)
		}
		for i := range in {
			if in[i].IsBuiltinCall() {
				return in, out, cert, premises, cert.Original[i]
			}
		}
		t.Fatal("no site")
		return nil, nil, cert, premises, 0
	}
	t.Run("wrong-site-immediate", func(t *testing.T) {
		in, out, cert, premises, site := postlude(t, LookupHit)
		if out[site+4].OpCode != asm.Mov.Imm32(asm.R2, 0).OpCode || out[site+4].Dst != asm.R2 {
			t.Fatalf("unexpected postlude: %v", out[site:site+9])
		}
		out = slices.Clone(out)
		out[site+4].Constant++
		_, err := injectcheck.Check(in, out, cert, premises)
		wantRejected(t, err)
	})
	t.Run("site-args-as-no-site-template", func(t *testing.T) {
		in, out, cert, premises, site := postlude(t, LookupHit)
		key := out[site+5]
		out = cut(out, &cert, &premises, site+5)
		key.Dst = asm.R2
		out[site+4], out[site+5] = key, asm.Mov.Reg(asm.R3, asm.R0)
		_, err := injectcheck.Check(in, out, cert, premises)
		wantRejected(t, err)
	})
}

// A miss-first layout (the jump-limit retry) is a planned wrapper body too.
func TestCheckerAcceptsMissFirstWrapper(t *testing.T) {
	for _, when := range []LookupWhen{LookupHit, LookupMiss, LookupAny} {
		t.Run(string(when), func(t *testing.T) {
			req := deepReq(-504, when)
			req.MissFirst = true
			in, out, cert, premises := wrapperPair(t, deepLookupFixture(-504), req)
			if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != 1 {
				t.Fatalf("counts = %+v, err = %v", counts, err)
			}
		})
	}
	t.Run("generic", func(t *testing.T) {
		req := deepReq(-504, LookupAny)
		req.MissFirst = true
		in, out, cert, premises := wrapperPair(t, mapInMapDeepFixture(), req)
		if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != 2 {
			t.Fatalf("counts = %+v, err = %v", counts, err)
		}
	})
}

// A callback site's ctx comes through its prologue slot, which a wrapper
// prelude does not read, so a callback frame without room is not wrapped. The
// combined limit skips such a site too, since the entry frame is never empty,
// so wrapSites is also checked on its own.
func TestCallbackSiteNotWrapped(t *testing.T) {
	site := discoveredLookup{LookupSite: LookupSite{FuncName: "cb", SitePC: 9, CtxSource: "callback:r2:fp-8"}}
	stack := LookupRequest{Stack: StackAudit{Frames: map[string]int16{"cb": -504}, Source: "verifier", FrameRounding: 16}}
	if group := wrapSites(lookupGroup{op: HookLookup, sites: []discoveredLookup{site}}, stack); group.sites[0].Wrapper == "" {
		t.Fatal("the same site outside a callback is not wrapped")
	}
	site.callback = &ctxflow.Callback{Helper: asm.FnLoop, Param: asm.R2, Arg: -8}
	if group := wrapSites(lookupGroup{op: HookLookup, sites: []discoveredLookup{site}}, stack); group.sites[0].Wrapper != "" {
		t.Fatalf("callback site wrapped as %q", group.sites[0].Wrapper)
	}
	req := autoReq()
	req.Stack = StackAudit{Frames: map[string]int16{"p": -16, "cb": -472}, Source: "verifier", FrameRounding: 16}
	plan, err := transformLookup(callbackSiteFixture("loop", true), req)
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range plan.sites {
		if site.Wrapper != "" {
			t.Fatalf("site %+v wrapped", site)
		}
	}
	if callbackSite(plan.sites) != nil || callbackSite(plan.skipped) == nil {
		t.Fatalf("sites = %+v, skipped = %+v", plan.sites, plan.skipped)
	}
}

// The planned arguments are premises: a wrapped site needs them, and only the
// lists a lookup hook can have are valid.
func TestWrapperABIPremises(t *testing.T) {
	for name, edit := range map[string]func(*injectcheck.SiteTarget){
		"wrapped-without-args": func(target *injectcheck.SiteTarget) { target.Args, target.SitePC = nil, 0 },
		"unknown-list": func(target *injectcheck.SiteTarget) {
			target.Args = []injectcheck.ArgRole{injectcheck.ArgCtx, injectcheck.ArgValue, injectcheck.ArgKey}
			target.SitePC = 0
		},
		"site-pc-without-site": func(target *injectcheck.SiteTarget) {
			target.Args = []injectcheck.ArgRole{injectcheck.ArgCtx, injectcheck.ArgKey, injectcheck.ArgValue}
		},
	} {
		t.Run(name, func(t *testing.T) {
			in, out, cert, premises := wrapperPair(t, deepLookupFixture(-504), deepReq(-504, LookupHit))
			premises.Targets = slices.Clone(premises.Targets)
			edit(&premises.Targets[0])
			_, err := injectcheck.Check(in, out, cert, premises)
			var input *injectcheck.InputError
			if !errors.As(err, &input) || input.Kind != injectcheck.InputTarget {
				t.Fatalf("got %v", err)
			}
		})
	}
}
