package inject

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// deepLookupFixture is lookupFixture with its frame reaching fp+floor.
func deepLookupFixture(floor int16) *ebpf.CollectionSpec {
	spec := lookupFixture()
	insns := spec.Programs["p"].Instructions
	spec.Programs["p"].Instructions = append(insns[:1:1], append(asm.Instructions{asm.StoreImm(asm.RFP, floor, 0, asm.Word)}, insns[1:]...)...)
	return spec
}

func deepReq(floor int16, when LookupWhen) LookupRequest {
	req := autoReq()
	req.Lookups = when
	req.Stack = StackAudit{Frames: map[string]int16{"p": floor}, Source: "verifier", FrameRounding: 16}
	return req
}

// A frame with one free slot used to refuse every lookup.
func TestDeepFrameLookupInstrumented(t *testing.T) {
	plan, err := transformLookup(deepLookupFixture(-504), deepReq(-504, LookupHit))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.sites) != 1 || len(plan.skipped) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestDeepFrameWrapperLimits(t *testing.T) {
	// The 32-byte rule charges the wrapper's frame.
	req := deepReq(-504, LookupHit)
	req.Stack.FrameRounding = 32
	if _, err := transformLookup(deepLookupFixture(-504), req); !errors.Is(err, ErrRefused) {
		t.Fatalf("32-byte rounding: %v", err)
	}
	// With no slot at all the entry frame cannot keep ctx.
	if _, err := transformLookup(deepLookupFixture(-512), deepReq(-512, LookupHit)); !errors.Is(err, ErrRefused) {
		t.Fatalf("no slot: %v", err)
	}
	// A frame with room for the slots keeps them.
	plan, err := transformLookup(deepLookupFixture(-480), deepReq(-480, LookupHit))
	if err != nil || plan.sites[0].Wrapper != "" {
		t.Fatalf("plan = %+v, err = %v", plan, err)
	}
	// A value copy needs stack.
	copied := deepLookupFixture(-504)
	copied.Maps["sessions"].Flags = bpfFRdonlyProg
	req = deepReq(-504, LookupHit)
	req.CopyReadOnly = true
	if _, err := transformLookup(copied, req); !errors.Is(err, ErrRefused) {
		t.Fatalf("copy: %v", err)
	}
}

// wrapperPair transforms spec and returns what the checker needs.
func wrapperPair(t *testing.T, spec *ebpf.CollectionSpec, req LookupRequest) (asm.Instructions, asm.Instructions, injectcheck.Certificate, injectcheck.Premises) {
	t.Helper()
	in := append(asm.Instructions(nil), spec.Programs["p"].Instructions...)
	injectcheck.Label(spec.Programs["p"].Instructions)
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	out := spec.Programs["p"].Instructions
	names, wrappers := map[string]bool{}, map[string]bool{}
	for _, hook := range plan.hooks {
		names[hook.Name] = true
		for _, site := range hook.Sites {
			if site.Wrapper == "" {
				t.Fatalf("site %d has no wrapper", site.SitePC)
			}
			wrappers[site.Wrapper] = true
		}
	}
	var hooks, wrapped []injectcheck.Span
	for i := range out {
		name := out[i].Symbol()
		if !names[name] && !wrappers[name] {
			continue
		}
		end := i + 1
		for end < len(out) && btf.FuncMetadata(&out[end]) == nil {
			end++
		}
		if wrappers[name] {
			wrapped = append(wrapped, injectcheck.Span{Start: i, End: end})
		} else {
			hooks = append(hooks, injectcheck.Span{Start: i, End: end})
		}
	}
	cert, err := injectcheck.FromLabels(out, len(in), hooks)
	if err != nil {
		t.Fatal(err)
	}
	cert.Wrappers = wrapped
	targets, err := BuildLookupTargets(out, plan.hooks)
	if err != nil {
		t.Fatal(err)
	}
	return in, out, cert, injectcheck.Premises{Frames: []injectcheck.FrameFloor{{Start: 0, LowestOffset: req.Stack.Frames["p"]}}, Targets: targets}
}

func TestCheckerAcceptsWrapper(t *testing.T) {
	for _, when := range []LookupWhen{LookupHit, LookupMiss, LookupAny} {
		t.Run(string(when), func(t *testing.T) {
			in, out, cert, premises := wrapperPair(t, deepLookupFixture(-504), deepReq(-504, when))
			counts, err := injectcheck.Check(in, out, cert, premises)
			if err != nil {
				t.Fatal(err)
			}
			if counts.Sites != 1 {
				t.Fatalf("counts = %+v", counts)
			}
		})
	}
	t.Run("generic", func(t *testing.T) {
		spec := mapInMapDeepFixture()
		in, out, cert, premises := wrapperPair(t, spec, deepReq(-504, LookupAny))
		if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != 2 {
			t.Fatalf("counts = %+v, err = %v", counts, err)
		}
	})
}

// mapInMapDeepFixture has two runtime-map lookups in a frame with one free slot.
func mapInMapDeepFixture() *ebpf.CollectionSpec {
	spec := mapInMapFixture()
	insns := spec.Programs["p"].Instructions
	spec.Programs["p"].Instructions = append(insns[:1:1], append(asm.Instructions{asm.StoreImm(asm.RFP, -504, 0, asm.Word)}, insns[1:]...)...)
	return spec
}

// Each fault must be one the wrapper rule exists to catch.
func TestCheckerRejectsBadWrapper(t *testing.T) {
	type fault struct {
		name  string
		kind  injectcheck.Kind
		plant func(in, out asm.Instructions, w int, site int)
	}
	// Wrapper body, hit arm: 0 r6=r4, 1 r7=r2, 2 helper, 3 r8=r0, 4 jeq, 5 r1=r6,
	// 6 r2=site, 7 r3=r7, 8 r4=r0, 9 call, 10 r0=r8, 11 exit.
	faults := []fault{
		{"writes-stack", injectcheck.WrapperShape, func(_, out asm.Instructions, w, _ int) {
			out[w+3] = asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord)
		}},
		{"loses-r0", injectcheck.WrapperShape, func(_, out asm.Instructions, w, _ int) { out[w+10] = asm.Mov.Imm(asm.R0, 0) }},
		{"other-helper", injectcheck.WrapperShape, func(_, out asm.Instructions, w, _ int) { out[w+2] = asm.FnMapDeleteElem.Call() }},
		{"wrong-key-role", injectcheck.WrapperShape, func(_, out asm.Instructions, w, _ int) { out[w+7] = asm.Mov.Reg(asm.R3, asm.R6) }},
		{"wrong-ctx-role", injectcheck.WrapperShape, func(_, out asm.Instructions, w, _ int) { out[w+5] = asm.Mov.Reg(asm.R1, asm.R7) }},
		{"reads-caller-r9", injectcheck.WrapperShape, func(_, out asm.Instructions, w, _ int) { out[w] = asm.Mov.Reg(asm.R6, asm.R9).WithSymbol(out[w].Symbol()) }},
		{"wrong-prelude-slot", injectcheck.WrapperPrelude, func(_, out asm.Instructions, _, site int) {
			out[site-1] = asm.LoadMem(asm.R4, asm.RFP, -8, asm.DWord)
		}},
		{"prelude-clobbers-r6", injectcheck.WrapperPrelude, func(_, out asm.Instructions, _, site int) {
			out[site-1] = asm.LoadMem(asm.R6, asm.RFP, -512, asm.DWord)
		}},
		{"prelude-overwrites-key", injectcheck.WrapperPrelude, func(_, out asm.Instructions, _, site int) {
			out[site-1] = asm.LoadMem(asm.R2, asm.RFP, -512, asm.DWord)
		}},
		{"postlude-beside-wrapper", injectcheck.WrapperShape, func(_, out asm.Instructions, _, site int) {
			out[site+1] = asm.Mov.Imm(asm.R0, 0)
		}},
		{"not-a-lookup", injectcheck.WrapperShape, func(in, _ asm.Instructions, _, _ int) {
			for i := range in {
				if in[i].IsBuiltinCall() {
					in[i] = asm.FnMapDeleteElem.Call()
				}
			}
		}},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			in, out, cert, premises := wrapperPair(t, deepLookupFixture(-504), deepReq(-504, LookupHit))
			if len(cert.Wrappers) != 1 {
				t.Fatalf("wrappers = %+v", cert.Wrappers)
			}
			if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
				t.Fatalf("clean pair: %v", err)
			}
			w, site := cert.Wrappers[0].Start, -1
			for i := range in {
				if in[i].IsBuiltinCall() {
					site = cert.Original[i]
				}
			}
			out = append(asm.Instructions(nil), out...)
			if f.name == "postlude-beside-wrapper" {
				// An inserted instruction, so the original after the site moves.
				out = append(out[:site+1:site+1], append(asm.Instructions{asm.Mov.Imm(asm.R0, 0)}, out[site+1:]...)...)
				for j := range out[:site] {
					if out[j].OpCode.JumpOp() == asm.JGT {
						out[j].Offset++ // the short-packet branch crosses the insertion
					}
				}
				for i := range cert.Original {
					if cert.Original[i] > site {
						cert.Original[i]++
					}
				}
				cert.Hooks = append([]injectcheck.Span(nil), cert.Hooks...)
				for i := range cert.Hooks {
					cert.Hooks[i].Start++
					cert.Hooks[i].End++
				}
				for i := range premises.Targets {
					premises.Targets[i].Hook++
				}
				cert.Wrappers = []injectcheck.Span{{Start: cert.Wrappers[0].Start + 1, End: cert.Wrappers[0].End + 1}}
			} else {
				f.plant(in, out, w, site)
			}
			_, err := injectcheck.Check(in, out, cert, premises)
			var rejection *injectcheck.Rejection
			if !errors.As(err, &rejection) || rejection.Kind != f.kind {
				t.Fatalf("got %v, want %s", err, f.kind)
			}
		})
	}
	t.Run("two-sites-one-wrapper", func(t *testing.T) {
		req := deepReq(-504, LookupHit)
		in, out, cert, premises := wrapperPair(t, func() *ebpf.CollectionSpec {
			spec := multiLookupFixture()
			insns := spec.Programs["p"].Instructions
			spec.Programs["p"].Instructions = append(insns[:1:1], append(asm.Instructions{asm.StoreImm(asm.RFP, -504, 0, asm.Word)}, insns[1:]...)...)
			return spec
		}(), req)
		if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
			t.Fatalf("clean pair: %v", err)
		}
		var calls []int
		for i := range in {
			if in[i].IsBuiltinCall() {
				calls = append(calls, cert.Original[i])
			}
		}
		out = append(asm.Instructions(nil), out...)
		out[calls[1]] = out[calls[1]].WithReference(out[calls[0]].Reference())
		_, err := injectcheck.Check(in, out, cert, premises)
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.WrapperCall {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("hit-planned-miss-called", func(t *testing.T) {
		in, out, cert, premises := wrapperPair(t, deepLookupFixture(-504), deepReq(-504, LookupHit))
		premises.Targets[0].When = injectcheck.TargetMiss
		_, err := injectcheck.Check(in, out, cert, premises)
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CallTarget {
			t.Fatalf("got %v", err)
		}
	})
}
