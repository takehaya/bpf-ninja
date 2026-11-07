package inject

import (
	"errors"
	"fmt"
	"slices"
	"strings"
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
	// The same two guards, at wrapSites itself: the transform refuses those
	// inputs again later, so only here does each guard decide alone.
	wraps := func(floor int16, rounding int, site LookupSite) bool {
		req := LookupRequest{Stack: StackAudit{Frames: map[string]int16{site.FuncName: floor}, Source: "verifier", FrameRounding: rounding}}
		group := wrapSites(lookupGroup{op: HookLookup, sites: []discoveredLookup{{LookupSite: site}}}, req)
		return group.sites[0].Wrapper != ""
	}
	sub := LookupSite{FuncName: "sub", SitePC: 9, CtxSource: "r6"}
	if !wraps(-504, 16, sub) || wraps(-504, 32, sub) {
		t.Fatal("FrameRounding: only the 16-byte rule wraps")
	}
	entry := LookupSite{FuncName: "p", SitePC: 9, CtxSource: "entry"}
	if !wraps(-504, 16, entry) || wraps(-512, 16, entry) {
		t.Fatal("entry ctx slot: only a frame with the slot left wraps")
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
	return lookupPair(t, spec, req, true)
}

// lookupPair is wrapperPair with every site wrapped or none.
func lookupPair(t *testing.T, spec *ebpf.CollectionSpec, req LookupRequest, wrap bool) (asm.Instructions, asm.Instructions, injectcheck.Certificate, injectcheck.Premises) {
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
			if (site.Wrapper != "") != wrap {
				t.Fatalf("site %d wrapper %q, want wrapped %v", site.SitePC, site.Wrapper, wrap)
			}
			if site.Wrapper != "" {
				wrappers[site.Wrapper] = true
			}
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
		{"reads-caller-r9", injectcheck.WrapperShape, func(_, out asm.Instructions, w, _ int) {
			out[w] = asm.Mov.Reg(asm.R6, asm.R9).WithSymbol(out[w].Symbol())
		}},
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
		// The expected body comes from the plan, so a hit arm where the plan
		// names only a miss is not the planned body.
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.WrapperShape {
			t.Fatalf("got %v", err)
		}
	})
}

// Wrapper names pass the same checks as other hook names.
func TestWrapperNameChecked(t *testing.T) {
	// The Auto hook of a map named _site12 is lookup_hook__site12, which is
	// also the wrapper of site 12.
	spec := deepLookupFixture(-504)
	m := spec.Maps["sessions"]
	delete(spec.Maps, "sessions")
	m.Name = "_site12"
	spec.Maps["_site12"] = m
	for i, ins := range spec.Programs["p"].Instructions {
		if ins.Reference() == "sessions" {
			spec.Programs["p"].Instructions[i] = ins.WithReference("_site12")
		}
	}
	if _, err := transformLookup(spec, deepReq(-504, LookupHit)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), `hook name "lookup_hook__site12" is invalid or used twice`) {
		t.Errorf("collision: %v", err)
	}
	// A 127-byte Dispatch hook name gives a wrapper name past MaxHookName.
	req := deepReq(-504, LookupHit)
	req.Dispatch = true
	req.HookName = strings.Repeat("h", MaxHookName)
	if _, err := transformLookup(deepLookupFixture(-504), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "is invalid or used twice") {
		t.Errorf("length: %v", err)
	}
}

// subWrapperPair is wrapperPair for subprogramLookupFixture(source) with the
// subprogram's frame at -496, so its site is wrapped with ctx from source.
func subWrapperPair(t *testing.T, source string) (asm.Instructions, asm.Instructions, injectcheck.Certificate, injectcheck.Premises, int) {
	t.Helper()
	spec := subprogramLookupFixture(source)
	insns := spec.Programs["p"].Instructions
	const subStart = 4
	spec.Programs["p"].Instructions = append(insns[:subStart+1:subStart+1], append(asm.Instructions{asm.StoreImm(asm.RFP, -496, 0, asm.Word)}, insns[subStart+1:]...)...)
	req := autoReq()
	req.Stack = StackAudit{Frames: map[string]int16{"p": 0, "sub": -496}, Source: "verifier", FrameRounding: 16}
	in, out, cert, premises := wrapperPair(t, spec, req)
	premises.Frames = []injectcheck.FrameFloor{{Start: 0, LowestOffset: 0}, {Start: subStart, LowestOffset: -496}}
	site := slices.IndexFunc(in, func(ins asm.Instruction) bool { return ins.IsBuiltinCall() })
	return in, out, cert, premises, cert.Original[site]
}

// A subprogram site's prelude must load the planned ctx source: never a slot
// below the frame floor, and never the entry ctx slot, which a subprogram
// does not have.
func TestWrapperPreludeSubprogram(t *testing.T) {
	for _, source := range []string{"register", "slot"} {
		in, out, cert, premises, _ := subWrapperPair(t, source)
		if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
			t.Fatalf("%s: %v", source, err)
		}
	}
	setCtx := func(ctx *injectcheck.CtxSource) func(*injectcheck.Premises) {
		return func(premises *injectcheck.Premises) {
			for i := range premises.Targets {
				premises.Targets[i].Ctx = ctx
			}
		}
	}
	for name, tc := range map[string]struct {
		source  string
		prelude *asm.Instruction
		edit    func(*injectcheck.Premises)
	}{
		"register-wrong-prelude": {"register", ptr(asm.Mov.Reg(asm.R4, asm.R7)), nil},
		"slot-wrong-prelude":     {"slot", ptr(asm.LoadMem(asm.R4, asm.RFP, -8, asm.DWord)), nil},
		"no-ctx-source":          {"register", nil, setCtx(nil)},
		// -504 is where an entry frame at -496 keeps ctx.
		"no-ctx-source-entry-slot-load": {"register", ptr(asm.LoadMem(asm.R4, asm.RFP, -504, asm.DWord)), setCtx(nil)},
		"slot-below-floor":              {"slot", ptr(asm.LoadMem(asm.R4, asm.RFP, -504, asm.DWord)), setCtx(&injectcheck.CtxSource{Slot: -504})},
	} {
		t.Run(name, func(t *testing.T) {
			in, out, cert, premises, site := subWrapperPair(t, tc.source)
			out = slices.Clone(out)
			premises.Targets = slices.Clone(premises.Targets)
			if tc.prelude != nil {
				out[site-1] = *tc.prelude
			}
			if tc.edit != nil {
				tc.edit(&premises)
			}
			_, err := injectcheck.Check(in, out, cert, premises)
			wantRejected(t, err)
		})
	}
}

// p -> s1 -> ... -> s5 -> sub is 7 frames, and the hook makes 8. A wrapper
// would make 9, past the kernel's 8-frame limit, so the site is refused.
func TestWrapperFrameLimit(t *testing.T) {
	for _, floor := range []int16{-8, -496} {
		spec := subprogramLookupFixture("register")
		insns := spec.Programs["p"].Instructions
		entry, sub := slices.Clone(insns[:4]), slices.Clone(insns[4:])
		subFn := btf.FuncMetadata(&sub[0])
		sub = append(sub[:1:1], append(asm.Instructions{asm.StoreImm(asm.RFP, floor, 0, asm.Word)}, sub[1:]...)...)
		entry[1] = entry[1].WithReference("s1")
		frames := map[string]int16{"p": 0, "sub": floor}
		for k := 1; k <= 5; k++ {
			name, next := fmt.Sprintf("s%d", k), fmt.Sprintf("s%d", k+1)
			if k == 5 {
				next = "sub"
			}
			fn := &btf.Func{Name: name, Linkage: btf.StaticFunc, Type: subFn.Type}
			entry = append(entry, btf.WithFuncMetadata(asm.Mov.Imm(asm.R2, 1).WithSymbol(name).WithSource(asm.Comment(name)), fn),
				asm.Call.Label(next), asm.Mov.Imm(asm.R0, 0), asm.Return())
			frames[name] = 0
		}
		spec.Programs["p"].Instructions = append(entry, sub...)
		req := autoReq()
		req.Stack = StackAudit{Frames: frames, Source: "verifier", FrameRounding: 16}
		plan, err := transformLookup(spec, req)
		if floor == -8 {
			if err != nil || len(plan.sites) != 1 || plan.sites[0].Wrapper != "" {
				t.Fatalf("8 frames unwrapped: plan = %+v, err = %v", plan, err)
			}
			continue
		}
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "9 frames deep, past the kernel's 8-frame limit") {
			t.Fatalf("9 frames: %v", err)
		}
	}
}

func ptr[T any](v T) *T { return &v }

// wrapSites never wraps a site that copies its value, but a wrapper has no
// stack for the copy: lookupWrapper refuses one instead of emitting it.
func TestLookupWrapperRefusesCopy(t *testing.T) {
	site := discoveredLookup{LookupSite: LookupSite{Op: HookLookup, SitePC: 11, Wrapper: "lookup_hook__site11"}}
	call := siteCall{hook: "lookup_hook", when: LookupHit, copySize: 16, frameFloor: -496}
	out, err := lookupWrapper(site, asm.FnMapLookupElem.Call(), call, &btf.Pointer{Target: &btf.Void{}})
	if !errors.Is(err, ErrRefused) || out != nil {
		t.Fatalf("copying site wrapped: %d instructions, err = %v", len(out), err)
	}
	call.copySize = 0
	if out, err := lookupWrapper(site, asm.FnMapLookupElem.Call(), call, &btf.Pointer{Target: &btf.Void{}}); err != nil || len(out) == 0 {
		t.Fatalf("plain site: %d instructions, err = %v", len(out), err)
	}
}
