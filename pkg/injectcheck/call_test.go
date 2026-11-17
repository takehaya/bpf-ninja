package injectcheck

// Call-site fixtures: a hook right after a helper or kernel-function call, in
// sequence A (result only) and B (argument and result), for each context
// source, and the mutations the checker must reject.

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

const callSitePC = 77

func kfuncCall(id int64) asm.Instruction {
	return asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: id}
}

type callCase struct {
	src    string // entry, reg, slot, pass or callback
	centre asm.Instruction
	argReg int // 0: sequence A; otherwise sequence B with the argument in this register
}

type callFixture struct {
	in, out  asm.Instructions
	cert     Certificate
	premises Premises
	site     int // original index of the centre
}

func (f callFixture) check() (Counts, error) { return Check(f.in, f.out, f.cert, f.premises) }

// build splices the site's prelude and postlude into the original, as the
// rewriter does with a floor of -8 (slots: ctx -16, key -24, result -32). edit,
// if set, changes them first.
func (c callCase) build(edit func(pre, post *asm.Instructions)) callFixture {
	own := asm.Instructions{asm.Mov.Imm(asm.R7, 0), asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord)}
	body := asm.Instructions{asm.Mov.Imm(asm.R1, 0), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.Mov.Imm(asm.R5, 0), c.centre, asm.Return()}
	entrySpill := asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord)
	gaps := map[int]asm.Instructions{}
	var in, init asm.Instructions
	var ctx *CtxSource
	sub := -1
	switch c.src {
	case "entry":
		in = slices.Concat(own, body)
		gaps[0] = asm.Instructions{entrySpill}
	case "reg":
		in = slices.Concat(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, own, body)
		ctx = &CtxSource{Reg: int(asm.R6)}
		init = asm.Instructions{asm.StoreMem(asm.RFP, -16, asm.R6, asm.DWord)}
	case "slot":
		in = slices.Concat(asm.Instructions{asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord)}, body)
		ctx = &CtxSource{Slot: -8}
		init = asm.Instructions{asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord)}
	case "pass":
		// The entry calls the site's function with the context in R5, which
		// the function stores in its own slot on entry.
		subOwn := slices.Clone(own)
		subOwn[0] = subOwn[0].WithSymbol("sub")
		in = slices.Concat(own, asm.Instructions{asm.Call.Label("sub"), asm.Return()}, subOwn, body)
		sub = len(own) + 2
		ctx = &CtxSource{Pass: []PassFrame{{Start: sub, Reg: int(asm.R5)}}}
		gaps[0] = asm.Instructions{entrySpill}
		gaps[len(own)] = asm.Instructions{asm.LoadMem(asm.R5, asm.RFP, -16, asm.DWord)}
		gaps[sub] = asm.Instructions{asm.StoreMem(asm.RFP, -16, asm.R5, asm.DWord).WithSymbol("sub")}
	case "callback":
		// The entry passes fp-8 to bpf_loop, whose callback gets it in R2 and
		// loads the entry's context slot through it on entry.
		cb := asm.LoadImm(asm.R2, -1, asm.DWord).WithReference("cb")
		cb.Src = asm.PseudoFunc
		cbOwn := slices.Clone(own)
		cbOwn[0] = cbOwn[0].WithSymbol("cb")
		in = slices.Concat(own, asm.Instructions{asm.Mov.Imm(asm.R1, 1), cb, asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8),
			asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return()}, cbOwn, body)
		sub = len(own) + 8
		ctx = &CtxSource{Param: int(asm.R2), Arg: -8}
		gaps[0] = asm.Instructions{entrySpill}
		gaps[sub] = asm.Instructions{asm.LoadMem(asm.R0, asm.R2, -8, asm.DWord).WithSymbol("cb"), asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord)}
	default:
		panic(c.src)
	}
	site := len(in) - 2
	var pre asm.Instructions
	if c.argReg != 0 {
		pre = asm.Instructions{asm.StoreMem(asm.RFP, -24, asm.Register(c.argReg), asm.DWord)}
	}
	pre = append(pre, init...)
	post := asm.Instructions{asm.StoreMem(asm.RFP, -32, asm.R0, asm.DWord), asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord), asm.Mov.Imm32(asm.R2, callSitePC)}
	args := callABIs[0]
	if c.argReg != 0 {
		post = append(post, asm.LoadMem(asm.R3, asm.RFP, -24, asm.DWord), asm.Mov.Reg(asm.R4, asm.R0))
		args = callABIs[1]
	} else {
		post = append(post, asm.Mov.Reg(asm.R3, asm.R0))
	}
	post = append(post, asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -32, asm.DWord))
	if edit != nil {
		edit(&pre, &post)
	}
	gaps[site] = append(gaps[site], pre...)
	f := callFixture{in: in, site: site}
	for i, ins := range in {
		f.out = append(f.out, gaps[i]...)
		f.cert.Original = append(f.cert.Original, len(f.out))
		if i == sub {
			ins = ins.WithSymbol("")
		}
		f.out = append(f.out, ins)
		if i == site {
			f.out = append(f.out, post...)
		}
	}
	h := len(f.out)
	f.out = append(f.out, asm.Mov.Imm(asm.R0, 0).WithSymbol("hook"), asm.Return())
	f.cert.Hooks = []Span{{h, len(f.out)}}
	f.premises = Premises{LowestOffset: -8, Targets: []SiteTarget{{Site: site, When: TargetAny, Hook: h, Ctx: ctx, Args: args, ArgReg: c.argReg, SitePC: callSitePC}}}
	return f
}

var callCentres = []struct {
	name   string
	centre asm.Instruction
	argReg int
}{
	{"helper-A", asm.FnKtimeGetNs.Call(), 0},
	{"helper-B", asm.FnFibLookup.Call(), int(asm.R2)},
	// 12 is the tail-call helper's id. The checker treats a kfunc with it as
	// any other kfunc and checks every call-site obligation; regionval never
	// validates such a site, because its centre reaches the cores as call 12.
	{"kfunc-A", kfuncCall(12), 0},
	{"kfunc-B", kfuncCall(12), int(asm.R4)},
}

func TestCallSiteAccepts(t *testing.T) {
	for _, src := range []string{"entry", "reg", "slot", "pass", "callback"} {
		for _, centre := range callCentres {
			t.Run(src+"/"+centre.name, func(t *testing.T) {
				counts, err := callCase{src, centre.centre, centre.argReg}.build(nil).check()
				if err != nil || counts.Sites != 1 {
					t.Fatalf("sites=%d err=%v", counts.Sites, err)
				}
			})
		}
	}
	// Kfunc ids equal to the lookup helpers' and the callback-taking loop's.
	for _, id := range []int64{1, 2, 3, 181, 195} {
		if _, err := (callCase{"entry", kfuncCall(id), 0}).build(nil).check(); err != nil {
			t.Fatalf("kfunc %d: %v", id, err)
		}
	}
}

func TestCallSiteRejects(t *testing.T) {
	helperB := callCase{"reg", asm.FnFibLookup.Call(), int(asm.R2)}
	kfuncA := callCase{"entry", kfuncCall(12), 0}
	at := func(post *asm.Instructions, i int, ins ...asm.Instruction) {
		*post = slices.Concat((*post)[:i], ins, (*post)[i:])
	}
	// helperB's postlude: 0 save, 1 ctx, 2 site, 3 arg, 4 ret, 5 call, 6 restore.
	for _, tc := range []struct {
		name   string
		c      callCase
		edit   func(pre, post *asm.Instructions)
		target func(*SiteTarget)
		kind   Kind
	}{
		{"r0-not-restored", helperB, func(_, post *asm.Instructions) { *post = (*post)[:6] }, nil, ResultSaveRestore},
		{"r0-restored-from-ctx-slot", helperB, func(_, post *asm.Instructions) { (*post)[6] = asm.LoadMem(asm.R0, asm.RFP, -16, asm.DWord) }, nil, ResultSaveRestore},
		{"ret-from-r1", helperB, func(_, post *asm.Instructions) { (*post)[4] = asm.Mov.Reg(asm.R4, asm.R1) }, nil, HookArguments},
		{"ret-32-bit-move", helperB, func(_, post *asm.Instructions) { (*post)[4] = asm.Mov.Reg32(asm.R4, asm.R0) }, nil, HookArguments},
		{"arg-from-r1", helperB, func(_, post *asm.Instructions) { (*post)[3] = asm.Mov.Reg(asm.R3, asm.R1) }, nil, HookArguments},
		{"arg-from-ctx-slot", helperB, func(_, post *asm.Instructions) { (*post)[3] = asm.LoadMem(asm.R3, asm.RFP, -16, asm.DWord) }, nil, HookArguments},
		{"key-store-wrong-register", helperB, func(pre, _ *asm.Instructions) { (*pre)[0] = asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord) }, nil, CtxProvenance},
		{"key-store-wrong-register-entry", callCase{"entry", asm.FnFibLookup.Call(), int(asm.R2)}, func(pre, _ *asm.Instructions) { (*pre)[0] = asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord) }, nil, PreludeShape},
		{"key-store-missing", callCase{"entry", asm.FnFibLookup.Call(), int(asm.R2)}, func(pre, _ *asm.Instructions) { *pre = nil }, nil, SpillUninitialized},
		{"key-store-above-floor", helperB, func(pre, _ *asm.Instructions) { (*pre)[0] = asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord) }, nil, CtxProvenance},
		{"ctx-init-in-pass-function", callCase{"pass", asm.FnKtimeGetNs.Call(), 0}, func(pre, _ *asm.Instructions) {
			*pre = asm.Instructions{asm.StoreMem(asm.RFP, -16, asm.R6, asm.DWord)}
		}, nil, PreludeShape},
		{"hook-called-twice", helperB, func(_, post *asm.Instructions) { at(post, 6, asm.Call.Label("hook")) }, nil, HelperStructure},
		{"branch-in-postlude", helperB, func(_, post *asm.Instructions) {
			j := asm.JSGE.Imm32(asm.R0, 0, "")
			j.Offset = 5
			at(post, 1, j)
		}, nil, HelperStructure},
		{"save-after-load", helperB, func(_, post *asm.Instructions) { (*post)[0], (*post)[1] = (*post)[1], (*post)[0] }, nil, ResultSaveRestore},
		{"store-above-floor", helperB, func(_, post *asm.Instructions) { at(post, 2, asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord)) }, nil, StoreBounds},
		{"r6-clobbered", helperB, func(_, post *asm.Instructions) { at(post, 1, asm.Mov.Imm(asm.R6, 0)) }, nil, ALUClobber},
		{"r6-loaded", helperB, func(_, post *asm.Instructions) { at(post, 1, asm.LoadMem(asm.R6, asm.RFP, -32, asm.DWord)) }, nil, LoadClobber},
		{"r5-set-past-arguments", helperB, func(_, post *asm.Instructions) { at(post, 5, asm.Mov.Reg(asm.R5, asm.R0)) }, nil, HookArguments},
		{"wrong-site-pc", helperB, func(_, post *asm.Instructions) { (*post)[2] = asm.Mov.Imm32(asm.R2, callSitePC+1) }, nil, HookArguments},
		{"kfunc-12-r0-not-restored", kfuncA, func(_, post *asm.Instructions) { *post = (*post)[:5] }, nil, ResultSaveRestore},
		{"kfunc-12-r0-zeroed", kfuncA, func(_, post *asm.Instructions) { (*post)[5] = asm.Mov.Imm(asm.R0, 0) }, nil, ResultSaveRestore},
		{"kfunc-12-ret-missing", kfuncA, func(_, post *asm.Instructions) { (*post)[3] = asm.Mov.Imm(asm.R3, 0) }, nil, HookArguments},
		{"argreg-without-arg", kfuncA, nil, func(t *SiteTarget) { t.ArgReg = int(asm.R2) }, InputTarget},
		{"arg-without-argreg", helperB, nil, func(t *SiteTarget) { t.ArgReg = 0 }, InputTarget},
		{"argreg-r6", helperB, nil, func(t *SiteTarget) { t.ArgReg = int(asm.R6) }, InputTarget},
		{"call-target-on-hit", helperB, nil, func(t *SiteTarget) { t.When = TargetHit }, InputTarget},
		{"call-target-on-non-call", kfuncA, nil, func(t *SiteTarget) { t.Site-- }, InputTarget},
		{"call-target-on-tail-call", callCase{"entry", asm.FnTailCall.Call(), 0}, nil, nil, InputTarget},
		{"call-target-on-lookup", callCase{"entry", asm.FnMapLookupElem.Call(), 0}, nil, nil, InputTarget},
		{"no-call-target", kfuncA, nil, func(t *SiteTarget) { t.Args, t.SitePC = nil, 0 }, U32Placement},
		{"lookup-abi-at-call", helperB, nil, func(t *SiteTarget) { t.Args, t.ArgReg = lookupABIs[3], 0 }, U32Placement},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.c.build(tc.edit)
			if tc.target != nil {
				tc.target(&f.premises.Targets[0])
			}
			_, err := f.check()
			assertKind(t, err, tc.kind)
			t.Logf("%s: %v", tc.name, err)
		})
	}
}

// callbackHelperIDs are the helpers with an ARG_PTR_TO_FUNC argument in Linux
// 6.12.111 and 7.0.13 (for_each_map_elem, timer_set_callback, find_vma, loop,
// user_ringbuf_drain), written out so that the test does not take the list
// from the function it tests.
var callbackHelperIDs = map[int64]bool{164: true, 170: true, 180: true, 181: true, 209: true}

// Every helper outside the map helpers and the tail call stays a call-target
// centre, except the ones that run or register a callback and id 0, which is
// not a helper.
func TestCallSiteHelperCentres(t *testing.T) {
	for id := int64(0); id <= 211; id++ {
		fn := asm.BuiltinFunc(id)
		if callbackHelper(fn) != callbackHelperIDs[id] {
			t.Errorf("callbackHelper(%v) = %v, want %v", fn, callbackHelper(fn), callbackHelperIDs[id])
		}
		counts, err := callCase{"entry", fn.Call(), 0}.build(nil).check()
		want := ""
		switch {
		case id == 0:
			want = "helper id 0, which is not a helper"
		case supportedHelper(fn.Call()):
			want = "not a call of a helper outside the map helpers"
		case callbackHelperIDs[id]:
			want = fn.String() + ", which runs or registers a callback"
		}
		if want == "" {
			if err != nil || counts.Sites != 1 {
				t.Errorf("%v: sites=%d err=%v", fn, counts.Sites, err)
			}
			continue
		}
		assertInputKind(t, err, InputTarget)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v, want %q", fn, err, want)
		}
	}
}

// A call site with a second target, and a call target on the pass fixture's
// BPF-to-BPF call, are input errors.
func TestCallSiteTargetInputs(t *testing.T) {
	f := callCase{"pass", asm.FnKtimeGetNs.Call(), 0}.build(nil)
	second := f.premises.Targets[0]
	second.When, second.Args, second.SitePC = TargetError, nil, 0
	f.premises.Targets = append(f.premises.Targets, second)
	_, err := f.check()
	assertInputKind(t, err, InputTarget)
	t.Logf("second target: %v", err)

	f = callCase{"pass", asm.FnKtimeGetNs.Call(), 0}.build(nil)
	f.premises.Targets[0].Site = 2 // call sub
	_, err = f.check()
	assertInputKind(t, err, InputTarget)
	t.Logf("bpf-to-bpf call: %v", err)
}

// insertOriginal adds ins to the original before index at and to the
// transformed stream at pos, and moves the certificate and the target.
func (f *callFixture) insertOriginal(at, pos int, ins asm.Instruction) {
	f.in = slices.Insert(slices.Clone(f.in), at, ins)
	f.out = slices.Insert(slices.Clone(f.out), pos, ins)
	shift := func(j int) int {
		if j >= pos {
			return j + 1
		}
		return j
	}
	var original []int
	for _, j := range f.cert.Original {
		original = append(original, shift(j))
	}
	f.cert.Original = slices.Insert(original, at, pos)
	for i := range f.cert.Hooks {
		f.cert.Hooks[i] = Span{shift(f.cert.Hooks[i].Start), shift(f.cert.Hooks[i].End)}
	}
	for i := range f.premises.Targets {
		target := &f.premises.Targets[i]
		if target.Site >= at {
			target.Site++
		}
		target.Hook = shift(target.Hook)
	}
	if f.site >= at {
		f.site++
	}
}

// startCase builds a call target at the first instruction of the entry
// ("main"), of a bpf_loop callback or of a function the context is passed
// to, with the context set up as callCase does.
func startCase(src string, centre asm.Instruction, argReg int) callFixture {
	own := asm.Instructions{asm.Mov.Imm(asm.R7, 0), asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord)}
	gaps := map[int]asm.Instructions{0: {asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord)}}
	var in asm.Instructions
	var ctx *CtxSource
	sub := 0
	switch src {
	case "main":
		in = asm.Instructions{centre, asm.Return()}
	case "callback":
		cb := asm.LoadImm(asm.R2, -1, asm.DWord).WithReference("cb")
		cb.Src = asm.PseudoFunc
		in = slices.Concat(own, asm.Instructions{asm.Mov.Imm(asm.R1, 1), cb, asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8),
			asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return(), centre.WithSymbol("cb"), asm.Return()})
		sub = len(own) + 8
		ctx = &CtxSource{Param: int(asm.R2), Arg: -8}
		gaps[sub] = asm.Instructions{asm.LoadMem(asm.R0, asm.R2, -8, asm.DWord).WithSymbol("cb"), asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord)}
	case "pass":
		in = slices.Concat(own, asm.Instructions{asm.Call.Label("sub"), asm.Return(), centre.WithSymbol("sub"), asm.Return()})
		sub = len(own) + 2
		ctx = &CtxSource{Pass: []PassFrame{{Start: sub, Reg: int(asm.R5)}}}
		gaps[len(own)] = asm.Instructions{asm.LoadMem(asm.R5, asm.RFP, -16, asm.DWord)}
		gaps[sub] = asm.Instructions{asm.StoreMem(asm.RFP, -16, asm.R5, asm.DWord).WithSymbol("sub")}
	default:
		panic(src)
	}
	site := sub
	if argReg != 0 {
		gaps[site] = append(gaps[site], asm.StoreMem(asm.RFP, -24, asm.Register(argReg), asm.DWord))
	}
	post := asm.Instructions{asm.StoreMem(asm.RFP, -32, asm.R0, asm.DWord), asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord), asm.Mov.Imm32(asm.R2, callSitePC)}
	args := callABIs[0]
	if argReg != 0 {
		post = append(post, asm.LoadMem(asm.R3, asm.RFP, -24, asm.DWord), asm.Mov.Reg(asm.R4, asm.R0))
		args = callABIs[1]
	} else {
		post = append(post, asm.Mov.Reg(asm.R3, asm.R0))
	}
	post = append(post, asm.Call.Label("hook"), asm.LoadMem(asm.R0, asm.RFP, -32, asm.DWord))
	f := callFixture{in: in, site: site}
	for i, ins := range in {
		f.out = append(f.out, gaps[i]...)
		f.cert.Original = append(f.cert.Original, len(f.out))
		if i == sub && i != 0 {
			ins = ins.WithSymbol("")
		}
		f.out = append(f.out, ins)
		if i == site {
			f.out = append(f.out, post...)
		}
	}
	h := len(f.out)
	f.out = append(f.out, asm.Mov.Imm(asm.R0, 0).WithSymbol("hook"), asm.Return())
	f.cert.Hooks = []Span{{h, len(f.out)}}
	f.premises = Premises{LowestOffset: -8, Targets: []SiteTarget{{Site: site, When: TargetAny, Hook: h, Ctx: ctx, Args: args, ArgReg: argReg, SitePC: callSitePC}}}
	return f
}

// A call target is refused where the transformer does not plan one: right
// before or after another original call, or at the first instruction of a
// function, whatever marks the start (instruction 0, a function reference,
// a frame floor). At a helper the argument register must be one the helper
// reads; a kernel function's arguments are not known, so any of r1-r5 is.
func TestCallSitePositions(t *testing.T) {
	const (
		neighbour = "the instruction before or after the call is a call"
		start     = "the call is the first instruction of its function"
	)
	callAfter := func(c callCase) callFixture {
		f := c.build(nil)
		f.insertOriginal(f.site+1, f.cert.Original[f.site+1], asm.FnGetPrandomU32.Call())
		return f
	}
	callBefore := func(c callCase) callFixture {
		f := c.build(nil)
		f.insertOriginal(f.site, f.cert.Original[f.site-1]+1, asm.FnGetPrandomU32.Call())
		return f
	}
	frameAtSite := func(c callCase) callFixture {
		f := c.build(nil)
		f.premises.Frames = []FrameFloor{{Start: 0, LowestOffset: -8}, {Start: f.site, LowestOffset: -8}}
		return f
	}
	helperA := callCase{"entry", asm.FnKtimeGetNs.Call(), 0}
	kfuncB := callCase{"entry", kfuncCall(60001), int(asm.R1)}
	for _, tc := range []struct {
		name string
		f    callFixture
		want string // "" accepts
	}{
		{"helper-B-r4-read", callCase{"reg", asm.FnFibLookup.Call(), int(asm.R4)}.build(nil), ""},
		{"kfunc-B-r5", callCase{"reg", kfuncCall(60001), int(asm.R5)}.build(nil), ""},
		{"helper-B-r5-not-read", callCase{"reg", asm.FnFibLookup.Call(), int(asm.R5)}.build(nil), "passes r5, which FnFibLookup does not read"},
		{"helper-B-r1-no-arguments", callCase{"reg", asm.FnKtimeGetNs.Call(), int(asm.R1)}.build(nil), "passes r1, which FnKtimeGetNs does not read"},
		{"helper-call-after", callAfter(helperA), neighbour},
		{"helper-call-before", callBefore(helperA), neighbour},
		{"kfunc-call-after", callAfter(kfuncB), neighbour},
		{"kfunc-call-before", callBefore(kfuncB), neighbour},
		{"helper-frame-start", frameAtSite(helperA), start},
		{"main-start-helper", startCase("main", asm.FnKtimeGetNs.Call(), 0), start},
		{"main-start-kfunc", startCase("main", kfuncCall(60001), int(asm.R1)), start},
		{"callback-start-helper-A", startCase("callback", asm.FnKtimeGetNs.Call(), 0), start},
		{"callback-start-helper-B", startCase("callback", asm.FnFibLookup.Call(), int(asm.R2)), start},
		{"callback-start-kfunc-A", startCase("callback", kfuncCall(60001), 0), start},
		{"pass-start-helper-A", startCase("pass", asm.FnKtimeGetNs.Call(), 0), start},
		{"pass-start-helper-B", startCase("pass", asm.FnFibLookup.Call(), int(asm.R4)), start},
		{"pass-start-kfunc-B", startCase("pass", kfuncCall(60001), int(asm.R1)), start},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counts, err := tc.f.check()
			if tc.want == "" {
				if err != nil || counts.Sites != 1 {
					t.Fatalf("sites=%d err=%v", counts.Sites, err)
				}
				return
			}
			assertInputKind(t, err, InputTarget)
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want %q", err, tc.want)
			}
		})
	}
}
