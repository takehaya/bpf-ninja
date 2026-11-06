package inject

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/ctxflow"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// callbackSiteFixture is p(ctx), which zeroes [fp-16], passes it to a callback
// and returns it, and the callback, which looks up key 0 and increments the
// counter through its pointer. form is loop, loop_rt0 (flags 0 hidden from the
// verifier, so no inlining) or foreach. entrySite adds a lookup in the entry
// on the same map.
func callbackSiteFixture(form string, entrySite bool) *ebpf.CollectionSpec {
	spec := lookupFixture()
	entryFn := btf.FuncMetadata(&spec.Programs["p"].Instructions[0])
	u64 := &btf.Int{Name: "u64", Size: 8}
	void := &btf.Pointer{Target: &btf.Void{}}
	cbParams, param := []btf.FuncParam{{Name: "i", Type: u64}, {Name: "data", Type: void}}, asm.R2
	if form == "foreach" {
		cbParams = []btf.FuncParam{{Name: "m", Type: void}, {Name: "k", Type: void}, {Name: "v", Type: void}, {Name: "data", Type: void}}
		param = asm.R4
	}
	cbFn := &btf.Func{Name: "cb", Linkage: btf.StaticFunc, Type: &btf.FuncProto{Return: &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed}, Params: cbParams}}
	spec.Maps["flags"] = &ebpf.MapSpec{Name: "flags", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}
	entry := asm.Instructions{btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("p").WithSource(asm.Comment("entry")), entryFn),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord)}
	lookup := func(k int16) asm.Instructions {
		return asm.Instructions{asm.StoreImm(asm.RFP, k, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, int32(k)),
			asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call()}
	}
	if entrySite {
		entry = append(entry, lookup(-4)...)
	}
	load := asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R2, Src: asm.PseudoFunc, Constant: -1}.WithReference("cb")
	r3 := asm.Instructions{asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16)}
	noFlags := asm.JEq.Imm(asm.R0, 0, "")
	noFlags.Offset = 1
	switch form {
	case "foreach":
		entry = append(entry, asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), load)
		entry = append(entry, r3...)
		entry = append(entry, asm.Mov.Imm(asm.R4, 0), asm.FnForEachMapElem.Call())
	case "loop_rt0":
		entry = append(entry, asm.StoreImm(asm.RFP, -8, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
			asm.LoadMapPtr(asm.R1, 0).WithReference("flags"), asm.FnMapLookupElem.Call(),
			asm.Mov.Imm(asm.R4, 0), noFlags, asm.LoadMem(asm.R4, asm.R0, 0, asm.DWord),
			asm.Mov.Imm(asm.R1, 3), load)
		entry = append(entry, r3...)
		entry = append(entry, asm.FnLoop.Call())
	default:
		entry = append(entry, asm.Mov.Imm(asm.R1, 3), load)
		entry = append(entry, r3...)
		entry = append(entry, asm.Mov.Imm(asm.R4, 0), asm.FnLoop.Call())
	}
	entry = append(entry, asm.LoadMem(asm.R0, asm.RFP, -16, asm.DWord), asm.Return())
	cb := asm.Instructions{btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, param).WithSymbol("cb").WithSource(asm.Comment("cb")), cbFn)}
	cb = append(cb, lookup(-8)...)
	cb = append(cb, asm.LoadMem(asm.R1, asm.R6, 0, asm.DWord), asm.Add.Imm(asm.R1, 1), asm.StoreMem(asm.R6, 0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0), asm.Return())
	spec.Programs["p"].Instructions = append(entry, cb...)
	return spec
}

func callbackSite(sites []LookupSite) *LookupSite {
	for i := range sites {
		if sites[i].FuncName == "cb" {
			return &sites[i]
		}
	}
	return nil
}

func TestCallbackSiteSource(t *testing.T) {
	for form, want := range map[string]string{"loop": "callback:r2:fp-16", "loop_rt0": "callback:r2:fp-16", "foreach": "callback:r4:fp-16"} {
		sites, err := discoverLookups(callbackSiteFixture(form, false), "p")
		if err != nil {
			t.Fatal(err)
		}
		if site := callbackSite(sites); site == nil || site.Reason != "" || site.CtxSource != want {
			t.Fatalf("%s: site = %+v, want source %s", form, site, want)
		}
	}
}

// A callback's key is typed only when it is the callback's own stack: a
// for_each key is map memory the verifier does not let a typed hook write.
func TestCallbackSiteReadOnlyArg(t *testing.T) {
	for _, tc := range []struct {
		name      string
		key       asm.Instructions // replaces the callback's r2 = r10; r2 += -8
		untrusted bool
	}{
		{"own stack", asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8)}, false},
		{"for_each key", asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Mov.Imm(asm.R0, 0)}, true},
		{"caller's frame", asm.Instructions{asm.Mov.Reg(asm.R2, asm.R6), asm.Add.Imm(asm.R2, 0)}, true},
		{"loaded from the stack", asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.LoadMem(asm.R2, asm.R2, -8, asm.DWord)}, true},
		{"overwritten by an atomic", asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.Xchg.Mem(asm.RFP, asm.R2, asm.DWord, -16)}, true},
		{"other arithmetic", asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.Sub.Imm(asm.R2, 8)}, true},
		{"set before a branch", asm.Instructions{asm.Mov.Reg(asm.R2, asm.RFP), asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Ja)}}, true}, // ja +0
	} {
		spec := callbackSiteFixture("foreach", false)
		insns := spec.Programs["p"].Instructions
		at := slices.IndexFunc(insns, func(ins asm.Instruction) bool {
			return ins.OpCode == asm.Mov.Reg(asm.R2, asm.RFP).OpCode && ins.Dst == asm.R2 && ins.Src == asm.RFP
		})
		copy(insns[at:at+2], tc.key)
		req := autoReq()
		req.Stack.LowestOffset = -16
		plan, err := transformLookup(spec, req)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.hooks) != 1 || plan.hooks[0].Untrusted != tc.untrusted {
			t.Errorf("%s: hooks %+v", tc.name, plan.hooks)
		}
	}
	// An entry site on the same map keeps the typed hook it has without
	// callbacks; the callback site that would make it untrusted is skipped.
	spec := callbackSiteFixture("foreach", true)
	insns := spec.Programs["p"].Instructions
	at := slices.IndexFunc(insns, func(ins asm.Instruction) bool {
		return btf.FuncMetadata(&ins) != nil && btf.FuncMetadata(&ins).Name == "cb"
	})
	at += slices.IndexFunc(insns[at:], func(ins asm.Instruction) bool {
		return ins.OpCode == asm.Mov.Reg(asm.R2, asm.RFP).OpCode && ins.Dst == asm.R2 && ins.Src == asm.RFP
	})
	copy(insns[at:at+2], asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Mov.Imm(asm.R0, 0)})
	req := autoReq()
	req.Stack.LowestOffset = -16
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || plan.hooks[0].Untrusted || len(plan.hooks[0].Sites) != 1 || plan.hooks[0].Sites[0].FuncName != "p" {
		t.Errorf("entry hook changed: %+v", plan.hooks)
	}
	if site := callbackSite(plan.skipped); site == nil || !strings.Contains(site.Reason, "untrusted") {
		t.Errorf("callback site not skipped: %+v", plan.skipped)
	}
}

func TestCallbackSiteContextBelowEntryFloor(t *testing.T) {
	spec := callbackSiteFixture("loop", true)
	for i, ins := range spec.Programs["p"].Instructions {
		if ins.OpCode == asm.Add.Imm(asm.R3, 0).OpCode && ins.Dst == asm.R3 {
			spec.Programs["p"].Instructions[i].Constant = -24
		}
	}
	req := autoReq()
	req.Stack.LowestOffset = -16
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if site := callbackSite(plan.skipped); site == nil || !strings.Contains(site.Reason, "below the entry stack floor") {
		t.Fatalf("skipped = %+v", plan.skipped)
	}
}

func TestCallbackSitePrologue(t *testing.T) {
	work := callbackSiteFixture("loop", false)
	req := autoReq()
	req.Stack = StackAudit{Frames: map[string]int16{"p": -16, "cb": -8}, Source: "verifier"}
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if site := callbackSite(plan.sites); site == nil {
		t.Fatalf("plan = %+v", plan)
	}
	out := work.Programs["p"].Instructions
	start := -1
	for i := range out {
		if fn := btf.FuncMetadata(&out[i]); fn != nil && fn.Name == "cb" {
			start = i
		}
	}
	if start < 0 {
		t.Fatal("callback lost its function metadata")
	}
	// The entry's context slot is -24, X is -16; the callback's own slot is -16.
	want := asm.Instructions{asm.LoadMem(asm.R0, asm.R2, -8, asm.DWord), asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord)}
	for i, ins := range want {
		got := out[start+i]
		if got.OpCode != ins.OpCode || got.Dst != ins.Dst || got.Src != ins.Src || got.Offset != ins.Offset {
			t.Fatalf("prologue[%d] = %v, want %v", i, got, ins)
		}
	}
	if out[start].Symbol() != "cb" || out[start+2].Symbol() != "" || btf.FuncMetadata(&out[start+2]) != nil {
		t.Fatalf("symbol and func info did not move to the prologue: %v, %v", out[start], out[start+2])
	}
}

// A branch to a callback's first instruction skips the prologue; a numeric
// function-pointer load enters through it.
func TestCallbackSiteEdges(t *testing.T) {
	work := callbackSiteFixture("loop", false)
	insns := work.Programs["p"].Instructions
	pcs := map[string]int{}
	cbIdx := 0
	for it := insns.Iterate(); it.Next(); {
		if fn := btf.FuncMetadata(it.Ins); fn != nil {
			pcs[fn.Name] = int(it.Offset)
			cbIdx = it.Index
		}
	}
	back := asm.JEq.Imm(asm.R6, 0, "")
	insns = append(insns[:len(insns)-2], append(asm.Instructions{back}, insns[len(insns)-2:]...)...)
	for it := insns.Iterate(); it.Next(); {
		if it.Index == len(insns)-3 {
			insns[it.Index].Offset = int16(pcs["cb"] - int(it.Offset) - 1)
		}
		if it.Ins.IsLoadOfFunctionPointer() {
			insns[it.Index] = asm.Instruction{OpCode: it.Ins.OpCode, Dst: asm.R2, Src: asm.PseudoFunc, Constant: int64(pcs["cb"] - int(it.Offset) - 1)}
		}
	}
	work.Programs["p"].Instructions = insns
	req := autoReq()
	req.Stack = StackAudit{Frames: map[string]int16{"p": -16, "cb": -8}, Source: "verifier"}
	in := append(asm.Instructions(nil), insns...)
	injectcheck.Label(insns)
	if _, err := transformLookup(work, req); err != nil {
		t.Fatal(err)
	}
	out := work.Programs["p"].Instructions
	raw := rawOffsets(out)
	cbStart := -1
	for it := out.Iterate(); it.Next(); {
		if fn := btf.FuncMetadata(it.Ins); fn != nil && fn.Name == "cb" {
			cbStart = int(it.Offset)
		}
	}
	first := cbStart + 2 // past the two prologue instructions
	var pointer, branch bool
	for it := out.Iterate(); it.Next(); {
		if it.Ins.IsLoadOfFunctionPointer() {
			pointer = int(it.Offset)+1+int(it.Ins.Constant) == cbStart
		}
		if it.Ins.OpCode == back.OpCode && it.Ins.Dst == asm.R6 {
			branch = int(it.Offset)+1+int(it.Ins.Offset) == first
		}
	}
	if !pointer || !branch || raw[first].OpCode != in[cbIdx].OpCode {
		t.Fatalf("function pointer enters prologue=%v, branch skips it=%v", pointer, branch)
	}
}

// A callback site that breaks a stack limit is skipped alone: the entry site
// of the same map keeps its hook, and a program with only callback sites is
// refused like any other that fits nowhere.
func TestCallbackSiteDroppedBeforeItsGroup(t *testing.T) {
	work := callbackSiteFixture("loop", true)
	req := autoReq()
	req.Stack = StackAudit{Frames: map[string]int16{"p": -416, "cb": -48}, Source: "verifier", FrameRounding: 32}
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	if callbackSite(plan.sites) != nil || len(plan.sites) != 1 || plan.sites[0].FuncName != "p" {
		t.Fatalf("sites = %+v", plan.sites)
	}
	if site := callbackSite(plan.skipped); site == nil || !strings.Contains(site.Reason, "combined limit") {
		t.Fatalf("skipped = %+v", plan.skipped)
	}
}

// The tail-call reachability guard also takes callback sites before their group.
func TestCallbackSiteDroppedByReachabilityGuard(t *testing.T) {
	work := callbackSiteFixture("loop", true)
	spec := work.Programs["p"]
	work.Maps["jmp"] = &ebpf.MapSpec{Name: "jmp", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1}
	for i := range spec.Instructions {
		if fn := btf.FuncMetadata(&spec.Instructions[i]); fn != nil && fn.Name == "cb" {
			// A tail call in the callback, with the hook call added, is the shape the guard refuses.
			tail := asm.Instructions{asm.Mov.Imm(asm.R1, 0), asm.LoadMapPtr(asm.R2, 0).WithReference("jmp"), asm.Mov.Imm(asm.R3, 0), asm.FnTailCall.Call()}
			at := len(spec.Instructions) - 2
			spec.Instructions = append(spec.Instructions[:at], append(tail, spec.Instructions[at:]...)...)
			break
		}
	}
	req := autoReq()
	req.Stack.LowestOffset = -16
	plan, err := transformLookupGuarded(work, req, func() error { return errors.New("planted") })
	if err != nil {
		t.Fatal(err)
	}
	if site := callbackSite(plan.skipped); site == nil || !strings.Contains(site.Reason, "planted") {
		t.Fatalf("skipped = %+v", plan.skipped)
	}
	if callbackSite(plan.sites) != nil {
		t.Fatalf("sites = %+v", plan.sites)
	}
}

func TestCallbackSiteRefusalsLeaveTheProgram(t *testing.T) {
	for name, mutate := range map[string]func(asm.Instructions){
		"NULL": func(insns asm.Instructions) {
			for i := range insns {
				if insns[i].IsLoadOfFunctionPointer() {
					insns[i+1], insns[i+2] = asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R3, 0)
				}
			}
		},
		"timer": func(insns asm.Instructions) {
			for i := range insns {
				if insns[i].IsBuiltinCall() && insns[i].Constant == int64(asm.FnLoop) {
					insns[i] = asm.FnTimerSetCallback.Call()
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			work := callbackSiteFixture("loop", true)
			mutate(work.Programs["p"].Instructions)
			plan, err := transformLookup(work, func() LookupRequest { r := autoReq(); r.Stack.LowestOffset = -16; return r }())
			if err != nil {
				t.Fatal(err)
			}
			site := callbackSite(plan.skipped)
			if site == nil || !strings.HasPrefix(site.Reason, "callback: ") || len(plan.sites) != 1 || plan.sites[0].FuncName != "p" {
				t.Fatalf("sites = %+v skipped = %+v", plan.sites, plan.skipped)
			}
		})
	}
}

func callbackPair(t *testing.T, form string) (in, out asm.Instructions, cert injectcheck.Certificate, premises injectcheck.Premises, prologue int) {
	t.Helper()
	work := callbackSiteFixture(form, true)
	in = append(asm.Instructions(nil), work.Programs["p"].Instructions...)
	injectcheck.Label(work.Programs["p"].Instructions)
	req := autoReq()
	req.Stack.LowestOffset = -16
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	out = work.Programs["p"].Instructions
	cert, premises = validationCertificate(t, in, out, plan.hooks, -16)
	for i := range out {
		if fn := btf.FuncMetadata(&out[i]); fn != nil && fn.Name == "cb" {
			prologue = i
		}
	}
	return in, out, cert, premises, prologue
}

func TestTranslationValidationCallbackSite(t *testing.T) {
	for _, form := range []string{"loop", "loop_rt0", "foreach"} {
		in, out, cert, premises, _ := callbackPair(t, form)
		counts, err := injectcheck.Check(in, out, cert, premises)
		if err != nil {
			t.Fatalf("%s: %v", form, err)
		}
		if counts.Sites != validationSitesFor(form) {
			t.Fatalf("%s: counts = %+v", form, counts)
		}
		pair := injectcheck.Pair{Format: injectcheck.FormatVersion, Original: injectcheck.Instructions(in), Transformed: injectcheck.Instructions(out), Certificate: cert, Premises: premises}
		encoded, err := json.Marshal(pair)
		if err != nil {
			t.Fatal(err)
		}
		var decoded injectcheck.Pair
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if verdict, err := decoded.Validate(); err != nil || !verdict.Accepted {
			t.Fatalf("%s: serialized pair: verdict=%+v err=%v", form, verdict, err)
		}
		old := strings.Replace(string(encoded), `"format":6`, `"format":4`, 1)
		if err := json.Unmarshal([]byte(old), &decoded); err == nil || !strings.Contains(err.Error(), "callback context") {
			t.Fatalf("%s: format 4 read a callback premise: %v", form, err)
		}
	}
}

// validationSitesFor counts the entry and callback sites; loop_rt0 has one more
// in the entry, for its flags.
func validationSitesFor(form string) int {
	if form == "loop_rt0" {
		return 3
	}
	return 2
}

func callbackTarget(premises injectcheck.Premises) *injectcheck.SiteTarget {
	for i := range premises.Targets {
		if ctx := premises.Targets[i].Ctx; ctx != nil && ctx.Param != 0 {
			return &premises.Targets[i]
		}
	}
	return nil
}

func TestTranslationValidationCallbackMutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(in, out asm.Instructions, at int, target *injectcheck.SiteTarget) (asm.Instructions, asm.Instructions)
		kind   injectcheck.Kind
	}{
		{"load offset", func(in, out asm.Instructions, at int, _ *injectcheck.SiteTarget) (asm.Instructions, asm.Instructions) {
			out[at].Offset += 8
			return in, out
		}, injectcheck.CtxProvenance},
		{"load register", func(in, out asm.Instructions, at int, _ *injectcheck.SiteTarget) (asm.Instructions, asm.Instructions) {
			out[at].Src = asm.R1
			return in, out
		}, injectcheck.CtxProvenance},
		{"store slot", func(in, out asm.Instructions, at int, _ *injectcheck.SiteTarget) (asm.Instructions, asm.Instructions) {
			out[at+1].Offset -= 8
			return in, out
		}, injectcheck.CtxProvenance},
		{"premise X and load offset together", func(in, out asm.Instructions, at int, target *injectcheck.SiteTarget) (asm.Instructions, asm.Instructions) {
			out[at].Offset -= 8
			target.Ctx.Arg += 8
			return in, out
		}, injectcheck.CtxProvenance},
		{"premise param", func(in, out asm.Instructions, at int, target *injectcheck.SiteTarget) (asm.Instructions, asm.Instructions) {
			target.Ctx.Param = int(asm.R4)
			out[at].Src = asm.R4
			return in, out
		}, injectcheck.CtxProvenance},
		{"second X in the original", func(in, out asm.Instructions, _ int, _ *injectcheck.SiteTarget) (asm.Instructions, asm.Instructions) {
			for _, stream := range []asm.Instructions{in, out} {
				for i := range stream {
					if stream[i].OpCode == asm.Add.Imm(asm.R3, 0).OpCode && stream[i].Dst == asm.R3 {
						stream[i].Constant = -8
					}
				}
			}
			return in, out
		}, injectcheck.CtxProvenance},
		{"branch into the prologue", func(in, out asm.Instructions, at int, _ *injectcheck.SiteTarget) (asm.Instructions, asm.Instructions) {
			// Enter past the load: the slot would keep whatever the frame held.
			for i := range out {
				if out[i].IsLoadOfFunctionPointer() {
					out[i] = asm.Instruction{OpCode: out[i].OpCode, Dst: out[i].Dst, Src: out[i].Src, Constant: -1}.WithReference("cb")
				}
			}
			out[at+1] = out[at+1].WithSymbol("cb")
			out[at] = btf.WithFuncMetadata(out[at].WithSymbol(""), nil)
			return in, out
		}, injectcheck.EdgeTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out, cert, premises, at := callbackPair(t, "loop")
			if callbackTarget(premises) == nil {
				t.Fatalf("no callback premise: %+v", premises)
			}
			in, out = tc.mutate(in, out, at, callbackTarget(premises))
			_, err := injectcheck.Check(in, out, cert, premises)
			var rejection *injectcheck.Rejection
			if !errors.As(err, &rejection) || rejection.Kind != tc.kind {
				t.Fatalf("mutation accepted or misclassified: %v", err)
			}
		})
	}
	// These change one instruction at the same place in both streams, so the
	// checker sees an original the transformer's proof would have refused.
	replace := func(in, out asm.Instructions, match func(asm.Instructions, int) bool, ins asm.Instruction) {
		for _, stream := range []asm.Instructions{in, out} {
			n := 0
			for i := range stream {
				if match(stream, i) {
					stream[i], n = ins, n+1
				}
			}
			if n != 1 {
				t.Fatalf("matched %d instructions", n)
			}
		}
	}
	beforeLoop := func(is asm.Instructions, i int) bool {
		return i+1 < len(is) && is[i+1].IsBuiltinCall() && is[i+1].Constant == int64(asm.FnLoop)
	}
	entersWindow := asm.JEq.Imm(asm.R1, 0, "")
	entersWindow.Offset = 3 // over the function pointer and r3 = r10, onto r3 += -16
	landsOnCall := asm.JEq.Imm(asm.R1, 0, "")
	landsOnCall.Offset = 5 // over the function pointer, the R3 setup and r4 = 0
	for _, tc := range []struct {
		name  string
		match func(asm.Instructions, int) bool
		ins   asm.Instruction
	}{
		{"xchg writes R3 before the helper", beforeLoop, asm.Xchg.Mem(asm.RFP, asm.R3, asm.DWord, -24)},
		{"load-acquire writes R3 before the helper", beforeLoop, asm.LoadAcquire(asm.R3, asm.RFP, asm.DWord, -24)},
		{"branch into the callback context window", func(is asm.Instructions, i int) bool {
			return i+1 < len(is) && is[i+1].IsLoadOfFunctionPointer()
		}, entersWindow},
		{"branch onto the helper call", func(is asm.Instructions, i int) bool {
			return i+1 < len(is) && is[i+1].IsLoadOfFunctionPointer()
		}, landsOnCall},
		{"callback also called directly", func(is asm.Instructions, i int) bool {
			return i+1 < len(is) && is[i+1].IsLoadOfFunctionPointer()
		}, asm.Call.Label("cb")},
		{"site unreachable from the callback", func(is asm.Instructions, i int) bool {
			return i > 0 && is[i-1].OpCode == asm.Mov.Reg(asm.R6, asm.R2).OpCode && is[i-1].Dst == asm.R6 && is[i-1].Src == asm.R2
		}, asm.Return()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out, cert, premises, _ := callbackPair(t, "loop")
			replace(in, out, tc.match, tc.ins)
			_, err := injectcheck.Check(in, out, cert, premises)
			var rejection *injectcheck.Rejection
			if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
				t.Fatalf("mutation accepted or misclassified: %v", err)
			}
		})
	}
	t.Run("frame starting inside the callback", func(t *testing.T) {
		in, out, cert, premises, _ := callbackPair(t, "loop")
		start := slices.IndexFunc(in, func(ins asm.Instruction) bool { return ins.Symbol() == "cb" })
		lowest := premises.LowestOffset
		premises.Frames = []injectcheck.FrameFloor{{Start: 0, LowestOffset: lowest}, {Start: start, LowestOffset: lowest},
			{Start: callbackTarget(premises).Site, LowestOffset: lowest - 8}}
		_, err := injectcheck.Check(in, out, cert, premises)
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
			t.Fatalf("mutation accepted or misclassified: %v (frames %+v)", err, premises.Frames)
		}
	})
	t.Run("callback premise on an entry site", func(t *testing.T) {
		in, out, cert, premises, _ := callbackPair(t, "loop")
		ctx := *callbackTarget(premises).Ctx
		for i := range premises.Targets {
			if premises.Targets[i].Ctx == nil {
				premises.Targets[i].Ctx = &ctx
			}
		}
		_, err := injectcheck.Check(in, out, cert, premises)
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
			t.Fatalf("mutation accepted or misclassified: %v", err)
		}
	})
	rejects := func(t *testing.T, in, out asm.Instructions, cert injectcheck.Certificate, premises injectcheck.Premises) {
		t.Helper()
		_, err := injectcheck.Check(in, out, cert, premises)
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
			t.Fatalf("mutation accepted or misclassified: %v", err)
		}
	}
	t.Run("callback_ctx below the entry floor", func(t *testing.T) {
		in, out, cert, premises, at := callbackPair(t, "loop")
		replace(in, out, func(is asm.Instructions, i int) bool {
			return is[i].OpCode == asm.Add.Imm(asm.R3, 0).OpCode && is[i].Dst == asm.R3
		}, asm.Add.Imm(asm.R3, -24))
		callbackTarget(premises).Ctx.Arg = -24
		out[at].Offset += 8
		rejects(t, in, out, cert, premises)
	})
	t.Run("register context premise on an entry site", func(t *testing.T) {
		in, out, cert, premises, _ := callbackPair(t, "loop")
		for i := range premises.Targets {
			if premises.Targets[i].Ctx == nil {
				premises.Targets[i].Ctx = &injectcheck.CtxSource{Reg: int(asm.R6)}
			}
		}
		rejects(t, in, out, cert, premises)
	})
	t.Run("frame floor starting inside the entry", func(t *testing.T) {
		in, out, cert, premises, _ := callbackPair(t, "loop")
		lowest := premises.LowestOffset
		premises.Frames = []injectcheck.FrameFloor{{Start: 0, LowestOffset: lowest}, {Start: 3, LowestOffset: lowest - 16}}
		rejects(t, in, out, cert, premises)
	})
	t.Run("site without a premise in a callback", func(t *testing.T) {
		in, out, cert, premises, _ := callbackPair(t, "loop")
		callbackTarget(premises).Ctx = nil
		if _, err := injectcheck.Check(in, out, cert, premises); err == nil {
			t.Fatal("accepted a callback site whose context the plan does not name")
		}
	})
	t.Run("prologue removed", func(t *testing.T) {
		in, out, cert, premises, at := callbackPair(t, "loop")
		symbol, fn := out[at].Symbol(), btf.FuncMetadata(&out[at])
		out[at+2] = btf.WithFuncMetadata(out[at+2].WithSymbol(symbol), fn)
		out = append(out[:at], out[at+2:]...)
		for i, j := range cert.Original {
			if j > at {
				cert.Original[i] = j - 2
			}
		}
		for i := range cert.Hooks {
			if cert.Hooks[i].Start > at {
				cert.Hooks[i].Start -= 2
				cert.Hooks[i].End -= 2
			}
		}
		_, err := injectcheck.Check(in, out, cert, premises)
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
			t.Fatalf("mutation accepted or misclassified: %v", err)
		}
	})
}

// A: a frame boundary inside the callback lowers the floor between the
// prologue and the site; an original store then overwrites the callback's
// context slot. Site and start keep the same floor.
func TestTranslationValidationCallbackFrameSplit(t *testing.T) {
	in, out, cert, premises, _ := callbackPair(t, "loop")
	start := slices.IndexFunc(in, func(ins asm.Instruction) bool { return ins.Symbol() == "cb" })
	// cb: r6 = r2; *(u32*)(r10-8) = 0; r2 = r10; r2 += -8; ...
	keyStore := start + 1
	keyAdd := start + 3
	if in[keyStore].OpCode != asm.StoreImm(asm.RFP, -8, 0, asm.Word).OpCode || in[keyAdd].OpCode != asm.Add.Imm(asm.R2, 0).OpCode {
		t.Fatalf("layout: %v / %v", in[keyStore], in[keyAdd])
	}
	for _, s := range []struct {
		stream asm.Instructions
		at     func(int) int
	}{{in, func(i int) int { return i }}, {out, func(i int) int { return cert.Original[i] }}} {
		s.stream[s.at(keyStore)] = asm.StoreImm(asm.RFP, -24, 0, asm.DWord) // the callback's ctx slot [f-8]
		s.stream[s.at(keyAdd)].Constant = -24
	}
	low := premises.LowestOffset
	premises.Frames = []injectcheck.FrameFloor{{Start: 0, LowestOffset: low}, {Start: start, LowestOffset: low},
		{Start: keyStore, LowestOffset: -24}, {Start: keyStore + 1, LowestOffset: low}}
	_, err := injectcheck.Check(in, out, cert, premises)
	var rejection *injectcheck.Rejection
	if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
		t.Fatalf("original store into the callback's context slot through a frame inside it: %v", err)
	}
}

// B: a u32 region inside the callback frame, before the callback site, saves
// R0 into the callback's context slot.
func TestTranslationValidationCallbackU32Region(t *testing.T) {
	in, out, cert, premises, _ := callbackPair(t, "loop")
	start := slices.IndexFunc(in, func(ins asm.Instruction) bool { return ins.Symbol() == "cb" })
	q := start + 2 // after *(u32*)(r10-8) = 0
	origIns := asm.Instructions{asm.Mov.Reg(asm.R0, asm.RFP), asm.Add.Imm(asm.R0, -8), asm.LoadMem(asm.R2, asm.R0, 0, asm.Word)}
	region := asm.Instructions{asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, -32, asm.R2, asm.DWord),
		asm.Mov.Imm32(asm.R1, 7), asm.Call.Label("u32hook"), asm.LoadMem(asm.R0, asm.RFP, -24, asm.DWord), asm.LoadMem(asm.R2, asm.RFP, -32, asm.DWord)}
	p := cert.Original[q] // insert before original q in out
	ins := append(append(asm.Instructions(nil), origIns...), region...)
	newOut := append(append(append(asm.Instructions(nil), out[:p]...), ins...), out[p:]...)
	newIn := append(append(append(asm.Instructions(nil), in[:q]...), origIns...), in[q:]...)
	shift := len(ins)
	newOrig := []int{}
	for i, j := range cert.Original {
		if i == q {
			newOrig = append(newOrig, p, p+1, p+2)
		}
		if j >= p {
			j += shift
		}
		newOrig = append(newOrig, j)
	}
	for i := range cert.Hooks {
		if cert.Hooks[i].Start >= p {
			cert.Hooks[i].Start += shift
			cert.Hooks[i].End += shift
		}
	}
	for i := range premises.Targets {
		if premises.Targets[i].Hook >= p {
			premises.Targets[i].Hook += shift
		}
		if premises.Targets[i].Site >= q {
			premises.Targets[i].Site += 3
		}
	}
	hook := len(newOut)
	newOut = append(newOut, asm.Mov.Reg32(asm.R0, asm.R1).WithSymbol("u32hook"), asm.Xor.Reg32(asm.R0, asm.R2), asm.Return())
	cert.Original = newOrig
	cert.Hooks = append(cert.Hooks, injectcheck.Span{Start: hook, End: hook + 3})
	premises.Targets = append(premises.Targets, injectcheck.SiteTarget{Site: q + 2, When: injectcheck.TargetAny, Hook: hook})
	_, err := injectcheck.Check(newIn, newOut, cert, premises)
	var rejection *injectcheck.Rejection
	if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
		t.Fatalf("u32 region overwriting the callback's context slot: %v", err)
	}
}

// Two paths both form R3 = fp-16 and merge between `r3 = r10` and the call.
// The checker sees R3 only in straight-line code, so the proof skips the
// callback site and the rest of the program still passes the checker.
func TestCallbackSiteMergedContext(t *testing.T) {
	spec := callbackSiteFixture("loop", true)
	insns := spec.Programs["p"].Instructions
	ld := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.IsLoadOfFunctionPointer() })
	cbStart := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Symbol() == "cb" })
	// entry: ..., r1 = 3 (ld-1), r2 = cb (ld), r3 = r10, r3 += -16, r4 = 0, call, r0 = *(fp-16), exit
	head := append(asm.Instructions(nil), insns[:ld]...) // up to r1 = 3
	load := insns[ld]
	tail := append(asm.Instructions(nil), insns[ld+3:cbStart]...) // r4 = 0, call, r0 = ..., exit
	cb := append(asm.Instructions(nil), insns[cbStart:]...)
	br := asm.JEq.Imm(asm.R1, 3, "")
	br.Offset = int16(2 + 2 + len(tail)) // to B: over r3 pair, ld (2 slots), tail
	var entry asm.Instructions
	entry = append(entry, head...)
	entry = append(entry, br, asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16), load)
	entry = append(entry, tail...)
	back := asm.Ja.Label("")
	back.Offset = int16(-(2 + len(tail) + 3)) // to the ld (L)
	entry = append(entry, asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -16), back)
	spec.Programs["p"].Instructions = append(entry, cb...)
	sites, err := discoverLookups(spec, "p")
	if err != nil {
		t.Fatal(err)
	}
	if site := callbackSite(sites); site == nil || !strings.Contains(site.Reason, "a branch lands") {
		t.Fatalf("callback site = %+v", site)
	}
	in := append(asm.Instructions(nil), spec.Programs["p"].Instructions...)
	injectcheck.Label(spec.Programs["p"].Instructions)
	req := autoReq()
	req.Stack.LowestOffset = -16
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	out := spec.Programs["p"].Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, -16)
	if _, err := injectcheck.Check(in, out, cert, premises); err != nil || len(plan.hooks) == 0 {
		t.Fatalf("hooks=%d Check: %v", len(plan.hooks), err)
	}
}

// An exception callback has BTF func info and no call or function-pointer
// reference; its frame floor is outside the entry and every callback.
func TestTranslationValidationCallbackUnreferencedFrame(t *testing.T) {
	work := callbackSiteFixture("loop", true)
	exFn := &btf.Func{Name: "excb", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: []btf.FuncParam{{Name: "cookie", Type: &btf.Int{Name: "u64", Size: 8}}}}}
	p := work.Programs["p"]
	p.Instructions = append(p.Instructions, btf.WithFuncMetadata(asm.Mov.Reg(asm.R0, asm.R1).WithSymbol("excb").WithSource(asm.Comment("excb")), exFn), asm.Return())
	in := append(asm.Instructions(nil), p.Instructions...)
	injectcheck.Label(p.Instructions)
	req := autoReq()
	req.Stack.LowestOffset = -16
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	out := p.Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, -16)
	cbStart, exStart := -1, -1
	for i := range in {
		if fn := btf.FuncMetadata(&in[i]); fn != nil {
			switch fn.Name {
			case "cb":
				cbStart = i
			case "excb":
				exStart = i
			}
		}
	}
	premises.Frames = []injectcheck.FrameFloor{{Start: 0, LowestOffset: -16}, {Start: cbStart, LowestOffset: -16}}
	if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
		t.Fatalf("without excb frame: %v", err)
	}
	premises.Frames = append(premises.Frames, injectcheck.FrameFloor{Start: exStart, LowestOffset: -16})
	if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
		t.Fatalf("with a frame for every BTF function: %v", err)
	}
}

// The callback's only reference sits in code unreachable from instruction 0,
// standing in for an exception callback placed before the callback: its frame
// has no spilled context.
func TestTranslationValidationCallbackReferenceOutsideEntry(t *testing.T) {
	in, out, cert, premises, _ := callbackPair(t, "loop")
	q := -1
	for i := range in {
		if in[i].IsLoadOfFunctionPointer() {
			q = i - 1 // r1 = 3
		}
	}
	ins := asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
	p := cert.Original[q]
	shift := len(ins)
	newOut := append(append(append(asm.Instructions(nil), out[:p]...), ins...), out[p:]...)
	newIn := append(append(append(asm.Instructions(nil), in[:q]...), ins...), in[q:]...)
	newOrig := []int{}
	for i, j := range cert.Original {
		if i == q {
			newOrig = append(newOrig, p, p+1)
		}
		if j >= p {
			j += shift
		}
		newOrig = append(newOrig, j)
	}
	for i := range cert.Hooks {
		if cert.Hooks[i].Start >= p {
			cert.Hooks[i].Start += shift
			cert.Hooks[i].End += shift
		}
	}
	for i := range premises.Targets {
		if premises.Targets[i].Hook >= p {
			premises.Targets[i].Hook += shift
		}
		if premises.Targets[i].Site >= q {
			premises.Targets[i].Site += 2
		}
	}
	cert.Original = newOrig
	_, err := injectcheck.Check(newIn, newOut, cert, premises)
	var rejection *injectcheck.Rejection
	if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
		t.Fatalf("reference unreachable from the entry: %v", err)
	}
}

// A generic callback site (its map pointer loaded from memory) below the entry
// floor is skipped too, not handed to the generic hook.
func cbGenericBelowFloor(t *testing.T, below bool) {
	spec := callbackSiteFixture("loop", true)
	insns := spec.Programs["p"].Instructions
	inCb := false
	for i, ins := range insns {
		if fn := btf.FuncMetadata(&ins); fn != nil {
			inCb = fn.Name == "cb"
		}
		if below && ins.OpCode == asm.Add.Imm(asm.R3, 0).OpCode && ins.Dst == asm.R3 {
			insns[i].Constant = -24
		}
		if inCb && ins.IsLoadFromMap() {
			insns[i] = asm.LoadMem(asm.R1, asm.R6, 0, asm.DWord)
		}
	}
	if _, err := discoverLookups(spec, "p"); err != nil {
		t.Fatal(err)
	}
	req := autoReq()
	req.Stack.LowestOffset = -16
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if below {
		requireCallbackSkipped(t, plan, "below the entry stack floor")
		return
	}
	requireCallbackSelected(t, plan)
}

func TestCallbackSiteGenericBelowEntryFloor(t *testing.T) { cbGenericBelowFloor(t, true) }
func TestCallbackSiteGenericAboveEntryFloor(t *testing.T) { cbGenericBelowFloor(t, false) }

// Every Dispatch hook is untrusted or static already, so a callback site is
// not skipped for sharing it.
func TestCallbackSiteDispatchNotSkippedForSharing(t *testing.T) {
	spec := callbackSiteFixture("foreach", true)
	insns := spec.Programs["p"].Instructions
	inCb := false
	for i, ins := range insns {
		if fn := btf.FuncMetadata(&ins); fn != nil {
			inCb = fn.Name == "cb"
		}
		if inCb && ins.OpCode == asm.Mov.Reg(asm.R2, asm.RFP).OpCode && ins.Dst == asm.R2 && ins.Src == asm.RFP {
			insns[i], insns[i+1] = asm.Mov.Imm(asm.R0, 0), asm.Mov.Imm(asm.R0, 0)
			break
		}
	}
	for _, dispatch := range []bool{true, false} {
		spec := spec.Copy()
		req := autoReq()
		req.Stack.LowestOffset = -32
		req.Dispatch, req.StaticUntrusted = dispatch, dispatch
		plan, err := transformLookup(spec, req)
		if err != nil {
			t.Fatal(err)
		}
		if dispatch {
			requireCallbackSelected(t, plan)
			continue
		}
		// Without Dispatch the read-only key would make the entry's typed hook untrusted.
		requireCallbackSkipped(t, plan, "would make the typed hook it shares untrusted")
	}
}

// genericCallbackFixture makes every lookup in callbackSiteFixture a generic
// site: sessions is a map-in-map whose lookup result is unused.
func genericCallbackFixture() *ebpf.CollectionSpec {
	spec := callbackSiteFixture("loop", true)
	m := spec.Maps["sessions"]
	m.Type, m.ValueSize = ebpf.HashOfMaps, 4
	m.Value = &btf.Int{Name: "u32", Size: 4}
	m.InnerMap = &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
	return spec
}

// A generic callback site whose function has no audited stack floor is
// skipped: the generic hook must not take a site in an unaudited frame, where
// the context spill would overlap the callback's own stack. The entry site,
// whose floor is audited, is kept.
func TestCallbackSiteGenericMissingFloor(t *testing.T) {
	for _, cbFloor := range []bool{false, true} {
		spec := genericCallbackFixture()
		req := autoReq()
		req.StaticUntrusted = true
		req.Stack = StackAudit{Frames: map[string]int16{"p": -16}, Source: "verifier"}
		if cbFloor {
			req.Stack.Frames["cb"] = -8
		}
		plan, err := transformLookup(spec, req)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(plan.sites, func(s LookupSite) bool { return s.FuncName == "p" }) {
			t.Fatalf("cb floor %v: entry site lost: %+v", cbFloor, plan.sites)
		}
		if cbFloor {
			requireCallbackSelected(t, plan)
			continue
		}
		requireCallbackSkipped(t, plan, "stack floor unavailable for this function")
	}
}

// selectLookups itself honours a missing floor: neither the generic nor the
// typed-only path revives the site.
func TestSelectLookupsMissingFloor(t *testing.T) {
	for _, typedOnly := range []bool{false, true} {
		site := discoveredLookup{LookupSite: LookupSite{Op: HookLookup, FuncName: "cb", Reason: "stack floor unavailable for this function", Generic: !typedOnly},
			generic: !typedOnly, typedOnly: typedOnly, noFloor: true, callback: &ctxflow.Callback{Helper: asm.FnLoop, Param: asm.R2, Arg: -16}}
		groups, skipped, err := selectLookups([]discoveredLookup{site}, autoReq(), nil)
		if err == nil || len(groups) != 0 || len(skipped) != 1 || skipped[0].Reason != site.Reason {
			t.Fatalf("typedOnly %v: groups=%+v skipped=%+v err=%v", typedOnly, groups, skipped, err)
		}
	}
}

// requireCallbackSelected fails unless the callback site is in the plan and
// in a hook, and not skipped.
func requireCallbackSelected(t *testing.T, plan lookupPlan) {
	t.Helper()
	if callbackSite(plan.sites) == nil {
		t.Fatalf("callback site not selected: skipped=%+v", plan.skipped)
	}
	if s := callbackSite(plan.skipped); s != nil {
		t.Fatalf("callback site skipped: %+v", *s)
	}
	for _, h := range plan.hooks {
		if callbackSite(h.Sites) != nil {
			return
		}
	}
	t.Fatalf("callback site in no hook: %+v", plan.hooks)
}

// requireCallbackSkipped fails unless the callback site is absent from the
// plan and every hook and skipped with a reason containing reason.
func requireCallbackSkipped(t *testing.T, plan lookupPlan, reason string) {
	t.Helper()
	if s := callbackSite(plan.sites); s != nil {
		t.Fatalf("callback site selected: %+v", *s)
	}
	for _, h := range plan.hooks {
		if s := callbackSite(h.Sites); s != nil {
			t.Fatalf("callback site in hook %s: %+v", h.Name, *s)
		}
	}
	if s := callbackSite(plan.skipped); s == nil || !strings.Contains(s.Reason, reason) {
		t.Fatalf("callback site not skipped for %q: %+v", reason, plan.skipped)
	}
}
