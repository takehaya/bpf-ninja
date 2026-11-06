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

// passSiteFixture is p(ctx) -> mid -> leaf, where leaf looks up key 0 and
// returns the session's seid, or 1 on a miss. leaf takes no context. mid takes
// the context as its parameter when saved, otherwise a number; a branch in mid
// lands on its call to leaf.
func passSiteFixture(saved bool) *ebpf.CollectionSpec {
	spec := lookupFixture()
	entryFn := btf.FuncMetadata(&spec.Programs["p"].Instructions[0])
	ctxParam := entryFn.Type.(*btf.FuncProto).Params[0]
	i64 := &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed}
	n := btf.FuncParam{Name: "n", Type: i64}
	fn := func(name string, param btf.FuncParam) *btf.Func {
		return &btf.Func{Name: name, Linkage: btf.StaticFunc, Type: &btf.FuncProto{Return: i64, Params: []btf.FuncParam{param}}}
	}
	entry := asm.Instructions{btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("p").WithSource(asm.Comment("entry")), entryFn)}
	midParam := ctxParam
	if !saved {
		entry, midParam = append(entry, asm.Mov.Imm(asm.R1, 7)), n
	}
	entry = append(entry, asm.Call.Label("mid"), asm.Return())
	onward := asm.JEq.Imm(asm.R6, 12345, "")
	onward.Offset = 1 // to the call, past r1 = 1
	mid := asm.Instructions{btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("mid").WithSource(asm.Comment("mid")), fn("mid", midParam)),
		onward, asm.Mov.Imm(asm.R1, 1), asm.Call.Label("leaf"), asm.Return()}
	miss := asm.JNE.Imm(asm.R0, 0, "")
	miss.Offset = 2
	leaf := asm.Instructions{btf.WithFuncMetadata(asm.StoreImm(asm.RFP, -4, 0, asm.Word).WithSymbol("leaf").WithSource(asm.Comment("leaf")), fn("leaf", n)),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(),
		miss, asm.Mov.Imm(asm.R0, 1), asm.Return(), asm.LoadMem(asm.R0, asm.R0, 0, asm.DWord), asm.Return()}
	spec.Programs["p"].Instructions = append(append(entry, mid...), leaf...)
	return spec
}

func passRequest() LookupRequest {
	req := autoReq()
	req.Stack.LowestOffset, req.Maps = -16, []string{"sessions"}
	return req
}

func TestPassSiteSource(t *testing.T) {
	for saved, want := range map[bool]string{false: "pass:r5@9,r5@4", true: "pass:r5@8,saved-r1@3"} {
		sites, err := discoverLookups(passSiteFixture(saved), "p")
		if err != nil {
			t.Fatal(err)
		}
		if len(sites) != 1 || sites[0].FuncName != "leaf" || sites[0].Reason != "" || sites[0].CtxSource != want {
			t.Fatalf("saved=%v: sites = %+v, want %s", saved, sites, want)
		}
	}
}

// The transform stores the register at each function's entry, loads it from
// the caller's slot before each call into a function taking it in a free
// register, and keeps branches to such a call on the load.
func TestPassSiteSplice(t *testing.T) {
	for _, saved := range []bool{false, true} {
		work := passSiteFixture(saved)
		plan, err := transformLookup(work, passRequest())
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.sites) != 1 || plan.sites[0].FuncName != "leaf" || len(plan.skipped) != 0 {
			t.Fatalf("saved=%v: plan = %+v", saved, plan)
		}
		out := work.Programs["p"].Instructions
		start := func(name string) int {
			return slices.IndexFunc(out, func(ins asm.Instruction) bool { fn := btf.FuncMetadata(&ins); return fn != nil && fn.Name == name })
		}
		call := func(name string) int {
			return slices.IndexFunc(out, func(ins asm.Instruction) bool { return ins.IsFunctionCall() && ins.Reference() == name })
		}
		mid, leaf := start("mid"), start("leaf")
		midReg := asm.R5
		if saved {
			midReg = asm.R1
		}
		if !sameInstr(out[mid].WithSymbol(""), asm.StoreMem(asm.RFP, -24, midReg, asm.DWord)) || !sameInstr(out[leaf].WithSymbol(""), asm.StoreMem(asm.RFP, -24, asm.R5, asm.DWord)) {
			t.Fatalf("saved=%v: prologues %v / %v", saved, out[mid], out[leaf])
		}
		if c := call("leaf"); !sameInstr(out[c-1], asm.LoadMem(asm.R5, asm.RFP, -24, asm.DWord)) {
			t.Fatalf("saved=%v: before the call to leaf: %v", saved, out[c-1])
		}
		if c := call("mid"); saved == sameInstr(out[c-1], asm.LoadMem(asm.R5, asm.RFP, -24, asm.DWord)) {
			t.Fatalf("saved=%v: before the call to mid: %v", saved, out[c-1])
		}
		// The prologue precedes the BTF function start's symbol, and the
		// branch in mid lands on the load, not on the call.
		if out[mid].Symbol() != "mid" || out[leaf].Symbol() != "leaf" {
			t.Fatalf("symbols moved: %q %q", out[mid].Symbol(), out[leaf].Symbol())
		}
	}
}

func passPair(t *testing.T, saved bool) (in, out asm.Instructions, cert injectcheck.Certificate, premises injectcheck.Premises) {
	t.Helper()
	work := passSiteFixture(saved)
	in = append(asm.Instructions(nil), work.Programs["p"].Instructions...)
	injectcheck.Label(work.Programs["p"].Instructions)
	plan, err := transformLookup(work, passRequest())
	if err != nil {
		t.Fatal(err)
	}
	out = work.Programs["p"].Instructions
	cert, premises = validationCertificate(t, in, out, plan.hooks, -16)
	return in, out, cert, premises
}

func TestTranslationValidationPassSite(t *testing.T) {
	for _, saved := range []bool{false, true} {
		in, out, cert, premises := passPair(t, saved)
		counts, err := injectcheck.Check(in, out, cert, premises)
		if err != nil || counts.Sites != 1 {
			t.Fatalf("saved=%v: counts=%+v err=%v", saved, counts, err)
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
			t.Fatalf("saved=%v: serialized pair: verdict=%+v err=%v", saved, verdict, err)
		}
		for _, format := range []string{`"format":6`, `"format":5`} {
			old := strings.Replace(string(encoded), `"format":7`, format, 1)
			if err := json.Unmarshal([]byte(old), &decoded); err == nil || !strings.Contains(err.Error(), "passed context") {
				t.Fatalf("saved=%v: %s read a passed-context premise: %v", saved, format, err)
			}
		}
		older := pair
		older.Format = 6
		if verdict, err := older.Validate(); err == nil || verdict.Kind != injectcheck.InputVersion {
			t.Fatalf("saved=%v: format 6 validated a passed-context premise: %+v %v", saved, verdict, err)
		}
	}
}

func passTarget(premises injectcheck.Premises) *injectcheck.SiteTarget {
	for i := range premises.Targets {
		if ctx := premises.Targets[i].Ctx; ctx != nil && len(ctx.Pass) != 0 {
			return &premises.Targets[i]
		}
	}
	return nil
}

// Each mutation keeps the inserted code consistent with the premise it
// changes where it can, so that only re-deriving the premise from the original
// stream rejects it; the others break the inserted code itself.
func TestTranslationValidationPassMutations(t *testing.T) {
	callTo := func(stream asm.Instructions, name string) int {
		return slices.IndexFunc(stream, func(ins asm.Instruction) bool { return ins.IsFunctionCall() && ins.Reference() == name })
	}
	symbol := func(stream asm.Instructions, name string) int {
		return slices.IndexFunc(stream, func(ins asm.Instruction) bool { return ins.Symbol() == name })
	}
	for _, tc := range []struct {
		name   string
		saved  bool
		mutate func(in, out asm.Instructions, cert injectcheck.Certificate, premises *injectcheck.Premises) asm.Instructions
		kind   injectcheck.Kind
		want   string
	}{
		// mid reads R1, its parameter: the context cannot travel there.
		{"register the function reads", false, func(in, out asm.Instructions, _ injectcheck.Certificate, premises *injectcheck.Premises) asm.Instructions {
			out[symbol(out, "mid")].Src = asm.R1
			out[callTo(out, "mid")-1].Dst = asm.R1
			passTarget(*premises).Ctx.Pass[1].Reg = int(asm.R1)
			return out
		}, injectcheck.CtxProvenance, "reads r1 before writing it"},
		// mid's premise, its prologue and the entry's load for it go: leaf's
		// load in mid then reads a slot nothing filled.
		{"caller's function without a premise", false, func(_, out asm.Instructions, cert injectcheck.Certificate, premises *injectcheck.Premises) asm.Instructions {
			target := passTarget(*premises)
			target.Ctx.Pass = target.Ctx.Pass[:1]
			at := symbol(out, "mid")
			out[at+1] = btf.WithFuncMetadata(out[at+1].WithSymbol("mid"), btf.FuncMetadata(&out[at]))
			out = deleteOut(out, cert, premises, at)
			return deleteOut(out, cert, premises, callTo(out, "mid")-1) // the entry's load for mid
		}, injectcheck.CtxProvenance, "in a function with no passed context"},
		{"site outside the premise's function", false, func(_, out asm.Instructions, _ injectcheck.Certificate, premises *injectcheck.Premises) asm.Instructions {
			pass := passTarget(*premises).Ctx.Pass
			pass[0], pass[1] = pass[1], pass[0]
			return out
		}, injectcheck.CtxProvenance, "is not reachable from the function"},
		{"frame floor inside a passing function", false, func(in, out asm.Instructions, _ injectcheck.Certificate, premises *injectcheck.Premises) asm.Instructions {
			premises.Frames = []injectcheck.FrameFloor{{Start: 0, LowestOffset: -16}, {Start: symbol(in, "mid") + 1, LowestOffset: -16}}
			return out
		}, injectcheck.CtxProvenance, "a frame floor starts"},
		{"function also used as a callback", false, func(in, out asm.Instructions, cert injectcheck.Certificate, _ *injectcheck.Premises) asm.Instructions {
			// The entry's r1 = 7 becomes a reference to leaf in both streams.
			at := callTo(in, "mid") - 1
			ref := asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R0, Src: asm.PseudoFunc, Constant: -1}.WithReference("leaf")
			in[at], out[cert.Original[at]] = ref, ref
			return out
		}, injectcheck.CtxProvenance, "is used as a callback"},
		{"load into another register", false, func(_, out asm.Instructions, _ injectcheck.Certificate, _ *injectcheck.Premises) asm.Instructions {
			out[callTo(out, "mid")-1].Dst = asm.R4
			return out
		}, injectcheck.CtxProvenance, "does not load the context into r5 first"},
		{"load from another slot", false, func(_, out asm.Instructions, _ injectcheck.Certificate, _ *injectcheck.Premises) asm.Instructions {
			out[callTo(out, "leaf")-1].Offset -= 8
			return out
		}, injectcheck.CtxProvenance, "does not load the context into r5 first"},
		{"prologue stores another register", true, func(_, out asm.Instructions, _ injectcheck.Certificate, _ *injectcheck.Premises) asm.Instructions {
			out[symbol(out, "mid")].Src = asm.R2
			return out
		}, injectcheck.CtxProvenance, "does not start by storing r1"},
		{"branch past the load", false, func(_, out asm.Instructions, _ injectcheck.Certificate, _ *injectcheck.Premises) asm.Instructions {
			out[symbol(out, "mid")+2].Offset++ // mid's branch, after the prologue and r6 = r1
			return out
		}, injectcheck.EdgeTarget, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out, cert, premises := passPair(t, tc.saved)
			if passTarget(premises) == nil {
				t.Fatalf("no pass premise: %+v", premises)
			}
			out = tc.mutate(in, out, cert, &premises)
			_, err := injectcheck.Check(in, out, cert, premises)
			var rejection *injectcheck.Rejection
			if !errors.As(err, &rejection) || rejection.Kind != tc.kind || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %s containing %q", err, tc.kind, tc.want)
			}
		})
	}
}

// passCallerFixture adds a call to leaf from the entry, before the call to mid.
func passCallerFixture() *ebpf.CollectionSpec {
	spec := passSiteFixture(false)
	insns := spec.Programs["p"].Instructions
	at := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.IsFunctionCall() })
	spec.Programs["p"].Instructions = slices.Insert(insns, at, asm.Call.Label("leaf"), asm.Mov.Imm(asm.R1, 7))
	return spec
}

// A call that does not load the context first leaves the function's slot with
// whatever the frame held.
func TestTranslationValidationPassMissingCallerLoad(t *testing.T) {
	work := passCallerFixture()
	in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
	injectcheck.Label(work.Programs["p"].Instructions)
	plan, err := transformLookup(work, passRequest())
	if err != nil || len(plan.sites) != 1 || plan.sites[0].CtxSource != "pass:r5@11,r5@6" {
		t.Fatalf("plan = %+v err = %v", plan, err)
	}
	out := work.Programs["p"].Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, -16)
	if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
		t.Fatal(err)
	}
	at := slices.IndexFunc(out, func(ins asm.Instruction) bool { return ins.IsFunctionCall() && ins.Reference() == "leaf" }) - 1
	if !sameInstr(out[at], asm.LoadMem(asm.R5, asm.RFP, -24, asm.DWord)) {
		t.Fatalf("no load before the entry's call to leaf: %v", out[at])
	}
	out = deleteOut(out, cert, &premises, at)
	_, err = injectcheck.Check(in, out, cert, premises)
	var rejection *injectcheck.Rejection
	if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance || !strings.Contains(err.Error(), "does not load the context into r5 first") {
		t.Fatalf("err = %v", err)
	}
}

// Every reason a site still has no context names why the context cannot be
// passed down either.
func TestPassSiteSkipReasons(t *testing.T) {
	leafStart := func(insns asm.Instructions) int {
		return slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Symbol() == "leaf" })
	}
	readAll := asm.Instructions{asm.Mov.Reg(asm.R0, asm.R1), asm.Add.Reg(asm.R0, asm.R2), asm.Add.Reg(asm.R0, asm.R3), asm.Add.Reg(asm.R0, asm.R4), asm.Add.Reg(asm.R0, asm.R5)}
	for _, tc := range []struct {
		name   string
		mutate func(spec *ebpf.CollectionSpec)
		want   string
	}{
		{"global", func(spec *ebpf.CollectionSpec) {
			insns := spec.Programs["p"].Instructions
			fn := *btf.FuncMetadata(&insns[leafStart(insns)])
			fn.Linkage = btf.GlobalFunc
			insns[leafStart(insns)] = btf.WithFuncMetadata(insns[leafStart(insns)], &fn)
		}, "function has no context parameter; ctx pass: not a static function"},
		{"every register read", func(spec *ebpf.CollectionSpec) {
			insns := spec.Programs["p"].Instructions
			at := leafStart(insns) + 1
			spec.Programs["p"].Instructions = slices.Insert(insns, at, readAll...)
		}, "function has no context parameter; ctx pass: every argument register is read before written"},
		{"caller cannot pass", func(spec *ebpf.CollectionSpec) {
			insns := spec.Programs["p"].Instructions
			at := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Symbol() == "mid" }) + 1
			spec.Programs["p"].Instructions = slices.Insert(insns, at, readAll...)
		}, "function has no context parameter; ctx pass: a caller cannot pass the context (mid@"},
		{"callback", func(spec *ebpf.CollectionSpec) {
			insns := spec.Programs["p"].Instructions
			at := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.IsFunctionCall() })
			ref := asm.Instruction{OpCode: asm.LoadImmOp(asm.DWord), Dst: asm.R0, Src: asm.PseudoFunc, Constant: -1}.WithReference("leaf")
			spec.Programs["p"].Instructions = slices.Insert(insns, at, ref)
		}, "; ctx pass: the function is used as a callback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := passSiteFixture(false)
			tc.mutate(spec)
			sites, err := discoverLookups(spec, "p")
			if err != nil || len(sites) != 1 || !strings.Contains(sites[0].Reason, tc.want) || sites[0].CtxSource != "" {
				t.Fatalf("sites = %+v err = %v, want reason %q", sites, err, tc.want)
			}
		})
	}
}

// The transform reserves a context slot in every function on the chain, so a
// missing or too low floor for any of them skips the site.
func TestPassSiteStackFloors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames map[string]int16
		want   string
	}{
		{"chain function unaudited", map[string]int16{"p": -16, "leaf": -16}, "ctx pass: stack floor unavailable for mid"},
		{"slot below the frame limit", map[string]int16{"p": -16, "mid": -480, "leaf": -16}, "ctx pass: the context slot of mid does not fit below its stack floor -480"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := passRequest()
			req.Entry = true // keep the program instrumented without the site
			req.Stack.Frames = tc.frames
			plan, err := transformLookup(passSiteFixture(false), req)
			if err != nil || len(plan.sites) != 0 || len(plan.skipped) != 1 || plan.skipped[0].Reason != tc.want {
				t.Fatalf("plan = %+v err = %v", plan, err)
			}
		})
	}
}

// A passed-context site never keeps a lookup wrapper. A wrapper serves a
// frame whose slots reach past 512 bytes, so the site's frame with its context
// slot rounds to 512, and the caller that passes the context has a slot of its
// own: the call chain passes the combined limit, and Auto drops the site as it
// drops any passed-context site, keeping the program's other sites.
func TestPassSiteNotWrapped(t *testing.T) {
	// wrapSites alone would wrap such a site.
	site := discoveredLookup{LookupSite: LookupSite{FuncName: "leaf", SitePC: 9, CtxSource: "pass:r5@9,r5@4"}, pass: []ctxflow.Pass{{Name: "leaf"}}}
	wrapReq := LookupRequest{Stack: StackAudit{Frames: map[string]int16{"leaf": -496}, Source: "verifier", FrameRounding: 16}}
	if group := wrapSites(lookupGroup{op: HookLookup, sites: []discoveredLookup{site}}, wrapReq); group.sites[0].Wrapper == "" {
		t.Fatal("wrapSites did not wrap the site")
	}
	for _, leaf := range []int16{-490, -496, -504} {
		req := passRequest()
		req.Entry = true // keep the program instrumented without the site
		req.Stack = StackAudit{Frames: map[string]int16{"p": -8, "mid": 0, "leaf": leaf}, Source: "verifier", FrameRounding: 16}
		plan, err := transformLookup(passSiteFixture(false), req)
		if err != nil || len(plan.sites) != 0 || len(plan.skipped) != 1 || !strings.Contains(plan.skipped[0].Reason, "call chain p -> mid -> leaf uses 544 bytes") {
			t.Fatalf("leaf floor %d: plan = %+v err = %v", leaf, plan, err)
		}
		for _, hook := range plan.hooks {
			for _, site := range hook.Sites {
				if site.Wrapper != "" {
					t.Fatalf("leaf floor %d: wrapper %q", leaf, site.Wrapper)
				}
			}
		}
	}
}

// When a stack limit breaks, Auto drops passed-context sites with the callback
// sites, before the program's other sites.
func TestPassSiteDroppedFirst(t *testing.T) {
	groups := []lookupGroup{{sites: []discoveredLookup{{LookupSite: LookupSite{SitePC: 1}}, {LookupSite: LookupSite{SitePC: 2}, pass: []ctxflow.Pass{{Name: "leaf"}}}}}}
	kept, skipped := dropCallbackSites(groups, nil, "limit")
	if len(kept) != 1 || len(kept[0].sites) != 1 || kept[0].sites[0].SitePC != 1 || len(skipped) != 1 || skipped[0].SitePC != 2 || skipped[0].Reason != "limit" {
		t.Fatalf("kept = %+v skipped = %+v", kept, skipped)
	}
}

// deleteOut removes the inserted instruction at out[at], keeping cert and the
// premises' hook indices on the instructions they name.
func deleteOut(out asm.Instructions, cert injectcheck.Certificate, premises *injectcheck.Premises, at int) asm.Instructions {
	for i, j := range cert.Original {
		if j > at {
			cert.Original[i] = j - 1
		}
	}
	for i := range cert.Hooks {
		if cert.Hooks[i].Start > at {
			cert.Hooks[i].Start--
			cert.Hooks[i].End--
		}
	}
	for i := range premises.Targets {
		if premises.Targets[i].Hook > at {
			premises.Targets[i].Hook--
		}
	}
	return slices.Delete(out, at, at+1)
}
