package inject

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// Layout extraction is deliberately separate from the checker decision. Labels
// only propose a correspondence; the checker compares the actual instructions.
func validationCertificate(t *testing.T, in, out asm.Instructions, hooks []LookupHook, floor int16) (injectcheck.Certificate, injectcheck.Premises) {
	t.Helper()
	names := map[string]bool{}
	for _, h := range hooks {
		names[h.Name] = true
	}
	var spans []injectcheck.Span
	for i := 0; i < len(out); i++ {
		if !names[out[i].Symbol()] {
			continue
		}
		end := i + 1
		for end < len(out) && btf.FuncMetadata(&out[end]) == nil {
			end++
		}
		spans = append(spans, injectcheck.Span{Start: i, End: end})
		i = end - 1
	}
	c, e := injectcheck.FromLabels(out, len(in), spans)
	if e != nil {
		t.Fatal(e)
	}
	targets, err := BuildLookupTargets(out, hooks)
	if err != nil {
		t.Fatal(err)
	}
	return c, injectcheck.Premises{LowestOffset: floor, Targets: targets}
}

func TestBuildLookupTargets(t *testing.T) {
	out := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0).WithSymbol("hit"), asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("miss"), asm.Return(),
	}
	hit := LookupHook{Name: "hit", Kind: HookLookup, Sites: []LookupSite{{InstructionIndex: 7}}}
	targets, err := BuildLookupTargets(out, []LookupHook{hit})
	if err != nil {
		t.Fatal(err)
	}
	want := injectcheck.SiteTarget{Site: 7, When: injectcheck.TargetHit, Hook: 0,
		Args: []injectcheck.ArgRole{injectcheck.ArgCtx, injectcheck.ArgKey, injectcheck.ArgValue}}
	if len(targets) != 1 || !reflect.DeepEqual(targets[0], want) {
		t.Fatalf("empty LookupWhen must mean hit: %+v", targets)
	}
	for _, tc := range []struct {
		name  string
		out   asm.Instructions
		hooks []LookupHook
	}{
		{"missing-symbol", out, []LookupHook{{Name: "absent", Kind: HookLookup, When: string(LookupAny)}}},
		{"duplicate-symbol", append(append(asm.Instructions(nil), out...), asm.Return().WithSymbol("hit")), []LookupHook{hit}},
		{"duplicate-target", out, []LookupHook{hit, {Name: "miss", Kind: HookLookup, Sites: []LookupSite{{InstructionIndex: 7}}}}},
		{"invalid-lookup-when", out, []LookupHook{{Name: "hit", Kind: HookLookup, When: "error"}}},
		{"invalid-call-when", out, []LookupHook{{Name: "hit", Kind: HookUpdate, When: "hit"}}},
		{"callback-source-trailing-text", out, []LookupHook{{Name: "hit", Kind: HookLookup, Sites: []LookupSite{{InstructionIndex: 7, CtxSource: "callback:r2:fp-16x"}}}}},
		{"callback-source-wraps-int16", out, []LookupHook{{Name: "hit", Kind: HookLookup, Sites: []LookupSite{{InstructionIndex: 7, CtxSource: "callback:r2:fp-65552"}}}}},
		{"indirect-callx", append(append(asm.Instructions(nil), out...), asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call).SetSource(asm.RegSource), Src: asm.R3}), []LookupHook{hit}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildLookupTargets(tc.out, tc.hooks); err == nil {
				t.Fatal("BuildLookupTargets accepted invalid input")
			} else if tc.name == "indirect-callx" && (!errors.Is(err, ErrCheckerNotApplicable) || !strings.Contains(err.Error(), "cannot pair indirect callx")) {
				t.Fatalf("callx was not classified as checker-inapplicable: %v", err)
			}
		})
	}
}

func TestTranslationValidationEquivalence(t *testing.T) {
	total, accepted, sites, zeroSites := 0, 0, 0, 0
	for _, seed := range equivDefaultSeeds {
		for _, config := range []string{"typed-any", "typed-error", "typed-miss", "static-any", "dispatch-any", "dispatch-static", "copy-readonly",
			"typed-any/miss-first", "typed-error/miss-first", "dispatch-any/miss-first", "copy-readonly/miss-first"} {
			t.Run(fmt.Sprintf("%d/%s", seed, config), func(t *testing.T) {
				total++
				c := newEquivCase(uint64(seed))
				work := c.spec()
				in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
				injectcheck.Label(work.Programs["p"].Instructions)
				req := c.request(config)
				plan, e := transformLookup(work, req)
				if e != nil {
					t.Fatalf("TRANSFORM_REFUSED %v", e)
				}
				out := work.Programs["p"].Instructions
				cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
				n, e := injectcheck.Check(in, out, cert, premises)
				if e != nil {
					t.Fatal(e)
				}
				if n.Sites != validationSites(plan.hooks) {
					t.Fatalf("checked sites %d, planned %d", n.Sites, validationSites(plan.hooks))
				}
				if n.Sites == 0 {
					zeroSites++
				}
				if dest := os.Getenv("BPF_NINJA_VALIDATE_OUTPUT"); dest != "" {
					if err := os.MkdirAll(dest, 0755); err != nil {
						t.Fatal(err)
					}
					validationSave(t, filepath.Join(dest, fmt.Sprintf("fixture-%d-%s.json", seed, strings.ReplaceAll(config, "/", "-"))), validationPairEvidence(t, in, out, cert, premises, nil, struct {
						Accepted bool             `json:"accepted"`
						Kind     injectcheck.Kind `json:"kind"`
					}{Accepted: true}, ""))
				}
				accepted++
				sites += n.Sites
				t.Logf("CHECK accepted original=%d sites=%d hooks=%d", n.Instructions, n.Sites, n.Hooks)
			})
		}
	}
	t.Logf("VALIDATION attempted=%d accepted=%d sites=%d site_bearing=%d zero_site=%d", total, accepted, sites, accepted-zeroSites, zeroSites)
	if accepted != total {
		t.Fatalf("accepted %d of %d fixtures; no refusals are allowed", accepted, total)
	}
}

func TestTranslationValidationSubprogramContextPairCorpus(t *testing.T) {
	for _, source := range []string{"register", "slot"} {
		t.Run(source, func(t *testing.T) {
			work := subprogramLookupFixture(source)
			in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
			injectcheck.Label(work.Programs["p"].Instructions)
			req := autoReq()
			req.Stack.LowestOffset = -16
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			out := work.Programs["p"].Instructions
			cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
			if len(premises.Targets) != 1 || premises.Targets[0].Ctx == nil {
				t.Fatalf("context premise = %+v", premises.Targets)
			}
			if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
				t.Fatalf("transform output rejected: target=%+v helper=%d around=%v: %v", premises.Targets[0], cert.Original[premises.Targets[0].Site], out[cert.Original[premises.Targets[0].Site]-6:cert.Original[premises.Targets[0].Site]], err)
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
				t.Fatalf("valid pair rejected: verdict=%+v err=%v", verdict, err)
			}

			target := premises.Targets[0]
			helper := cert.Original[target.Site]
			if source == "register" {
				t.Run("matching-premise-is-trusted", func(t *testing.T) {
					// The checker binds code to trusted plan data. It does not
					// reconstruct BTF provenance, so a consistently changed
					// premise and prelude remains a valid conditional proof.
					forged := append(asm.Instructions(nil), out...)
					forged[helper-1] = asm.StoreMem(asm.RFP, forged[helper-1].Offset, asm.R7, asm.DWord)
					forgedPremises := premises
					forgedPremises.Targets = append([]injectcheck.SiteTarget(nil), premises.Targets...)
					ctx := *forgedPremises.Targets[0].Ctx
					ctx.Reg = int(asm.R7)
					forgedPremises.Targets[0].Ctx = &ctx
					if _, err := injectcheck.Check(in, forged, cert, forgedPremises); err != nil {
						t.Fatalf("matching trusted premise rejected: %v", err)
					}
				})
			}
			for _, mutation := range []string{"wrong-source", "missing-init"} {
				t.Run(mutation, func(t *testing.T) {
					bad := append(asm.Instructions(nil), out...)
					switch {
					case source == "register" && mutation == "wrong-source":
						bad[helper-1] = asm.StoreMem(asm.RFP, bad[helper-1].Offset, asm.R7, asm.DWord)
					case source == "slot" && mutation == "wrong-source":
						bad[helper-2] = asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord)
					default:
						bad[helper-1] = asm.StoreMem(asm.RFP, bad[helper-1].Offset, asm.R1, asm.DWord)
					}
					_, err := injectcheck.Check(in, bad, cert, premises)
					var rejection *injectcheck.Rejection
					if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CtxProvenance {
						t.Fatalf("mutation accepted or misclassified: %v", err)
					}
				})
			}
		})
	}
}

type validationRow struct {
	Object, Program, Form, Status, Reason, FloorSource     string
	Sites, Hooks, Instructions, PlannedSites, SkippedSites int
	Floor                                                  int16
	SerializedProjection                                   bool
}

// Opt-in corpus checking does no loading or attaching. Census floors are taken
// from the recorded plain-program stack bounds; they remain caller audits.
func TestTranslationValidationCensus(t *testing.T) {
	root := os.Getenv("BPF_NINJA_VALIDATE_OBJECTS")
	if root == "" {
		t.Skip("set BPF_NINJA_VALIDATE_OBJECTS, BPF_NINJA_VALIDATE_CENSUS and BPF_NINJA_VALIDATE_OUTPUT")
	}
	if os.Getenv("BPF_NINJA_VALIDATE_CENSUS") == "" {
		t.Fatal("BPF_NINJA_VALIDATE_CENSUS is required")
	}
	dest := os.Getenv("BPF_NINJA_VALIDATE_OUTPUT")
	if dest == "" {
		t.Fatal("output directory required")
	}
	if err := os.MkdirAll(dest, 0755); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "*.o"))
	if err != nil || len(files) == 0 {
		t.Fatalf("corpus: %v", err)
	}
	var rows []validationRow
	for _, file := range files {
		data, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		src, e := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
		if e != nil {
			t.Fatal(e)
		}
		var names []string
		for name, p := range src.Programs {
			if p.Type == ebpf.XDP || p.Type == ebpf.SchedCLS || p.Type == ebpf.SchedACT {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			floor := int16(0)
			// Use the same per-program audit bound recorded by the census CLI.
			boundFile := filepath.Join(os.Getenv("BPF_NINJA_VALIDATE_CENSUS"), filepath.Base(file)+"--"+name, "plain", "load.json")
			b, e := os.ReadFile(boundFile)
			if e != nil {
				if !os.IsNotExist(e) {
					t.Fatalf("required census bound %s: %v", boundFile, e)
				}
				for _, form := range []string{"typed", "static", "raw-typed", "raw-static"} {
					rows = append(rows, validationRow{Object: filepath.Base(file), Program: name, Form: form, Status: "INPUT_REFUSED", FloorSource: "missing-census-bound", Reason: "required census bound is missing"})
				}
				t.Logf("INPUT_REFUSED %s %s: required census bound is missing; all four forms excluded", filepath.Base(file), name)
				continue
			}
			var bound struct{ Bound *int16 }
			if e = json.Unmarshal(b, &bound); e != nil || bound.Bound == nil {
				t.Fatalf("invalid census Bound in %s: %v", boundFile, e)
			}
			if *bound.Bound > 0 || *bound.Bound < -512 {
				t.Fatalf("census Bound outside [-512,0] in %s: %d", boundFile, *bound.Bound)
			}
			floor = *bound.Bound

			for _, ins := range src.Programs[name].Instructions {
				cl := ins.OpCode.Class()
				if cl == asm.LdXClass && ins.Src == asm.RFP || (cl == asm.StClass || cl == asm.StXClass) && ins.Dst == asm.RFP {
					floor = min(floor, ins.Offset)
				}
			}
			for _, form := range []string{"typed", "static"} {
				r := validationRow{Object: filepath.Base(file), Program: name, Form: form, Floor: floor, FloorSource: "census-bound-and-direct-accesses", SerializedProjection: true}
				work := src.Copy()
				in := append(asm.Instructions(nil), work.Programs[name].Instructions...)
				injectcheck.Label(work.Programs[name].Instructions)
				tail := false
				for _, ins := range in {
					if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnTailCall {
						tail = true
					}
				}
				req := LookupRequest{ProgramName: name, Auto: true, Entry: true, TailCalls: tail, Lookups: LookupAny, Updates: CallAny, Deletes: CallAny, Pushes: CallAny, Pops: CallAny, Peeks: CallAny, HookName: "n", StaticUntrusted: form == "static", Stack: StackAudit{LowestOffset: floor}}
				plan, e := transformLookup(work, req)
				if e != nil {
					r.Status = "TRANSFORM_REFUSED"
					r.Reason = e.Error()
					rows = append(rows, r)
					rows = append(rows, validationRow{Object: r.Object, Program: name, Form: "raw-" + form, Floor: floor, FloorSource: r.FloorSource, Status: "RAW_NOT_RUN", Reason: "typed transform refused: " + e.Error()})
					continue
				}
				r.PlannedSites = validationSites(plan.hooks)
				r.SkippedSites = len(plan.skipped)
				out := work.Programs[name].Instructions
				cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
				counts, e := injectcheck.Check(in, out, cert, premises)
				if e == nil && counts.Sites != r.PlannedSites {
					t.Fatalf("checked sites %d planned %d", counts.Sites, r.PlannedSites)
				}
				r.Sites = counts.Sites
				r.Hooks = counts.Hooks
				r.Instructions = counts.Instructions
				r.Status = "ACCEPTED"
				if e != nil {
					r.Status = "REJECTED"
					r.Reason = e.Error()
				}
				stem := filepath.Base(file) + "--" + name + "--" + form
				validationSave(t, filepath.Join(dest, stem+".json"), validationPairEvidence(t, in, out, cert, premises, req, r, ""))
				rows = append(rows, r)
				t.Logf("%s %s %s %s sites=%d %s", r.Object, name, form, r.Status, r.Sites, r.Reason)
				// Also exercise the fixed raw front end with numeric instructions/map FDs.
				// Its labels survive the metadata reconstruction; the decision sees actual
				// raw-transform output, including numeric branch/call/callback relocation.
				raw := rawLookupFixture(t, src, name, true)
				injectcheck.Label(raw.Instructions)
				// Reproduce inject-run's eager BTF function decoding (DECL_TAG regression).
				if len(raw.FuncInfo) >= 8 {
					id := btf.TypeID(src.ByteOrder.Uint32(raw.FuncInfo[4:8]))
					if _, e := raw.BTF.TypeByID(id); e != nil {
						t.Fatal(e)
					}
				}
				rr := LookupRequestRaw{Auto: true, Entry: true, TailCalls: tail, Lookups: LookupAny, Updates: CallAny, Deletes: CallAny, Pushes: CallAny, Pops: CallAny, Peeks: CallAny, HookName: "n", StaticUntrusted: form == "static", Stack: StackAudit{LowestOffset: floor}}
				result, e := TransformLookupRaw(raw, rr)
				r = validationRow{Object: filepath.Base(file), Program: name, Form: "raw-" + form, Floor: floor, FloorSource: "census-bound-and-direct-accesses", SerializedProjection: true}
				if e != nil {
					r.Status = "TRANSFORM_REFUSED"
					r.Reason = e.Error()
					rows = append(rows, r)
					continue
				}
				r.PlannedSites = validationSites(result.Hooks)
				r.SkippedSites = len(result.Skipped)
				cert, premises = validationCertificate(t, raw.Instructions, result.Instructions, result.Hooks, floor)
				counts, e = injectcheck.Check(raw.Instructions, result.Instructions, cert, premises)
				r.Status = "ACCEPTED"
				r.Reason = ""
				if e == nil && counts.Sites != r.PlannedSites {
					t.Fatalf("checked sites %d planned %d", counts.Sites, r.PlannedSites)
				}
				r.Sites = counts.Sites
				r.Hooks = counts.Hooks
				r.Instructions = counts.Instructions
				if e != nil {
					r.Status = "REJECTED"
					r.Reason = e.Error()
				}
				validationSave(t, filepath.Join(dest, stem+"--raw.json"), validationPairEvidence(t, raw.Instructions, result.Instructions, cert, premises, rr, r, ""))
				rows = append(rows, r)
				t.Logf("%s %s %s %s sites=%d %s", r.Object, name, r.Form, r.Status, r.Sites, r.Reason)
			}
		}
	}
	validationSave(t, filepath.Join(dest, "rows.json"), rows)
	rejected := 0
	for _, r := range rows {
		if r.Status == "REJECTED" {
			rejected++
		}
	}
	accepted, missing, rawNotRun, zeroSites := 0, 0, 0, 0
	for _, r := range rows {
		switch r.Status {
		case "ACCEPTED":
			accepted++
			if r.Sites == 0 {
				zeroSites++
			}
		case "INPUT_REFUSED":
			missing++
		case "RAW_NOT_RUN":
			rawNotRun++
		}
	}
	t.Logf("CORPUS rows=%d accepted=%d checker_rejected=%d missing_bound=%d raw_not_run=%d zero_site_accepted=%d", len(rows), accepted, rejected, missing, rawNotRun, zeroSites)
	// Rejections are findings, not a passing equivalence claim. Preserve all rows.
	if rejected > 0 {
		t.Fatalf("checker rejected %d transformed programs", rejected)
	}
}
func validationSave(t *testing.T, path string, v any) {
	t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0644); e != nil {
		t.Fatal(e)
	}
}

func TestTranslationValidationMutations(t *testing.T) {
	c := newEquivCase(1)
	work := c.spec()
	in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
	injectcheck.Label(work.Programs["p"].Instructions)
	req := c.request("typed-any")
	plan, e := transformLookup(work, req)
	if e != nil {
		t.Fatal(e)
	}
	out := work.Programs["p"].Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
	if _, e = injectcheck.Check(in, out, cert, premises); e != nil {
		t.Fatal(e)
	}
	// Mutate code and independently repair correspondence hints where needed;
	// Each assertion below identifies the rejecting check, including instruction
	// comparison for a complete, increasing but forged correspondence.
	cases := []string{"callee-saved-clobber", "drop-original", "wrong-jump", "hook-store", "missing-restore", "wrong-spill", "helper-in-hook", "forged-certificate", "map-swap", "map-fd-value-swap", "ldimm64-pseudo-kind"}
	want := map[string]injectcheck.Kind{
		"callee-saved-clobber": injectcheck.ALUClobber,
		"drop-original":        injectcheck.OriginalChanged,
		"forged-certificate":   injectcheck.OriginalChanged,
		"wrong-spill":          injectcheck.PreludeShape,
		"wrong-jump":           injectcheck.EdgeTarget,
		"hook-store":           injectcheck.HookShape,
		"helper-in-hook":       injectcheck.HookShape,
		"missing-restore":      injectcheck.ResultSaveRestore,
		"map-swap":             injectcheck.OriginalReference,
		"map-fd-value-swap":    injectcheck.OriginalChanged,
		"ldimm64-pseudo-kind":  injectcheck.OriginalChanged,
	}
	killed := 0
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			original := append(asm.Instructions(nil), in...)
			bad := append(asm.Instructions(nil), out...)
			cc := cert
			cc.Original = append([]int(nil), cert.Original...)
			cc.Hooks = append([]injectcheck.Span(nil), cert.Hooks...)
			pp := premises
			pp.Targets = append([]injectcheck.SiteTarget(nil), premises.Targets...)
			switch kind {
			case "map-swap", "map-fd-value-swap", "ldimm64-pseudo-kind":
				found := false
				for i, x := range in {
					if !x.IsLoadFromMap() {
						continue
					}
					at := cc.Original[i]
					switch kind {
					case "map-swap":
						bad[at] = bad[at].WithReference(x.Reference() + "_other")
					case "map-fd-value-swap":
						// Use a numeric FD operand: a symbolic load's placeholder
						// constant can be overwritten when its map is associated.
						original[i] = original[i].WithReference("")
						original[i].Constant = 100
						bad[at] = original[i]
						if _, err := injectcheck.Check(original, bad, cc, pp); err != nil {
							t.Fatalf("numeric FD baseline: %v", err)
						}
						bad[at].Constant = 101
					case "ldimm64-pseudo-kind":
						bad[at].Src ^= asm.PseudoMapFD ^ asm.PseudoMapValue
					}
					found = true
					break
				}
				if !found {
					t.Fatal("mutation requires a map load")
				}
			case "callee-saved-clobber":
				for i, x := range bad {
					if i > cc.Original[0] && x.IsFunctionCall() && strings.HasPrefix(x.Reference(), "eq_") {
						bad[i-1] = asm.Mov.Imm(asm.R6, 0)
						break
					}
				}
			case "drop-original":
				// Remove the first helper: its postlude provides room for a
				// complete, increasing mapping with no missing (-1) indices.
				at := -1
				for i, x := range original {
					if x.IsBuiltinCall() {
						at = cc.Original[i]
						break
					}
				}
				if at < 0 {
					t.Fatal("mutation requires a helper")
				}
				bad = validationDelete(bad, at)
				for i, j := range cc.Original {
					if j > at {
						cc.Original[i]--
					}
				}
				for i, h := range cc.Hooks {
					if h.Start > at {
						cc.Hooks[i].Start--
						cc.Hooks[i].End--
					}
				}
				var err error
				pp.Targets, err = BuildLookupTargets(bad, plan.hooks)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-jump":
				for i, x := range in {
					if x.OpCode.Class().IsJump() && x.OpCode.JumpOp() != asm.Call && x.OpCode.JumpOp() != asm.Exit {
						bad[cc.Original[i]].Offset++
						break
					}
				}
			case "hook-store":
				bad[cc.Hooks[0].Start] = asm.StoreMem(asm.R1, 0, asm.R0, asm.DWord)
			case "missing-restore":
				for i, x := range bad {
					if x.OpCode.Class() == asm.LdXClass && x.Dst == asm.R0 && x.Src == asm.RFP {
						bad[i] = asm.Mov.Imm(asm.R0, 0)
						break
					}
				}
			case "wrong-spill":
				found := false
				for i, x := range original {
					at := cc.Original[i]
					if x.IsBuiltinCall() && at > 0 && stackSpillForValidation(bad[at-1]) {
						bad[at-1].Offset = 0
						found = true
						break
					}
				}
				if !found {
					t.Fatal("mutation requires a site spill")
				}
			case "helper-in-hook":
				bad[cc.Hooks[0].Start] = asm.FnGetPrandomU32.Call()
			case "forged-certificate":
				// Forge a still-increasing mapping into the entry prologue.
				cc.Original[0]--
			}
			_, err := injectcheck.Check(original, bad, cc, pp)
			if dest := os.Getenv("BPF_NINJA_VALIDATE_OUTPUT"); dest != "" {
				if e := os.MkdirAll(dest, 0755); e != nil {
					t.Fatal(e)
				}
				reason := ""
				if err != nil {
					reason = err.Error()
				}
				validationSave(t, filepath.Join(dest, "mutation-"+kind+".json"), validationPairEvidence(t, original, bad, cc, pp, nil, struct {
					Accepted bool             `json:"accepted"`
					Kind     injectcheck.Kind `json:"kind"`
				}{Kind: want[kind]}, reason))
			}
			if err == nil {
				t.Fatal("SURVIVED")
			} else {
				var rejection *injectcheck.Rejection
				if !errors.As(err, &rejection) || rejection.Kind != want[kind] {
					t.Fatalf("wrong rejecting check: got %v, want kind %s", err, want[kind])
				}
				killed++
				t.Logf("KILLED %s: %v", kind, err)
			}
		})
	}
	t.Logf("MUTATION killed=%d total=%d", killed, len(cases))
}

func TestTranslationValidationCheckerGaps(t *testing.T) {
	t.Run("site-call-target", func(t *testing.T) {
		c := newEquivCase(1)
		work := c.spec()
		in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
		injectcheck.Label(work.Programs["p"].Instructions)
		req := c.request("typed-any")
		plan, err := transformLookup(work, req)
		if err != nil {
			t.Fatal(err)
		}
		out := work.Programs["p"].Instructions
		cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
		withoutTargets := premises
		withoutTargets.Targets = nil
		_, err = injectcheck.Check(in, out, cert, withoutTargets)
		var input *injectcheck.InputError
		if !errors.As(err, &input) || input.Kind != injectcheck.InputTargetMissing {
			t.Fatal("checker accepted inserted calls without planned targets")
		}
		bad := append(asm.Instructions(nil), out...)
		changed := false
		for _, hook := range plan.hooks {
			if hook.When != string(LookupHit) {
				continue
			}
			for i, ins := range bad {
				if ins.IsFunctionCall() && ins.Reference() == hook.Name {
					bad[i] = ins.WithReference(hook.Name + "_miss")
					changed = true
					break
				}
			}
			if changed {
				break
			}
		}
		if !changed {
			t.Fatal("fixture has no typed hit/miss hook call")
		}
		_, err = injectcheck.Check(in, bad, cert, premises)
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CallTarget {
			t.Fatal("checker accepted a site call retargeted to another generated hook")
		}
	})

	t.Run("generic-argument-conditions", func(t *testing.T) {
		c := newEquivCase(8)
		work := c.spec()
		in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
		injectcheck.Label(work.Programs["p"].Instructions)
		req := c.request("typed-any")
		plan, err := transformLookup(work, req)
		if err != nil {
			t.Fatal(err)
		}
		var site LookupSite
		hookName := ""
		for _, hook := range plan.hooks {
			if hook.Generic && hook.Kind == HookLookup {
				hookName = hook.Name
				if len(hook.Sites) > 0 {
					site = hook.Sites[0]
				}
				break
			}
		}
		out := work.Programs["p"].Instructions
		cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
		start, end := cert.Original[site.InstructionIndex], cert.Original[site.InstructionIndex+1]
		call, r1, r3, r4, r5 := -1, -1, -1, -1, -1
		for i := start + 1; i < end; i++ {
			ins := out[i]
			if ins.IsFunctionCall() && ins.Reference() == hookName {
				call = i
				break
			}
			if ins.OpCode.Class() == asm.LdXClass {
				switch ins.Dst {
				case asm.R1:
					r1 = i
				case asm.R3:
					r3 = i
				case asm.R5:
					r5 = i
				}
			}
			if ins.OpCode.ALUOp() == asm.Mov && ins.Dst == asm.R4 {
				r4 = i
			}
		}
		if call < 0 || r1 < 0 || r3 < 0 || r4 < 0 || r5 < 0 {
			t.Fatalf("generic call shape not found: call=%d r1=%d r3=%d r4=%d r5=%d", call, r1, r3, r4, r5)
		}
		for _, tc := range []struct {
			name   string
			mutate func(asm.Instructions)
		}{
			{"R1", func(bad asm.Instructions) { bad[r1].Offset = bad[r3].Offset }},
			{"R3", func(bad asm.Instructions) { bad[r3].Offset = bad[r5].Offset }},
			{"R4", func(bad asm.Instructions) { bad[r4] = asm.Mov.Imm(asm.R4, 0) }},
			{"R5", func(bad asm.Instructions) { bad[r5].Offset = bad[r3].Offset }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				bad := append(asm.Instructions(nil), out...)
				tc.mutate(bad)
				_, err := injectcheck.Check(in, bad, cert, premises)
				var rejection *injectcheck.Rejection
				if !errors.As(err, &rejection) || rejection.Kind != injectcheck.HookArguments {
					t.Fatalf("checker accepted wrong %s provenance: %v", tc.name, err)
				}
			})
		}
	})

	t.Run("static-body", func(t *testing.T) {
		c := newEquivCase(8)
		work := c.spec()
		in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
		injectcheck.Label(work.Programs["p"].Instructions)
		req := c.request("static-any")
		plan, err := transformLookup(work, req)
		if err != nil {
			t.Fatal(err)
		}
		var site LookupSite
		for _, candidate := range plan.sites {
			if candidate.Generic && candidate.Op == HookLookup {
				site = candidate
				break
			}
		}
		if !site.Generic {
			t.Fatal("fixture has no static generic lookup site")
		}
		hookName := ""
		for _, hook := range plan.hooks {
			if hook.Generic && hook.Kind == HookLookup {
				hookName = hook.Name
				break
			}
		}
		out := work.Programs["p"].Instructions
		cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
		bad := append(asm.Instructions(nil), out...)
		start := cert.Original[site.InstructionIndex]
		end := cert.Original[site.InstructionIndex+1]
		call, key, mapArg := -1, -1, -1
		for i := start + 1; i < end; i++ {
			ins := bad[i]
			if ins.IsFunctionCall() && ins.Reference() == hookName {
				call = i
				break
			}
		}
		for i := start + 1; i < call; i++ {
			ins := bad[i]
			if ins.OpCode.Class() == asm.LdXClass && ins.Dst == asm.R3 {
				key = i
			}
			if ins.OpCode.Class() == asm.LdXClass && ins.Dst == asm.R5 {
				mapArg = i
			}
		}
		if call < 0 || key < 0 || mapArg < 0 {
			t.Fatalf("generic call shape not found: call=%d key=%d map=%d", call, key, mapArg)
		}
		bad[mapArg].Offset = bad[key].Offset
		_, err = injectcheck.Check(in, bad, cert, premises)
		var rejection *injectcheck.Rejection
		if !errors.As(err, &rejection) || rejection.Kind != injectcheck.HookArguments {
			t.Fatal("checker accepted wrong static-body map argument")
		}
	})
}

func genericArgumentFixture(t *testing.T, seed uint64, kind HookKind) (asm.Instructions, asm.Instructions, injectcheck.Certificate, injectcheck.Premises, int) {
	t.Helper()
	c := newEquivCase(seed)
	work := c.spec()
	in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
	injectcheck.Label(work.Programs["p"].Instructions)
	req := c.request("dispatch-static")
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	var selected LookupHook
	for _, hook := range plan.hooks {
		if hook.Kind == kind && hook.Dispatch && len(hook.Sites) != 0 {
			selected = hook
			break
		}
	}
	if len(selected.Sites) == 0 {
		t.Fatalf("seed %d has no dispatch %s site", seed, kind)
	}
	out := work.Programs["p"].Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
	site := selected.Sites[0].InstructionIndex
	for i := cert.Original[site] + 1; i < cert.Original[site+1]; i++ {
		if out[i].IsFunctionCall() && out[i].Reference() == selected.Name {
			return in, out, cert, premises, i
		}
	}
	t.Fatalf("seed %d has no dispatch %s hook call", seed, kind)
	return nil, nil, injectcheck.Certificate{}, injectcheck.Premises{}, 0
}

func TestTranslationValidationMapCallArgumentConditions(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed uint64
		kind HookKind
	}{
		{"update", 11, HookUpdate},
		{"delete", 15, HookDelete},
		{"push", 2, HookPush},
		{"pop", 10, HookPop},
		{"peek", 1, HookPeek},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out, cert, premises, call := genericArgumentFixture(t, tc.seed, tc.kind)
			for _, reg := range []asm.Register{asm.R3, asm.R4} {
				t.Run(reg.String(), func(t *testing.T) {
					bad := append(asm.Instructions(nil), out...)
					definition := -1
					for i := cert.Original[findOriginalSite(cert, call)] + 1; i < call; i++ {
						if !bad[i].OpCode.Class().IsJump() && bad[i].Dst == reg {
							definition = i
						}
					}
					if definition < 0 {
						t.Fatalf("%s has no R%d definition", tc.kind, reg)
					}
					bad[definition] = asm.Mov.Reg(reg, asm.R1)
					_, err := injectcheck.Check(in, bad, cert, premises)
					var rejection *injectcheck.Rejection
					if !errors.As(err, &rejection) || rejection.Kind != injectcheck.HookArguments {
						t.Fatalf("checker accepted wrong %s R%d provenance: %v", tc.kind, reg, err)
					}
				})
			}
		})
	}
}

func findOriginalSite(cert injectcheck.Certificate, call int) int {
	site := -1
	for i, at := range cert.Original {
		if at >= call {
			break
		}
		site = i
	}
	return site
}

func TestTranslationValidationPlannedLookupArms(t *testing.T) {
	for _, config := range []string{"typed-any", "dispatch-any"} {
		t.Run(config, func(t *testing.T) {
			c := newEquivCase(1)
			work := c.spec()
			in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
			injectcheck.Label(work.Programs["p"].Instructions)
			req := c.request(config)
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			out := work.Programs["p"].Instructions
			cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
			site, jump, restore := -1, -1, -1
			for i, ins := range in {
				if !ins.IsBuiltinCall() || (asm.BuiltinFunc(ins.Constant) != asm.FnMapLookupElem && asm.BuiltinFunc(ins.Constant) != asm.FnMapLookupPercpuElem) {
					continue
				}
				start, end := cert.Original[i], cert.Original[i+1]
				calls := 0
				for j := start + 1; j < end; j++ {
					if out[j].IsFunctionCall() {
						calls++
					}
					if out[j].OpCode.Class() == asm.JumpClass && out[j].OpCode.JumpOp() == asm.Ja {
						jump = j
					}
				}
				if calls == 2 && jump >= 0 {
					site, restore = i, end-1
					break
				}
			}
			if site < 0 {
				t.Fatal("fixture has no two-arm lookup")
			}
			bad := append(asm.Instructions(nil), out...)
			mutated := cert
			mutated.Original = append([]int(nil), cert.Original...)
			mutated.Hooks = append([]injectcheck.Span(nil), cert.Hooks...)
			for range restore - jump {
				bad = validationDelete(bad, jump)
				for i, at := range mutated.Original {
					if at > jump {
						mutated.Original[i]--
					}
				}
				for i, h := range mutated.Hooks {
					if h.Start > jump {
						mutated.Hooks[i].Start--
						mutated.Hooks[i].End--
					}
				}
			}
			targets, err := BuildLookupTargets(bad, plan.hooks)
			if err != nil {
				t.Fatal(err)
			}
			premises.Targets = targets
			_, err = injectcheck.Check(in, bad, mutated, premises)
			var rejection *injectcheck.Rejection
			if !errors.As(err, &rejection) || rejection.Kind != injectcheck.CallTarget {
				t.Fatalf("checker accepted dropped lookup arm at site %d: %v", site, err)
			}
		})
	}
}

func TestTranslationValidationErrorAndSuccessArms(t *testing.T) {
	c := newEquivCase(1)
	work := c.spec()
	in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
	injectcheck.Label(work.Programs["p"].Instructions)
	req := c.request("typed-error")
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	out := work.Programs["p"].Instructions
	cert, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
	if _, err := injectcheck.Check(in, out, cert, premises); err != nil {
		t.Fatalf("checker confused the error and success arms: %v", err)
	}
}

func TestTranslationValidationNullArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed uint64
		kind HookKind
		reg  asm.Register
	}{
		{"delete-R4", 15, HookDelete, asm.R4},
		{"keyless-R3", 2, HookPush, asm.R3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out, cert, premises, call := genericArgumentFixture(t, tc.seed, tc.kind)
			bad := append(asm.Instructions(nil), out...)
			changed := false
			for i := call - 1; i > cert.Original[findOriginalSite(cert, call)]; i-- {
				ins := bad[i]
				if ins.Dst == tc.reg && ins.OpCode.Class() == asm.ALU64Class && ins.OpCode.ALUOp() == asm.Mov && ins.OpCode.Source() == asm.ImmSource && ins.Constant == 0 {
					bad[i].Constant = 0x1000
					changed = true
					break
				}
			}
			if !changed {
				t.Fatalf("%s has no NULL R%d definition", tc.kind, tc.reg)
			}
			_, err := injectcheck.Check(in, bad, cert, premises)
			var rejection *injectcheck.Rejection
			if !errors.As(err, &rejection) || rejection.Kind != injectcheck.HookArguments {
				t.Fatalf("checker accepted non-NULL %s R%d: %v", tc.kind, tc.reg, err)
			}
		})
	}
}

// validationDelete repairs numeric edges crossing a deleted single-slot
// instruction. Correspondence hints are repaired separately by each mutation.
func validationDelete(is asm.Instructions, at int) asm.Instructions {
	removedPC := 0
	for _, x := range is[:at] {
		removedPC += int(x.Size() / asm.InstructionSize)
	}
	pc := 0
	for i, x := range is {
		cl, op := x.OpCode.Class(), x.OpCode.JumpOp()
		if x.Reference() == "" && (x.IsFunctionReference() || cl.IsJump() && op != asm.Call && op != asm.Exit) {
			delta := int(x.Offset)
			constant := x.IsFunctionReference() || cl == asm.Jump32Class && op == asm.Ja
			if constant {
				delta = int(x.Constant)
			}
			target := pc + 1 + delta
			if pc < removedPC && target > removedPC {
				delta--
			}
			if pc > removedPC && target <= removedPC {
				delta++
			}
			if constant {
				is[i].Constant = int64(delta)
			} else {
				is[i].Offset = int16(delta)
			}
		}
		pc += int(x.Size() / asm.InstructionSize)
	}
	return append(is[:at:at], is[at+1:]...)
}

func stackSpillForValidation(i asm.Instruction) bool {
	return i.OpCode == asm.StoreMem(asm.RFP, 0, asm.R0, asm.DWord).OpCode && i.Dst == asm.RFP
}

func validationStream(is asm.Instructions) injectcheck.Instructions {
	// Census artefacts deliberately save the compared instruction projection.
	// Check above separately enforces in-memory load-time metadata identity.
	out := make(injectcheck.Instructions, len(is))
	for i, ins := range is {
		out[i] = ins
		out[i].Metadata = asm.Metadata{}
		out[i] = out[i].WithSymbol(ins.Symbol()).WithReference(ins.Reference())
	}
	return out
}
func validationSites(hooks []LookupHook) int {
	sites := map[uint32]bool{}
	for _, h := range hooks {
		for _, s := range h.Sites {
			sites[s.SitePC] = true
		}
	}
	return len(sites)
}

func TestTranslationValidationSubprogramTail(t *testing.T) {
	for _, dispatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("dispatch=%t", dispatch), func(t *testing.T) {
			work := subTailCallerFixture()
			in := append(asm.Instructions(nil), work.Programs["caller"].Instructions...)
			injectcheck.Label(work.Programs["caller"].Instructions)
			req := LookupRequest{ProgramName: "caller", TailCalls: true, Dispatch: dispatch, HookName: "obs", Stack: StackAudit{LowestOffset: 0}}
			plan, err := transformLookup(work, req)
			if err != nil {
				t.Fatal(err)
			}
			out := work.Programs["caller"].Instructions
			c, premises := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
			if _, err := injectcheck.Check(in, out, c, premises); err != nil {
				t.Fatal(err)
			}
			if dispatch {
				call := -1
				for i, ins := range out {
					if ins.IsFunctionCall() && ins.Reference() == "obs" {
						call = i
					}
				}
				if call < 2 {
					t.Fatal("dispatch tail fixture has no hook call")
				}
				for _, reg := range []asm.Register{asm.R3, asm.R4, asm.R5} {
					bad := append(asm.Instructions(nil), out...)
					for i := call - 1; i >= 0; i-- {
						if bad[i].Dst == reg {
							source := asm.R3
							if reg == asm.R3 {
								source = asm.R1
							}
							bad[i] = asm.Mov.Reg(reg, source)
							break
						}
					}
					_, err := injectcheck.Check(in, bad, c, premises)
					var rejection *injectcheck.Rejection
					if !errors.As(err, &rejection) || rejection.Kind != injectcheck.HookArguments {
						t.Fatalf("dispatch tail R%d: %v", reg, err)
					}
				}
				t.Run("R4-must-be-NULL", func(t *testing.T) {
					bad := append(asm.Instructions(nil), out...)
					changed := false
					for i := call - 1; i >= 0; i-- {
						ins := bad[i]
						if ins.Dst == asm.R4 && ins.OpCode.Class() == asm.ALU64Class && ins.OpCode.ALUOp() == asm.Mov && ins.OpCode.Source() == asm.ImmSource && ins.Constant == 0 {
							bad[i].Constant = 0x1000
							changed = true
							break
						}
					}
					if !changed {
						t.Fatal("dispatch tail fixture has no NULL R4 definition")
					}
					_, err := injectcheck.Check(in, bad, c, premises)
					var rejection *injectcheck.Rejection
					if !errors.As(err, &rejection) || rejection.Kind != injectcheck.HookArguments {
						t.Fatalf("dispatch tail non-NULL R4: %v", err)
					}
				})
			}
			// The entry frame's ctx spill must not initialize the subprogram
			// frame: dropping its localCtx spill leaves the postlude load invalid.
			removed := false
			for j, ins := range out {
				if j > c.Original[1] && stackSpillForValidation(ins) && ins.Src == asm.R1 && ins.Offset == -8 {
					out = validationDelete(out, j)
					removed = true
					break
				}
			}
			if !removed {
				t.Fatal("fixture requires a local ctx spill")
			}
			c, premises = validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
			_, err = injectcheck.Check(in, out, c, premises)
			var rejection *injectcheck.Rejection
			if !errors.As(err, &rejection) || rejection.Kind != injectcheck.SpillUninitialized {
				t.Fatalf("missing subprogram ctx spill: %v", err)
			} else {
				t.Logf("missing subprogram ctx spill rejected: %v", err)
			}
			changed := false
			for j, ins := range out {
				if j > c.Original[1] && ins.OpCode.Class() == asm.LdXClass && ins.Dst == asm.R1 && ins.Src == asm.RFP && ins.Offset == -8 {
					out[j].Offset = -16
					changed = true
				}
			}
			if !changed {
				t.Fatal("fixture has no postlude context reload")
			}
			_, err = injectcheck.Check(in, out, c, premises)
			if !errors.As(err, &rejection) || rejection.Kind != injectcheck.HookArguments {
				t.Fatalf("missing context slot did not fail closed: %v", err)
			}
		})
	}
}

func TestTranslationValidationU32Fixture(t *testing.T) {
	work := buildTarget(7)
	in := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
	injectcheck.Label(work.Programs["p"].Instructions)
	req := shapeReq(kernelSitePC)
	if err := transform(work, req); err != nil {
		t.Fatal(err)
	}
	out := work.Programs["p"].Instructions
	site, pc := -1, uint32(0)
	for i, ins := range in {
		if pc == req.SitePC {
			site = i
			break
		}
		pc += uint32(ins.Size() / asm.InstructionSize)
	}
	if site < 0 {
		t.Fatalf("raw site PC %d is not an instruction", req.SitePC)
	}
	c, premises := validationCertificate(t, in, out, []LookupHook{{
		Name: req.HookName, Kind: HookLookup, When: string(LookupAny),
		Sites: []LookupSite{{InstructionIndex: site}},
	}}, req.Stack.LowestOffset)
	if _, err := injectcheck.Check(in, out, c, premises); err != nil {
		t.Fatal(err)
	}
}

func validationPair(in, out asm.Instructions, c injectcheck.Certificate, premises injectcheck.Premises) injectcheck.Pair {
	return injectcheck.Pair{Format: injectcheck.FormatVersion, Original: validationStream(in), Transformed: validationStream(out), Certificate: c, Premises: premises}
}
func validationPairEvidence(t *testing.T, in, out asm.Instructions, c injectcheck.Certificate, premises injectcheck.Premises, request, result any, reason string) injectcheck.Pair {
	t.Helper()
	p := validationPair(in, out, c, premises)
	var err error
	if request != nil {
		p.Request, err = json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
	}
	if result != nil {
		p.Result, err = json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
	}
	p.Reason = reason
	return p
}

func TestIndirectJumpRefused(t *testing.T) {
	spec := lookupFixture()
	p := spec.Programs["p"]
	p.Instructions = append(p.Instructions, asm.Instruction{OpCode: asm.Ja.Op(asm.RegSource), Dst: asm.R3}, asm.Return())
	raw := rawLookupFixture(t, spec, "p", false)
	req := LookupRequestRaw{Site: LookupSelector{MapName: "sessions"}, HookName: "h", Stack: StackAudit{LowestOffset: -8}}
	if _, err := TransformLookupRaw(raw, req); err == nil || !strings.Contains(err.Error(), "indirect jump at 17") {
		t.Fatalf("transform: %v", err)
	}
	if _, err := DiscoverMapCallsRaw(raw); err == nil || !strings.Contains(err.Error(), "indirect jump at 17") {
		t.Fatalf("discovery: %v", err)
	}
	if pc, ok := IndirectJump(raw.Instructions); !ok || pc != 17 {
		t.Fatalf("IndirectJump = %d, %v", pc, ok)
	}
}
