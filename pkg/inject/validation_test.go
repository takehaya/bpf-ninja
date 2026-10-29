package inject

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
func validationCertificate(t *testing.T, in, out asm.Instructions, hooks []LookupHook) injectcheck.Certificate {
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
	return c
}

func TestTranslationValidationEquivalence(t *testing.T) {
	total, accepted, sites, zeroSites := 0, 0, 0, 0
	for _, seed := range equivDefaultSeeds {
		for _, config := range []string{"typed-any", "typed-error", "typed-miss", "static-any", "dispatch-any", "dispatch-static", "copy-readonly"} {
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
				cert := validationCertificate(t, in, out, plan.hooks)
				n, e := injectcheck.Check(in, out, cert, injectcheck.Premises{LowestOffset: req.Stack.LowestOffset})
				if e != nil {
					t.Fatal(e)
				}
				if n.Sites != validationSites(plan.hooks) || n.Hooks != len(cert.Hooks) {
					t.Fatalf("checked sites/hooks %d/%d, planned %d/%d", n.Sites, n.Hooks, validationSites(plan.hooks), len(cert.Hooks))
				}
				if n.Sites == 0 {
					zeroSites++
				}
				if dest := os.Getenv("BPF_NINJA_VALIDATE_OUTPUT"); dest != "" {
					if err := os.MkdirAll(dest, 0755); err != nil {
						t.Fatal(err)
					}
					validationSave(t, filepath.Join(dest, fmt.Sprintf("fixture-%d-%s.json", seed, config)), validationPair(in, out, cert, req.Stack.LowestOffset))
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
				cert := validationCertificate(t, in, out, plan.hooks)
				counts, e := injectcheck.Check(in, out, cert, injectcheck.Premises{LowestOffset: req.Stack.LowestOffset})
				if e == nil && (counts.Sites != r.PlannedSites || counts.Hooks != len(cert.Hooks)) {
					t.Fatalf("checked %d/%d planned %d/%d", counts.Sites, counts.Hooks, r.PlannedSites, len(cert.Hooks))
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
				validationSave(t, filepath.Join(dest, stem+".json"), validationPairEvidence(t, in, out, cert, floor, req, r, ""))
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
				cert = validationCertificate(t, raw.Instructions, result.Instructions, result.Hooks)
				counts, e = injectcheck.Check(raw.Instructions, result.Instructions, cert, injectcheck.Premises{LowestOffset: floor})
				r.Status = "ACCEPTED"
				r.Reason = ""
				if e == nil && (counts.Sites != r.PlannedSites || counts.Hooks != len(cert.Hooks)) {
					t.Fatalf("checked %d/%d planned %d/%d", counts.Sites, counts.Hooks, r.PlannedSites, len(cert.Hooks))
				}
				r.Sites = counts.Sites
				r.Hooks = counts.Hooks
				r.Instructions = counts.Instructions
				if e != nil {
					r.Status = "REJECTED"
					r.Reason = e.Error()
				}
				validationSave(t, filepath.Join(dest, stem+"--raw.json"), validationPairEvidence(t, raw.Instructions, result.Instructions, cert, floor, rr, r, ""))
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
	cert := validationCertificate(t, in, out, plan.hooks)
	if _, e = injectcheck.Check(in, out, cert, injectcheck.Premises{LowestOffset: req.Stack.LowestOffset}); e != nil {
		t.Fatal(e)
	}
	// Mutate code and independently repair correspondence hints where needed;
	// Each assertion below identifies the rejecting check, including instruction
	// comparison for a complete, increasing but forged correspondence.
	cases := []string{"callee-saved-clobber", "drop-original", "wrong-jump", "hook-store", "missing-restore", "wrong-spill", "helper-in-hook", "forged-certificate", "map-swap", "map-fd-value-swap", "ldimm64-pseudo-kind"}
	killed := 0
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			original := append(asm.Instructions(nil), in...)
			bad := append(asm.Instructions(nil), out...)
			cc := cert
			cc.Original = append([]int(nil), cert.Original...)
			cc.Hooks = append([]injectcheck.Span(nil), cert.Hooks...)
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
						if _, err := injectcheck.Check(original, bad, cc, injectcheck.Premises{LowestOffset: req.Stack.LowestOffset}); err != nil {
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
			_, err := injectcheck.Check(original, bad, cc, injectcheck.Premises{LowestOffset: req.Stack.LowestOffset})
			if dest := os.Getenv("BPF_NINJA_VALIDATE_OUTPUT"); dest != "" {
				if e := os.MkdirAll(dest, 0755); e != nil {
					t.Fatal(e)
				}
				reason := ""
				if err != nil {
					reason = err.Error()
				}
				validationSave(t, filepath.Join(dest, "mutation-"+kind+".json"), validationPairEvidence(t, original, bad, cc, req.Stack.LowestOffset, nil, nil, reason))
			}
			if err == nil {
				t.Fatal("SURVIVED")
			} else {
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
			c := validationCertificate(t, in, out, plan.hooks)
			if _, err := injectcheck.Check(in, out, c, injectcheck.Premises{LowestOffset: req.Stack.LowestOffset}); err != nil {
				t.Fatal(err)
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
			c = validationCertificate(t, in, out, plan.hooks)
			_, err = injectcheck.Check(in, out, c, injectcheck.Premises{LowestOffset: req.Stack.LowestOffset})
			var rejection *injectcheck.Rejection
			if !errors.As(err, &rejection) || rejection.Kind != injectcheck.SpillUninitialized {
				t.Fatalf("missing subprogram ctx spill: %v", err)
			} else {
				t.Logf("missing subprogram ctx spill rejected: %v", err)
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
	c := validationCertificate(t, in, out, []LookupHook{{Name: req.HookName}})
	if _, err := injectcheck.Check(in, out, c, injectcheck.Premises{LowestOffset: req.Stack.LowestOffset}); err != nil {
		t.Fatal(err)
	}
}

func validationPair(in, out asm.Instructions, c injectcheck.Certificate, floor int16) injectcheck.Pair {
	return injectcheck.Pair{Format: injectcheck.FormatVersion, Original: validationStream(in), Transformed: validationStream(out), Certificate: c, Premises: injectcheck.Premises{LowestOffset: floor}}
}
func validationPairEvidence(t *testing.T, in, out asm.Instructions, c injectcheck.Certificate, floor int16, request, result any, reason string) injectcheck.Pair {
	t.Helper()
	p := validationPair(in, out, c, floor)
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
