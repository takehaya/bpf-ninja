package inject

import (
	"bytes"
	"encoding/json"
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
func validationCertificate(t *testing.T, in, out asm.Instructions, hooks []LookupHook, floor int16) injectcheck.Certificate {
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
	c, e := injectcheck.FromLabels(out, len(in), spans, floor)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestTranslationValidationEquivalence(t *testing.T) {
	total, accepted, sites := 0, 0, 0
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
					t.Logf("TRANSFORM_REFUSED %v", e)
					return
				}
				out := work.Programs["p"].Instructions
				cert := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
				n, e := injectcheck.Check(in, out, cert)
				if e != nil {
					t.Fatal(e)
				}
				accepted++
				sites += n.Sites
				t.Logf("CHECK accepted original=%d sites=%d hooks=%d", n.Instructions, n.Sites, n.Hooks)
			})
		}
	}
	t.Logf("VALIDATION attempted=%d accepted=%d sites=%d", total, accepted, sites)
}

type validationRow struct {
	Object, Program, Form, Status, Reason                  string
	Sites, Hooks, Instructions, PlannedSites, SkippedSites int
	Floor                                                  int16
}

// Opt-in corpus checking does no loading or attaching. Census floors are taken
// from the recorded plain-program stack bounds; they remain caller audits.
func TestTranslationValidationCensus(t *testing.T) {
	root := os.Getenv("BPF_NINJA_VALIDATE_OBJECTS")
	if root == "" {
		t.Skip("set BPF_NINJA_VALIDATE_OBJECTS and BPF_NINJA_VALIDATE_OUTPUT")
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
			if b, e := os.ReadFile(boundFile); e == nil {
				var r struct{ Bound int16 }
				if e = json.Unmarshal(b, &r); e != nil {
					t.Fatal(e)
				}
				floor = r.Bound
			}
			for _, ins := range src.Programs[name].Instructions {
				cl := ins.OpCode.Class()
				if cl == asm.LdXClass && ins.Src == asm.RFP || (cl == asm.StClass || cl == asm.StXClass) && ins.Dst == asm.RFP {
					floor = min(floor, ins.Offset)
				}
			}
			for _, form := range []string{"typed", "static"} {
				r := validationRow{Object: filepath.Base(file), Program: name, Form: form, Floor: floor}
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
					continue
				}
				r.PlannedSites = validationSites(plan.hooks)
				r.SkippedSites = len(plan.skipped)
				out := work.Programs[name].Instructions
				cert := validationCertificate(t, in, out, plan.hooks, floor)
				counts, e := injectcheck.Check(in, out, cert)
				r.Sites = counts.Sites
				r.Hooks = counts.Hooks
				r.Instructions = counts.Instructions
				r.Status = "ACCEPTED"
				if e != nil {
					r.Status = "REJECTED"
					r.Reason = e.Error()
				}
				stem := filepath.Base(file) + "--" + name + "--" + form
				validationSave(t, filepath.Join(dest, stem+".json"), map[string]any{"request": req, "certificate": cert, "original": validationStream(in), "transformed": validationStream(out), "result": r})
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
				r.Form = "raw-" + form
				if e != nil {
					r.Status = "TRANSFORM_REFUSED"
					r.Reason = e.Error()
					rows = append(rows, r)
					continue
				}
				cert = validationCertificate(t, raw.Instructions, result.Instructions, result.Hooks, floor)
				counts, e = injectcheck.Check(raw.Instructions, result.Instructions, cert)
				r.Status = "ACCEPTED"
				r.Reason = ""
				r.Sites = counts.Sites
				r.Hooks = counts.Hooks
				if e != nil {
					r.Status = "REJECTED"
					r.Reason = e.Error()
				}
				validationSave(t, filepath.Join(dest, stem+"--raw.json"), map[string]any{"certificate": cert, "original": validationStream(raw.Instructions), "transformed": validationStream(result.Instructions), "result": r})
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
	t.Logf("CORPUS rows=%d checker_rejected=%d", len(rows), rejected)
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
	cert := validationCertificate(t, in, out, plan.hooks, req.Stack.LowestOffset)
	if _, e = injectcheck.Check(in, out, cert); e != nil {
		t.Fatal(e)
	}
	// Mutate code and independently repair correspondence hints where needed;
	// detection must come from checking semantics/patterns, not stale indices.
	cases := []string{"live-register", "drop-original", "wrong-jump", "hook-store", "missing-restore", "wrong-spill", "helper-in-hook", "forged-certificate", "map-swap", "map-fd-value-swap", "ldimm64-pseudo-kind"}
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
						if _, err := injectcheck.Check(original, bad, cc); err != nil {
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
			case "live-register":
				for i, x := range bad {
					if i > cc.Original[0] && x.IsFunctionCall() && strings.HasPrefix(x.Reference(), "eq_") {
						bad[i-1] = asm.Mov.Imm(asm.R6, 0)
						break
					}
				}
			case "drop-original":
				at := cc.Original[1]
				bad = append(bad[:at:at], bad[at+1:]...)
				for i, j := range cc.Original {
					if j == at {
						cc.Original[i] = -1
					} else if j > at {
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
				for i, x := range bad {
					if stackSpillForValidation(x) {
						bad[i].Offset = 0
						break
					}
				}
			case "helper-in-hook":
				bad[cc.Hooks[0].Start] = asm.FnGetPrandomU32.Call()
			case "forged-certificate":
				cc.Original[1] = cc.Original[0]
			}
			_, err := injectcheck.Check(original, bad, cc)
			if dest := os.Getenv("BPF_NINJA_VALIDATE_OUTPUT"); dest != "" {
				if e := os.MkdirAll(dest, 0755); e != nil {
					t.Fatal(e)
				}
				reason := ""
				if err != nil {
					reason = err.Error()
				}
				validationSave(t, filepath.Join(dest, "mutation-"+kind+".json"), map[string]any{"original": validationStream(original), "transformed": validationStream(bad), "certificate": cc, "reason": reason})
			}
			if err == nil {
				t.Fatal("SURVIVED")
			} else {
				killed++
				t.Logf("KILLED %s: %v", kind, err)
			}
		})
	}
	t.Logf("MUTATION killed=%d total=%d", killed, len(cases))
}
func stackSpillForValidation(i asm.Instruction) bool {
	return i.OpCode == asm.StoreMem(asm.RFP, 0, asm.R0, asm.DWord).OpCode && i.Dst == asm.RFP
}

func validationStream(is asm.Instructions) injectcheck.Instructions {
	return injectcheck.Instructions(is)
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
			c := validationCertificate(t, in, out, plan.hooks, 0)
			if _, err := injectcheck.Check(in, out, c); err != nil {
				t.Fatal(err)
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
	c := validationCertificate(t, in, out, []LookupHook{{Name: req.HookName}}, req.Stack.LowestOffset)
	if _, err := injectcheck.Check(in, out, c); err != nil {
		t.Fatal(err)
	}
}
