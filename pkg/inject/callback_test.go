package inject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func callbackLoad(dst asm.Register, offset int64, ref string) asm.Instruction {
	ins := asm.LoadImm(dst, offset, asm.DWord).WithReference(ref)
	ins.Src = asm.PseudoFunc
	return ins
}

func callbackHead(name string) asm.Instruction {
	return btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R2, 0, asm.DWord).
		WithSymbol(name).WithSource(asm.Comment("callback fixture")), &btf.Func{
		Name: name, Linkage: btf.StaticFunc, Type: &btf.FuncProto{
			Return: &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed},
			Params: []btf.FuncParam{
				{Name: "index", Type: &btf.Int{Name: "u32", Size: 4}},
				{Name: "data", Type: &btf.Pointer{Target: &btf.Void{}}},
			},
		},
	})
}

func TestCallbackClassification(t *testing.T) {
	input := asm.Instructions{asm.Return().WithSymbol("entry"), callbackLoad(asm.R2, -1, "cb"), asm.Return(), callbackHead("cb"), asm.Return()}
	indices := map[int]int{0: 0, 1: 1, 3: 2, 4: 3, 5: 4}
	for _, tc := range []struct {
		name     string
		ins      asm.Instruction
		relative bool
	}{
		{"symbolic", input[1], false},
		{"numeric", callbackLoad(asm.R2, 2, ""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.ins
			target, relative, function, err := relocTarget(&tc.ins, 1, indices, input)
			if err != nil || target != 4 || relative != tc.relative || !function || !reflect.DeepEqual(before, tc.ins) {
				t.Fatalf("target=%d relative=%v function=%v err=%v", target, relative, function, err)
			}
		})
	}
	// Ordinary immediates, even with the same value, must not be relocated.
	imm := asm.LoadImm(asm.R2, 2, asm.DWord)
	if _, relative, _, err := relocTarget(&imm, 1, indices, input); err != nil || relative {
		t.Fatalf("ordinary immediate: %v", err)
	}
}

func TestCallbackRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(asm.Instructions)
	}{
		{"missing-symbol", "definitions", func(i asm.Instructions) { i[1] = i[1].WithReference("absent") }},
		{"duplicate-symbol", "definitions", func(i asm.Instructions) { i[2] = i[2].WithSymbol("cb") }},
		{"resolved-symbol", "already resolved", func(i asm.Instructions) { i[1].Constant = 2 }},
		{"entry-symbol", "subprogram start", func(i asm.Instructions) { i[1] = i[1].WithReference("p") }},
		{"entry-numeric", "subprogram start", func(i asm.Instructions) { i[1] = callbackLoad(asm.R2, -2, "") }},
		{"middle-of-function", "subprogram start", func(i asm.Instructions) { i[1] = callbackLoad(asm.R2, 3, "") }},
		{"missing-btf", "subprogram start", func(i asm.Instructions) { i[3] = btf.WithFuncMetadata(i[3], nil) }},
		{"continuation", "instruction boundary", func(i asm.Instructions) { i[1] = callbackLoad(asm.R2, 0, "") }},
		{"past-end", "instruction boundary", func(i asm.Instructions) { i[1] = callbackLoad(asm.R2, 4, "") }},
		{"before-start", "instruction boundary", func(i asm.Instructions) { i[1] = callbackLoad(asm.R2, -3, "") }},
		{"upper-half", "malformed", func(i asm.Instructions) { i[1] = callbackLoad(asm.R2, 1<<32|2, "") }},
		{"underflow", "malformed", func(i asm.Instructions) { i[1] = callbackLoad(asm.R2, math.MinInt32-1, "") }},
		{"nonzero-offset", "malformed", func(i asm.Instructions) { i[1].Offset = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := asm.Instructions{asm.Return().WithSymbol("p"), callbackLoad(asm.R2, -1, "cb"), asm.Return(), callbackHead("cb"), asm.Return()}
			tc.change(input)
			before := append(asm.Instructions(nil), input...)
			_, _, _, err := relocTarget(&input[1], 1, map[int]int{0: 0, 1: 1, 3: 2, 4: 3, 5: 4}, input)
			if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want %q refusal, got %v", tc.reason, err)
			}
			spec := lookupFixture()
			// Keep the valid entry lookup and append the malformed callback stream.
			// Full transform checks must also refuse without publishing any changes.
			spec.Programs["p"].Instructions = append(spec.Programs["p"].Instructions, input[1:]...)
			original := append(asm.Instructions(nil), spec.Programs["p"].Instructions...)
			if _, err := transformLookup(spec, lookupReq()); !errors.Is(err, ErrRefused) {
				t.Fatalf("transform: %v", err)
			}
			if !reflect.DeepEqual(original, spec.Programs["p"].Instructions) || !reflect.DeepEqual(before, input) {
				t.Fatal("refusal mutated input")
			}
		})
	}
}

func TestCallbackRelocation(t *testing.T) {
	// Two function starts straddle both insertions. Loads cross them in both
	// directions; ordinary LDIMM64 also separates the raw PCs from indices.
	for _, sites := range [][]uint32{{6}, {6, 10}} {
		for _, symbolic := range []bool{false, true} {
			t.Run(fmt.Sprintf("sites=%v/symbolic=%v", sites, symbolic), func(t *testing.T) {
				forward, back := callbackLoad(asm.R2, 11, ""), callbackLoad(asm.R2, -7, "") // 0 -> 12; 8 -> 2
				if symbolic {
					forward = callbackLoad(asm.R2, -1, "late")
					back = callbackLoad(asm.R2, -1, "early")
				}
				forward = forward.WithSource(asm.Comment("forward callback load"))
				back = back.WithSource(asm.Comment("backward callback load"))
				input := asm.Instructions{forward, callbackHead("early"), asm.LoadImm(asm.R7, 123, asm.DWord), asm.Mov.Imm(asm.R0, 0), asm.FnMapLookupElem.Call(), asm.Return(), back, asm.FnMapLookupElem.Call(), asm.Return(), callbackHead("late"), asm.Return()}
				before := append(asm.Instructions(nil), input...)
				out, err := spliceLookup(input, sites, lookupReq())
				if err != nil {
					t.Fatal(err)
				}
				// Entry spill shifts everything once; each selected site adds eight slots.
				late := 13 + 8*len(sites)
				offsets := rawOffsets(out)
				for _, pair := range [][2]int{{1, late}, {17, 3}} {
					ins := offsets[pair[0]]
					if !ins.IsLoadOfFunctionPointer() {
						t.Fatalf("missing callback at %d", pair[0])
					}
					if symbolic {
						if ins.Constant != -1 || ins.Reference() == "" {
							t.Fatal("symbolic callback resolved early")
						}
					} else if got := pair[0] + 1 + int(ins.Constant); got != pair[1] {
						t.Fatalf("target=%d want=%d", got, pair[1])
					}
				}
				for _, pair := range [][2]int{{0, 1}, {6, 17}, {1, 3}, {9, late}} {
					original, relocated := input[pair[0]], offsets[pair[1]]
					if original.Source() != relocated.Source() || original.Reference() != relocated.Reference() ||
						btf.FuncMetadata(&original) != btf.FuncMetadata(&relocated) {
						t.Fatal("callback metadata changed")
					}
				}
				if !reflect.DeepEqual(before, input) {
					t.Fatal("input mutated")
				}
				// Marshal on a copy exercises the loader's symbolic resolution.
				encoded := append(asm.Instructions(nil), out...)
				// Satisfy the generated hook reference without loading BPF.
				encoded = append(encoded, asm.Return().WithSymbol(lookupReq().HookName))
				if err := encoded.Marshal(new(bytes.Buffer), binary.LittleEndian); err != nil {
					t.Fatal(err)
				}
				resolved := rawOffsets(encoded)
				for _, pair := range [][2]int{{1, late}, {17, 3}} {
					if got := pair[0] + 1 + int(resolved[pair[0]].Constant); got != pair[1] {
						t.Fatalf("loader target=%d want=%d", got, pair[1])
					}
				}
			})
		}
	}
}

func TestCallbackRelocationOverflow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pc, target int
		want       bool
	}{
		{"maximum", 0, math.MaxInt32 + 1, true}, {"positive-overflow", 0, math.MaxInt32 + 2, false},
		{"minimum", math.MaxInt32, 0, true}, {"negative-overflow", math.MaxInt32 + 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ins := callbackLoad(asm.R2, 0, "")
			before := ins
			err := relocateOffset(&ins, tc.pc, tc.target, true)
			if tc.want {
				if err != nil || ins.Constant != int64(tc.target)-int64(tc.pc)-1 {
					t.Fatalf("ins=%v err=%v", ins, err)
				}
			} else if !errors.Is(err, ErrRefused) || !reflect.DeepEqual(before, ins) {
				t.Fatalf("overflow: %v", err)
			}
		})
	}
}

func TestTransformCallbackSupport(t *testing.T) {
	for _, symbolic := range []bool{false, true} {
		spec := buildTarget(7)
		ins := spec.Programs["p"].Instructions
		// Insert a load before the u32 site; existing branch and site semantics remain.
		fp := callbackLoad(asm.R3, int64(ins.Size()/8)+1, "")
		if symbolic {
			fp = callbackLoad(asm.R3, -1, "cb")
		}
		fn := btf.FuncMetadata(&ins[0])
		fp = btf.WithFuncMetadata(fp.WithSymbol(ins[0].Symbol()).WithSource(ins[0].Source()), fn)
		ins[0] = btf.WithFuncMetadata(ins[0].WithSymbol(""), nil)
		ins = append(asm.Instructions{fp}, ins...)
		ins = append(ins, callbackHead("cb"), asm.Return())
		spec.Programs["p"].Instructions = ins
		if err := transform(spec, shapeReq(kernelSitePC+2)); err != nil {
			t.Fatal(err)
		}
		out := spec.Programs["p"].Instructions
		if symbolic {
			if out[0].Constant != -1 || out[0].Reference() != "cb" {
				t.Fatal("symbolic callback changed")
			}
		} else {
			target := 1 + int(out[0].Constant)
			if rawOffsets(out)[target].Symbol() != "cb" {
				t.Fatal("numeric callback not relocated")
			}
		}
	}
}

func TestLookupInsideCallbackRefused(t *testing.T) {
	spec := lookupFixture()
	p := spec.Programs["p"]
	p.Instructions = append(p.Instructions, callbackLoad(asm.R2, -1, "cb"), asm.Return(), callbackHead("cb"), asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(), asm.Return())
	sites, err := discoverLookups(spec, "p")
	if err != nil || len(sites) != 2 || sites[0].Reason != "" || !strings.Contains(sites[1].Reason, "another stack frame") {
		t.Fatalf("sites=%+v err=%v", sites, err)
	}
	req := lookupReq()
	req.Site.FuncName = "cb"
	if _, err := transformLookup(spec, req); !errors.Is(err, ErrRefused) {
		t.Fatalf("callback site accepted: %v", err)
	}
	req.Site.FuncName = "p"
	if _, err := transformLookup(spec, req); err != nil {
		t.Fatalf("entry site refused: %v", err)
	}
	var funcs []string
	for i := range p.Instructions {
		if fn := btf.FuncMetadata(&p.Instructions[i]); fn != nil {
			funcs = append(funcs, fn.Name)
		}
	}
	if !reflect.DeepEqual(funcs, []string{"p", req.HookName, "cb"}) {
		t.Fatalf("func_info order = %v, want [p %s cb]", funcs, req.HookName)
	}
}

func TestLookupHookPlacedBeforeSubprograms(t *testing.T) {
	for _, symbolic := range []bool{false, true} {
		spec := callbackLookupFixture(symbolic)
		req := lookupReq()
		req.Stack.LowestOffset = -16
		if _, err := transformLookup(spec, req); err != nil {
			t.Fatal(err)
		}
		out := spec.Programs["p"].Instructions
		var funcs []string
		for i := range out {
			if fn := btf.FuncMetadata(&out[i]); fn != nil {
				funcs = append(funcs, fn.Name)
			}
		}
		if !reflect.DeepEqual(funcs, []string{"p", req.HookName, "unused", "callback"}) {
			t.Fatalf("symbolic=%v: func_info order = %v", symbolic, funcs)
		}
		encoded := append(asm.Instructions(nil), out...)
		if err := encoded.Marshal(new(bytes.Buffer), binary.LittleEndian); err != nil {
			t.Fatal(err)
		}
		offsets := rawOffsets(encoded)
		for pc, ins := range offsets {
			if ins.IsLoadOfFunctionPointer() {
				target := pc + 1 + int(ins.Constant)
				if offsets[target].Symbol() != "callback" {
					t.Fatalf("symbolic=%v: callback at %d targets %d (%q)", symbolic, pc, target, offsets[target].Symbol())
				}
			}
		}
	}
}
