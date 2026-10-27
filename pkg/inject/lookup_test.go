package inject

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Map call discovery lists update and delete next to lookups, and lookup
// discovery still lists only lookups.
func TestMapCallDiscovery(t *testing.T) {
	spec := lookupFixture()
	insns := asm.Instructions{
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), // 0-1
		asm.FnMapUpdateElem.Call(),                          // 2
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), // 3-4
		asm.FnMapDeleteElem.Call(),                          // 5
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), // 6-7
		asm.FnMapLookupElem.Call(),                          // 8
		asm.FnMapUpdateElem.Call(),                          // 9: R1 clobbered
		asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol("p"), btf.FuncMetadata(&spec.Programs["p"].Instructions[0]))
	sites, err := discoverMapCalls(insns, ebpf.XDP, elfLookupMaps(spec))
	if err != nil {
		t.Fatal(err)
	}
	type got struct {
		op     HookKind
		pc     uint32
		mapNm  string
		reason string
	}
	var have []got
	for _, site := range sites {
		have = append(have, got{site.Op, site.SitePC, site.MapName, site.Reason})
	}
	want := []got{
		{HookUpdate, 2, "sessions", ""}, {HookDelete, 5, "sessions", ""}, {HookLookup, 8, "sessions", ""},
		{HookUpdate, 9, "", "R1 is not a direct map reference in this basic block"},
	}
	if !reflect.DeepEqual(have, want) {
		t.Fatalf("map calls = %+v\nwant %+v", have, want)
	}
	if sites[3].generic {
		t.Error("an update site is routed to the generic hook")
	}
	lookups, err := discoverLookupProgram(insns, ebpf.XDP, elfLookupMaps(spec))
	if err != nil || len(lookups) != 1 || lookups[0].SitePC != 8 {
		t.Fatalf("lookups = %+v, %v", lookups, err)
	}
}

func TestLookupDiscovery(t *testing.T) {
	spec := lookupFixture()
	sites, err := discoverLookups(spec, "p")
	want := []LookupSite{{Op: HookLookup, MapName: "sessions", KeyTypeName: "u32", ValueTypeName: "session",
		FuncName: "p", SitePC: 11, InstructionIndex: 10}}
	if err != nil || !reflect.DeepEqual(sites, want) {
		t.Fatalf("discovery = %+v, %v; want %+v", sites, err, want)
	}
	// Type spelling retains typedef names instead of inventing C types.
	spec.Maps["sessions"].Key = &btf.Typedef{Name: "session_key", Type: spec.Maps["sessions"].Key}
	sites, err = discoverLookups(spec, "p")
	if err != nil || sites[0].KeyTypeName != "session_key" {
		t.Fatalf("typedef: %+v, %v", sites, err)
	}
}

func TestLookupMapProvenance(t *testing.T) {
	load := asm.LoadMapPtr(asm.R1, 0).WithReference("sessions")
	lookup := asm.FnMapLookupElem.Call()
	jump := asm.JEq.Imm(asm.R0, 0, "")
	jump.Offset = 2 // jump across the two-slot map load straight to the helper
	for _, tc := range []struct {
		name     string
		body     asm.Instructions
		resolved bool
	}{
		{"direct", asm.Instructions{load, lookup}, true},
		{"key-setup", asm.Instructions{load, asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), lookup}, true},
		{"read-r1", asm.Instructions{load, asm.Mov.Reg(asm.R6, asm.R1), lookup}, true},
		{"overwrite", asm.Instructions{load, asm.Mov.Imm(asm.R1, 0), lookup}, false},
		{"arithmetic", asm.Instructions{load, asm.Add.Imm(asm.R1, 0), lookup}, false},
		{"indirect", asm.Instructions{asm.LoadMapPtr(asm.R3, 0).WithReference("sessions"), asm.Mov.Reg(asm.R1, asm.R3), lookup}, false},
		{"prior-helper", asm.Instructions{load, asm.FnGetPrandomU32.Call(), lookup}, false},
		{"join-at-helper", asm.Instructions{jump, load, lookup}, false},
		{"branch-between", asm.Instructions{load, asm.JEq.Imm(asm.R0, 0, ""), lookup}, false},
		{"no-reference", asm.Instructions{asm.LoadMapPtr(asm.R1, 0), lookup}, false},
		{"map-value", asm.Instructions{asm.LoadMapValue(asm.R1, 0, 0).WithReference("sessions"), lookup}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := lookupFixture()
			prog := spec.Programs["p"]
			prog.Instructions = append(asm.Instructions{prog.Instructions[0]}, tc.body...)
			prog.Instructions = append(prog.Instructions, asm.Return())
			sites, err := discoverLookups(spec, "p")
			if err != nil || len(sites) != 1 {
				t.Fatalf("discovery: %+v, %v", sites, err)
			}
			if (sites[0].MapName == "sessions" && sites[0].Reason == "") != tc.resolved {
				t.Fatalf("site = %+v, want resolved=%v", sites[0], tc.resolved)
			}
		})
	}
}

func TestLookupTransformCloneAndMetadata(t *testing.T) {
	src := lookupFixture()
	src.Programs["other"] = lookupFixture().Programs["p"]
	work := src.Copy()
	before := append(asm.Instructions(nil), src.Programs["p"].Instructions...)
	plan, err := transformLookup(work, lookupReq())
	if err != nil || len(plan.sites) != 1 || plan.sites[0].SitePC != 11 {
		t.Fatalf("transform: %+v, %v", plan, err)
	}
	out := work.Programs["p"].Instructions
	if out.Size()-src.Programs["p"].Instructions.Size() != 16*8 {
		t.Fatal("want entry spill + 8 site instructions + 7 hook instructions")
	}
	if !reflect.DeepEqual(src.Programs["p"].Instructions, before) ||
		!reflect.DeepEqual(work.Programs["other"].Instructions, src.Programs["other"].Instructions) {
		t.Fatal("source or other program changed")
	}
	if !sameInstr(out[0], asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord).WithSymbol("p")) ||
		btf.FuncMetadata(&out[0]) == nil || out[0].Symbol() != "p" || out[0].Source() == nil ||
		btf.FuncMetadata(&out[1]) != nil || out[1].Symbol() != "" {
		t.Fatal("entry metadata was not moved to ctx spill")
	}
	hook := btf.FuncMetadata(&out[len(out)-7])
	if hook == nil || hook.Name != lookupReq().HookName || hook.Linkage != btf.GlobalFunc {
		t.Fatalf("hook BTF = %+v", hook)
	}
	proto := hook.Type.(*btf.FuncProto)
	if len(proto.Params) != 3 || proto.Params[0].Type != btf.FuncMetadata(&out[0]).Type.(*btf.FuncProto).Params[0].Type {
		t.Fatal("hook does not preserve entry context BTF")
	}
	for i, typ := range []btf.Type{work.Maps["sessions"].Key, work.Maps["sessions"].Value} {
		p := proto.Params[i+1].Type.(*btf.Pointer)
		if p.Target.(*btf.Const).Type != typ {
			t.Fatal("hook argument does not use the map's original BTF type")
		}
	}
	if !sameInstr(out[len(out)-2], asm.Mov.Imm(asm.R0, 0)) || !sameInstr(out[len(out)-1], asm.Return()) {
		t.Fatal("hook must return zero")
	}
	if err := checkExtInfo(out); err != nil {
		t.Fatal(err)
	}
	a, _ := checksum(before, src.ByteOrder)
	b, _ := checksum(out, work.ByteOrder)
	if a == b {
		t.Fatal("checksums should differ")
	}
}

func TestLookupRefusalsDoNotMutate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ebpf.CollectionSpec, *LookupRequest)
	}{
		{"missing-program", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.ProgramName = "absent" }},
		{"unsupported-type", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Programs["p"].Type = ebpf.SocketFilter }},
		{"empty-map", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.Site.MapName = "" }},
		{"wrong-map", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.Site.MapName = "absent" }},
		{"wrong-function", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.Site.FuncName = "absent" }},
		{"wrong-line", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.Site.Line = 999 }},
		{"missing-map", func(s *ebpf.CollectionSpec, r *LookupRequest) { delete(s.Maps, "sessions") }},
		{"key-size", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Maps["sessions"].KeySize = 8 }},
		{"value-size", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Maps["sessions"].ValueSize = 8 }},
		{"unsized-value", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Maps["sessions"].Value = &btf.Fwd{Name: "session"} }},
		{"map-in-map", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Maps["sessions"].Type = ebpf.HashOfMaps }},
		{"special-value", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Maps["sessions"].Value.(*btf.Struct).Name = "xdp_md" }},
		{"stack-direct", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.Stack.LowestOffset = 0 }},
		{"stack-room", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.Stack.LowestOffset = -489 }},
		{"stack-overflow", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.Stack.LowestOffset = -32768 }},
		{"stack-positive", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.Stack.LowestOffset = 8 }},
		{"collision", func(s *ebpf.CollectionSpec, r *LookupRequest) { r.HookName = "p" }},
		{"missing-func", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			p := s.Programs["p"]
			p.Instructions[0] = btf.WithFuncMetadata(p.Instructions[0], nil)
		}},
		{"missing-line", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			p := s.Programs["p"]
			p.Instructions[0] = p.Instructions[0].WithSource(nil)
		}},
		{"wrong-ctx", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			f := btf.FuncMetadata(&s.Programs["p"].Instructions[0])
			f.Type.(*btf.FuncProto).Params[0].Type = &btf.Int{Size: 4}
		}},
		{"subprogram", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			p := s.Programs["p"]
			fn := *btf.FuncMetadata(&p.Instructions[0])
			fn.Name = "sub"
			p.Instructions[9] = btf.WithFuncMetadata(p.Instructions[9].WithSource(asm.Comment("sub")), &fn)
		}},
		{"ambiguous", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			p := s.Programs["p"]
			p.Instructions = append(p.Instructions, asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(), asm.Return())
		}},
		{"function-pointer", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			i := asm.LoadImm(asm.R3, 0, asm.DWord)
			i.Src = asm.PseudoFunc
			s.Programs["p"].Instructions = append(s.Programs["p"].Instructions, i)
		}},
		{"unknown-reference", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			s.Programs["p"].Instructions[1] = asm.Mov.Imm(asm.R2, 0).WithReference("unknown")
		}},
		{"symbolic-branch", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Programs["p"].Instructions[4] = asm.Ja.Label("p") }},
		{"off-boundary", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Programs["p"].Instructions[4].Offset = 5 }},
		{"long-jump", func(s *ebpf.CollectionSpec, r *LookupRequest) { s.Programs["p"].Instructions[4] = asm.LongJump("") }},
		{"resolved-call", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			c := asm.Call.Label("p")
			c.Constant = 0
			s.Programs["p"].Instructions = append(s.Programs["p"].Instructions, c)
		}},
		{"unresolved-call", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			s.Programs["p"].Instructions = append(s.Programs["p"].Instructions, asm.Call.Label("absent"))
		}},
		{"hook-reference", func(s *ebpf.CollectionSpec, r *LookupRequest) {
			s.Programs["p"].Instructions = append(s.Programs["p"].Instructions, asm.Call.Label(r.HookName))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, req := lookupFixture(), lookupReq()
			tc.change(spec, &req)
			before := append(asm.Instructions(nil), spec.Programs["p"].Instructions...)
			if _, err := transformLookup(spec, req); !errors.Is(err, ErrRefused) {
				t.Fatalf("want ErrRefused, got %v", err)
			}
			if !reflect.DeepEqual(before, spec.Programs["p"].Instructions) {
				t.Fatal("refusal mutated instructions or metadata")
			}
		})
	}
}

func TestLookupRelocation(t *testing.T) {
	branch := asm.JEq.Imm(asm.R6, 0, "")
	branch.Offset = 3 // 0 -> 4 (helper)
	back := asm.JNE.Imm(asm.R6, 0, "")
	back.Offset = -6 // 5 -> 0
	call := asm.Call.Label("")
	call.Constant = 2 // 6 -> 9
	bypass := asm.Ja.Label("")
	bypass.Offset = -3 // 7 -> 5 (post-helper original instruction)
	input := asm.Instructions{branch, asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.FnMapLookupElem.Call(), back, call, bypass,
		asm.Return(), asm.Mov.Imm(asm.R0, 0).WithSymbol("sub"), asm.Return()}
	out, err := spliceLookup(input, []uint32{4}, lookupReq())
	if err != nil {
		t.Fatal(err)
	}
	ins := rawOffsets(out)
	for _, tc := range []struct {
		pc, target int
		call       bool
	}{
		{1, 5, false},   // branch to helper now targets key spill
		{14, 1, false},  // back edge to entry skips ctx spill
		{15, 18, true},  // numeric call keeps its subprogram
		{16, 14, false}, // bypass still skips the hook
	} {
		i := ins[tc.pc]
		delta := int(i.Offset)
		if tc.call {
			delta = int(i.Constant)
		}
		if got := tc.pc + 1 + delta; got != tc.target {
			t.Fatalf("relocation at %d -> %d, want %d", tc.pc, got, tc.target)
		}
	}
	if !sameInstr(ins[5], asm.StoreMem(asm.RFP, -24, asm.R2, asm.DWord)) ||
		!sameInstr(ins[13], asm.LoadMem(asm.R0, asm.RFP, -32, asm.DWord)) {
		t.Fatal("key/result spills misplaced")
	}
	hookCall := ins[12]
	if ins[8].Offset != 4 || !hookCall.IsFunctionCall() || ins[12].Reference() != lookupReq().HookName {
		t.Fatal("null guard must skip only argument setup and hook")
	}
}

func TestLookupBranchOverflow(t *testing.T) {
	jump := asm.JEq.Imm(asm.R6, 0, "")
	jump.Offset = 32767
	input := asm.Instructions{jump, asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call()}
	for len(input) < 32768 {
		input = append(input, asm.Return())
	}
	if _, err := spliceLookup(input, []uint32{3}, lookupReq()); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("want branch overflow refusal, got %v", err)
	}
}

func TestLookupStackBoundary(t *testing.T) {
	for _, lowest := range []int16{0, -1, -488, -489, -512, -32768} {
		req := lookupReq()
		req.Stack.LowestOffset = lowest
		out, err := spliceLookup(lookupFixture().Programs["p"].Instructions, []uint32{11}, req)
		if lowest < -488 {
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("bound %d: %v", lowest, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("bound %d: %v", lowest, err)
		}
		for _, ins := range out {
			if ins.Src == asm.RFP || ins.Dst == asm.RFP {
				if ins.Offset < -512 {
					t.Fatalf("out of range slot %d", ins.Offset)
				}
			}
		}
	}
}

func TestLookupMultipleSelection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector LookupSelector
		want     []uint32
	}{
		{"default-ambiguous", LookupSelector{MapName: "sessions"}, nil},
		{"all", LookupSelector{MapName: "sessions", AllMatches: true}, []uint32{12, 18}},
		{"explicit-reordered", LookupSelector{MapName: "sessions", SitePCs: []uint32{18, 12}}, []uint32{12, 18}},
		{"explicit-single", LookupSelector{MapName: "sessions", SitePCs: []uint32{18}}, []uint32{18}},
		{"duplicate", LookupSelector{MapName: "sessions", SitePCs: []uint32{12, 12}}, nil},
		{"missing-pc", LookupSelector{MapName: "sessions", SitePCs: []uint32{12, 99}}, nil},
		{"continuation-pc", LookupSelector{MapName: "sessions", SitePCs: []uint32{11}}, nil},
		{"non-lookup-pc", LookupSelector{MapName: "sessions", SitePCs: []uint32{0}}, nil},
		{"both", LookupSelector{MapName: "sessions", SitePCs: []uint32{12}, AllMatches: true}, nil},
		{"wrong-function", LookupSelector{MapName: "sessions", FuncName: "other", SitePCs: []uint32{12}}, nil},
		{"wrong-line", LookupSelector{MapName: "sessions", Line: 42, SitePCs: []uint32{12}}, nil},
		{"all-no-match", LookupSelector{MapName: "absent", AllMatches: true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, req := multiLookupFixture(), lookupReq()
			req.Site = tc.selector
			before := append(asm.Instructions(nil), spec.Programs["p"].Instructions...)
			plan, err := transformLookup(spec, req)
			sites := plan.sites
			if tc.want == nil {
				if !errors.Is(err, ErrRefused) {
					t.Fatalf("want refusal: %v", err)
				}
				if !reflect.DeepEqual(before, spec.Programs["p"].Instructions) {
					t.Fatal("refusal mutated input")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []uint32
			for _, site := range sites {
				got = append(got, site.SitePC)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("sites=%v want=%v", got, tc.want)
			}
			out := spec.Programs["p"].Instructions
			if out.Size()-before.Size() != uint64(8+8*len(sites))*8 {
				t.Fatal("incorrect insertion size")
			}
			var calls, hooks, ctxSpills int
			for _, ins := range out {
				if ins.IsFunctionCall() && ins.Reference() == req.HookName {
					calls++
				}
				if ins.Symbol() == req.HookName {
					hooks++
				}
				if sameInstr(ins, asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord).WithSymbol("p")) {
					ctxSpills++
				}
			}
			if calls != len(sites) || hooks != 1 || ctxSpills != 1 {
				t.Fatalf("calls=%d hooks=%d ctxSpills=%d", calls, hooks, ctxSpills)
			}
		})
	}
}

func TestLookupMultipleRefusal(t *testing.T) {
	for _, mode := range []string{"different-map", "unsupported-site"} {
		t.Run(mode, func(t *testing.T) {
			spec, req := multiLookupFixture(), lookupReq()
			sites, err := discoverLookups(spec, "p")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "different-map" {
				spec.Maps["other"] = spec.Maps["sessions"].Copy()
				idx := sites[1].InstructionIndex - 1
				spec.Programs["p"].Instructions[idx] = spec.Programs["p"].Instructions[idx].WithReference("other")
				req.Site.SitePCs = []uint32{12, 18}
			} else {
				idx := sites[1].InstructionIndex - 1
				fn := *btf.FuncMetadata(&spec.Programs["p"].Instructions[0])
				fn.Name = "sub"
				spec.Programs["p"].Instructions[idx] = btf.WithFuncMetadata(spec.Programs["p"].Instructions[idx], &fn)
				req.Site.AllMatches = true
			}
			before := append(asm.Instructions(nil), spec.Programs["p"].Instructions...)
			if _, err := transformLookup(spec, req); !errors.Is(err, ErrRefused) {
				t.Fatalf("want refusal: %v", err)
			}
			if !reflect.DeepEqual(before, spec.Programs["p"].Instructions) {
				t.Fatal("refusal mutated input")
			}
		})
	}
}

func TestLookupMultipleRelocation(t *testing.T) {
	forward, toSecond, back, toFirst, bypass := asm.Ja.Label(""), asm.JEq.Imm(asm.R6, 0, ""), asm.JNE.Imm(asm.R6, 0, ""), asm.JNE.Imm(asm.R6, 0, ""), asm.Ja.Label("")
	forward.Offset, toSecond.Offset, back.Offset, toFirst.Offset, bypass.Offset = 13, 3, -7, -7, -2
	call := asm.Call.Label("")
	call.Constant = 2
	input := asm.Instructions{forward, asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.Mov.Reg(asm.R2, asm.RFP), asm.FnMapLookupElem.Call(), toSecond, back,
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(), toFirst, bypass, call, asm.Call.Label("sub"), asm.Return(), asm.Mov.Imm(asm.R0, 0).WithSymbol("sub"), asm.Return()}
	out, err := spliceLookup(input, []uint32{4, 9}, lookupReq())
	if err != nil {
		t.Fatal(err)
	}
	ins := rawOffsets(out)
	for _, tc := range []struct {
		pc, target int
		call       bool
	}{{1, 31, false}, {14, 18, false}, {15, 1, false}, {27, 5, false}, {28, 27, false}, {29, 32, true}} {
		delta := int(ins[tc.pc].Offset)
		if tc.call {
			delta = int(ins[tc.pc].Constant)
		}
		if got := tc.pc + 1 + delta; got != tc.target {
			t.Fatalf("%d -> %d, want %d", tc.pc, got, tc.target)
		}
	}
	for _, pc := range []int{5, 18} {
		if !sameInstr(ins[pc], asm.StoreMem(asm.RFP, -24, asm.R2, asm.DWord)) || !sameInstr(ins[pc+8], asm.LoadMem(asm.R0, asm.RFP, -32, asm.DWord)) || ins[pc+3].Offset != 4 || ins[pc+7].Reference() != lookupReq().HookName {
			t.Fatalf("incorrect instrumentation at %d", pc)
		}
	}
	if ins[30].Reference() != "sub" || ins[30].Constant != -1 {
		t.Fatal("symbolic call changed")
	}
}

func TestLookupDiscoveryFunctionPointer(t *testing.T) {
	for _, dst := range []asm.Register{asm.R1, asm.R2} {
		t.Run(dst.String(), func(t *testing.T) {
			spec := lookupFixture()
			p := spec.Programs["p"]
			fp := asm.LoadImm(dst, -1, asm.DWord).WithReference("callback")
			fp.Src = asm.PseudoFunc
			// Insert between map load and helper: R1 must lose provenance, R2 must not.
			p.Instructions = append(append(append(asm.Instructions(nil), p.Instructions[:10]...), fp), p.Instructions[10:]...)
			p.Instructions = append(p.Instructions, callbackHead("callback"), asm.Return())
			before := append(asm.Instructions(nil), p.Instructions...)
			sites, err := discoverLookups(spec, "p")
			if err != nil || len(sites) != 1 {
				t.Fatalf("sites=%+v err=%v", sites, err)
			}
			if dst == asm.R1 {
				if sites[0].MapName != "" {
					t.Fatal("stale R1 map provenance")
				}
			} else if sites[0].MapName != "sessions" || sites[0].Reason != "" {
				t.Fatalf("site=%+v", sites[0])
			}
			if !reflect.DeepEqual(before, p.Instructions) {
				t.Fatal("discovery mutated input")
			}
			_, err = transformLookup(spec, lookupReq())
			if dst == asm.R1 {
				if !errors.Is(err, ErrRefused) || !reflect.DeepEqual(before, p.Instructions) {
					t.Fatalf("want refusal without mutation: %v", err)
				}
			} else if err != nil {
				t.Fatalf("valid callback refused: %v", err)
			}
		})
	}
}

func TestLookupMultipleCallRelocation(t *testing.T) {
	call := asm.Call.Label("")
	call.Constant = 7 // slot 0 -> subprogram at 8, across both insertions
	input := asm.Instructions{
		call,
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"),
		asm.FnMapLookupElem.Call(), // 3
		asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"),
		asm.FnMapLookupElem.Call(), // 6
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("sub"), // 8
		asm.Return(),
	}
	out, err := spliceLookup(input, []uint32{3, 6}, lookupReq())
	if err != nil {
		t.Fatal(err)
	}
	ins := rawOffsets(out)
	if got := 1 + 1 + int(ins[1].Constant); got != 25 || ins[got].Symbol() != "sub" {
		t.Fatalf("call target = %d, want relocated subprogram at 25", got)
	}
}

func TestLookupMultipleBranchOverflow(t *testing.T) {
	jump := asm.JEq.Imm(asm.R6, 0, "")
	jump.Offset = 32759
	input := asm.Instructions{jump, asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call(), asm.LoadMapPtr(asm.R1, 0).WithReference("sessions"), asm.FnMapLookupElem.Call()}
	for len(input) < 32759 {
		input = append(input, asm.Return())
	}
	if _, err := spliceLookup(input, []uint32{3}, lookupReq()); err != nil {
		t.Fatalf("one insertion should fit: %v", err)
	}
	if _, err := spliceLookup(input, []uint32{3, 6}, lookupReq()); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("want combined insertion overflow: %v", err)
	}
}
