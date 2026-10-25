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

func autoReq() LookupRequest {
	req := lookupReq()
	req.Site, req.Auto = LookupSelector{}, true
	return req
}

func TestLookupAutoPerMapHooks(t *testing.T) {
	spec, req := multiMapFixture(), autoReq()
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || len(plan.skipped) != 0 || len(plan.sites) != 2 {
		t.Fatalf("plan: %+v", plan)
	}
	want := map[string]uint32{"lookup_hook_sessions": 12, "lookup_hook_flows": 18}
	for _, hook := range plan.hooks {
		if len(hook.Sites) != 1 || want[hook.Name] != hook.Sites[0].SitePC || hook.MapName != hook.Sites[0].MapName {
			t.Fatalf("hook: %+v", hook)
		}
	}
	out := spec.Programs["p"].Instructions
	calls, symbols := map[string]int{}, map[string]int{}
	for i, ins := range out {
		if ins.IsFunctionCall() {
			// R2 carries the original SitePC: ctx, site, key, value, call.
			if site := out[i-3]; !sameInstr(site, asm.Mov.Imm32(asm.R2, int32(want[ins.Reference()]))) {
				t.Fatalf("call %s: site argument %v", ins.Reference(), site)
			}
			calls[ins.Reference()]++
		}
		if fn := btf.FuncMetadata(&out[i]); fn != nil {
			symbols[fn.Name]++
			if proto := fn.Type.(*btf.FuncProto); want[fn.Name] != 0 && (len(proto.Params) != 4 || proto.Params[1].Name != "site") {
				t.Fatalf("hook %s params: %+v", fn.Name, proto.Params)
			}
		}
	}
	for name := range want {
		if calls[name] != 1 || symbols[name] != 1 {
			t.Fatalf("%s: calls=%d symbols=%d", name, calls[name], symbols[name])
		}
	}
	if err := checkExtInfo(out); err != nil {
		t.Fatal(err)
	}
}

func TestLookupAutoSkipsUnsupported(t *testing.T) {
	spec, req := multiLookupFixture(), autoReq()
	sites, err := discoverLookups(spec, "p")
	if err != nil {
		t.Fatal(err)
	}
	// Move the second lookup into a subprogram, which the transform cannot reach.
	idx := sites[1].InstructionIndex - 1
	fn := *btf.FuncMetadata(&spec.Programs["p"].Instructions[0])
	fn.Name = "sub"
	insns := spec.Programs["p"].Instructions
	insns[idx] = btf.WithFuncMetadata(insns[idx], &fn).WithSource(insns[0].Source())
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.sites) != 1 || plan.sites[0].SitePC != 12 || len(plan.skipped) != 1 || plan.skipped[0].SitePC != 18 ||
		plan.skipped[0].Reason == "" || len(plan.hooks) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
}

func TestLookupAutoRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*LookupRequest)
	}{
		{"with-map", func(r *LookupRequest) { r.Site.MapName = "sessions" }},
		{"with-pcs", func(r *LookupRequest) { r.Site.SitePCs = []uint32{12} }},
		{"with-all", func(r *LookupRequest) { r.Site.AllMatches = true }},
		{"with-line", func(r *LookupRequest) { r.Site.Line = 1 }},
		{"name-collision", func(r *LookupRequest) { r.HookName = "p" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, req := multiLookupFixture(), autoReq()
			tc.edit(&req)
			if tc.name == "name-collision" {
				// p_sessions collides with an existing function name.
				fn := *btf.FuncMetadata(&spec.Programs["p"].Instructions[0])
				fn.Name = "p_sessions"
				spec.Programs["p"].Instructions = append(spec.Programs["p"].Instructions,
					btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("p_sessions"), &fn), asm.Return())
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

func TestAutoHookName(t *testing.T) {
	used := map[string]bool{}
	for _, tc := range []struct{ mapName, want string }{
		{"sessions", "h_sessions"},
		{"pdr.map", "h_pdr_map"},
		{"pdr_map", "h_2"}, // sanitizes to an existing name
		{"", "h_3"},
		{"h_3", "h_h_3"},
	} {
		if got := autoHookName("h", tc.mapName, len(used), used); got != tc.want {
			t.Fatalf("%q: got %q want %q", tc.mapName, got, tc.want)
		}
	}
}

func TestLookupRawAutoPerMapHooks(t *testing.T) {
	req := autoReq()
	plan, err := transformLookup(multiMapFixture(), req)
	if err != nil {
		t.Fatal(err)
	}
	p := rawLookupFixture(t, multiMapFixture(), "p", true)
	got, err := TransformLookupRaw(p, rawLookupRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	assertRawMetadata(t, p, got)
	if len(got.Hooks) != len(plan.hooks) || got.Hooks[0].TypeID == got.Hooks[1].TypeID {
		t.Fatalf("hooks: %+v", got.Hooks)
	}
	for i, hook := range plan.hooks {
		if got.Hooks[i].Name != hook.Name || !reflect.DeepEqual(got.Hooks[i].Sites, hook.Sites) {
			t.Fatalf("raw hook %d: %+v, ELF %+v", i, got.Hooks[i], hook)
		}
	}
}

func TestTailCallAndEntryHooks(t *testing.T) {
	spec := tailCallerFixture()
	plan, err := transformLookup(spec, LookupRequest{ProgramName: "caller", Entry: true, TailCalls: true,
		HookName: "h", Stack: StackAudit{LowestOffset: -8}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.sites) != 0 || len(plan.hooks) != 2 || plan.hooks[0].Kind != HookEntry || plan.hooks[0].Name != "h_entry" ||
		plan.hooks[1].Kind != HookTailCall || plan.hooks[1].Name != "h_tail_call" ||
		len(plan.hooks[1].Sites) != 1 || plan.hooks[1].Sites[0].SitePC != 10 {
		t.Fatalf("plan: %+v", plan)
	}
	out := spec.Programs["caller"].Instructions
	// ctx spill, entry hook call, ctx reload, then the original entry.
	if !sameInstr(out[1], asm.Call.Label("h_entry")) || out[1].Reference() != "h_entry" ||
		!sameInstr(out[2], asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord)) || !sameInstr(out[3], asm.Mov.Reg(asm.R6, asm.R1)) {
		t.Fatalf("entry prologue: %v", out[:4])
	}
	var tail int
	for i, ins := range out {
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall) {
			tail = i
		}
	}
	// The index is spilled before the helper and passed with the site after it.
	if !sameInstr(out[tail-1], asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord)) ||
		!sameInstr(out[tail+2], asm.Mov.Imm32(asm.R2, 10)) || out[tail+5].Reference() != "h_tail_call" {
		t.Fatalf("tail-call site: %v", out[tail-1:tail+6])
	}
	// The short-packet branch still lands on the original XDP_PASS.
	pcs := rawOffsets(out)
	var branchPC int
	for pc, ins := range pcs {
		if ins.OpCode.JumpOp() == asm.JGT {
			branchPC = pc
		}
	}
	if land := pcs[branchPC+1+int(pcs[branchPC].Offset)]; !sameInstr(land, asm.Mov.Imm(asm.R0, 2)) {
		t.Fatalf("branch lands on %v", land)
	}
	if err := checkExtInfo(out); err != nil {
		t.Fatal(err)
	}
}

func TestTailCallHookRefusalsAndSkips(t *testing.T) {
	req := LookupRequest{ProgramName: "p", TailCalls: true, HookName: "h", Stack: StackAudit{LowestOffset: -8}}
	if _, err := transformLookup(lookupFixture(), req); !errors.Is(err, ErrRefused) {
		t.Fatalf("no tail call: %v", err)
	}
	// A tail call in a subprogram is skipped, not instrumented.
	spec := tailCallerFixture()
	prog := spec.Programs["caller"]
	sub := xdpFunc("sub")
	call := asm.Call.Label("sub")
	prog.Instructions = append(asm.Instructions{prog.Instructions[0], call}, prog.Instructions[1:]...)
	prog.Instructions = append(prog.Instructions,
		btf.WithFuncMetadata(asm.FnTailCall.Call().WithSymbol("sub").WithSource(asm.Comment("sub")), sub),
		asm.Mov.Imm(asm.R0, 0), asm.Return())
	req.ProgramName = "caller"
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.skipped) != 1 || plan.skipped[0].FuncName != "sub" || len(plan.hooks[0].Sites) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	// Auto names avoid the entry hook name; a map named "entry" falls back.
	auto := lookupFixture()
	auto.Maps["entry"] = auto.Maps["sessions"]
	delete(auto.Maps, "sessions")
	for i := range auto.Programs["p"].Instructions {
		if ins := &auto.Programs["p"].Instructions[i]; ins.IsLoadFromMap() {
			*ins = ins.WithReference("entry")
		}
	}
	plan, err = transformLookup(auto, LookupRequest{ProgramName: "p", Auto: true, Entry: true, HookName: "h", Stack: StackAudit{LowestOffset: -8}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 2 || plan.hooks[0].Name != "h_0" || plan.hooks[1].Name != "h_entry" {
		t.Fatalf("hooks: %+v", plan.hooks)
	}
}

func TestTailCallRawParity(t *testing.T) {
	req := LookupRequest{ProgramName: "caller", Entry: true, TailCalls: true, HookName: "h", Stack: StackAudit{LowestOffset: -8}}
	work := tailCallerFixture()
	plan, err := transformLookup(work, req)
	if err != nil {
		t.Fatal(err)
	}
	p := rawLookupFixture(t, tailCallerFixture(), "caller", false)
	got, err := TransformLookupRaw(p, LookupRequestRaw{Entry: true, TailCalls: true, HookName: "h", Stack: req.Stack})
	if err != nil {
		t.Fatal(err)
	}
	assertRawMetadata(t, p, got)
	want := work.Programs["caller"].Instructions
	if len(got.Instructions) != len(want) || len(got.Hooks) != len(plan.hooks) {
		t.Fatal("raw and ELF outputs differ in length")
	}
	for i := range want {
		if !sameInstr(want[i], got.Instructions[i]) {
			t.Fatalf("instruction %d: %v vs %v", i, want[i], got.Instructions[i])
		}
	}
}

// A map that programs cannot write gets a hook whose key and value are
// const void * tagged arg:untrusted; other maps keep their typed hooks.
func TestLookupReadOnlyMap(t *testing.T) {
	work := multiMapFixtureFlags(bpfFRdonlyProg)
	plan, err := transformLookup(work, autoReq())
	if err != nil || len(plan.hooks) != 2 || len(plan.skipped) != 0 {
		t.Fatalf("auto: %+v %v", plan, err)
	}
	for _, hook := range plan.hooks {
		if hook.Untrusted != (hook.MapName == "flows") {
			t.Fatalf("hook %s untrusted=%v", hook.Name, hook.Untrusted)
		}
		var fn *btf.Func
		for _, ins := range work.Programs["p"].Instructions {
			if f := btf.FuncMetadata(&ins); f != nil && f.Name == hook.Name {
				fn = f
			}
		}
		params := fn.Type.(*btf.FuncProto).Params
		_, void := params[3].Type.(*btf.Pointer).Target.(*btf.Const).Type.(*btf.Void)
		tagged := len(fn.ParamTags) == 4 && reflect.DeepEqual(fn.ParamTags[2], []string{"arg:untrusted"}) &&
			reflect.DeepEqual(fn.ParamTags[3], []string{"arg:untrusted"})
		if void != hook.Untrusted || tagged != hook.Untrusted {
			t.Fatalf("hook %s: void=%v tags=%v", hook.Name, void, fn.ParamTags)
		}
	}
}

func multiMapFixtureFlags(flags uint32) *ebpf.CollectionSpec {
	spec := multiMapFixture()
	spec.Maps["flows"].Flags = flags
	return spec
}

func TestAutoHookNameLength(t *testing.T) {
	req := autoReq()
	req.HookName = strings.Repeat("h", maxHookName-1)
	if _, err := transformLookup(multiLookupFixture(), req); !errors.Is(err, ErrRefused) {
		t.Fatalf("overlong auto hook name: %v", err)
	}
}

// hookParams returns the BTF parameters of the generated function name.
func hookParams(t *testing.T, insns asm.Instructions, name string) []btf.FuncParam {
	t.Helper()
	for _, ins := range insns {
		if fn := btf.FuncMetadata(&ins); fn != nil && fn.Name == name {
			return fn.Type.(*btf.FuncProto).Params
		}
	}
	t.Fatalf("no hook %s", name)
	return nil
}

// opaqueSize is the size of a const pointer parameter's struct { u8 bytes[N]; }.
func opaqueSize(t *testing.T, param btf.FuncParam) uint32 {
	t.Helper()
	s, ok := param.Type.(*btf.Pointer).Target.(*btf.Const).Type.(*btf.Struct)
	if !ok || s.Name != "" || len(s.Members) != 1 || s.Members[0].Name != "bytes" {
		t.Fatalf("%s is not opaque bytes: %v", param.Name, param.Type)
	}
	return s.Size
}

// A side the map declares only by size is passed as opaque bytes of that size.
func TestLookupOpaqueTypes(t *testing.T) {
	spec := lookupFixture()
	spec.Maps["sessions"].Key, spec.Maps["sessions"].Value = nil, nil
	if _, err := transformLookup(spec, lookupReq()); err != nil {
		t.Fatal(err)
	}
	params := hookParams(t, spec.Programs["p"].Instructions, "lookup_hook")
	if len(params) != 3 || opaqueSize(t, params[1]) != 4 || opaqueSize(t, params[2]) != 16 {
		t.Fatalf("params: %+v", params)
	}

	p := rawLookupFixture(t, lookupFixture(), "p", true)
	m := p.Maps[40]
	m.Value = nil
	p.Maps[40] = m
	got, err := TransformLookupRaw(p, rawLookupRequest(lookupReq()))
	if err != nil {
		t.Fatal(err)
	}
	assertRawMetadata(t, p, got)
	params = hookParams(t, got.Instructions, "lookup_hook")
	if opaqueSize(t, params[2]) != 16 {
		t.Fatalf("raw params: %+v", params)
	}
}

// An LPM trie lookup returns ordinary value memory, like a hash map.
func TestLookupLPMTrie(t *testing.T) {
	spec := lookupFixture()
	spec.Maps["sessions"].Type = ebpf.LPMTrie
	if _, err := transformLookup(spec, lookupReq()); err != nil {
		t.Fatal(err)
	}
}
