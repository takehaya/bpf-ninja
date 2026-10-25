package inject

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
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

// Auto keeps the entry and tail-call hooks even when no lookup is supported;
// it refuses only when nothing at all is instrumented.
func TestSelectLookupsAutoEntryTailNoLookups(t *testing.T) {
	base := func() LookupRequest {
		return LookupRequest{ProgramName: "caller", Auto: true, HookName: "obs", Stack: StackAudit{LowestOffset: 0}}
	}
	req := base()
	req.Entry, req.TailCalls = true, true
	plan, err := transformLookup(tailCallerFixture(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.sites) != 0 || len(plan.skipped) != 0 || len(plan.hooks) != 2 ||
		plan.hooks[0].Name != "obs_entry" || plan.hooks[1].Name != "obs_tail_call" || len(plan.hooks[1].Sites) != 1 {
		t.Fatalf("entry+tail: %+v", plan)
	}
	if _, err := transformLookup(tailCallerFixture(), base()); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no supported lookup sites") {
		t.Fatalf("auto only: %v", err)
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

// A skip or refusal reason is a bare phrase; only the refusal wraps it with
// the ErrRefused prefix, and only once.
func TestLookupSkipReason(t *testing.T) {
	skb := func() *ebpf.CollectionSpec {
		spec := multiMapFixture()
		spec.Maps["flows"].Value.(*btf.Struct).Name = "xdp_md"
		return spec
	}
	want := `map value type "xdp_md" has a special global-function pointer ABI`
	sites, err := discoverLookups(skb(), "p")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range sites {
		if s.SitePC == 18 {
			found = s.Reason == want
		}
	}
	if !found {
		t.Fatalf("discovery reason not bare: %+v", sites)
	}
	req := lookupReq()
	req.Site.MapName = "flows"
	if _, err := transformLookup(skb(), req); !errors.Is(err, ErrRefused) || err.Error() != "inject: refused: lookup at 18: "+want {
		t.Fatalf("explicit: %v", err)
	}
}

// A direct lookup on an XSK map or devmap, which a typed hook refuses, goes to
// the generic hook under Auto; Auto skips every other kind a typed hook
// refuses, since no kernel test loads it through the generic hook. Explicit
// selection refuses them all.
func TestLookupAutoTypedOnlyGoesGeneric(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(*ebpf.MapSpec)
		reason  string
		generic bool
	}{
		{"xskmap", func(m *ebpf.MapSpec) { m.Type, m.ValueSize, m.Value = ebpf.XSKMap, 4, nil }, "map type XSKMap is unsupported", true},
		{"devmap", func(m *ebpf.MapSpec) { m.Type, m.ValueSize, m.Value = ebpf.DevMap, 4, nil }, "map type DevMap is unsupported", true},
		{"sockmap", func(m *ebpf.MapSpec) { m.Type, m.ValueSize, m.Value = ebpf.SockMap, 8, nil }, "map type SockMap is unsupported", false},
		{"sockhash", func(m *ebpf.MapSpec) { m.Type, m.ValueSize, m.Value = ebpf.SockHash, 8, nil }, "map type SockHash is unsupported", false},
		{"devmap-hash", func(m *ebpf.MapSpec) { m.Type, m.ValueSize, m.Value = ebpf.DevMapHash, 4, nil }, "map type DevMapHash is unsupported", false},
		{"cpumap", func(m *ebpf.MapSpec) { m.Type, m.ValueSize, m.Value = ebpf.CPUMap, 4, nil }, "map type CPUMap is unsupported", false},
		{"reuseport", func(m *ebpf.MapSpec) { m.Type, m.ValueSize, m.Value = ebpf.ReusePortSockArray, 8, nil }, "map type ReusePortSockArray is unsupported", false},
		{"special-value", func(m *ebpf.MapSpec) { m.Value.(*btf.Struct).Name = "xdp_md" }, `map value type "xdp_md" has a special global-function pointer ABI`, false},
		{"size-mismatch", func(m *ebpf.MapSpec) { m.ValueSize = 8 }, "map value BTF size does not match map size 8", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := func() *ebpf.CollectionSpec {
				spec := multiMapFixture()
				tc.edit(spec.Maps["flows"])
				return spec
			}
			// Discovery lists the bare reason for the typed-only site.
			sites, err := discoverLookups(fixture(), "p")
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range sites {
				if s.SitePC == 18 && s.Reason != tc.reason {
					t.Fatalf("discovery reason %q, want %q", s.Reason, tc.reason)
				}
			}
			// Explicit selection of the same map refuses, with one prefix.
			req := lookupReq()
			req.Site.MapName = "flows"
			if _, err := transformLookup(fixture(), req); !errors.Is(err, ErrRefused) || err.Error() != "inject: refused: lookup at 18: "+tc.reason {
				t.Fatalf("explicit: %v", err)
			}
			work := fixture()
			plan, err := transformLookup(work, autoReq())
			if err != nil {
				t.Fatal(err)
			}
			if !tc.generic {
				// Auto keeps the typed sessions hook and skips flows.
				if len(plan.hooks) != 1 || plan.hooks[0].MapName != "sessions" ||
					len(plan.skipped) != 1 || plan.skipped[0].SitePC != 18 || plan.skipped[0].Reason != tc.reason {
					t.Fatalf("auto: %+v", plan)
				}
				return
			}
			// Auto keeps the typed hook for sessions and adds a generic hook
			// carrying the flows site; nothing is skipped.
			if len(plan.skipped) != 0 || len(plan.hooks) != 2 {
				t.Fatalf("auto: %+v", plan)
			}
			var generic *LookupHook
			for i := range plan.hooks {
				if plan.hooks[i].Generic {
					generic = &plan.hooks[i]
				}
			}
			if generic == nil || len(generic.Sites) != 1 || generic.Sites[0].SitePC != 18 {
				t.Fatalf("generic hook: %+v", plan.hooks)
			}
			// The generic site spills the map pointer to the fourth slot once.
			spills := 0
			for _, ins := range work.Programs["p"].Instructions {
				if sameInstr(ins, asm.StoreMem(asm.RFP, -40, asm.R1, asm.DWord)) {
					spills++
				}
			}
			if spills != 1 {
				t.Fatalf("map pointer spilled %d times", spills)
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
	// A tail call in a subprogram saves its own ctx before the helper.
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
	if len(plan.skipped) != 0 || len(plan.hooks[0].Sites) != 2 || plan.hooks[0].Sites[1].FuncName != "sub" {
		t.Fatalf("plan: %+v", plan)
	}
	out := spec.Programs["caller"].Instructions
	var fn string
	for i, ins := range out {
		if f := btf.FuncMetadata(&ins); f != nil {
			fn = f.Name
			// sub starts at the tail call, so it starts at the spills.
			if fn == "sub" && !sameInstr(ins, asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord).WithSymbol("sub")) {
				t.Fatalf("sub starts at %v", ins)
			}
		}
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall) {
			// Only the subprogram's site spills R1, after the index.
			index := out[i-1]
			if fn == "sub" {
				if !sameInstr(out[i-1], asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord)) {
					t.Fatalf("sub tail call: %v", out[i-2:i+1])
				}
				index = out[i-2]
			}
			if !sameInstr(index.WithSymbol(""), asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord)) {
				t.Fatalf("%s tail call: %v", fn, out[i-2:i+1])
			}
		}
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

// The transform refuses a tail-call program whose entry frame it would deepen
// to or past the 256-byte caller-depth limit; one slot less transforms.
func TestTailCallStackLimit(t *testing.T) {
	for _, tc := range []struct {
		bound  int16
		refuse bool
	}{{-216, false}, {-224, true}} {
		work := paddedSubTailCaller(tc.bound)
		_, err := transformLookup(work, LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: StackAudit{LowestOffset: tc.bound}})
		if tc.refuse {
			if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "caller-depth limit") {
				t.Fatalf("bound %d: want refusal, got %v", tc.bound, err)
			}
		} else if err != nil {
			t.Fatalf("bound %d: %v", tc.bound, err)
		}
	}
}

// The caller-depth check sums every frame above a tail-calling subprogram: the
// entry's ctx spill through a stack-using middle frame, and the entry's own
// tail-call spill when the entry then calls another tail-calling subprogram.
// The shallower variants transform. Both the ELF and the raw call forms resolve.
func TestTailCallDepthSumsCallers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		spec   func() *ebpf.CollectionSpec
		req    LookupRequest
		refuse bool
	}{
		{"chain", func() *ebpf.CollectionSpec { return chainTailCaller(192) },
			LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Stack: StackAudit{LowestOffset: -192}}, true},
		{"chain-shallow", func() *ebpf.CollectionSpec { return chainTailCaller(96) },
			LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Stack: StackAudit{LowestOffset: -96}}, false},
		{"nested", func() *ebpf.CollectionSpec { return nestedTailCaller(-216) },
			LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: StackAudit{LowestOffset: -216}}, true},
		{"nested-shallow", func() *ebpf.CollectionSpec { return nestedTailCaller(-208) },
			LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: StackAudit{LowestOffset: -208}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(form string, err error) {
				t.Helper()
				if tc.refuse && (!errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "caller-depth limit") || !strings.Contains(err.Error(), "sub")) {
					t.Fatalf("%s: want refusal naming sub, got %v", form, err)
				}
				if !tc.refuse && err != nil {
					t.Fatalf("%s: %v", form, err)
				}
			}
			_, err := transformLookup(tc.spec(), tc.req)
			check("elf", err)
			for _, numeric := range []bool{false, true} {
				p := rawLookupFixture(t, tc.spec(), "caller", numeric)
				_, err := TransformLookupRaw(p, LookupRequestRaw{Entry: tc.req.Entry, TailCalls: tc.req.TailCalls, HookName: tc.req.HookName, Stack: tc.req.Stack})
				check(map[bool]string{false: "raw-symbolic", true: "raw-numeric"}[numeric], err)
			}
		})
	}
}

// stackLimitCase is a program and request at a bound where the transform
// would reach a kernel call-chain limit (refuse names the limit and chain),
// or, for a -shallow twin, one step shallower where it does not.
type stackLimitCase struct {
	name   string
	spec   func() *ebpf.CollectionSpec
	req    LookupRequest
	refuse []string
}

func stackLimitCases() []stackLimitCase {
	entry := func(bound int16) LookupRequest {
		return LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Stack: StackAudit{LowestOffset: bound}}
	}
	tails := func(bound int16) LookupRequest {
		return LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "obs", Stack: StackAudit{LowestOffset: bound}}
	}
	deepAuto := func(bound int16) LookupRequest {
		req := autoReq()
		req.Stack.LowestOffset = bound
		return req
	}
	callback := []string{"caller-depth limit", "caller -> cb -> sub"}
	return []stackLimitCase{
		// The entry frame plus the callback's 32-byte frame are sub's callers.
		{"callback", func() *ebpf.CollectionSpec { return loopTailCaller(-192, btf.StaticFunc) }, entry(-192), callback},
		{"callback-shallow", func() *ebpf.CollectionSpec { return loopTailCaller(-184, btf.StaticFunc) }, entry(-184), nil},
		{"callback-global", func() *ebpf.CollectionSpec { return loopTailCaller(-192, btf.GlobalFunc) }, entry(-192), callback},
		{"callback-global-shallow", func() *ebpf.CollectionSpec { return loopTailCaller(-184, btf.GlobalFunc) }, entry(-184), nil},
		// The entry's tail-call spill pushes entry + wide past 512 bytes.
		{"combined", func() *ebpf.CollectionSpec { return wideCaller(248) }, tails(-248), []string{"512-byte combined limit", "caller -> wide"}},
		{"combined-shallow", func() *ebpf.CollectionSpec { return wideCaller(240) }, tails(-240), nil},
		// The tail-call hook called from the 8th frame is a 9th.
		{"frames", func() *ebpf.CollectionSpec { return frameChain(8) }, tails(0),
			[]string{"8-frame limit", "caller -> f1 -> f2 -> f3 -> f4 -> f5 -> f6 -> sub -> obs_tail_call"}},
		{"frames-shallow", func() *ebpf.CollectionSpec { return frameChain(7) }, tails(0), nil},
		// A lookup site's frame plus its hook's 32-byte frame: Auto skips
		// every site whose slots pass 480 bytes.
		{"site-frame", multiMapFixture, deepAuto(-464), []string{"leaves no room"}},
		{"site-frame-shallow", multiMapFixture, deepAuto(-456), nil},
		// sub reaches its stack only through a copy of R10, which the audit
		// covers: the entry's ctx spill plus sub's 256 bytes pass 512.
		{"alias", func() *ebpf.CollectionSpec { return aliasCallee(256) }, entry(-256), []string{"512-byte combined limit", "caller -> sub"}},
		{"alias-shallow", func() *ebpf.CollectionSpec { return aliasCallee(224) }, entry(-224), nil},
	}
}

// autoRetryCase is an Auto request whose lookup slots alone push the entry,
// sub's caller, to the 256-byte caller-depth limit. Auto keeps the hooks
// named in hooks and skips the sites at skipped, each with the limit as its
// reason, or refuses with refuse when nothing would be instrumented.
type autoRetryCase struct {
	name    string
	spec    func() *ebpf.CollectionSpec
	req     LookupRequest
	hooks   []string
	skipped []uint32
	refuse  string
}

func autoRetryCases() []autoRetryCase {
	auto := func(bound int16, edit func(*LookupRequest)) LookupRequest {
		req := autoReq()
		req.HookName, req.Stack.LowestOffset = "obs", bound
		edit(&req)
		return req
	}
	plain := func(*LookupRequest) {}
	tails := func(r *LookupRequest) { r.TailCalls = true }
	copyRO := func(r *LookupRequest) { r.CopyReadOnly = true }
	single := func() *ebpf.CollectionSpec { return lookupSubTailCaller(lookupFixture(), -208) }
	readOnly := func() *ebpf.CollectionSpec { return lookupSubTailCaller(multiMapFixtureFlags(bpfFRdonlyProg), -200) }
	mapInMap := func() *ebpf.CollectionSpec {
		spec := multiMapFixture()
		spec.Maps["flows"].Type = ebpf.HashOfMaps
		return lookupSubTailCaller(spec, -200)
	}
	return []autoRetryCase{
		// The entry's three base slots reach 232 bytes, 256 rounded to 32;
		// the tail-call hook alone reaches 216.
		{"tails-208", single, auto(-208, tails), []string{"obs_tail_call"}, []uint32{15}, ""},
		{"no-entry-tails-208", single, auto(-208, plain), nil, nil, "no lookup site fits the audited stack (1 skipped): after the transform"},
		// The flows copy or map slot reaches 248 or 232 bytes; the base
		// slots alone reach 224, so only flows is dropped.
		{"copy-200", readOnly, auto(-200, copyRO), []string{"obs_sessions"}, []uint32{22}, ""},
		{"map-in-map-200", mapInMap, auto(-200, plain), []string{"obs_sessions"}, []uint32{22}, ""},
		{"plain-200", readOnly, auto(-200, plain), []string{"obs_sessions", "obs_flows"}, nil, ""},
	}
}

// Auto drops the groups that reach below the base slots first, then every
// lookup, and keeps the entry and tail-call hooks, when only the lookup slots
// break a call-chain limit; explicit selection still refuses. ELF and raw
// forms; a refusal leaves the input unchanged.
func TestAutoRetryStackLimits(t *testing.T) {
	for _, tc := range autoRetryCases() {
		t.Run(tc.name, func(t *testing.T) {
			check := func(form string, hooks []LookupHook, skipped []LookupSite, err error) {
				t.Helper()
				if tc.refuse != "" {
					if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), tc.refuse) || !strings.Contains(err.Error(), "caller-depth limit") {
						t.Fatalf("%s: want refusal %q, got %v", form, tc.refuse, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("%s: %v", form, err)
				}
				var names []string
				for _, hook := range hooks {
					names = append(names, hook.Name)
				}
				var pcs []uint32
				for _, site := range skipped {
					pcs = append(pcs, site.SitePC)
					if !strings.HasPrefix(site.Reason, "after the transform the frames calling sub (p -> sub)") || !strings.Contains(site.Reason, "caller-depth limit") {
						t.Fatalf("%s: skip reason %q", form, site.Reason)
					}
				}
				if !reflect.DeepEqual(names, tc.hooks) || !reflect.DeepEqual(pcs, tc.skipped) {
					t.Fatalf("%s: hooks %v skipped %v, want %v %v", form, names, pcs, tc.hooks, tc.skipped)
				}
			}
			work := tc.spec()
			before := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
			plan, err := transformLookup(work, tc.req)
			check("elf", plan.hooks, plan.skipped, err)
			if err != nil && !reflect.DeepEqual(before, work.Programs["p"].Instructions) {
				t.Fatal("refusal mutated input")
			}
			// The fixtures' maps all load fd 0, so only the numeric form, which
			// numbers them apart, resolves them.
			p := rawLookupFixture(t, tc.spec(), "p", true)
			got, err := TransformLookupRaw(p, LookupRequestRaw{Auto: true, TailCalls: tc.req.TailCalls, CopyReadOnly: tc.req.CopyReadOnly,
				HookName: tc.req.HookName, Stack: tc.req.Stack})
			if err != nil {
				check("raw", nil, nil, err)
			} else {
				check("raw", got.Hooks, got.Skipped, err)
			}
		})
	}
	// Explicit selection of a site the chain limit rules out refuses.
	req := lookupReq()
	req.TailCalls, req.Stack.LowestOffset = true, -208
	if _, err := transformLookup(lookupSubTailCaller(lookupFixture(), -208), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "caller-depth limit") {
		t.Fatalf("explicit: want refusal, got %v", err)
	}
}

// overestimatedReq deepens deadStoreCallee's entry by its ctx spill.
var overestimatedReq = LookupRequest{ProgramName: "caller", Entry: true, HookName: "obs", Stack: StackAudit{LowestOffset: -288}}

// The original's instruction depths already pass 512 bytes on caller -> sub,
// but the kernel counts 512; the transform deepens the chain, so it refuses
// rather than treat the limit as already crossed. ELF and both raw forms.
func TestStackLimitsOverestimatedOriginal(t *testing.T) {
	check := func(form string, err error) {
		t.Helper()
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "512-byte combined limit") || !strings.Contains(err.Error(), "caller -> sub") {
			t.Fatalf("%s: want combined-limit refusal naming caller -> sub, got %v", form, err)
		}
	}
	_, err := transformLookup(deadStoreCallee(), overestimatedReq)
	check("elf", err)
	for _, numeric := range []bool{false, true} {
		p := rawLookupFixture(t, deadStoreCallee(), "caller", numeric)
		_, err := TransformLookupRaw(p, LookupRequestRaw{Entry: true, HookName: "obs", Stack: overestimatedReq.Stack})
		check(map[bool]string{false: "raw-symbolic", true: "raw-numeric"}[numeric], err)
	}
}

// Only a chain the transform left as it was may stay past a limit: the
// unreached orphan -> deep chain is 608 bytes in both programs and passes
// while the transform only deepens the entry, and is refused once orphan is
// deeper too.
func TestStackLimitsUnchangedChain(t *testing.T) {
	program := func(entry, orphan int16) asm.Instructions {
		return asm.Instructions{
			btf.WithFuncMetadata(asm.StoreImm(asm.RFP, entry, 0, asm.Word).WithSymbol("caller"), xdpFunc("caller")),
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
			btf.WithFuncMetadata(asm.StoreImm(asm.RFP, orphan, 0, asm.Word).WithSymbol("orphan"), staticFunc("orphan")),
			asm.Call.Label("deep"),
			asm.Return(),
			btf.WithFuncMetadata(asm.StoreImm(asm.RFP, -304, 0, asm.Word).WithSymbol("deep"), staticFunc("deep")),
			asm.Return(),
		}
	}
	in := program(-8, -304)
	if err := checkStackLimits(in, program(-16, -304), -304); err != nil {
		t.Fatalf("unchanged chain: %v", err)
	}
	err := checkStackLimits(in, program(-16, -312), -304)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "orphan -> deep") {
		t.Fatalf("deepened chain: want refusal naming orphan -> deep, got %v", err)
	}
}

// reserveCase is a request without lookups at a bound CheckLookupStack and
// the transform both accept (ok) or both refuse.
type reserveCase struct {
	name string
	req  LookupRequest
	ok   bool
}

func reserveCases() []reserveCase {
	req := func(entry, tails bool, bound int16) LookupRequest {
		return LookupRequest{ProgramName: "caller", Entry: entry, TailCalls: tails, HookName: "obs", Stack: StackAudit{LowestOffset: bound}}
	}
	return []reserveCase{
		{"entry-472", req(true, false, -472), true},
		{"entry-473", req(true, false, -473), false},
		{"entry-480", req(true, false, -480), false},
		{"tails-464", req(false, true, -464), true},
		{"tails-465", req(false, true, -465), false},
		{"tails-472", req(false, true, -472), false},
		{"entry-tails-464", req(true, true, -464), true},
		{"entry-tails-472", req(true, true, -472), false},
	}
}

// Entry and TailCalls without a lookup site reserve 8 and 16 bytes, not the
// 24 a lookup needs, in CheckLookupStack and the transform alike (ELF and
// raw forms); a request that may hold a lookup site still reserves 24.
func TestEntryTailReserve(t *testing.T) {
	for _, tc := range reserveCases() {
		t.Run(tc.name, func(t *testing.T) {
			check := func(form string, err error) {
				t.Helper()
				if tc.ok && err != nil {
					t.Fatalf("%s: %v", form, err)
				}
				if !tc.ok && !errors.Is(err, ErrRefused) {
					t.Fatalf("%s: want refusal, got %v", form, err)
				}
			}
			check("CheckLookupStack", CheckLookupStack(tc.req))
			// The fixture's own reference stays at the bound the audit claims.
			spec := func() *ebpf.CollectionSpec { return paddedTailCaller(max(tc.req.Stack.LowestOffset, -472)) }
			_, err := transformLookup(spec(), tc.req)
			check("elf", err)
			for _, numeric := range []bool{false, true} {
				p := rawLookupFixture(t, spec(), "caller", numeric)
				_, err := TransformLookupRaw(p, LookupRequestRaw{Entry: tc.req.Entry, TailCalls: tc.req.TailCalls, HookName: tc.req.HookName, Stack: tc.req.Stack})
				check(map[bool]string{false: "raw-symbolic", true: "raw-numeric"}[numeric], err)
			}
		})
	}
	for _, req := range []LookupRequest{
		{Entry: true, Auto: true, Stack: StackAudit{LowestOffset: -464}},
		{TailCalls: true, Site: LookupSelector{MapName: "m"}, Stack: StackAudit{LowestOffset: -464}},
	} {
		if err := CheckLookupStack(req); !errors.Is(err, ErrRefused) {
			t.Fatalf("%+v: a possible lookup site must reserve 24 bytes, got %v", req, err)
		}
	}
}

func findStackLimitCase(name string) stackLimitCase {
	for _, tc := range stackLimitCases() {
		if tc.name == name {
			return tc
		}
	}
	panic(name)
}

// The limit check walks callback references and hook calls, and sums whole
// chains, in the ELF and both raw call forms.
func TestStackLimitsAcrossCalls(t *testing.T) {
	for _, tc := range stackLimitCases() {
		t.Run(tc.name, func(t *testing.T) {
			check := func(form string, err error) {
				t.Helper()
				if tc.refuse == nil {
					if err != nil {
						t.Fatalf("%s: %v", form, err)
					}
					return
				}
				if !errors.Is(err, ErrRefused) {
					t.Fatalf("%s: want refusal, got %v", form, err)
				}
				for _, want := range tc.refuse {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("%s: refusal %q does not mention %q", form, err, want)
					}
				}
			}
			_, err := transformLookup(tc.spec(), tc.req)
			check("elf", err)
			for _, numeric := range []bool{false, true} {
				p := rawLookupFixture(t, tc.spec(), tc.req.ProgramName, numeric)
				_, err := TransformLookupRaw(p, LookupRequestRaw{Auto: tc.req.Auto, Entry: tc.req.Entry, TailCalls: tc.req.TailCalls, HookName: tc.req.HookName, Stack: tc.req.Stack})
				check(map[bool]string{false: "raw-symbolic", true: "raw-numeric"}[numeric], err)
			}
		})
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
		if hook.Untrusted != (hook.MapName == "flows") || hook.ReadOnly != hook.Untrusted {
			t.Fatalf("hook %s untrusted=%v read-only=%v", hook.Name, hook.Untrusted, hook.ReadOnly)
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
		if hook.Untrusted {
			assertNoPointerCompare(t, work.Programs["p"].Instructions, hook.Name)
		}
	}
	plan, err = transformLookup(multiMapFixtureFlags(bpfFWronlyProg), autoReq())
	if err != nil || len(plan.hooks) != 2 || !plan.hooks[1].Untrusted || plan.hooks[1].ReadOnly {
		t.Fatalf("write-only: %+v %v", plan, err)
	}
}

// With CopyReadOnly the read-only map keeps a typed hook and its site copies
// the 16-byte value below the four spill slots; a write-only map stays untrusted.
func TestLookupReadOnlyMapCopy(t *testing.T) {
	req := autoReq()
	req.CopyReadOnly = true
	work := multiMapFixtureFlags(bpfFRdonlyProg)
	plan, err := transformLookup(work, req)
	if err != nil || len(plan.hooks) != 2 {
		t.Fatalf("copy: %+v %v", plan, err)
	}
	for _, hook := range plan.hooks {
		if hook.Untrusted || hook.Copied != (hook.MapName == "flows") {
			t.Fatalf("hook %s untrusted=%v copied=%v", hook.Name, hook.Untrusted, hook.Copied)
		}
	}
	floor := int16(req.Stack.LowestOffset) - 32
	var stores []int16
	for _, ins := range work.Programs["p"].Instructions {
		if ins.OpCode.Class().IsStore() && ins.Dst == asm.RFP && ins.Offset < floor {
			stores = append(stores, ins.Offset)
		}
	}
	if !reflect.DeepEqual(stores, []int16{floor - 16, floor - 8}) {
		t.Fatalf("value copy stores at %v, want [%d %d]", stores, floor-16, floor-8)
	}
	plan, err = transformLookup(multiMapFixtureFlags(bpfFWronlyProg), req)
	if err != nil || !plan.hooks[1].Untrusted || plan.hooks[1].Copied {
		t.Fatalf("write-only: %+v %v", plan, err)
	}
	// A copy that does not fit is skipped under Auto, not refused: at -448 the
	// read-only flows copy (-496) passes the 480 bytes a frame calling a hook
	// may use, while the typed sessions hook (-472) fits.
	req.Stack.LowestOffset = -448
	plan, err = transformLookup(multiMapFixtureFlags(bpfFRdonlyProg), req)
	if err != nil || len(plan.hooks) != 1 || plan.hooks[0].MapName != "sessions" ||
		len(plan.skipped) != 1 || plan.skipped[0].MapName != "flows" || plan.skipped[0].Reason == "" {
		t.Fatalf("copy below the stack limit: %+v %v", plan, err)
	}
}

// With StaticUntrusted the hooks that would take arg:untrusted pointers are
// static and only return zero; with CopyReadOnly a read-only map keeps the
// copied typed hook.
func TestLookupStaticUntrusted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture *ebpf.CollectionSpec
		copyRO  bool
		static  string // the static hook's map, "" for the generic hook or none
		none    bool
	}{
		{"read-only", multiMapFixtureFlags(bpfFRdonlyProg), false, "flows", false},
		{"write-only", multiMapFixtureFlags(bpfFWronlyProg), true, "flows", false},
		{"read-only copied", multiMapFixtureFlags(bpfFRdonlyProg), true, "", true},
		{"generic", mapInMapFixture(), false, "", false},
	} {
		req := autoReq()
		req.StaticUntrusted, req.CopyReadOnly = true, tc.copyRO
		plan, err := transformLookup(tc.fixture, req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		statics := 0
		for _, hook := range plan.hooks {
			if hook.Untrusted || hook.Static != (!tc.none && hook.MapName == tc.static) {
				t.Fatalf("%s: hook %s untrusted=%v static=%v", tc.name, hook.Name, hook.Untrusted, hook.Static)
			}
			if !hook.Static {
				continue
			}
			statics++
			insns := tc.fixture.Programs["p"].Instructions
			for i, ins := range insns {
				if fn := btf.FuncMetadata(&ins); fn != nil && fn.Name == hook.Name {
					if fn.Linkage != btf.StaticFunc || fn.ParamTags != nil ||
						!sameInstr(ins, asm.Mov.Imm(asm.R0, 0).WithSymbol(hook.Name)) || insns[i+1].OpCode.JumpOp() != asm.Exit {
						t.Fatalf("%s: hook %s: %+v %v %v", tc.name, hook.Name, fn, ins, insns[i+1])
					}
				}
			}
		}
		if statics != map[bool]int{true: 0, false: 1}[tc.none] {
			t.Fatalf("%s: %d static hooks: %+v", tc.name, statics, plan.hooks)
		}
	}
}

// Dispatch generates one generic hook named HookName for every site and
// reports the sites grouped as without it.
func TestLookupDispatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture *ebpf.CollectionSpec
		req     func(*LookupRequest)
		kinds   []HookKind
	}{
		{"auto+entry", multiMapFixture(), func(r *LookupRequest) { r.Entry = true }, []HookKind{HookLookup, HookLookup, HookEntry}},
		{"single site", lookupFixture(), func(r *LookupRequest) { r.Auto, r.Site = false, LookupSelector{MapName: "sessions"} }, []HookKind{HookLookup}},
		{"generic", mapInMapFixture(), func(*LookupRequest) {}, []HookKind{HookLookup}},
	} {
		req := autoReq()
		req.Dispatch = true
		tc.req(&req)
		plan, err := transformLookup(tc.fixture, req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var kinds []HookKind
		for _, hook := range plan.hooks {
			if hook.Name != req.HookName || !hook.Dispatch || !hook.Untrusted || hook.Static {
				t.Fatalf("%s: hook %+v", tc.name, hook)
			}
			kinds = append(kinds, hook.Kind)
		}
		if !slices.Equal(kinds, tc.kinds) {
			t.Fatalf("%s: kinds %v, want %v", tc.name, kinds, tc.kinds)
		}
		insns := tc.fixture.Programs["p"].Instructions
		var funcs []string
		for _, ins := range insns {
			if fn := btf.FuncMetadata(&ins); fn != nil {
				funcs = append(funcs, fn.Name)
			}
		}
		if len(funcs) != 2 || funcs[1] != req.HookName || len(hookParams(t, insns, req.HookName)) != 5 {
			t.Fatalf("%s: functions %v", tc.name, funcs)
		}
		assertNoPointerCompare(t, insns, req.HookName)
	}
	// The entry spill, 6 entry, 11 lookup and 9 tail-call slots, and the
	// 6-slot hook (2 when static).
	for static, want := range map[bool]int{false: 33, true: 29} {
		spec := dispatchFixture()
		before := spec.Programs["p"].Instructions.Size()
		req := autoReq()
		req.Dispatch, req.Entry, req.TailCalls, req.StaticUntrusted = true, true, true, static
		if _, err := transformLookup(spec, req); err != nil {
			t.Fatal(err)
		}
		if got := int(spec.Programs["p"].Instructions.Size()-before) / asm.InstructionSize; got != want {
			t.Fatalf("static=%v: %d inserted slots, want %d", static, got, want)
		}
	}
	req := autoReq()
	req.Dispatch, req.CopyReadOnly = true, true
	if _, err := transformLookup(multiMapFixtureFlags(bpfFRdonlyProg), req); !errors.Is(err, ErrRefused) {
		t.Fatalf("Dispatch with CopyReadOnly: %v", err)
	}
	// No suffix is appended, so the longest hook name is accepted.
	req = autoReq()
	req.Dispatch, req.Entry, req.HookName = true, true, strings.Repeat("h", MaxHookName)
	if _, err := transformLookup(multiLookupFixture(), req); err != nil {
		t.Fatalf("longest dispatch hook name: %v", err)
	}
}

// assertNoPointerCompare checks that hook's body has no conditional jump: an
// arg:untrusted pointer compared with zero needs CAP_PERFMON.
func assertNoPointerCompare(t *testing.T, insns asm.Instructions, hook string) {
	t.Helper()
	in := false
	for _, ins := range insns {
		if fn := btf.FuncMetadata(&ins); fn != nil {
			in = fn.Name == hook
		}
		if in && ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() != asm.Exit {
			t.Fatalf("hook %s compares an untrusted pointer: %v", hook, ins)
		}
	}
}

func multiMapFixtureFlags(flags uint32) *ebpf.CollectionSpec {
	spec := multiMapFixture()
	spec.Maps["flows"].Flags = flags
	return spec
}

// CheckLookupStack accepts and refuses exactly the audited bounds that the
// transform's own spill-slot placement does.
func TestCheckLookupStack(t *testing.T) {
	for _, lo := range []int16{-8, -456, -457, -464, -480, -488, -512, -513, 1, -32768} {
		check := CheckLookupStack(LookupRequest{Stack: StackAudit{LowestOffset: lo}})
		req := lookupReq()
		req.Stack.LowestOffset = lo
		_, transform := transformLookup(lookupFixture(), req)
		if (check == nil) != (transform == nil) {
			t.Fatalf("lo=%d: CheckLookupStack=%v transform=%v", lo, check, transform)
		}
	}
}

// ValidateRaw checks the hook name, leaving room for the longest suffix the
// request's flags make the transform append, then the stack bound with
// CheckLookupStack's own message.
func TestValidateRaw(t *testing.T) {
	h := func(n int) string { return strings.Repeat("h", n) }
	m := LookupSelector{MapName: "m"}
	for _, tc := range []struct {
		name string
		req  LookupRequestRaw
		want string // "" accepts
	}{
		{"map-127", LookupRequestRaw{Site: m, HookName: h(MaxHookName)}, ""},
		{"map-128", LookupRequestRaw{Site: m, HookName: h(MaxHookName + 1)}, "valid C/BTF identifier"},
		{"bad-ident", LookupRequestRaw{Site: m, HookName: "bad-name"}, "valid C/BTF identifier"},
		{"auto-125", LookupRequestRaw{Auto: true, HookName: h(125)}, ""},
		{"auto-126", LookupRequestRaw{Auto: true, HookName: h(126)}, `suffix "_0"`},
		{"entry-121", LookupRequestRaw{Entry: true, HookName: h(121)}, ""},
		{"entry-122", LookupRequestRaw{Entry: true, HookName: h(122)}, `suffix "_entry"`},
		{"auto-entry-122", LookupRequestRaw{Auto: true, Entry: true, HookName: h(122)}, `suffix "_entry"`},
		{"tails-117", LookupRequestRaw{TailCalls: true, HookName: h(117)}, ""},
		{"tails-118", LookupRequestRaw{TailCalls: true, HookName: h(118)}, `suffix "_tail_call"`},
		{"dispatch-127", LookupRequestRaw{Auto: true, Entry: true, TailCalls: true, Dispatch: true, HookName: h(MaxHookName), Stack: StackAudit{LowestOffset: -448}}, ""},
		{"dispatch-copy", LookupRequestRaw{Auto: true, Dispatch: true, CopyReadOnly: true, HookName: "h"}, "does not combine with CopyReadOnly"},
		{"dispatch-stack", LookupRequestRaw{TailCalls: true, Dispatch: true, HookName: "h", Stack: StackAudit{LowestOffset: -449}}, "32 reserved bytes"},
		{"stack", LookupRequestRaw{Site: m, HookName: "h", Stack: StackAudit{LowestOffset: -457}}, "Stack.LowestOffset -457 leaves no room"},
	} {
		err := ValidateRaw(tc.req)
		if tc.want == "" && err != nil || tc.want != "" && (!errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// Auto skips a generic group whose map slot overflows the stack while keeping
// the typed hooks that fit, instead of refusing the whole transform.
func TestLookupAutoSkipsOverflowingGeneric(t *testing.T) {
	spec := multiMapFixture()
	spec.Maps["flows"].Type = ebpf.HashOfMaps // a map-in-map site goes to the generic hook
	req := autoReq()
	req.Stack.LowestOffset = -456 // the 4th slot (-488) is past the 480-byte site frame; the three base slots fit
	plan, err := transformLookup(spec, req)
	if err != nil || len(plan.hooks) != 1 || plan.hooks[0].MapName != "sessions" ||
		len(plan.skipped) != 1 || plan.skipped[0].SitePC != 18 || !strings.Contains(plan.skipped[0].Reason, "4th spill slot") {
		t.Fatalf("plan: %+v %v", plan, err)
	}
}

// Auto without Entry or TailCalls refuses when every lookup it found is
// dropped for its slots, rather than report success with nothing
// instrumented; the refusal leaves the input unchanged. mapInMapFixture's two
// lookups both go to the generic hook, whose map slot (-488) is past the
// 480-byte site frame at -456. ELF and both raw forms.
func TestLookupAutoNothingFits(t *testing.T) {
	req := autoReq()
	req.Stack.LowestOffset = -456
	check := func(form string, err error) {
		t.Helper()
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no lookup site fits the audited stack (2 skipped)") {
			t.Fatalf("%s: want refusal, got %v", form, err)
		}
	}
	work := mapInMapFixture()
	before := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
	_, err := transformLookup(work, req)
	check("elf", err)
	if !reflect.DeepEqual(before, work.Programs["p"].Instructions) {
		t.Fatal("refusal mutated input")
	}
	for _, numeric := range []bool{false, true} {
		p := rawLookupFixture(t, mapInMapFixture(), "p", numeric)
		_, err := TransformLookupRaw(p, rawLookupRequest(req))
		check(map[bool]string{false: "raw-symbolic", true: "raw-numeric"}[numeric], err)
	}
}

// Auto skips a group whose hook name cannot be formed within MaxHookName and
// keeps the others; it refuses only when no group is left.
func TestAutoHookNameLength(t *testing.T) {
	req := autoReq()
	req.HookName = strings.Repeat("h", MaxHookName-1)
	if _, err := transformLookup(multiLookupFixture(), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no supported lookup sites (2 skipped)") {
		t.Fatalf("overlong auto hook name: %v", err)
	}
	// With a 125-byte prefix, PREFIX_<index> fits for indexes 0-9 only.
	var sites []discoveredLookup
	for i := range 11 {
		name := fmt.Sprintf("map_with_a_long_name_%d", i)
		sites = append(sites, discoveredLookup{LookupSite: LookupSite{MapName: name, SitePC: uint32(i)}, mapID: name})
	}
	req.HookName = strings.Repeat("h", MaxHookName-2)
	groups, skipped, err := selectLookups(sites, req, nil)
	if err != nil || len(groups) != 10 || len(skipped) != 1 || skipped[0].SitePC != 10 ||
		skipped[0].Reason != fmt.Sprintf("hook name %q is longer than 127 bytes", req.HookName+"_10") {
		t.Fatalf("groups=%d skipped=%+v err=%v", len(groups), skipped, err)
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

// Both map-in-map lookups go to the generic hook, which saves R1 before each
// helper; explicit selection still refuses them.
func TestLookupGenericHook(t *testing.T) {
	work := mapInMapFixture()
	plan, err := transformLookup(work, autoReq())
	if err != nil || len(plan.hooks) != 1 || !plan.hooks[0].Generic || len(plan.hooks[0].Sites) != 2 || plan.hooks[0].Name != "lookup_hook_any" {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	out := work.Programs["p"].Instructions
	for i, ins := range out {
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnMapLookupElem) &&
			!sameInstr(out[i-1], asm.StoreMem(asm.RFP, -40, asm.R1, asm.DWord)) {
			t.Fatalf("lookup at %d: %v", i, out[i-2:i+1])
		}
	}
	assertNoPointerCompare(t, out, "lookup_hook_any")
	req := lookupReq()
	req.Site.MapName = "outer"
	if _, err := transformLookup(mapInMapFixture(), req); !errors.Is(err, ErrRefused) {
		t.Fatalf("explicit map-in-map selection: %v", err)
	}
}
