package inject

import (
	"errors"
	"reflect"
	"testing"

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
