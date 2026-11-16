package inject

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// The transform golden pins what the lookup transform returns for a fixed
// set of requests, so a change that should leave existing requests alone
// shows that it does. A change that means to move the output regenerates
// the file:
//
//	go test ./pkg/inject -run '^TestTransformGolden$' -update
var goldenUpdate = flag.Bool("update", false, "rewrite testdata/transform.golden from the current transform")

const goldenFile = "testdata/transform.golden"

// goldenEquivConfigs are the configs of TestBpfMapCallEquivalence, which
// keeps its list inline.
var goldenEquivConfigs = []string{"typed-any", "typed-error", "typed-miss", "static-any", "dispatch-any", "dispatch-static", "copy-readonly",
	"typed-any/miss-first", "typed-error/miss-first", "dispatch-any/miss-first", "copy-readonly/miss-first"}

type goldenCase struct {
	name string
	spec func() *ebpf.CollectionSpec
	req  LookupRequest
}

// goldenCases are the generated equivalence programs under every config,
// then the hand-written fixtures of the unit and kernel tests under the
// requests those tests make.
func goldenCases() []goldenCase {
	var cases []goldenCase
	// Seeds 1 and 15 are random entry programs; 2-14 are the fixed feature
	// programs, which 16-28 repeat.
	for seed := uint64(1); seed <= 28; seed++ {
		c := newEquivCase(seed)
		for _, config := range goldenEquivConfigs {
			cases = append(cases, goldenCase{fmt.Sprintf("equiv/seed=%d/%s", seed, config), c.spec, c.request(config)})
		}
	}
	add := func(name string, spec func() *ebpf.CollectionSpec, req LookupRequest, edits ...func(*LookupRequest)) {
		for _, edit := range edits {
			edit(&req)
		}
		cases = append(cases, goldenCase{name, spec, req})
	}
	floor := func(off int16) func(*LookupRequest) {
		return func(r *LookupRequest) { r.Stack.LowestOffset = off }
	}
	lookups := func(when LookupWhen) func(*LookupRequest) { return func(r *LookupRequest) { r.Lookups = when } }
	missFirst := func(r *LookupRequest) { r.MissFirst = true }
	entry := func(r *LookupRequest) { r.Entry = true }
	static := func(r *LookupRequest) { r.StaticUntrusted = true }
	copied := func(r *LookupRequest) { r.CopyReadOnly = true }
	dispatch := func(r *LookupRequest) { r.Dispatch = true }
	obs := LookupRequest{ProgramName: "p", Auto: true, HookName: "obs", Stack: StackAudit{LowestOffset: -8}}
	frames := func(rounding int, floors map[string]int16) func(*LookupRequest) {
		return func(r *LookupRequest) {
			r.Stack = StackAudit{Frames: floors, Source: "verifier", FrameRounding: rounding}
		}
	}

	// One selected lookup: the typed hook without a site argument.
	add("lookup/hit", lookupFixture, lookupReq())
	add("lookup/miss", lookupFixture, lookupReq(), lookups(LookupMiss))
	add("lookup/any", lookupFixture, lookupReq(), lookups(LookupAny))
	add("lookup/hit-miss-first", lookupFixture, lookupReq(), missFirst)
	add("lookup/any-miss-first", lookupFixture, lookupReq(), lookups(LookupAny), missFirst)
	add("lookup/entry", lookupFixture, lookupReq(), entry)
	add("lookup/all-matches", multiLookupFixture, lookupReq(), func(r *LookupRequest) { r.Site.AllMatches = true })
	add("lookup/site-pcs", multiLookupFixture, lookupReq(), func(r *LookupRequest) { r.Site.FuncName, r.Site.SitePCs = "p", []uint32{18} })
	add("lookup/lpm", lpmFixture, lookupReq())
	for _, symbolic := range []bool{false, true} {
		add(fmt.Sprintf("lookup/before-subprograms/symbolic=%t", symbolic),
			func() *ebpf.CollectionSpec { return callbackLookupFixture(symbolic) }, lookupReq(), floor(-24))
	}
	add("lookup/tc", func() *ebpf.CollectionSpec { return asTC(lookupFixture()) }, lookupReq(), entry)
	add("lookup/cgroup-skb", func() *ebpf.CollectionSpec { return asCGroupSKB(lookupFixture()) }, lookupReq(), entry)
	add("lookup/netfilter", func() *ebpf.CollectionSpec { return asNetfilter(lookupFixture()) }, lookupReq(), entry)
	readOnly := func() *ebpf.CollectionSpec { return multiMapFixtureFlags(bpfFRdonlyProg) }
	flows := func(r *LookupRequest) { r.Site.MapName, r.Lookups = "flows", LookupAny }
	add("lookup/read-only", readOnly, lookupReq(), flows)
	add("lookup/read-only-copy", readOnly, lookupReq(), flows, copied)
	add("lookup/read-only-static", readOnly, lookupReq(), flows, static)

	// Auto: a typed hook per map with the site, and the generic hook.
	add("auto/per-map", multiMapFixture, autoReq())
	add("auto/one-map", multiLookupFixture, autoReq())
	add("auto/miss", multiMapFixture, autoReq(), lookups(LookupMiss))
	add("auto/any", multiMapFixture, autoReq(), lookups(LookupAny))
	add("auto/any-miss-first", multiMapFixture, autoReq(), lookups(LookupAny), missFirst)
	add("auto/entry", multiMapFixture, autoReq(), entry)
	add("auto/maps", multiMapFixture, autoReq(), func(r *LookupRequest) { r.Maps = []string{"flows"} })
	add("auto/read-only", readOnly, autoReq(), lookups(LookupAny))
	add("auto/read-only-copy", readOnly, autoReq(), lookups(LookupAny), copied)
	add("auto/read-only-static", readOnly, autoReq(), lookups(LookupAny), static)
	add("auto/write-only", func() *ebpf.CollectionSpec { return multiMapFixtureFlags(bpfFWronlyProg) }, autoReq())
	add("auto/generic", mapInMapFixture, obs)
	add("auto/generic-any", mapInMapFixture, obs, lookups(LookupAny))
	add("auto/generic-miss-first", mapInMapFixture, obs, lookups(LookupAny), missFirst)
	add("auto/generic-static", mapInMapFixture, obs, static)
	add("auto/percpu", percpuFixture, autoReq(), lookups(LookupAny))
	for _, kind := range []struct {
		typ  ebpf.MapType
		size uint32
	}{{ebpf.XSKMap, 4}, {ebpf.SockMap, 8}, {ebpf.SockHash, 8}, {ebpf.DevMap, 4}, {ebpf.DevMap, 8}, {ebpf.DevMapHash, 4}} {
		add(fmt.Sprintf("auto/kind/%s-%d", kind.typ, kind.size), func() *ebpf.CollectionSpec { return kindFixture(kind.typ, kind.size) }, obs)
	}
	devMap := func() *ebpf.CollectionSpec { return kindFixture(ebpf.DevMap, 4) }
	add("auto/kind/DevMap-4/static", devMap, obs, static)
	add("auto/kind/DevMap-4/copy", devMap, obs, copied)
	add("auto/kind/DevMap-4/dispatch", devMap, obs, dispatch)
	for _, kind := range []string{"spin_lock", "timer", "kptr"} {
		add("auto/special/"+kind, func() *ebpf.CollectionSpec { return withSpecialValue(lookupFixture(), kind) }, autoReq())
	}
	add("auto/special/spin_lock/static", func() *ebpf.CollectionSpec { return withSpecialValue(lookupFixture(), "spin_lock") }, autoReq(), static)
	for _, source := range []string{"register", "slot", "dead"} {
		spec := func() *ebpf.CollectionSpec { return subprogramLookupFixture(source) }
		add("auto/subprogram/"+source, spec, autoReq(), floor(-16))
		add("auto/subprogram/"+source+"/dispatch", spec, autoReq(), floor(-16), dispatch, lookups(LookupAny))
	}
	add("auto/subprogram/per-frame", func() *ebpf.CollectionSpec { return subprogramLookupFixture("register") }, autoReq(),
		frames(16, map[string]int16{"p": -8, "sub": -168}))
	add("auto/tc", func() *ebpf.CollectionSpec { return asTC(multiMapFixture()) }, autoReq(), entry)
	add("auto/netfilter", func() *ebpf.CollectionSpec { return asNetfilter(multiMapFixture()) }, autoReq(), entry)

	// A frame without room for the slots calls a wrapper.
	deep := func() *ebpf.CollectionSpec { return deepLookupFixture(-504) }
	for _, when := range []LookupWhen{LookupHit, LookupMiss, LookupAny} {
		add("wrapper/"+string(when), deep, deepReq(-504, when))
		add("wrapper/generic/"+string(when), mapInMapDeepFixture, deepReq(-504, when))
	}
	add("wrapper/miss-first", deep, deepReq(-504, LookupAny), missFirst)
	add("wrapper/dispatch", deep, deepReq(-504, LookupAny), dispatch, static)
	add("wrapper/percpu", percpuDeepFixture, deepReq(-504, LookupHit))
	add("wrapper/room", func() *ebpf.CollectionSpec { return deepLookupFixture(-480) }, deepReq(-480, LookupAny))
	for _, source := range []string{"register", "slot"} {
		add("wrapper/subprogram/"+source, func() *ebpf.CollectionSpec {
			spec := subprogramLookupFixture(source)
			insns := spec.Programs["p"].Instructions
			spec.Programs["p"].Instructions = slices.Insert(insns, 5, asm.StoreImm(asm.RFP, -496, 0, asm.Word))
			return spec
		}, autoReq(), frames(16, map[string]int16{"p": 0, "sub": -496}))
	}

	// The context passed down to functions that lack one, and callbacks.
	for _, saved := range []bool{false, true} {
		spec := func() *ebpf.CollectionSpec { return passSiteFixture(saved) }
		add(fmt.Sprintf("pass/saved=%t", saved), spec, passRequest())
		add(fmt.Sprintf("pass/saved=%t/dispatch", saved), spec, passRequest(), entry, dispatch, lookups(LookupAny))
	}
	add("pass/caller", passCallerFixture, passRequest())
	add("pass/direct", directPassFixture, passRequest())
	add("pass/direct-deep", directPassFixture, passRequest(), entry, dispatch, frames(16, map[string]int16{"p": 0, "leaf": -488}))
	for _, entrySite := range []bool{false, true} {
		add(fmt.Sprintf("pass/callback/entry-site=%t", entrySite), func() *ebpf.CollectionSpec { return callbackPassFixture(entrySite) }, autoReq(),
			frames(32, map[string]int16{"p": -16, "cb": -48, "mid": -400, "leaf": -16}))
		for _, form := range []string{"loop", "loop_rt0", "foreach"} {
			spec := func() *ebpf.CollectionSpec { return callbackSiteFixture(form, entrySite) }
			name := fmt.Sprintf("callback/%s/entry-site=%t", form, entrySite)
			add(name, spec, callbackRequest(false), lookups(LookupAny))
			add(name+"/dispatch-static", spec, callbackRequest(true))
		}
	}
	add("callback/generic", genericCallbackFixture, autoReq(), static, frames(0, map[string]int16{"p": -16, "cb": -8}))
	add("callback/generic/no-floor", genericCallbackFixture, autoReq(), static, frames(0, map[string]int16{"p": -16}))

	// Dispatch: one hook for every site.
	add("dispatch/lookups", multiMapFixture, autoReq(), dispatch)
	add("dispatch/lookups-static", multiMapFixture, autoReq(), dispatch, static)
	add("dispatch/miss", multiMapFixture, autoReq(), dispatch, lookups(LookupMiss))
	add("dispatch/any-miss-first", multiMapFixture, autoReq(), dispatch, lookups(LookupAny), missFirst)
	add("dispatch/generic", mapInMapFixture, obs, dispatch)
	for _, typ := range []struct {
		name string
		conv func(*ebpf.CollectionSpec) *ebpf.CollectionSpec
	}{{"xdp", func(spec *ebpf.CollectionSpec) *ebpf.CollectionSpec { return spec }}, {"tc", asTC}, {"netfilter", asNetfilter}} {
		spec := func() *ebpf.CollectionSpec { return typ.conv(dispatchFixture()) }
		all := func(r *LookupRequest) { r.Entry, r.TailCalls, r.Lookups = true, true, LookupAny }
		add("dispatch/entry-tail-call/"+typ.name, spec, obs, all, dispatch)
		add("dispatch/entry-tail-call/"+typ.name+"/static", spec, obs, all, dispatch, static)
		add("auto/entry-tail-call/"+typ.name, spec, obs, all)
	}

	// Updates and deletes.
	add("map-call/mixed", mixedFixture, mixedReq())
	add("map-call/mixed-dispatch", mixedFixture, mixedReq(), dispatch)
	for _, when := range []CallWhen{CallAny, CallError} {
		calls := func(r *LookupRequest) { r.Lookups, r.Updates, r.Deletes = LookupNone, when, when }
		add("map-call/typed/"+string(when), mapCallFixture, autoReq(), calls, floor(-24))
		add("map-call/tc/"+string(when), func() *ebpf.CollectionSpec { return asTC(mapCallFixture()) }, autoReq(), calls, floor(-24))
		add("map-call/dispatch/"+string(when), mapCallFixture, autoReq(), calls, floor(-440), dispatch)
		add("map-call/dispatch-static/"+string(when), mapCallFixture, autoReq(), calls, floor(-440), dispatch, static)
		add("map-call/inner-update/"+string(when), innerUpdateFixture, obs, calls, floor(-24))
		add("map-call/inner-update-static/"+string(when), innerUpdateFixture, obs, calls, floor(-24), static)
		add("map-call/sock-update/"+string(when), sockUpdateFixture, obs, calls)
		add("map-call/special-update/"+string(when), func() *ebpf.CollectionSpec { return specialUpdateFixture("spin_lock") }, autoReq(), calls, floor(-24))
	}
	add("map-call/stack-bound", func() *ebpf.CollectionSpec { return stackBoundFixture(8) }, stackBoundRequest(false))
	add("map-call/stack-bound-dispatch", func() *ebpf.CollectionSpec { return stackBoundFixture(8) }, stackBoundRequest(true))
	add("map-call/stack-bound-refused", func() *ebpf.CollectionSpec { return stackBoundFixture(248) }, stackBoundRequest(false))

	// Pushes, pops and peeks.
	for _, when := range []CallWhen{CallAny, CallError} {
		calls := func(r *LookupRequest) {
			r.Lookups, r.Pushes, r.Pops, r.Peeks, r.Updates = LookupNone, when, when, when, when
		}
		for _, typ := range []ebpf.MapType{ebpf.Queue, ebpf.BloomFilter} {
			spec := func() *ebpf.CollectionSpec { return queueFixture(typ, typ == ebpf.BloomFilter) }
			name := fmt.Sprintf("queue/%s/%s", typ, when)
			add(name, spec, autoReq(), calls)
			add(name+"/dispatch", spec, autoReq(), calls, dispatch)
			add(name+"/tc", func() *ebpf.CollectionSpec { return asTC(spec()) }, autoReq(), calls)
		}
		add("queue/inner/"+string(when), innerQueueFixture, obs, calls, floor(-16))
		add("queue/inner-static/"+string(when), innerQueueFixture, obs, calls, floor(-16), static)
		add("queue/pop-uninit/"+string(when), popUninitFixture, autoReq(), calls)
		add("queue/pop-uninit-dispatch/"+string(when), popUninitFixture, autoReq(), calls, dispatch, static)
		add("queue/read-only-arg/"+string(when), readOnlyArgFixture, autoReq(), calls)
		add("queue/read-only-arg-static/"+string(when), readOnlyArgFixture, autoReq(), calls, static)
	}

	// Entry and failed tail calls, in the entry function and in a subprogram.
	tails := LookupRequest{ProgramName: "caller", TailCalls: true, HookName: "h", Stack: StackAudit{LowestOffset: -8}}
	for _, caller := range []struct {
		name string
		spec func() *ebpf.CollectionSpec
	}{{"entry-function", tailCallerFixture}, {"subprogram", subTailCallerFixture}, {"subprogram-fallthrough-call", subTailCallerWithFallthroughCallFixture}} {
		add("tail-call/"+caller.name, caller.spec, tails)
		add("tail-call/"+caller.name+"/entry", caller.spec, tails, entry)
		add("tail-call/"+caller.name+"/dispatch", caller.spec, tails, entry, dispatch)
		add("tail-call/"+caller.name+"/dispatch-static", caller.spec, tails, entry, dispatch, static)
	}
	add("tail-call/subprogram-lookup", subprogramTailLookupFixture, autoReq(), floor(-16), func(r *LookupRequest) { r.TailCalls = true })
	add("tail-call/auto-without-lookups", tailCallerFixture, tails, entry, func(r *LookupRequest) { r.Auto = true })
	add("refused/no-lookups", tailCallerFixture, tails, func(r *LookupRequest) { r.Auto, r.TailCalls = true, false })

	// Shared code the call-site hooks also use.
	add("stack/fib-lookup-buffer", fibStackFixture, autoReq(), frames(16, map[string]int16{"p": -8, "sub": -168, "fib": -400}))
	return cases
}

// fibStackFixture is subprogramLookupFixture("register") whose sub first
// calls the static function fib, which passes the stack buffer fp-64 to
// bpf_fib_lookup.
func fibStackFixture() *ebpf.CollectionSpec {
	spec := subprogramLookupFixture("register")
	insns := spec.Programs["p"].Instructions
	at := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Symbol() == "sub" }) + 1
	insns = slices.Insert(insns, at, asm.Mov.Reg(asm.R1, asm.R6), asm.Call.Label("fib"))
	proto := btf.FuncMetadata(&insns[at-1]).Type
	fib := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R2, asm.RFP).WithSymbol("fib").WithSource(asm.Comment("fib")),
			&btf.Func{Name: "fib", Linkage: btf.StaticFunc, Type: proto}),
		asm.Add.Imm(asm.R2, -64), asm.Mov.Imm(asm.R3, 64), asm.Mov.Imm(asm.R4, 0),
		asm.FnFibLookup.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return(),
	}
	spec.Programs["p"].Instructions = append(insns, fib...)
	return spec
}

// goldenHash is the hash of one transform result: the wire instructions,
// each instruction's symbol and reference, which the wire form drops, the
// BTF, func_info and line_info, and the plan as JSON.
func goldenHash(t *testing.T, insns asm.Instructions, btfBytes, funcInfo, lineInfo []byte, hooks []LookupHook, sites, skipped []LookupSite) string {
	t.Helper()
	h := sha256.New()
	for _, ins := range insns {
		h.Write([]byte(ins.Symbol() + "\x00" + ins.Reference() + "\x00"))
	}
	if err := insns.Marshal(h, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(struct {
		Hooks          []LookupHook
		Sites, Skipped []LookupSite
	}{hooks, sites, skipped})
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range [][]byte{btfBytes, funcInfo, lineInfo, plan} {
		h.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(part))))
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestTransformGolden compares each case's result with testdata/transform.golden,
// through transformLookup, which TransformLookup runs on a parsed ELF, and
// through TransformLookupRaw on the same program with numeric map references.
// A refusal is pinned by its message. The ELF path returns instructions that
// carry their metadata; it is hashed in the form a loader encodes it to.
func TestTransformGolden(t *testing.T) {
	if rawByteOrder() != binary.LittleEndian {
		t.Skip("the raw path's BTF, func_info and line_info are native-endian; the golden is little-endian")
	}
	var lines []string
	seen := map[string]bool{}
	for _, c := range goldenCases() {
		if seen[c.name] {
			t.Fatalf("duplicate case %s", c.name)
		}
		seen[c.name] = true

		work := c.spec()
		value := ""
		if plan, err := transformLookup(work, c.req); err != nil {
			value = "error " + strconv.Quote(err.Error())
		} else {
			p, blob := rawLookupFixtureBTF(t, work, c.req.ProgramName, false)
			value = goldenHash(t, p.Instructions, blob, p.FuncInfo, p.LineInfo, plan.hooks, plan.sites, plan.skipped)
		}
		lines = append(lines, c.name+"\telf\t"+value)

		r := c.req
		raw := LookupRequestRaw{Site: r.Site, Auto: r.Auto, Maps: r.Maps, Entry: r.Entry, TailCalls: r.TailCalls,
			CopyReadOnly: r.CopyReadOnly, StaticUntrusted: r.StaticUntrusted, Dispatch: r.Dispatch, MissFirst: r.MissFirst,
			Lookups: r.Lookups, Updates: r.Updates, Deletes: r.Deletes, Pushes: r.Pushes, Pops: r.Pops, Peeks: r.Peeks,
			HookName: r.HookName, Stack: r.Stack}
		back := raw.Request()
		back.ProgramName = r.ProgramName
		if !reflect.DeepEqual(back, r) {
			t.Fatalf("%s: the raw request drops a field: %+v, want %+v", c.name, back, r)
		}
		if got, err := TransformLookupRaw(rawLookupFixture(t, c.spec(), r.ProgramName, true), raw); err != nil {
			value = "error " + strconv.Quote(err.Error())
		} else {
			value = goldenHash(t, got.Instructions, got.BTFBytes, got.FuncInfo, got.LineInfo, got.Hooks, got.Sites, got.Skipped)
		}
		lines = append(lines, c.name+"\traw\t"+value)
	}
	if *goldenUpdate {
		if err := os.WriteFile(goldenFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	file, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("%v; run `go test ./pkg/inject -run '^TestTransformGolden$' -update`", err)
	}
	want := strings.Split(strings.TrimSuffix(string(file), "\n"), "\n")
	for _, line := range lines {
		if !slices.Contains(want, line) {
			t.Errorf("not in %s: %s", goldenFile, line)
		}
	}
	for _, line := range want {
		if !slices.Contains(lines, line) {
			t.Errorf("only in %s: %s", goldenFile, line)
		}
	}
	if t.Failed() {
		t.Log("if the change is intended, run `go test ./pkg/inject -run '^TestTransformGolden$' -update`")
	}
}
