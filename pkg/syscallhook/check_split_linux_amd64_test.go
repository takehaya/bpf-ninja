//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// wrappedSubprogram is the raw load of p(ctx), which calls sub(ctx), whose
// frame reaches -496 and which looks up key 0 in sessions (fd 7). Under the
// 6.9+ JIT rule the lookup's slots do not fit below that floor, so the
// transform moves the lookup into a wrapper function.
func wrappedSubprogram(t *testing.T) inject.RawProgram {
	t.Helper()
	u32 := &btf.Int{Name: "u32", Size: 4}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	ctx := &btf.Pointer{Target: &btf.Struct{Name: "xdp_md", Size: 24, Members: []btf.Member{
		{Name: "data", Type: u32}, {Name: "data_end", Type: u32, Offset: 32}}}}
	pFn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: i32, Params: []btf.FuncParam{{Name: "ctx", Type: ctx}}}}
	subFn := &btf.Func{Name: "sub", Linkage: btf.StaticFunc, Type: &btf.FuncProto{Return: i32, Params: []btf.FuncParam{{Name: "ctx", Type: ctx}}}}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R2, 1).WithSymbol("p").WithSource(asm.Comment("entry")), pFn),
		asm.Call.Label("sub"), asm.Mov.Imm(asm.R0, 2), asm.Return(),
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R6, asm.R1).WithSymbol("sub").WithSource(asm.Comment("sub")), subFn),
		asm.StoreImm(asm.RFP, -496, 0, asm.Word),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 7), asm.FnMapLookupElem.Call(),
		asm.Mov.Imm(asm.R0, 0), asm.Return(),
	}
	builder := new(btf.Builder)
	fi, li, err := btf.MarshalExtInfos(insns, builder)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	types, err := btf.LoadSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	// As the tracee hands it over: no symbols or metadata, numeric map fds.
	var buf bytes.Buffer
	if err := insns.Marshal(&buf, wire); err != nil {
		t.Fatal(err)
	}
	raw, err := asm.AppendInstructions(nil, &buf, wire, "linux")
	if err != nil {
		t.Fatal(err)
	}
	value := &btf.Struct{Name: "session", Size: 16, Members: []btf.Member{{Name: "a", Type: &btf.Int{Name: "u64", Size: 8}}, {Name: "b", Type: &btf.Int{Name: "u64", Size: 8}, Offset: 64}}}
	return inject.RawProgram{Instructions: raw, Type: ebpf.XDP, BTF: types, FuncInfo: fi, LineInfo: li,
		Maps: map[int32]inject.RawMap{7: {Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 16, Key: u32, Value: value}}}
}

// loadCheckInputs gives the checker each hook as a hook span and each
// wrapper as a wrapper span, and the checker accepts the load built from them.
func TestLoadCheckInputsSplitsWrappers(t *testing.T) {
	raw := wrappedSubprogram(t)
	injectcheck.Label(raw.Instructions)
	stack := inject.StackReport{Source: "verifier", FrameRounding: 16, Functions: []inject.FrameFloor{
		{Name: "p", Start: 0, Floor: 0}, {Name: "sub", Start: 4, Floor: -496}}}
	audit := inject.StackAudit{Frames: stack.Frames(), Source: stack.Source, FrameRounding: stack.FrameRounding}
	result, err := inject.TransformLookupRaw(raw, inject.LookupRequestRaw{Auto: true, HookName: "lookup_hook", Stack: audit})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].Wrapper == "" {
		t.Fatalf("site not wrapped: %+v", result.Sites)
	}
	wrapper := result.Sites[0].Wrapper
	cert, premises, err := loadCheckInputs(raw.Instructions, result, audit, stack)
	if err != nil {
		t.Fatal(err)
	}
	name := func(s injectcheck.Span) string { return btf.FuncMetadata(&result.Instructions[s.Start]).Name }
	if len(cert.Wrappers) != 1 || name(cert.Wrappers[0]) != wrapper {
		t.Fatalf("wrapper spans %+v, want one for %s", cert.Wrappers, wrapper)
	}
	var hooks []string
	for _, s := range cert.Hooks {
		hooks = append(hooks, name(s))
	}
	if !slices.Equal(hooks, []string{"lookup_hook_sessions"}) {
		t.Fatalf("hook spans name %v", hooks)
	}
	var encoded bytes.Buffer
	if err := result.Instructions.Marshal(&encoded, wire); err != nil {
		t.Fatal(err)
	}
	if verdict, err := checkLoad(raw.Instructions, encoded.Bytes(), cert, premises); err != nil || !verdict.Accepted {
		t.Fatalf("checker: %+v: %v", verdict, err)
	}
}
