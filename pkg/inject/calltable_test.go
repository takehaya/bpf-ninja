package inject

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
)

// specOf is the parsed BTF of types.
func specOf(t testing.TB, types ...btf.Type) *btf.Spec {
	t.Helper()
	builder, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// testKernelSpec is a kernel BTF with the conntrack kfuncs bpf_xdp_ct_lookup,
// bpf_skb_ct_lookup and bpf_ct_release, struct bpf_fib_lookup (64 bytes) and
// struct bpf_ct_opts (16 bytes).
func testKernelSpec(t testing.TB) *btf.Spec {
	t.Helper()
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}
	types := []btf.Type{
		&btf.Struct{Name: "bpf_fib_lookup", Size: 64},
		&btf.Struct{Name: "bpf_ct_opts", Size: 16},
	}
	for _, name := range []string{"bpf_xdp_ct_lookup", "bpf_skb_ct_lookup", "bpf_ct_release"} {
		types = append(types, &btf.Func{Name: name, Type: proto, Linkage: btf.GlobalFunc})
	}
	return specOf(t, types...)
}

// testKfunc is the raw-path call of the kfunc name in spec.
func testKfunc(t testing.TB, spec *btf.Spec, name string) asm.Instruction {
	t.Helper()
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		t.Fatal(err)
	}
	id, err := spec.TypeID(fn)
	if err != nil {
		t.Fatal(err)
	}
	return kfuncCall(int64(id))
}

func callRow(t testing.TB, name string) *CallRow {
	t.Helper()
	for i := range callTable {
		if callTable[i].Name == name {
			return &callTable[i]
		}
	}
	t.Fatalf("no row %s", name)
	return nil
}

func TestCallTable(t *testing.T) {
	want := []string{"bpf_ktime_get_ns", "bpf_jiffies64", "bpf_get_prandom_u32", "bpf_get_smp_processor_id", "bpf_get_hash_recalc", "bpf_get_socket_cookie", "bpf_xdp_get_buff_len", "bpf_skb_load_bytes", "bpf_xdp_load_bytes", "bpf_sk_lookup_tcp", "bpf_sk_lookup_udp", "bpf_skc_lookup_tcp", "bpf_probe_read_kernel", "bpf_fib_lookup", "bpf_xdp_ct_lookup", "bpf_skb_ct_lookup",
		"bpf_xdp_metadata_rx_timestamp", "bpf_xdp_metadata_rx_hash", "bpf_xdp_metadata_rx_vlan_tag"}
	if got := SupportedCalls(); !slices.Equal(got, want) {
		t.Fatalf("SupportedCalls() = %v, want %v", got, want)
	}
	for name, id := range map[string]asm.BuiltinFunc{"bpf_ktime_get_ns": 5, "bpf_jiffies64": 118, "bpf_get_prandom_u32": 7, "bpf_get_smp_processor_id": 8, "bpf_get_hash_recalc": 34, "bpf_get_socket_cookie": 46, "bpf_xdp_get_buff_len": 188, "bpf_skb_load_bytes": 26, "bpf_xdp_load_bytes": 189, "bpf_sk_lookup_tcp": 84, "bpf_sk_lookup_udp": 85, "bpf_skc_lookup_tcp": 99, "bpf_probe_read_kernel": 113, "bpf_fib_lookup": 69} {
		if got := callRow(t, name).Helper; got != id {
			t.Errorf("%s helper %d, want %d", name, got, id)
		}
	}
}

func TestCallee(t *testing.T) {
	kernel := testKernelSpec(t)
	byID := testKfunc(t, kernel, "bpf_skb_ct_lookup")
	module := byID
	module.Offset = 1
	var opts *btf.Struct
	if err := kernel.TypeByName("bpf_ct_opts", &opts); err != nil {
		t.Fatal(err)
	}
	optsID, err := kernel.TypeID(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		ins    asm.Instruction
		kernel *btf.Spec
		row    string
		callee string
		named  bool
	}{
		{"helper", asm.FnKtimeGetNs.Call(), nil, "bpf_ktime_get_ns", "bpf_ktime_get_ns", true},
		{"helper with argument", asm.FnFibLookup.Call(), kernel, "bpf_fib_lookup", "bpf_fib_lookup", true},
		{"helper outside table", asm.FnSpinLock.Call(), kernel, "", "", true},
		{"not a call", asm.Mov.Imm(asm.R0, 0), kernel, "", "", true},
		{"bpf-to-bpf call", asm.Call.Label("f"), kernel, "", "", true},
		{"referenced kfunc", kfuncCall(-1).WithReference("bpf_xdp_ct_lookup"), nil, "bpf_xdp_ct_lookup", "bpf_xdp_ct_lookup", true},
		{"referenced kfunc outside table", kfuncCall(-1).WithReference("bpf_ct_release"), nil, "", "bpf_ct_release", true},
		{"kfunc by id", byID, kernel, "bpf_skb_ct_lookup", "bpf_skb_ct_lookup", true},
		{"kfunc by id outside table", testKfunc(t, kernel, "bpf_ct_release"), kernel, "", "bpf_ct_release", true},
		{"kfunc id of a struct", kfuncCall(int64(optsID)), kernel, "", fmt.Sprintf("kfunc_0_%d", optsID), false},
		{"kfunc id not in kernel", kfuncCall(1 << 20), kernel, "", "kfunc_0_1048576", false},
		{"module offset", module, kernel, "", fmt.Sprintf("kfunc_%d_%d", module.Offset, module.Constant), false},
		{"nil kernel", byID, nil, "", fmt.Sprintf("kfunc_0_%d", byID.Constant), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, name, named := callee(&tc.ins, tc.kernel, nil)
			got := ""
			if row != nil {
				got = row.Name
			}
			if got != tc.row || name != tc.callee || named != tc.named {
				t.Fatalf("callee = (%q, %q, %v), want (%q, %q, %v)", got, name, named, tc.row, tc.callee, tc.named)
			}
		})
	}
}

// A kfunc call with a nonzero offset is named through the module BTF of that
// fd_array offset, and stays unnamed without one or with an id it lacks.
func TestCalleeModule(t *testing.T) {
	kernel := testKernelSpec(t)
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}
	mod := specOf(t, &btf.Func{Name: "bpf_xdp_ct_lookup", Type: proto, Linkage: btf.GlobalFunc})
	call := testKfunc(t, mod, "bpf_xdp_ct_lookup")
	call.Offset = 2
	wrongID := kfuncCall(1 << 20)
	wrongID.Offset = 2
	for _, tc := range []struct {
		name    string
		ins     asm.Instruction
		modules map[int16]*btf.Spec
		row     string
		named   bool
	}{
		{"module entry", call, map[int16]*btf.Spec{2: mod}, "bpf_xdp_ct_lookup", true},
		{"no entry for offset", call, map[int16]*btf.Spec{1: mod}, "", false},
		{"no modules", call, nil, "", false},
		{"id not in module", wrongID, map[int16]*btf.Spec{2: mod}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, _, named := callee(&tc.ins, kernel, tc.modules)
			got := ""
			if row != nil {
				got = row.Name
			}
			if got != tc.row || named != tc.named {
				t.Fatalf("callee = (%q, %v), want (%q, %v)", got, named, tc.row, tc.named)
			}
		})
	}
}

func TestCallArgType(t *testing.T) {
	kernel := testKernelSpec(t)
	other := &btf.Struct{Name: "pdr_info", Size: 64}
	for _, tc := range []struct {
		name   string
		row    string
		n      uint32
		prog   *btf.Spec
		kernel *btf.Spec
		want   string // pointee name; "" for bytes
		size   uint32
		from   string // "prog", "kernel" or "bytes"
	}{
		{"eUPF-like: no struct in program", "bpf_fib_lookup", 64, specOf(t, other), kernel, "bpf_fib_lookup", 64, "kernel"},
		{"Calico-like: program struct", "bpf_fib_lookup", 64, specOf(t, &btf.Struct{Name: "bpf_fib_lookup", Size: 64}), kernel, "bpf_fib_lookup", 64, "prog"},
		{"program struct of another size", "bpf_fib_lookup", 64, specOf(t, &btf.Struct{Name: "bpf_fib_lookup", Size: 48}), kernel, "bpf_fib_lookup", 64, "kernel"},
		{"Flux-like: 12-byte program struct", "bpf_xdp_ct_lookup", 12, specOf(t, &btf.Struct{Name: "bpf_ct_opts", Size: 12}), kernel, "bpf_ct_opts", 12, "prog"},
		{"Flux-like: 12 bytes, kernel struct larger", "bpf_xdp_ct_lookup", 12, specOf(t, other), kernel, "", 12, "bytes"},
		{"natpool-like: ___local", "bpf_skb_ct_lookup", 16, specOf(t, &btf.Struct{Name: "bpf_ct_opts___local", Size: 16}), kernel, "bpf_ct_opts___local", 16, "prog"},
		{"kernel struct smaller than size", "bpf_xdp_ct_lookup", 20, nil, kernel, "bpf_ct_opts", 16, "kernel"},
		{"no BTF", "bpf_fib_lookup", 64, nil, nil, "", 64, "bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			typ, name := callArgType(callRow(t, tc.row), tc.n, tc.prog, tc.kernel)
			s, ok := typ.(*btf.Struct)
			if !ok || name != tc.want || s.Name != tc.want || s.Size != tc.size {
				t.Fatalf("callArgType = (%v, %q), want struct %q of %d bytes", typ, name, tc.want, tc.size)
			}
			var from string
			switch {
			case tc.prog != nil && slices.ContainsFunc(typesOf(tc.prog), func(p btf.Type) bool { return p == typ }):
				from = "prog"
			case len(s.Members) == 1 && s.Members[0].Name == "bytes":
				from = "bytes"
			default:
				var k *btf.Struct
				if err := tc.kernel.TypeByName(tc.want, &k); err != nil || k == s {
					t.Fatalf("pointee is not a copy of the kernel struct (err %v)", err)
				}
				from = "kernel"
			}
			if from != tc.from {
				t.Fatalf("pointee from %s, want %s", from, tc.from)
			}
		})
	}
}

func typesOf(spec *btf.Spec) []btf.Type {
	var types []btf.Type
	for typ, err := range spec.All() {
		if err == nil {
			types = append(types, typ)
		}
	}
	return types
}

// metadataKernelSpec is a kernel BTF with the prototypes of the XDP
// receive-metadata kfuncs.
func metadataKernelSpec(t testing.TB) *btf.Spec {
	t.Helper()
	ret := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	ctx := &btf.Pointer{Target: &btf.Const{Type: &btf.Struct{Name: "xdp_md", Size: 24}}}
	u16 := &btf.Typedef{Name: "u16", Type: &btf.Int{Name: "unsigned short", Size: 2}}
	be16 := &btf.Typedef{Name: "__be16", Type: &btf.Typedef{Name: "__u16", Type: &btf.Int{Name: "unsigned short", Size: 2}}}
	fn := func(name string, params ...btf.FuncParam) *btf.Func {
		return &btf.Func{Name: name, Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: ret, Params: append([]btf.FuncParam{{Name: "ctx", Type: ctx}}, params...)}}
	}
	return specOf(t,
		fn("bpf_xdp_metadata_rx_timestamp", btf.FuncParam{Name: "timestamp", Type: &btf.Pointer{Target: &btf.Typedef{Name: "u64", Type: &btf.Int{Name: "unsigned long long", Size: 8}}}}),
		fn("bpf_xdp_metadata_rx_hash", btf.FuncParam{Name: "hash", Type: &btf.Pointer{Target: &btf.Typedef{Name: "u32", Type: &btf.Int{Name: "unsigned int", Size: 4}}}},
			btf.FuncParam{Name: "rss_type", Type: &btf.Pointer{Target: &btf.Enum{Name: "xdp_rss_hash_type", Size: 4}}}),
		fn("bpf_xdp_metadata_rx_vlan_tag", btf.FuncParam{Name: "vlan_proto", Type: &btf.Pointer{Target: be16}},
			btf.FuncParam{Name: "vlan_tci", Type: &btf.Pointer{Target: u16}}),
		fn("bpf_not_a_pointer", btf.FuncParam{Name: "x", Type: ret}),
	)
}

// A receive-metadata value buffer that is not on the program's own stack
// (here the packet's data pointer) gets the untrusted hook, not the typed one.
func TestCallHookMetadataArgNotStack(t *testing.T) {
	spec := xdpMetadataFixture(kfuncCall(-1).WithReference("bpf_xdp_metadata_rx_timestamp"), false)
	insns := spec.Programs["p"].Instructions
	at := slices.IndexFunc(insns, func(ins asm.Instruction) bool {
		return ins.Dst == asm.R2 && ins.Src == asm.RFP && ins.OpCode.ALUOp() == asm.Mov
	})
	if at < 0 {
		t.Fatal("fixture has no R2 = R10")
	}
	insns[at] = asm.LoadMem(asm.R2, asm.R6, 0, asm.Word) // xdp_md->data
	insns[at+1] = asm.Mov.Reg(asm.R2, asm.R2)
	req := callReq("bpf_xdp_metadata_rx_timestamp")
	req.Kernel = metadataKernelSpec(t)
	plan, err := transformLookup(spec, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || !plan.hooks[0].Untrusted || plan.hooks[0].Static {
		t.Fatalf("hooks %+v skipped %+v, want one untrusted hook", plan.hooks, plan.skipped)
	}
}

// The receive-metadata rows take a value argument, whose size the prototype
// gives: the timestamp, the hash, or the VLAN tag control information.
func TestKfuncArg(t *testing.T) {
	kernel := metadataKernelSpec(t)
	for _, tc := range []struct {
		name, typ string
		size      uint32
		reg       asm.Register
	}{
		{"bpf_xdp_metadata_rx_timestamp", "u64", 8, asm.R2},
		{"bpf_xdp_metadata_rx_hash", "u32", 4, asm.R2},
		{"bpf_xdp_metadata_rx_vlan_tag", "u16", 2, asm.R3},
	} {
		row := callRow(t, tc.name)
		if row.ArgReg != tc.reg || row.SizeReg != 0 || !row.Writes || row.RetSize != 4 || !row.RetSigned || row.RetPtr {
			t.Errorf("%s row %+v", tc.name, row)
		}
		typ, size := kfuncArg(row, kernel)
		if typ == nil || typ.TypeName() != tc.typ || size != tc.size {
			t.Errorf("%s: arg %v size %d, want %s and %d", tc.name, typ, size, tc.typ, tc.size)
		}
		if typ, _ := kfuncArg(row, nil); typ != nil {
			t.Errorf("%s without kernel BTF: arg %v", tc.name, typ)
		}
	}
	if typ, _ := kfuncArg(&CallRow{Name: "bpf_not_a_pointer", ArgReg: asm.R2}, kernel); typ != nil {
		t.Errorf("a scalar parameter gave arg %v", typ)
	}
}

// A metadata kfunc's hook takes const T *arg, T the prototype's pointee, for
// a buffer on the program's own stack; without the prototype at hand the
// call keeps the result-only hook and says why.
func TestCallHookMetadataArg(t *testing.T) {
	for _, tc := range []struct {
		name, typ string
		size      uint32
		third     bool
		reg       int
	}{
		{"bpf_xdp_metadata_rx_timestamp", "u64", 8, false, 2},
		{"bpf_xdp_metadata_rx_hash", "u32", 4, true, 2},
		{"bpf_xdp_metadata_rx_vlan_tag", "u16", 2, true, 3},
	} {
		for _, withKernel := range []bool{true, false} {
			spec := xdpMetadataFixture(kfuncCall(-1).WithReference(tc.name), tc.third)
			req := callReq(tc.name)
			if withKernel {
				req.Kernel = metadataKernelSpec(t)
			}
			plan, err := transformLookup(spec, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 1 {
				t.Fatalf("%s: hooks %+v skipped %+v", tc.name, plan.hooks, plan.skipped)
			}
			h := plan.hooks[0]
			fn, params := callHookFn(t, spec.Programs["p"].Instructions, h.Name)
			if !slices.Contains(fn.Tags, hookabi.SizeTag("ret", 4)) || !slices.Contains(fn.Tags, hookabi.RetSignedTag) {
				t.Errorf("%s (kernel BTF %v): hook tags %v lack the narrow signed ret", tc.name, withKernel, fn.Tags)
			}
			if !withKernel {
				if h.ArgReg != 0 || !strings.Contains(h.ArgReason, "not in the kernel BTF") || slices.Contains(params, "arg") || h.RetSize != 4 {
					t.Errorf("%s without kernel BTF: hook %+v params %v", tc.name, h, params)
				}
				continue
			}
			if h.ArgReg != tc.reg || h.ArgSize != tc.size || h.ArgType != tc.typ || h.Untrusted || h.Static || h.ArgReason != "" || h.RetSize != 4 || !h.RetSigned {
				t.Fatalf("%s: hook %+v", tc.name, h)
			}
			if !slices.Equal(params, []string{"ctx", "site", "arg", "ret"}) {
				t.Fatalf("%s: params %v", tc.name, params)
			}
			arg := fn.Type.(*btf.FuncProto).Params[2].Type
			ptr, ok := arg.(*btf.Pointer)
			if !ok {
				t.Fatalf("%s: arg is %v", tc.name, arg)
			}
			target := ptr.Target
			if c, ok := target.(*btf.Const); ok {
				target = c.Type
			}
			if target.TypeName() != tc.typ {
				t.Fatalf("%s: arg points to %v", tc.name, ptr.Target)
			}
		}
	}
}

// The receive-metadata hooks carry the narrow signed ret in every form: as
// the capture reads the hook's parameters (attach.GetFuncParamsFromSpec),
// ret is a signed 4-byte result with the typed, result-only, untrusted and
// static hooks alike.
func TestCallHookMetadataRetEveryForm(t *testing.T) {
	for _, name := range []string{"bpf_xdp_metadata_rx_timestamp", "bpf_xdp_metadata_rx_hash", "bpf_xdp_metadata_rx_vlan_tag"} {
		for _, form := range []string{"typed", "no-kernel", "untrusted", "static"} {
			spec := xdpMetadataFixture(kfuncCall(-1).WithReference(name), name != "bpf_xdp_metadata_rx_timestamp")
			req := callReq(name)
			if form != "no-kernel" {
				req.Kernel = metadataKernelSpec(t)
			}
			if form == "untrusted" || form == "static" {
				// The argument comes from the packet, not the stack.
				insns := spec.Programs["p"].Instructions
				reg := asm.R2
				if name == "bpf_xdp_metadata_rx_vlan_tag" {
					reg = asm.R3
				}
				at := slices.IndexFunc(insns, func(ins asm.Instruction) bool {
					return ins.Dst == reg && ins.Src == asm.RFP && ins.OpCode.ALUOp() == asm.Mov
				})
				if at < 0 {
					t.Fatalf("%s: no argument set from the stack", name)
				}
				insns[at] = asm.LoadMem(reg, asm.R6, 0, asm.Word)
				insns[at+1] = asm.Mov.Reg(reg, reg)
				req.StaticUntrusted = form == "static"
			}
			plan, err := transformLookup(spec, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.hooks) != 1 || (form == "untrusted") != plan.hooks[0].Untrusted || (form == "static") != plan.hooks[0].Static {
				t.Fatalf("%s %s: hooks %+v skipped %+v", name, form, plan.hooks, plan.skipped)
			}
			fn, _ := callHookFn(t, spec.Programs["p"].Instructions, plan.hooks[0].Name)
			params, err := attach.GetFuncParamsFromSpec(specOf(t, fn), plan.hooks[0].Name)
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(params, func(p attach.FuncParamInfo) bool { return p.Name == "ret" })
			if i < 0 || params[i].Size != 4 || !params[i].Signed || params[i].RetSize != 4 || !params[i].RetSigned {
				t.Errorf("%s %s: ret is not a narrow signed result: %+v (tags %v)", name, form, params, fn.Tags)
			}
		}
	}
}
