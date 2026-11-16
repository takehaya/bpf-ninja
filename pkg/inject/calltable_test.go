package inject

import (
	"bytes"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
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
	want := []string{"bpf_ktime_get_ns", "bpf_jiffies64", "bpf_get_prandom_u32", "bpf_get_smp_processor_id", "bpf_get_hash_recalc", "bpf_get_socket_cookie", "bpf_xdp_get_buff_len", "bpf_skb_load_bytes", "bpf_xdp_load_bytes", "bpf_sk_lookup_tcp", "bpf_sk_lookup_udp", "bpf_skc_lookup_tcp", "bpf_probe_read_kernel", "bpf_fib_lookup", "bpf_xdp_ct_lookup", "bpf_skb_ct_lookup"}
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
		{"kfunc id of a struct", kfuncCall(int64(optsID)), kernel, "", "", false},
		{"kfunc id not in kernel", kfuncCall(1 << 20), kernel, "", "", false},
		{"module offset", module, kernel, "", "", false},
		{"nil kernel", byID, nil, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, name, named := callee(&tc.ins, tc.kernel)
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

func TestCallsBlocked(t *testing.T) {
	kernel := testKernelSpec(t)
	ret := []asm.Instruction{asm.Mov.Imm(asm.R0, 0), asm.Return()}
	prog := func(calls ...asm.Instruction) asm.Instructions { return append(calls, ret...) }
	ct := ctFixture(ebpf.XDP, func(name string) asm.Instruction { return testKfunc(t, kernel, name) }, 8, 80, false)
	for _, tc := range []struct {
		name   string
		insns  asm.Instructions
		kernel *btf.Spec
		want   string
	}{
		{"helpers only", prog(asm.FnKtimeGetNs.Call(), asm.FnMapLookupElem.Call()), nil, ""},
		{"conntrack kfuncs by id", ct.Programs["p"].Instructions, kernel, ""},
		{"spin lock", prog(asm.FnKtimeGetNs.Call(), asm.FnSpinLock.Call()), nil, "call: the program calls bpf_spin_lock, under which a hook call may be refused"},
		{"preempt disable", prog(kfuncCall(-1).WithReference("bpf_preempt_disable")), nil, "call: the program calls bpf_preempt_disable, under which a hook call may be refused"},
		{"res spin lock", prog(kfuncCall(-1).WithReference("bpf_res_spin_lock_irqsave")), nil, "call: the program calls bpf_res_spin_lock_irqsave, under which a hook call may be refused"},
		{"kfunc by id, nil kernel", ct.Programs["p"].Instructions, nil, "call: a kernel-function call in the program cannot be named"},
		{"kfunc in a module", prog(asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoKfuncCall, Constant: 5, Offset: 1}), kernel, "call: a kernel-function call in the program cannot be named"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := callsBlocked(tc.insns, tc.kernel); got != tc.want {
				t.Fatalf("callsBlocked = %q, want %q", got, tc.want)
			}
		})
	}
}
