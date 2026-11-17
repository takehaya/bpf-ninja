package inject

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/injectcheck"
)

// A helper without a row gets the result-only hook PREFIX_<name>(ctx, site,
// u64 ret) with sequence A, as a scalar row without an argument does, and the
// load-time checker accepts it.
func TestCallResultOnlyScalar(t *testing.T) {
	work := ctxScalarFixture(ebpf.XDP, asm.FnGetNumaNodeId)
	in := slices.Clone(work.Programs["p"].Instructions)
	injectcheck.Label(work.Programs["p"].Instructions)
	plan, err := transformLookup(work, callReq("bpf_get_numa_node_id"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.hooks) != 1 || len(plan.skipped) != 0 {
		t.Fatalf("hooks %+v skipped %+v", plan.hooks, plan.skipped)
	}
	h := plan.hooks[0]
	if h.Name != "obs_bpf_get_numa_node_id" || h.Kind != HookCall || h.Call != "bpf_get_numa_node_id" || h.ArgReg != 0 || h.RetPtr || h.Untrusted || h.Static {
		t.Fatalf("hook %+v", h)
	}
	out := work.Programs["p"].Instructions
	fn, params := callHookFn(t, out, h.Name)
	if !slices.Equal(params, []string{"ctx", "site", "ret"}) || fn.Linkage != btf.GlobalFunc || fn.ParamTags != nil {
		t.Errorf("hook %v params %v", fn, params)
	}
	slots := lookupSlots(-64)
	at := callAt(t, out, h.Name)
	want := asm.Instructions{
		asm.FnGetNumaNodeId.Call(),
		asm.StoreMem(asm.RFP, int16(slots.result), asm.R0, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, int16(slots.ctx), asm.DWord),
		asm.Mov.Imm32(asm.R2, int32(h.Sites[0].SitePC)),
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Call.Label(h.Name),
		asm.LoadMem(asm.R0, asm.RFP, int16(slots.result), asm.DWord),
	}
	if len(at) != 1 || !sameInsns(out[at[0]-5:at[0]+2], want) {
		t.Fatalf("site:\n%v\nwant\n%v", out, want)
	}
	cert, premises := validationCertificate(t, in, out, plan.hooks, -64)
	if counts, err := injectcheck.Check(in, out, cert, premises); err != nil || counts.Sites != 1 {
		t.Fatalf("checker: counts %+v err %v", counts, err)
	}
}

// The result-only pointer form: global with ret tagged arg:untrusted, or with
// StaticUntrusted static with an empty body; both pass ret in R3.
func TestCallResultOnlyPointerForm(t *testing.T) {
	ctx := xdpFunc("p").Type.(*btf.FuncProto).Params[0].Type
	group := lookupGroup{name: "obs_bpf_x", call: &CallRow{Name: "bpf_x", Helper: 1, RetPtr: true}}
	for _, static := range []bool{false, true} {
		hook, plan := callHook(group, ctx, LookupRequest{StaticUntrusted: static})
		fn := btf.FuncMetadata(&hook[0])
		params := fn.Type.(*btf.FuncProto).Params
		if len(params) != 3 || params[2].Name != "ret" || !plan.RetPtr || plan.Static != static || plan.Untrusted == static || plan.ArgReg != 0 {
			t.Fatalf("static %v: plan %+v params %+v", static, plan, params)
		}
		if _, ok := btf.UnderlyingType(params[2].Type).(*btf.Pointer); !ok {
			t.Errorf("static %v: ret is %v, want a pointer", static, params[2].Type)
		}
		switch {
		case static && (fn.Linkage != btf.StaticFunc || fn.ParamTags != nil):
			t.Errorf("static hook %+v", fn)
		case !static && (fn.Linkage != btf.GlobalFunc || !slices.Equal(fn.ParamTags[2], []string{"arg:untrusted"})):
			t.Errorf("global hook %+v", fn)
		}
	}
}

// Every helper of the table is hookable or has a reason, and a rule may name
// exactly the hookable ones.
func TestHookableHelpers(t *testing.T) {
	names := hookableHelpers()
	for id, h := range helperTable {
		row, reason := helperCall(asm.BuiltinFunc(id))
		if (row == nil) == (reason == "") {
			t.Errorf("%s: row %v reason %q", h.Name, row, reason)
		}
		if row != nil && (row.Name != h.Name || row.RetPtr != (h.Ret == RetPointer) || !slices.Contains(names, h.Name)) {
			t.Errorf("%s: row %+v", h.Name, row)
		}
		if err := checkOps(LookupRequest{Calls: []string{h.Name}}); (err == nil) != (row != nil) {
			t.Errorf("%s: checkOps %v, row %v", h.Name, err, row)
		}
	}
	for _, name := range []string{"bpf_get_numa_node_id", "bpf_redirect", "bpf_csum_diff", "bpf_ktime_get_ns"} {
		if !slices.Contains(names, name) {
			t.Errorf("%s is not hookable", name)
		}
	}
}

// The helpers that read native code addresses or branch records are denied by name.
func TestDenyNativeAddressHelpers(t *testing.T) {
	for _, name := range []string{"bpf_get_stack", "bpf_get_stackid", "bpf_get_task_stack", "bpf_get_branch_snapshot", "bpf_get_func_ip"} {
		if row, reason := namedCall(name, nil, nil); row != nil || reason != "reads native code addresses or branch records, which inserted code may change" {
			t.Errorf("%s: row %v reason %q", name, row, reason)
		}
	}
	if row, _ := namedCall("bpf_get_attach_cookie", nil, nil); row == nil {
		t.Error("bpf_get_attach_cookie is denied; it reads the attachment's cookie only")
	}
}

// spinLockFixture (XDP) calls bpf_get_numa_node_id, takes the lock of
// locked[0], increments its counter, releases the lock, calls
// bpf_ktime_get_ns, stores the node and the counter in out slots 0 and 1
// and returns XDP_PASS; XDP_DROP if the lookup fails.
func spinLockFixture() *ebpf.CollectionSpec {
	u32 := &btf.Int{Name: "u32", Size: 4}
	u64 := &btf.Int{Name: "u64", Size: 8}
	lock := &btf.Struct{Name: "bpf_spin_lock", Size: 4, Members: []btf.Member{{Name: "val", Type: u32}}}
	value := &btf.Struct{Name: "locked_value", Size: 16, Members: []btf.Member{
		{Name: "lock", Type: lock}, {Name: "pad", Type: u32, Offset: 32}, {Name: "cnt", Type: u64, Offset: 64}}}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetNumaNodeId.Call(),
		asm.Mov.Reg(asm.R8, asm.R0),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, 0).WithReference("locked"), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.Mov.Reg(asm.R1, asm.R7), asm.FnSpinLock.Call(),
		asm.LoadMem(asm.R1, asm.R7, 8, asm.DWord), asm.Add.Imm(asm.R1, 1), asm.StoreMem(asm.R7, 8, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R7), asm.FnSpinUnlock.Call(),
		asm.Mov.Reg(asm.R9, asm.R8),
		asm.FnKtimeGetNs.Call(),
		asm.LoadMem(asm.R7, asm.R7, 8, asm.DWord),
	}
	insns = append(append(insns, outStore(0, asm.R9)...), outStore(1, asm.R7)...)
	insns = append(insns, asm.Mov.Imm(asm.R0, 2), asm.Return(), asm.Mov.Imm(asm.R0, 1).WithSymbol("drop"), asm.Return())
	spec := callFixtureSpec(ebpf.XDP, insns)
	spec.Maps["locked"] = &ebpf.MapSpec{Name: "locked", Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 1, Key: u32, Value: value}
	return spec
}
