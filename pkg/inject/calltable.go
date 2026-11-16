package inject

import (
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// CallRow is one callee a rule may name in Calls.
type CallRow struct {
	Name    string          // exact kernel name, the rule-file spelling
	Helper  asm.BuiltinFunc // helper id; 0 for a kernel function (kfunc)
	RetPtr  bool            // the result is a pointer; the hook takes const void *ret
	ArgReg  asm.Register    // R1..R5: the memory argument the hook also takes; 0: none
	SizeReg asm.Register    // register holding the argument's size in bytes at the call
	ArgType string          // struct name looked up for the pointee
	Writes  bool            // the callee's own argument check is a write on every supported kernel
}

// callTable lists the callees LookupRequest.Calls may name. A row is never
// added for a callee that runs a callback, returns nothing, does not return,
// or takes or releases a lock; a row with an argument is never added for a
// packet-changing callee; a callee returning an integer narrower than 64 bits
// needs a width column first; and each row lands with its kernel test.
var callTable = []CallRow{
	{Name: "bpf_ktime_get_ns", Helper: asm.FnKtimeGetNs},
	{Name: "bpf_jiffies64", Helper: asm.FnJiffies64},
	{Name: "bpf_get_prandom_u32", Helper: asm.FnGetPrandomU32},
	{Name: "bpf_fib_lookup", Helper: asm.FnFibLookup, ArgReg: asm.R2, SizeReg: asm.R3, ArgType: "bpf_fib_lookup", Writes: true},
	{Name: "bpf_xdp_ct_lookup", RetPtr: true, ArgReg: asm.R4, SizeReg: asm.R5, ArgType: "bpf_ct_opts", Writes: true},
	{Name: "bpf_skb_ct_lookup", RetPtr: true, ArgReg: asm.R4, SizeReg: asm.R5, ArgType: "bpf_ct_opts", Writes: true},
}

// SupportedCalls returns the names of callTable in table order.
func SupportedCalls() []string {
	names := make([]string, len(callTable))
	for i, row := range callTable {
		names[i] = row.Name
	}
	return names
}

// callee names the callee of a helper or kfunc call and returns its row, nil when the table has none.
// A helper is found by id. A kfunc is named by ins.Reference() when set (ELF path), else, when
// ins.Offset == 0 and kernel != nil, by the FUNC whose BTF id is ins.Constant (raw path).
// named is false only for a kfunc call that cannot be named.
func callee(ins *asm.Instruction, kernel *btf.Spec) (row *CallRow, name string, named bool) { //nolint:unused // stub until the call-site rewriter uses it
	return nil, "", true
}

// callArgType returns the pointee of the hook's arg parameter for a site whose size register holds n,
// and its name ("" for bytes): the program's struct named row.ArgType, or row.ArgType + "___" + suffix,
// of size n; else a copy (btf.Copy) of the kernel's struct of that name when its size is at most n;
// else orBytes(nil, n).
func callArgType(row *CallRow, n uint32, prog, kernel *btf.Spec) (typ btf.Type, name string) { //nolint:unused // stub until the call-site rewriter uses it
	return orBytes(nil, n), ""
}

// callsBlocked returns why no call site of the program may be hooked, or "": the program calls
// bpf_spin_lock, bpf_preempt_disable or a kfunc whose name starts with bpf_res_spin_lock, under which
// a hook call may be refused, or holds a kfunc call that cannot be named (see callee).
func callsBlocked(insns asm.Instructions, kernel *btf.Spec) string { //nolint:unused // stub until the call-site rewriter uses it
	return ""
}
