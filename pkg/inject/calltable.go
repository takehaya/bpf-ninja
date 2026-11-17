package inject

import (
	"fmt"
	"slices"
	"strings"

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
	{Name: "bpf_get_smp_processor_id", Helper: asm.FnGetSmpProcessorId},
	{Name: "bpf_get_hash_recalc", Helper: asm.FnGetHashRecalc},
	{Name: "bpf_get_socket_cookie", Helper: asm.FnGetSocketCookie},
	{Name: "bpf_xdp_get_buff_len", Helper: asm.FnXdpGetBuffLen},
	{Name: "bpf_skb_load_bytes", Helper: asm.FnSkbLoadBytes, ArgReg: asm.R3, SizeReg: asm.R4, Writes: true},
	{Name: "bpf_xdp_load_bytes", Helper: asm.FnXdpLoadBytes, ArgReg: asm.R3, SizeReg: asm.R4, Writes: true},
	{Name: "bpf_sk_lookup_tcp", Helper: asm.FnSkLookupTcp, RetPtr: true, ArgReg: asm.R2, SizeReg: asm.R3, ArgType: "bpf_sock_tuple"},
	{Name: "bpf_sk_lookup_udp", Helper: asm.FnSkLookupUdp, RetPtr: true, ArgReg: asm.R2, SizeReg: asm.R3, ArgType: "bpf_sock_tuple"},
	{Name: "bpf_skc_lookup_tcp", Helper: asm.FnSkcLookupTcp, RetPtr: true, ArgReg: asm.R2, SizeReg: asm.R3, ArgType: "bpf_sock_tuple"},
	{Name: "bpf_probe_read_kernel", Helper: asm.FnProbeReadKernel, ArgReg: asm.R1, SizeReg: asm.R2, Writes: true},
	{Name: "bpf_fib_lookup", Helper: asm.FnFibLookup, ArgReg: asm.R2, SizeReg: asm.R3, ArgType: "bpf_fib_lookup", Writes: true},
	{Name: "bpf_xdp_ct_lookup", RetPtr: true, ArgReg: asm.R4, SizeReg: asm.R5, ArgType: "bpf_ct_opts", Writes: true},
	{Name: "bpf_skb_ct_lookup", RetPtr: true, ArgReg: asm.R4, SizeReg: asm.R5, ArgType: "bpf_ct_opts", Writes: true},
}

// pointerResults are the helpers with a pointer result and no row that get
// the result-only pointer hook. A pointer kind is listed only when its kernel
// test (calls_all_kernel_test.go) passes on 6.1, 6.12, 6.18 and 7.0.
var pointerResults = []string{"bpf_sk_fullsock", "bpf_tcp_sock", "bpf_ringbuf_reserve", "bpf_this_cpu_ptr", "bpf_kptr_xchg"}

// noPointerTest is the reason a helper with a pointer result outside
// pointerResults gets no hook.
const noPointerTest = "a pointer result of a kind no kernel test covers yet"

// helperCall returns the row a call of helper id gets when a rule names it:
// its call-table row, else a result-only row (no argument; RetPtr for a
// pointer result). Otherwise the row is nil and reason says why.
func helperCall(id asm.BuiltinFunc) (row *CallRow, reason string) {
	for i := range callTable {
		if callTable[i].Helper != 0 && callTable[i].Helper == id {
			return &callTable[i], ""
		}
	}
	h, ok := helperByID(int64(id))
	_, mapCall := mapCallOps[id]
	switch {
	case !ok:
		return nil, fmt.Sprintf("helper id %d is past the helper table", id)
	case h.Ret == RetUnsupported:
		return nil, "not a callable helper"
	case mapCall:
		return nil, "a map helper: the rule's maps and ops observe it"
	case id == asm.FnTailCall:
		return nil, "a tail call: the rule's tail_calls observes it"
	case denyReason(h.Name) != "":
		return nil, denyReason(h.Name)
	case h.Ret == RetVoid:
		return nil, "returns nothing"
	case h.Ret == RetPointer && !slices.Contains(pointerResults, h.Name):
		return nil, noPointerTest
	}
	return &CallRow{Name: h.Name, Helper: id, RetPtr: h.Ret == RetPointer}, ""
}

// namedCall is helperCall for a rule's Calls name: the row of a kernel
// function with a row, else of the helper of that name. A kernel function
// without a row gets its deny reason, any other name a nil row and "".
func namedCall(name string) (*CallRow, string) {
	for i := range callTable {
		if callTable[i].Name == name {
			return &callTable[i], ""
		}
	}
	if id := slices.IndexFunc(helperTable[:], func(h helperRow) bool { return h.Name == name }); id >= 0 {
		return helperCall(asm.BuiltinFunc(id))
	}
	return nil, denyReason(name)
}

// hookableHelpers returns the names of the helpers a rule's Calls may name, in id order.
func hookableHelpers() []string {
	var names []string
	for id := range helperTable {
		if row, _ := helperCall(asm.BuiltinFunc(id)); row != nil {
			names = append(names, row.Name)
		}
	}
	return names
}

// kfuncRows returns the names of the kernel functions of callTable in table order.
func kfuncRows() []string {
	var names []string
	for _, row := range callTable {
		if row.Helper == 0 {
			names = append(names, row.Name)
		}
	}
	return names
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
// by the FUNC whose BTF id is ins.Constant (raw path) in kernel when ins.Offset == 0, else in
// modules[ins.Offset], the module BTF of that fd_array offset.
// named is false only for a kfunc call that cannot be named.
func callee(ins *asm.Instruction, kernel *btf.Spec, modules map[int16]*btf.Spec) (row *CallRow, name string, named bool) {
	switch {
	case ins.IsBuiltinCall():
		for i := range callTable {
			if callTable[i].Helper != 0 && callTable[i].Helper == asm.BuiltinFunc(ins.Constant) {
				return &callTable[i], callTable[i].Name, true
			}
		}
		return nil, "", true
	case ins.IsKfuncCall():
		name = ins.Reference()
		if name == "" {
			spec := kernel
			if ins.Offset != 0 {
				spec = modules[ins.Offset] // a module kfunc: off indexes the load's fd_array of module BTF fds
			}
			if spec == nil {
				return nil, "", false
			}
			typ, err := spec.TypeByID(btf.TypeID(ins.Constant))
			fn, ok := typ.(*btf.Func)
			if err != nil || !ok {
				return nil, "", false
			}
			name = fn.Name
		}
		for i := range callTable {
			if callTable[i].Helper == 0 && callTable[i].Name == name {
				return &callTable[i], name, true
			}
		}
		return nil, name, true
	}
	return nil, "", true
}

// callArgType returns the pointee of the hook's arg parameter for a site whose size register holds n,
// and its name ("" for bytes): the program's struct named row.ArgType, or row.ArgType + "___" + suffix,
// of size n; else a copy (btf.Copy) of the kernel's struct of that name when its size is at most n;
// else orBytes(nil, n).
func callArgType(row *CallRow, n uint32, prog, kernel *btf.Spec) (typ btf.Type, name string) {
	if row.ArgType == "" {
		return orBytes(nil, n), ""
	}
	if prog != nil {
		var flavour *btf.Struct
		for t, err := range prog.All() {
			s, ok := t.(*btf.Struct)
			if err != nil || !ok || s.Size != n {
				continue
			}
			if s.Name == row.ArgType {
				return s, s.Name
			}
			if flavour == nil && strings.HasPrefix(s.Name, row.ArgType+"___") {
				flavour = s
			}
		}
		if flavour != nil {
			return flavour, flavour.Name
		}
	}
	if kernel != nil {
		var s *btf.Struct
		if kernel.TypeByName(row.ArgType, &s) == nil && s.Size <= n {
			return btf.Copy(s), s.Name
		}
	}
	return orBytes(nil, n), ""
}
