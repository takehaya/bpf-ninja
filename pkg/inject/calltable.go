package inject

import (
	"fmt"
	"maps"
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
	RetSize uint32          // byte size of a kernel function's integer result narrower than 8 bytes; 0: 8
	RetSigned bool          // that narrow result is a signed integer or enum
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
// test (calls_all_kernel_test.go, calls_helpers_kernel_test.go) passes on 6.1,
// 6.12, 6.18 and 7.0 where the helper exists and XDP or tc may call it
// (bpf_task_storage_get: tc from 6.18). Off: bpf_get_local_storage,
// bpf_inode_storage_get and bpf_sock_from_file, which neither XDP nor tc may
// call.
var pointerResults = []string{"bpf_sk_fullsock", "bpf_tcp_sock", "bpf_ringbuf_reserve", "bpf_this_cpu_ptr", "bpf_kptr_xchg",
	"bpf_get_listener_sock", "bpf_skc_to_tcp6_sock", "bpf_skc_to_tcp_sock", "bpf_skc_to_tcp_timewait_sock", "bpf_skc_to_tcp_request_sock",
	"bpf_skc_to_udp6_sock", "bpf_skc_to_unix_sock", "bpf_skc_to_mptcp_sock", "bpf_sk_storage_get", "bpf_per_cpu_ptr", "bpf_dynptr_data",
	"bpf_get_current_task_btf", "bpf_task_pt_regs", "bpf_cgrp_storage_get",
	"bpf_task_storage_get"}

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
// function with a row, else of the helper of that name, else kfuncRow of the
// kernel function of that name in kernel or one of modules. Without kernel, or
// for a name neither has, a denied name gets its deny reason and any other
// name a nil row and "".
func namedCall(name string, kernel *btf.Spec, modules map[int16]*btf.Spec) (*CallRow, string) {
	for i := range callTable {
		if callTable[i].Name == name {
			return &callTable[i], ""
		}
	}
	if id := slices.IndexFunc(helperTable[:], func(h helperRow) bool { return h.Name == name }); id >= 0 {
		return helperCall(asm.BuiltinFunc(id))
	}
	if proto := kfuncByName(name, kernel, modules); proto != nil {
		return kfuncRow(name, proto)
	}
	return nil, denyReason(name)
}

// kfuncRow returns the row a call of the kernel function name without a row
// gets when a rule names it: a result-only row, RetPtr for any pointer result
// (void * included) and RetSize for an integer or enum narrower than 8 bytes,
// with RetSigned when it is signed.
// Otherwise the row is nil and reason says why: the deny list, a parameter
// that points to a function prototype (the verifier's callback test), no
// result, or a prototype that cannot be read (proto nil).
func kfuncRow(name string, proto *btf.FuncProto) (row *CallRow, reason string) {
	if reason := denyReason(name); reason != "" {
		return nil, reason
	}
	if proto == nil {
		return nil, "its prototype is not in the kernel BTF at hand"
	}
	for _, p := range proto.Params {
		if ptr, ok := btf.UnderlyingType(p.Type).(*btf.Pointer); ok {
			if _, ok := btf.UnderlyingType(ptr.Target).(*btf.FuncProto); ok {
				return nil, "runs or registers a callback"
			}
		}
	}
	var size uint32
	var signed bool
	switch ret := btf.UnderlyingType(proto.Return).(type) {
	case *btf.Pointer:
		return &CallRow{Name: name, RetPtr: true}, ""
	case *btf.Int:
		size, signed = ret.Size, ret.Encoding == btf.Signed
	case *btf.Enum:
		size, signed = ret.Size, ret.Signed
	case *btf.Void, nil:
		return nil, "returns nothing"
	default:
		return nil, "its result is neither an integer nor a pointer"
	}
	row = &CallRow{Name: name}
	if size < 8 {
		row.RetSize, row.RetSigned = size, signed
	}
	return row, ""
}

// kfuncProto is the BTF prototype of a kernel-function call: by the BTF id
// ins.Constant in kernel, or for a module kfunc in modules[ins.Offset]; by
// name (kfuncByName) when the call carries a reference (ELF path). nil when
// it cannot be read.
func kfuncProto(ins *asm.Instruction, kernel *btf.Spec, modules map[int16]*btf.Spec) *btf.FuncProto {
	if ins.Reference() != "" {
		return kfuncByName(ins.Reference(), kernel, nil)
	}
	spec := kernel
	if ins.Offset != 0 {
		spec = modules[ins.Offset]
	}
	if spec == nil {
		return nil
	}
	typ, err := spec.TypeByID(btf.TypeID(ins.Constant))
	if fn, ok := typ.(*btf.Func); err == nil && ok {
		proto, _ := fn.Type.(*btf.FuncProto)
		return proto
	}
	return nil
}

// kfuncByName is the prototype of the function name in kernel, else in the
// module BTF of modules (split on kernel) in offset order; nil when none has
// it. This is the BTF a load passes: a module kfunc the program does not
// reference in its fd_array is not found.
func kfuncByName(name string, kernel *btf.Spec, modules map[int16]*btf.Spec) *btf.FuncProto {
	specs := []*btf.Spec{kernel}
	for _, off := range slices.Sorted(maps.Keys(modules)) {
		specs = append(specs, modules[off])
	}
	for _, spec := range specs {
		if spec == nil {
			continue
		}
		types, _ := spec.AnyTypesByName(name)
		for _, typ := range types {
			if fn, ok := typ.(*btf.Func); ok {
				if proto, ok := fn.Type.(*btf.FuncProto); ok {
					return proto
				}
			}
		}
	}
	return nil
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

// SupportedCalls returns the names of callTable in table order.
func SupportedCalls() []string {
	names := make([]string, len(callTable))
	for i, row := range callTable {
		names[i] = row.Name
	}
	return names
}

// callee names the callee of a helper or kfunc call and returns its row, nil when the table has none.
// A helper is found by id. A kfunc is named by ins.Reference() when set (ELF path), else by the
// FUNC whose BTF id is ins.Constant (raw path) in kernel when ins.Offset == 0, else in
// modules[ins.Offset], the module BTF of that fd_array offset.
// named is false only for a kfunc call that cannot be named; name is then unnamedKfuncName.
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
				return nil, unnamedKfuncName(ins), false
			}
			typ, err := spec.TypeByID(btf.TypeID(ins.Constant))
			fn, ok := typ.(*btf.Func)
			if err != nil || !ok {
				return nil, unnamedKfuncName(ins), false
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

// unnamedKfuncReason is the reason a kernel-function call that cannot be
// named gets no hook.
const unnamedKfuncReason = "a kernel-function call that cannot be named"

// unnamedKfuncName stands for the callee of a kernel-function call that
// cannot be named: kfunc_OFF_ID from the call's fd_array offset and BTF id, so
// that calls of different kernel functions stay apart in a listing.
func unnamedKfuncName(ins *asm.Instruction) string {
	return fmt.Sprintf("kfunc_%d_%d", ins.Offset, ins.Constant)
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
