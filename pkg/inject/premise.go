package inject

import (
	"cmp"
	"slices"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// The reasons helperPremise gives, one per clause of its rule. The deny list
// of kernel functions (denyReason) shares premiseLockReason, so it names a
// critical section too.
const (
	premiseCodeReason    = "reads native code addresses or branch records, which inserted code may change"
	premiseCounterReason = "reads a perf event counter, which counts inserted code too"
	premiseLockReason    = "takes or releases a lock or a critical section"
)

// helperPremise is the rule that puts a load calling helper name outside the
// equivalence claim; it returns the reason, or "". A helper marks a load
// when it
//
//  1. returns code addresses, a call stack or branch records to the
//     program, which inserted code changes;
//  2. returns a perf counter to the program, which counts inserted code too;
//  3. calls back into a subprogram of the same program, or registers one to
//     be called later (the subprogram's code is the rewritten code);
//  4. takes or releases a lock the verifier tracks across instructions.
//
// Helpers that only cause other programs to run (a tail call, a sockmap
// update, a clone redirect, a hash computed through a flow dissector) do
// not mark, nor do helpers that take and release a lock inside the call.
// The raw memory readers and the output helpers do not mark either: the
// claim assumes that a program does not hand them its own code or the
// kernel stack, and that a consumer compares their records without the
// fields it adds (docs/en/inject-run.md, the premise of the claim).
//
// testdata/helper_premise.tsv gives every helper id the clause it falls
// under, with the evidence; TestHelperPremiseTable keeps the two equal.
func helperPremise(name string) string {
	switch name {
	case "bpf_get_stack", "bpf_get_stackid", "bpf_get_task_stack", "bpf_get_branch_snapshot", "bpf_get_func_ip",
		"bpf_read_branch_records":
		return premiseCodeReason
	case "bpf_perf_event_read", "bpf_perf_event_read_value", "bpf_perf_prog_read_value":
		// XDP and tc reach the first two through bpf_base_func_proto with
		// CAP_PERFMON (7.0); the event counts on the current CPU, inserted
		// code included.
		return premiseCounterReason
	case "bpf_for_each_map_elem", "bpf_loop", "bpf_find_vma", "bpf_user_ringbuf_drain", "bpf_timer_set_callback":
		return callbackReason
	case "bpf_spin_lock", "bpf_spin_unlock":
		return premiseLockReason
	}
	return ""
}

// reviewedKfuncs are the kernel functions with a review record: the
// function was read, its definition is noted here (Linux 7.0.13, and
// 6.12.111 in parentheses), and it neither returns code addresses, stacks,
// branch records or counters to the program, nor runs or registers program
// code, nor holds a lock across instructions. The conntrack lookups read
// the time for timeouts, which the claim excludes by statement. A record
// names the function together with where it is defined: KernelHome for
// vmlinux, or the module whose BTF the load passes (nf_conntrack builds
// nf_conntrack_bpf.c into vmlinux or into its module). A call counts as
// reviewed only when both match.
var reviewedKfuncs = map[kfuncHome]string{
	{KernelHome, "bpf_xdp_ct_lookup"}:     "net/netfilter/nf_conntrack_bpf.c:325 (:327)",
	{KernelHome, "bpf_skb_ct_lookup"}:     "net/netfilter/nf_conntrack_bpf.c:391 (:395)",
	{KernelHome, "bpf_ct_release"}:        "net/netfilter/nf_conntrack_bpf.c:440 (:445)",
	{"nf_conntrack", "bpf_xdp_ct_lookup"}: "net/netfilter/nf_conntrack_bpf.c:325 (:327)",
	{"nf_conntrack", "bpf_skb_ct_lookup"}: "net/netfilter/nf_conntrack_bpf.c:391 (:395)",
	{"nf_conntrack", "bpf_ct_release"}:    "net/netfilter/nf_conntrack_bpf.c:440 (:445)",
}

// kfuncHome is a kernel function's name and where it is defined: KernelHome
// or a module's name.
type kfuncHome struct{ home, name string }

// KernelHome is where a kernel function of vmlinux is defined.
const KernelHome = "vmlinux"

// driverKfuncs are the kernel functions whose implementation the device's
// driver supplies: the verifier puts the driver's function in their place.
// They never count as reviewed.
var driverKfuncs = []string{"bpf_xdp_metadata_rx_timestamp", "bpf_xdp_metadata_rx_hash", "bpf_xdp_metadata_rx_vlan_tag"}

// DriverNote follows the name of a function of driverKfuncs in NotReviewed.
const DriverNote = " (the device's driver supplies the implementation)"

// NotReviewed returns the kernel functions insns calls that have no review
// record (reviewedKfuncs) for where they are defined, in call order without
// repeats. A call into module BTF is defined in moduleNames[offset]; one
// whose name has a record elsewhere gets " (in HOME)", and a function of
// driverKfuncs gets DriverNote. A call that kernel and modules cannot name
// is UnnamedKfunc, never reviewed. The claim is stated only for a load that
// calls none. Hooks do not depend on it.
func NotReviewed(insns asm.Instructions, kernel *btf.Spec, modules map[int16]*btf.Spec, moduleNames map[int16]string) []string {
	var names []string
	for i := range insns {
		ins := &insns[i]
		if !ins.IsKfuncCall() {
			continue
		}
		_, name, named := callee(ins, kernel, modules)
		home := KernelHome
		if ins.Offset != 0 {
			home = moduleNames[ins.Offset]
		}
		switch {
		case !named:
			name = UnnamedKfunc
		case slices.Contains(driverKfuncs, name):
			name += DriverNote
		case reviewedKfuncs[kfuncHome{home, name}] != "":
			continue
		case hasRecord(name):
			name += " (in " + cmp.Or(home, "a module not named") + ")"
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// hasRecord says whether a function called name has a review record
// anywhere.
func hasRecord(name string) bool {
	for record := range reviewedKfuncs {
		if record.name == name {
			return true
		}
	}
	return false
}
