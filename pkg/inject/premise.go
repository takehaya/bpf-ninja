package inject

// The reasons helperPremise gives, one per clause of its rule.
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
