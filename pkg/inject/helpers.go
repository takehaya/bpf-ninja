package inject

// CalleeRet is the kind of a helper's or kernel function's result.
type CalleeRet string

const (
	RetScalar      CalleeRet = "scalar"      // RET_INTEGER, or an integer or enum kfunc result
	RetPointer     CalleeRet = "pointer"     // any pointer result
	RetVoid        CalleeRet = "void"        // RET_VOID: R0 is not readable after the call
	RetUnsupported CalleeRet = "unsupported" // helper id 0 (unspec): not a callable helper
)

// helperRow is one helper id of the generated table helperTable.
type helperRow struct {
	Name string // kernel name with the bpf_ prefix, e.g. bpf_map_lookup_elem
	Ret  CalleeRet
	// RetType is the kernel struct behind a pointer result, from the
	// helper's struct bpf_func_proto (tools/helpergen); "" when the result
	// is untyped: a map value, memory, dynptr data or a kptr.
	RetType string
}

// helperByID returns the row of helper id, false past the table.
func helperByID(id int64) (helperRow, bool) {
	if id < 0 || id >= int64(len(helperTable)) {
		return helperRow{}, false
	}
	return helperTable[id], true
}
