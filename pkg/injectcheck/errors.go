package injectcheck

import "fmt"

// Kind identifies a stable validation rule, independently of instruction indices.
type Kind string

const (
	MetadataUnsupported    Kind = "metadata_unsupported"
	MetadataChanged        Kind = "metadata_changed"
	LabelInvalid           Kind = "label_invalid"
	EdgeResolved           Kind = "edge_resolved"
	SymbolAmbiguous        Kind = "symbol_ambiguous"
	SymbolUnresolved       Kind = "symbol_unresolved"
	EdgeSlot               Kind = "edge_slot"
	OriginalOrder          Kind = "original_order"
	HookRange              Kind = "hook_range"
	HookOverlap            Kind = "hook_overlap"
	HookFallthrough        Kind = "hook_fallthrough"
	RegionSplit            Kind = "region_split"
	EdgeTarget             Kind = "edge_target"
	OriginalReference      Kind = "original_reference"
	OriginalChanged        Kind = "original_changed"
	StackAudit             Kind = "stack_audit"
	SpillBounds            Kind = "spill_bounds"
	PreludeShape           Kind = "prelude_shape"
	HookShape              Kind = "hook_shape"
	HookBody               Kind = "hook_body"
	CallKind               Kind = "call_kind"
	CallTarget             Kind = "call_target"
	EntrySpill             Kind = "entry_spill"
	EntryArguments         Kind = "entry_arguments"
	EntryRestore           Kind = "entry_restore"
	PostludeMissing        Kind = "postlude_missing"
	ResultSaveRestore      Kind = "result_save_restore"
	LookupStructure        Kind = "lookup_structure"
	HelperStructure        Kind = "helper_structure"
	PathBudget             Kind = "path_budget"
	ResultPath             Kind = "result_path"
	RegisterInvalid        Kind = "register_invalid"
	RegisterRead           Kind = "register_read"
	RegisterUndefined      Kind = "register_undefined"
	StoreBounds            Kind = "store_bounds"
	StoreShape             Kind = "store_shape"
	LoadClobber            Kind = "load_clobber"
	ResultLoad             Kind = "result_load"
	SpillUninitialized     Kind = "spill_uninitialized"
	CopyShape              Kind = "copy_shape"
	ALUClobber             Kind = "alu_clobber"
	ALUEncoding            Kind = "alu_encoding"
	PointerCalculation     Kind = "pointer_calculation"
	PointerBounds          Kind = "pointer_bounds"
	ALUOperation           Kind = "alu_operation"
	MultipleCalls          Kind = "multiple_calls"
	BranchForward          Kind = "branch_forward"
	BranchEscape           Kind = "branch_escape"
	BranchEncoding         Kind = "branch_encoding"
	BranchGuard            Kind = "branch_guard"
	PostludeInstruction    Kind = "postlude_instruction"
	U32Placement           Kind = "u32_placement"
	U32Live                Kind = "u32_live"
	U32Length              Kind = "u32_length"
	U32Shape               Kind = "u32_shape"
	U32Hook                Kind = "u32_hook"
	AssociatedMap          Kind = "associated_map"
	InputOriginalEmpty     Kind = "input.original_empty"
	InputCertificateEmpty  Kind = "input.certificate_empty"
	InputCertificateLength Kind = "input.certificate_length"
	InputStackFloor        Kind = "input.stack_floor"
	InputJSON              Kind = "input.json"
	InputMissing           Kind = "input.missing"
	InputVersion           Kind = "input.version"
	InputRegister          Kind = "input.register"
	InputOriginalCFG       Kind = "input.original_cfg"
)

// Rejection means a well-formed proposed transformation violates a checked rule.
// Use errors.As to inspect Kind; Detail is intended for human diagnostics.
type Rejection struct {
	Kind   Kind
	Detail string
}

func (e *Rejection) Error() string { return e.Detail }
func reject(kind Kind, format string, args ...any) error {
	return &Rejection{kind, fmt.Sprintf(format, args...)}
}

// InputError means the caller must repair the inputs before validation can run.
type InputError struct {
	Kind   Kind
	Detail string
}

func (e *InputError) Error() string { return e.Detail }
func inputError(kind Kind, format string, args ...any) error {
	return &InputError{kind, fmt.Sprintf(format, args...)}
}
