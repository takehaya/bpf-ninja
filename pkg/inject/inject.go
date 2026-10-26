// Package inject performs a bounded, load-time transformation of a BPF ELF:
// it splices a single typed observation call into one explicitly selected,
// caller-audited site of one native XDP program and appends a generated global
// BTF function
//
//	int HOOK(u32 site, u32 value)
//
// that an injected BPF-to-BPF call invokes and that an fentry program can
// attach to. The transform runs on the instruction stream parsed from ELF
// bytes, before [ebpf.NewCollectionWithOptions]; it never rewrites a running
// program, loads anything, attaches anything, or reads any path a second time.
//
// # Trust boundary
//
// This package does NOT compute liveness, alias, or stack-overlap safety. It
// consumes an explicit, hash-bound caller audit of the target build and
// validates only the mechanical properties it can see in the bytecode:
//
//   - the supplied ELF bytes are cloned and hashed to [Request.ELFSHA256]
//     before they are parsed, so the audit binds the exact bytes this package
//     parses (no path re-read, no caller-visible time-of-check/time-of-use gap);
//   - the selected program is a native [ebpf.XDP] program, it exists, and the
//     instruction at [Request.SitePC] has exactly the load shape the caller
//     declared, with the immediately following instruction cleanly redefining
//     the clobbered site register (R1);
//   - the target carries BTF function and source-line metadata, so the appended
//     generated function does not produce an inconsistent ext-info mix the
//     kernel would reject;
//   - every DIRECT R10/RFP stack reference in the program is at or above the
//     caller-audited low-water mark, so the two 8-byte spill slots placed
//     below it (8-byte aligned, within 512 bytes) cannot collide with a direct
//     reference;
//   - every relocated branch/call/callback target is an original instruction boundary
//     and no branch overflows int16 (nor a function reference its int32 constant) after
//     insertion;
//   - every symbolic function reference resolves to exactly one symbol in the
//     selected program's flattened instruction stream, and every map load
//     names a map the collection defines;
//   - the generated hook name does not collide with an existing instruction
//     symbol, function-metadata name, or BTF Func, and no original instruction
//     already references that name.
//
// The caller certifies, and this package CANNOT verify, that: the only live
// caller-saved registers across the site are R0 and the value register (all
// other caller-saved registers, including R1, are dead or redefined before
// use); no pointer aliases R10 to reach the spill region; and no called
// subprogram's stack reaches below the audited mark. The audit is a trust
// boundary, not a safety inference. The transformed program must still be
// accepted by the kernel verifier; that is a separate step this package does
// not perform.
//
// Any refusal returns a nil result and leaves every input untouched.
//
// [DiscoverLookups] and [TransformLookup] provide a separate map-lookup
// transform with ctx/key/value hooks (see [LookupRequest]). It reserves three
// stack slots below the audited bound, four when a hook takes the map pointer,
// plus any CopyReadOnly value copy, and relies on the helper calling
// convention instead of a caller liveness certification.
package inject

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// insertSlots is the number of raw BPF slots the spliced call site occupies:
// two spill stores, the site-immediate move, the call, and two fills.
const insertSlots = 6

// genSlots is the number of raw slots the appended generated function occupies.
const genSlots = 3

// maxHookName bounds the generated name to a conservative kernel symbol length.
const maxHookName = 127

// ErrRefused is wrapped by every refusal so callers can branch on it without
// string matching. A refusal never mutates any input.
var ErrRefused = errors.New("inject: refused")

// identRe matches a valid C / BTF identifier, which is also what the kernel
// accepts for a BTF function name.
var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// Fixed registers of the narrow supported shape. The observed u32 must land in
// R2 (the hook's second argument), and the call clobbers R1 (the hook's first
// argument, set to the site) and R0 (the return register). R0 and R2 are
// saved and restored around the call; R1 is clobbered, so the caller must
// certify it dead — see LoadShape.
const (
	valueReg = asm.R2 // observed value / hook arg 2; saved and restored
	siteReg  = asm.R1 // hook arg 1 (site immediate); clobbered across the call
)

// LoadShape describes the exact audited observation load at the site. The
// transform refuses unless the instruction at SitePC is
//
//	R2 = *(u32 *)(R0 + Offset)
//
// (a 32-bit / asm.Word memory load into R2 from R0) and the immediately
// following instruction cleanly redefines R1: a MOV (immediate, or register
// from a source other than R1), a 64-bit immediate load, or a memory load from
// a pointer other than R1. That redefinition is the structural confirmation
// that R1 — which the spliced call overwrites with the site immediate — is dead
// at the site. PtrReg is fixed to R0: a valid original load through R0 shows R0
// is initialized at the site, which is what lets the splice spill and restore
// it. Only R0 and R2 are preserved across the call; the caller certifies every
// other caller-saved register (R1, R3, R4, R5) is dead or redefined before use.
type LoadShape struct {
	PtrReg asm.Register // source pointer register of the u32 load; must be R0
	Offset int16        // load offset from PtrReg
}

// StackAudit carries the caller's certification of the target's stack usage.
type StackAudit struct {
	// LowestOffset is the most-negative R10/RFP byte offset the program uses,
	// INCLUDING pointer aliases and called subprograms, as audited by the
	// caller. It must be in [-512, 0]. The spill slots are placed strictly
	// below the 8-byte-aligned floor of this value; the transform additionally
	// refuses if any direct RFP reference it can see is below LowestOffset.
	// Transform reserves two slots; TransformLookup three, four with a generic
	// hook, and CopyReadOnly adds a value copy below them.
	LowestOffset int16
}

// Request is the hash-bound description of one transformation. Every field is
// required; there is no path-based entry point, so the supported API cannot
// accidentally accept the wrong ELF.
type Request struct {
	ELFSHA256   string     // hex SHA-256 of the exact ELF bytes passed to Transform
	ProgramName string     // program (ELF symbol) to transform
	SitePC      uint32     // raw BPF slot index in flattened ProgramSpec.Instructions; LDIMM64 occupies two
	HookName    string     // symbol / BTF name of the generated function
	Load        LoadShape  // required instruction shape at SitePC
	Stack       StackAudit // caller-audited stack bound
}

// Result reports what the transform produced.
type Result struct {
	// Spec is the transformed collection, ready for ebpf.NewCollectionWithOptions.
	// It is an independent clone; the parsed source spec is left pristine.
	Spec *ebpf.CollectionSpec

	// HookName echoes the generated function name.
	HookName string

	// SourceChecksum and TransformedChecksum are SHA-256 over the raw
	// per-instruction encoding of the target program before and after the
	// transform. This encoding covers opcodes, registers, offsets and
	// constants, with symbolic function references left unresolved (-1); it does NOT
	// cover BTF, source lines, CO-RE relocations, map or symbol references, and
	// so does not pin the resolved hook-call target or identify the full loaded
	// kernel artifact. Pin these to detect instruction-level changes to the
	// stream; the input ELF hash remains the binding for all source content.
	SourceChecksum      string
	TransformedChecksum string

	// InsertedAt is the raw slot index of the first spliced call-site slot.
	// For Transform, InsertedSlots is insertSlots + genSlots. TransformLookup
	// also counts its entry ctx spill; see LookupResult.
	InsertedAt    uint32
	InsertedSlots int

	// AddedBytes is the growth in raw instruction bytes (InsertedSlots*8).
	AddedBytes int
}

// Transform clones the collection parsed from elf and splices the audited
// observation hook into req.ProgramName per req. On any refusal it returns a
// nil Result and a non-nil error wrapping ErrRefused, having mutated nothing.
func Transform(elf []byte, req Request) (*Result, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}

	// Clone the caller-owned bytes so the bytes we hash are exactly the bytes we
	// parse, even if the caller mutates its slice concurrently. There is no path
	// read here or anywhere in the package, so there is no TOCTOU window between
	// the audit and the parse.
	elf = bytes.Clone(elf)
	sum := sha256.Sum256(elf)
	want, err := hex.DecodeString(req.ELFSHA256) // validated as hex above
	if err != nil {
		return nil, refuse("ELFSHA256 is not hex: %v", err)
	}
	if !bytes.Equal(sum[:], want) {
		return nil, refuse("ELF hash %s does not match audited %s",
			hex.EncodeToString(sum[:]), hex.EncodeToString(want))
	}

	src, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return nil, fmt.Errorf("inject: parsing ELF: %w", err)
	}

	srcProg := src.Programs[req.ProgramName]
	if srcProg == nil {
		return nil, refuse("program %q not found", req.ProgramName)
	}
	sourceChecksum, err := checksum(srcProg.Instructions, src.ByteOrder)
	if err != nil {
		return nil, fmt.Errorf("inject: checksumming source: %w", err)
	}

	// Work on an isolated clone. Copy() deep-copies Types and every program's
	// instruction slice, so nothing we touch is shared with src; src stays
	// pristine for the source checksum and as the caller's untouched input.
	work := src.Copy()
	if err := transform(work, req); err != nil {
		return nil, err
	}
	prog := work.Programs[req.ProgramName]

	transformedChecksum, err := checksum(prog.Instructions, work.ByteOrder)
	if err != nil {
		return nil, fmt.Errorf("inject: checksumming result: %w", err)
	}

	return &Result{
		Spec:                work,
		HookName:            req.HookName,
		SourceChecksum:      sourceChecksum,
		TransformedChecksum: transformedChecksum,
		InsertedAt:          req.SitePC + 1,
		InsertedSlots:       insertSlots + genSlots,
		AddedBytes:          (insertSlots + genSlots) * 8,
	}, nil
}

// transform applies every check and the splice/append to work in place. It is
// the shared core of Transform; it builds a fresh instruction slice and only
// publishes it onto the program once every check has passed, so a refusal
// leaves work exactly as received (no partial mutation). It assumes
// validateRequest has already run.
func transform(work *ebpf.CollectionSpec, req Request) error {
	prog := work.Programs[req.ProgramName]
	if prog == nil {
		return refuse("program %q not found", req.ProgramName)
	}
	if prog.Type != ebpf.XDP {
		return refuse("program %q is type %s, only native XDP is supported", req.ProgramName, prog.Type)
	}
	if err := checkNoCollision(work, req.HookName); err != nil {
		return err
	}
	if err := checkReferences(work, prog, req.HookName); err != nil {
		return err
	}
	if err := checkExtInfo(prog.Instructions); err != nil {
		return err
	}
	if err := checkStackBound(prog.Instructions, req.Stack.LowestOffset); err != nil {
		return err
	}
	// splice validates the site shape and places the spill slots itself.
	spliced, err := splice(prog.Instructions, req)
	if err != nil {
		return err
	}
	prog.Instructions = appendHook(spliced, req)
	return nil
}

func validateRequest(req Request) error {
	switch {
	case req.ELFSHA256 == "":
		return refuse("ELFSHA256 is required")
	case len(req.ELFSHA256) != 64:
		return refuse("ELFSHA256 must be 64 hex chars")
	case req.ProgramName == "":
		return refuse("ProgramName is required")
	case req.HookName == "":
		return refuse("HookName is required")
	case !validIdent(req.HookName):
		return refuse("HookName %q must be a valid C/BTF identifier (1-%d chars, [A-Za-z_][A-Za-z0-9_]*)", req.HookName, maxHookName)
	case req.Load.PtrReg != asm.R0:
		return refuse("Load.PtrReg must be R0, got R%d", req.Load.PtrReg)
	case req.Stack.LowestOffset > 0:
		return refuse("StackAudit.LowestOffset must be <= 0")
	case req.Stack.LowestOffset < -512:
		return refuse("StackAudit.LowestOffset must be >= -512")
	}
	if _, err := hex.DecodeString(req.ELFSHA256); err != nil {
		return refuse("ELFSHA256 is not hex: %v", err)
	}
	return nil
}

func validIdent(s string) bool {
	return len(s) >= 1 && len(s) <= maxHookName && identRe.MatchString(s)
}

// checkNoCollision refuses if HookName already exists as an instruction symbol,
// function-metadata name, or BTF Func anywhere in the collection.
func checkNoCollision(spec *ebpf.CollectionSpec, hook string) error {
	for name, p := range spec.Programs {
		if err := checkInstructionCollision(p.Instructions, hook); err != nil {
			return fmt.Errorf("program %q: %w", name, err)
		}
	}
	return checkBTFCollision(spec.Types, hook)
}

func checkInstructionCollision(insns asm.Instructions, hook string) error {
	for i := range insns {
		ins := &insns[i]
		if ins.Symbol() == hook {
			return refuse("hook name %q collides with a symbol", hook)
		}
		if fn := btf.FuncMetadata(ins); fn != nil && fn.Name == hook {
			return refuse("hook name %q collides with function metadata", hook)
		}
	}
	return nil
}

func checkBTFCollision(types *btf.Spec, hook string) error {
	if types != nil {
		if types, err := types.AnyTypesByName(hook); err == nil {
			for _, t := range types {
				if _, ok := t.(*btf.Func); ok {
					return refuse("hook name %q collides with a BTF Func", hook)
				}
			}
		}
	}
	return nil
}

// checkReferences validates that the target program's symbolic references
// resolve within its flattened instruction stream, and that none names the
// hook. A symbolic function reference must resolve to exactly one symbol there;
// an ambiguous (duplicated) definition and an unresolved call are
// both refused, as is a map load that names a map the collection does not
// define. Refusing an original reference equal to the hook name stops the
// appended hook from silently satisfying a previously unresolved call.
func checkReferences(spec *ebpf.CollectionSpec, target *ebpf.ProgramSpec, hook string) error {
	return checkInstructionReferences(target.Instructions, hook, func(ins *asm.Instruction) bool {
		return spec.Maps[ins.Reference()] != nil
	})
}

func checkInstructionReferences(insns asm.Instructions, hook string, hasMap func(*asm.Instruction) bool) error {
	symCount := map[string]int{}
	for i := range insns {
		if s := insns[i].Symbol(); s != "" {
			symCount[s]++
		}
	}
	for i := range insns {
		ins := &insns[i]
		ref := ins.Reference()
		if ref == "" {
			continue
		}
		if ref == hook {
			return refuse("instruction %d references %q, the generated hook name", i, ref)
		}
		switch {
		case ins.IsFunctionReference():
			switch {
			case symCount[ref] == 0:
				return refuse("symbolic function reference to %q does not resolve to a defined function", ref)
			case symCount[ref] > 1:
				return refuse("symbolic function reference to %q is ambiguous (%d definitions)", ref, symCount[ref])
			}
		case ins.IsLoadFromMap():
			if !hasMap(ins) {
				return refuse("map load references %q, which the collection does not define", ref)
			}
		}
	}
	return nil
}

// checkExtInfo refuses a target whose BTF ext-info is incomplete for appending
// a generated function. The kernel requires the first func_info at instruction
// offset 0 and line info for every function, so a program that lacks function
// metadata on its first instruction, or source lines on any function start,
// would become an inconsistent mix once the hook's func and line info are added.
func checkExtInfo(insns asm.Instructions) error {
	if len(insns) == 0 {
		return refuse("program has no instructions")
	}
	if btf.FuncMetadata(&insns[0]) == nil {
		return refuse("target lacks BTF function info on its first instruction; a generated function cannot be added consistently")
	}
	for i := range insns {
		if btf.FuncMetadata(&insns[i]) != nil && insns[i].Source() == nil {
			return refuse("function at instruction %d lacks source line info", i)
		}
	}
	return nil
}

// checkStackBound refuses if any direct R10/RFP reference the transform can see
// lies below the caller-audited low-water mark. Aliases and callee stacks are
// outside what bytecode inspection can establish and are the caller's audit.
func checkStackBound(insns asm.Instructions, lowest int16) error {
	for i := range insns {
		ins := &insns[i]
		if ins.Dst == asm.RFP || ins.Src == asm.RFP {
			if ins.Offset < lowest {
				return refuse("direct stack offset %d is below audited bound %d", ins.Offset, lowest)
			}
		}
	}
	return nil
}

// spillSlots places two 8-byte-aligned DWord spill slots strictly below the
// 8-byte floor of the audited mark, refusing if they would pass -512. All
// arithmetic is done in int so a very negative mark cannot wrap through int16
// into a positive, wrongly accepted offset.
func spillSlots(lowest int16) (spillR0, spillVal int16, err error) {
	floor := int(lowest)
	if m := floor % 8; m != 0 {
		floor -= 8 + m // round toward -inf to an 8-byte boundary
	}
	r0 := floor - 8
	val := floor - 16
	if val < -512 {
		return 0, 0, refuse("spill region [%d,%d] exceeds the 512-byte stack", val, r0)
	}
	return int16(r0), int16(val), nil
}

// splice rebuilds the instruction stream with the call site inserted on the
// load's fall-through edge, relocating every numeric branch and call for the
// raw-slot shift. It returns a fresh slice and never mutates input.
func splice(input asm.Instructions, req Request) (asm.Instructions, error) {
	site := int(req.SitePC)

	// Raw slot -> slice index, honoring the two-slot width of LDIMM64.
	indices := map[int]int{}
	it := input.Iterate()
	for it.Next() {
		indices[int(it.Offset)] = it.Index
	}
	idx, ok := indices[site]
	if !ok {
		return nil, refuse("SitePC %d is not an instruction boundary", site)
	}
	if idx+1 >= len(input) {
		return nil, refuse("SitePC %d has no following instruction to redefine the site register", site)
	}
	if err := checkShape(input[idx], input[idx+1], req.Load); err != nil {
		return nil, err
	}

	// The insertion runs only on the load's fall-through edge. A branch to the
	// next original instruction must land past the insertion, keeping its old
	// meaning; so everything strictly after the site shifts by insertSlots.
	mapped := func(pc int) int {
		if pc > site {
			return pc + insertSlots
		}
		return pc
	}

	spillR0, spillVal, err := spillSlots(req.Stack.LowestOffset)
	if err != nil {
		return nil, err
	}
	insert := asm.Instructions{
		asm.StoreMem(asm.RFP, spillR0, asm.R0, asm.DWord),
		asm.StoreMem(asm.RFP, spillVal, valueReg, asm.DWord),
		asm.Mov.Imm32(siteReg, int32(req.SitePC)), // zero-extended u32 site
		asm.Call.Label(req.HookName),
		asm.LoadMem(asm.R0, asm.RFP, spillR0, asm.DWord),
		asm.LoadMem(valueReg, asm.RFP, spillVal, asm.DWord),
	}

	output := make(asm.Instructions, 0, len(input)+insertSlots)
	it = input.Iterate()
	for it.Next() {
		ins := *it.Ins // carries original BTF func, line, map and CO-RE metadata
		pc := int(it.Offset)

		target, relative, function, err := relocTarget(&ins, pc, indices, input)
		if err != nil {
			return nil, err
		}
		if relative {
			if err := relocateOffset(&ins, mapped(pc), mapped(target), function); err != nil {
				return nil, err
			}
		}

		output = append(output, ins)
		if pc == site {
			output = append(output, insert...)
		}
	}
	return output, nil
}

// relocTarget classifies branches, calls and callback loads. Function references
// use an int32 constant; branches use an int16 offset. Symbolic references stay
// unresolved for the loader. Numeric targets must be instruction boundaries;
// callback targets additionally require a non-entry BTF function start.
func relocTarget(ins *asm.Instruction, pc int, indices map[int]int, input asm.Instructions) (target int, relative, function bool, err error) {
	switch {
	case ins.IsLoadOfFunctionPointer():
		if ins.Offset != 0 || ins.Constant < math.MinInt32 || ins.Constant > math.MaxInt32 {
			return 0, false, false, refuse("malformed function-pointer load at %d", pc)
		}
		t := pc + 1 + int(ins.Constant)
		if ref := ins.Reference(); ref != "" {
			if ins.Constant != -1 {
				return 0, false, false, refuse("symbolic function-pointer load at %d is already resolved", pc)
			}
			count := 0
			for offset, idx := range indices {
				if input[idx].Symbol() == ref {
					t = offset
					count++
				}
			}
			if count != 1 {
				return 0, false, false, refuse("function-pointer reference %q at %d has %d definitions", ref, pc, count)
			}
		}
		idx, ok := indices[t]
		if !ok {
			return 0, false, false, refuse("function-pointer load at %d targets %d, not an instruction boundary", pc, t)
		}
		if t == 0 || btf.FuncMetadata(&input[idx]) == nil {
			return 0, false, false, refuse("function-pointer load at %d targets %d, not a subprogram start", pc, t)
		}
		return t, ins.Reference() == "", true, nil

	case ins.IsFunctionCall():
		if ins.Reference() != "" {
			// Symbolic bpf2bpf call: resolved by name at marshal time against
			// the rebuilt stream, so leave it untouched. A resolved symbolic
			// call (constant already set) would be ambiguous; refuse it.
			if ins.Constant != -1 {
				return 0, false, false, refuse("symbolic call at %d is already resolved", pc)
			}
			return 0, false, true, nil
		}
		t := pc + 1 + int(ins.Constant)
		if _, ok := indices[t]; !ok {
			return 0, false, false, refuse("numeric call at %d targets %d, not an instruction boundary", pc, t)
		}
		return t, true, true, nil

	case ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() != asm.Call && ins.OpCode.JumpOp() != asm.Exit:
		if ins.Reference() != "" {
			return 0, false, false, refuse("symbolic branch at %d is unsupported", pc)
		}
		if ins.OpCode.Class() == asm.Jump32Class && ins.OpCode.JumpOp() == asm.Ja {
			return 0, false, false, refuse("long jump at %d is unsupported", pc)
		}
		t := pc + 1 + int(ins.Offset)
		if _, ok := indices[t]; !ok {
			return 0, false, false, refuse("branch at %d targets %d, not an instruction boundary", pc, t)
		}
		return t, true, false, nil

	default:
		// Non-branch instruction. A dangling reference that is neither a call,
		// branch, nor map load is something we do not understand; refuse it.
		if ins.Reference() != "" && !ins.IsLoadFromMap() {
			return 0, false, false, refuse("unknown reference %q at %d", ins.Reference(), pc)
		}
		return 0, false, false, nil
	}
}

// relocateOffset uses the first raw slot plus one even for two-slot LDIMM64
// callback loads, matching the kernel and the loader's function references.
func relocateOffset(ins *asm.Instruction, pc, target int, function bool) error {
	delta := int64(target) - int64(pc) - 1
	if function {
		if delta < math.MinInt32 || delta > math.MaxInt32 {
			return refuse("function reference at %d overflows int32 after insertion", pc)
		}
		ins.Constant = delta
	} else {
		if delta < math.MinInt16 || delta > math.MaxInt16 {
			return refuse("branch at %d overflows int16 after insertion", pc)
		}
		ins.Offset = int16(delta)
	}
	return nil
}

// checkShape enforces the audited load shape and site-register redefinition.
func checkShape(load, next asm.Instruction, shape LoadShape) error {
	if shape.PtrReg != asm.R0 {
		return refuse("unsupported pointer register R%d: only R0 is supported", shape.PtrReg)
	}
	want := asm.LoadMem(valueReg, shape.PtrReg, shape.Offset, asm.Word)
	if load.OpCode != want.OpCode || load.Dst != want.Dst || load.Src != want.Src ||
		load.Offset != want.Offset || load.Constant != want.Constant {
		return refuse("site instruction is not the audited load %s", want)
	}
	if !redefinesSiteReg(next) {
		return refuse("instruction after site does not cleanly redefine the site register R%d", siteReg)
	}
	return nil
}

// redefinesSiteReg reports whether next is a full write of the site register
// (R1) that does not also read it: a MOV (immediate, or register from a source
// other than R1), a 64-bit immediate load, or a memory load from a pointer
// other than R1. A read-modify-write ALU op, a jump that tests R1, a store, or
// a call all leave R1 live, so the splice's clobber of R1 would corrupt the
// program; those are refused.
func redefinesSiteReg(next asm.Instruction) bool {
	if next.Dst != siteReg {
		return false
	}
	op := next.OpCode
	switch op.Class() {
	case asm.ALUClass, asm.ALU64Class:
		if op.ALUOp() != asm.Mov {
			return false // read-modify-write reads R1
		}
		if op.Source() == asm.RegSource && next.Src == siteReg {
			return false // mov r1, r1 reads R1
		}
		return true
	case asm.LdClass:
		return op == asm.LoadImmOp(asm.DWord) // LDIMM64 reads no register
	case asm.LdXClass:
		return next.Src != siteReg // memory load; pointer must not be R1
	default:
		return false
	}
}

// appendHook appends the generated typed global function with both BTF function
// metadata and generated source-line info. The kernel requires line info for
// every function, so the generated function needs a source line of its own in
// addition to its func metadata.
func appendHook(insns asm.Instructions, req Request) asm.Instructions {
	u32 := &btf.Int{Name: "unsigned int", Size: 4, Encoding: btf.Unsigned}
	fn := &btf.Func{
		Name:    req.HookName,
		Linkage: btf.GlobalFunc,
		Type: &btf.FuncProto{
			Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
			Params: []btf.FuncParam{
				{Name: "site", Type: u32},
				{Name: "value", Type: u32},
			},
		},
	}
	head := btf.WithFuncMetadata(
		asm.Mov.Reg32(asm.R0, siteReg).
			WithSymbol(req.HookName).
			WithSource(asm.Comment("generated typed observation hook "+req.HookName)),
		fn,
	)
	return append(insns,
		head,
		asm.Xor.Reg32(asm.R0, valueReg),
		asm.Return(),
	)
}

// checksum is a stable SHA-256 over the raw encoding of an instruction stream,
// independent of map file descriptors (absent at spec stage). It covers the
// per-instruction encoding only; see Result for the metadata it excludes.
func checksum(insns asm.Instructions, bo binary.ByteOrder) (string, error) {
	h := sha256.New()
	for i := range insns {
		if _, err := insns[i].Marshal(h, bo); err != nil {
			return "", fmt.Errorf("instruction %d: %w", i, err)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
