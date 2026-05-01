package vocab

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
)

// Load reads every *.p4 file directly under root in the given file
// system, parses each with p4lite, and classifies its dispatch
// constants into a ProtocolSpec keyed by lowercase protocol name.
//
// Only files directly in root are considered; subdirectories are
// ignored.
func Load(fsys fs.FS, root string) (map[string]*ProtocolSpec, error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("read vocab dir %q: %w", root, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".p4") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	out := make(map[string]*ProtocolSpec, len(names))
	for _, name := range names {
		full := path.Join(root, name)
		spec, err := loadFile(fsys, full)
		if err != nil {
			return nil, err
		}
		if prev, ok := out[spec.Name]; ok {
			return nil, fmt.Errorf("duplicate protocol %q: %s and %s", spec.Name, prev.Source, spec.Source)
		}
		out[spec.Name] = spec
	}
	return out, nil
}

func loadFile(fsys fs.FS, p string) (*ProtocolSpec, error) {
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", p, err)
	}
	file, err := p4lite.Parse(data, p)
	if err != nil {
		return nil, err
	}
	base := path.Base(p)
	protoName := strings.ToLower(strings.TrimSuffix(base, ".p4"))
	if protoName == "" {
		return nil, fmt.Errorf("%s: empty protocol name after stripping .p4", p)
	}
	// A vocab file must declare a primary header named "<protoname>_h".
	// Additional headers are allowed for auxiliary layouts (GTP option
	// headers, SRv6 segment entries, etc.) and are accessible via File.
	// Reject duplicate header names up-front: p4lite/parser.go does not
	// dedup on its own, so without this loop a typo like
	// `header ipv4_h { ... } header ipv4_h { ... }` would silently pick
	// the first copy and the second would never load-bear anything.
	primaryName := protoName + "_h"
	var primary *p4lite.Header
	seenHeaders := make(map[string]bool, len(file.Headers))
	for _, h := range file.Headers {
		if seenHeaders[h.Name] {
			return nil, fmt.Errorf("%s: duplicate header %q", p, h.Name)
		}
		seenHeaders[h.Name] = true
		if h.Name == primaryName {
			primary = h
		}
	}
	if primary == nil {
		names := make([]string, len(file.Headers))
		for i, h := range file.Headers {
			names[i] = h.Name
		}
		return nil, fmt.Errorf("%s: missing primary header %q (declared headers: %v)", p, primaryName, names)
	}
	fields := make([]Field, len(primary.Fields))
	for i, f := range primary.Fields {
		fields[i] = Field{Name: f.Name, Bits: f.Bits}
	}
	res, err := classifyConsts(file.Consts, protoName, p)
	if err != nil {
		return nil, err
	}
	machine, err := buildParseStateMachine(file, primary, p)
	if err != nil {
		return nil, err
	}
	suffix, err := buildVariableSuffix(res.VarExt, fields, p)
	if err != nil {
		return nil, err
	}
	flagsOff, triggers, err := buildFlagTriggers(res.OptFlags, fields, p)
	if err != nil {
		return nil, err
	}
	spec := &ProtocolSpec{
		Name:              protoName,
		HeaderName:        primary.Name,
		Fields:            fields,
		Consts:            res.Consts,
		MaxDepth:          res.MaxDepth,
		ChainEnd:          res.ChainEnd,
		VariableSuffix:    suffix,
		FlagTriggers:      triggers,
		FlagsByteOffset:   flagsOff,
		ParseStateMachine: machine,
		File:              file,
		Source:            p,
	}
	if res.ChainEnd != nil {
		// Validate the field exists in the primary header now; the
		// loader is the right place because resolver / codegen otherwise
		// have to re-derive the same diagnostic per-call.
		if _, ok := spec.FindField(res.ChainEnd.FieldName); !ok {
			return nil, fmt.Errorf("%s: CHAIN_END const %q references unknown field %q", p, res.ChainEnd.Name, res.ChainEnd.FieldName)
		}
	}
	if err := validateLayoutExclusivity(spec); err != nil {
		return nil, err
	}
	return spec, nil
}

// validateLayoutExclusivity rejects vocab files that combine
// variable-layout features in ways the codegen does not handle. A
// parser-state-machine block is the canonical "complex layout"
// channel and already lets the protocol express aux extracts and
// per-iteration advances; declarative VAREXT_LEN_* / OPT_TRIGGER_*
// consts are the simpler channel for primary-header trailers /
// flag-gated optional fields. Mixing both on the same protocol
// hits two issues at once:
//
//   - genLayerInner dispatches on ParseStateMachine first, so a
//     parser-machine layer silently ignores VariableSuffix and
//     FlagTriggers — a real bug masquerading as success.
//   - The semantics overlap (which trailer wins?) is undefined.
//
// We refuse the combination at load time so the silent miss never
// reaches codegen.
func validateLayoutExclusivity(s *ProtocolSpec) error {
	if s.ParseStateMachine == nil {
		return nil
	}
	if s.VariableSuffix != nil {
		return fmt.Errorf("%s: protocol %q declares both a non-trivial parser block and VAREXT_LEN_* — choose one channel for variable-length layout", s.Source, s.Name)
	}
	if len(s.FlagTriggers) > 0 {
		return fmt.Errorf("%s: protocol %q declares both a non-trivial parser block and OPT_TRIGGER_* — choose one channel for variable-length layout", s.Source, s.Name)
	}
	return nil
}

// maxDepthCap bounds the MAX_DEPTH value so the future bpf_loop
// callback cannot spin for absurd numbers of iterations even if a
// vocab author sets a silly value.
const maxDepthCap = 64

// Regexes applied to the suffix after "<SELF>_". Parent names are
// single tokens (no underscores); field names may contain underscores.
//
// Order in classifyConsts matters: reChainEnd is matched *before*
// reField so a const literally named `<SELF>_CHAIN_END_<X>` is
// classified as a chain-end signal even though reField would also
// accept it (parent="CHAIN", field="END_X"). A protocol whose
// parent is genuinely named "chain" therefore cannot use a Field
// dispatch const whose field name starts with "END_".
var (
	reNoCheck  = regexp.MustCompile(`^([A-Z0-9]+)_NO_CHECK$`)
	reSanity   = regexp.MustCompile(`^([A-Z0-9]+)_SANITY_([A-Z0-9_]+)$`)
	reChainEnd = regexp.MustCompile(`^CHAIN_END_([A-Z0-9_]+)$`)
	reField    = regexp.MustCompile(`^([A-Z0-9]+)_([A-Z0-9_]+)$`)
)

// classifyResult bundles the per-protocol metadata classifyConsts
// peels out of the raw const list. Every field is optional; the
// loader fills in whatever the .p4 declared.
type classifyResult struct {
	Consts   []DispatchConst
	MaxDepth int
	ChainEnd *ChainEndConst
	VarExt   varExtConsts
	OptFlags optFlagConsts
}

// optFlagConsts collects raw <SELF>_OPT_{FLAGS_BYTE_OFFSET, TRIGGER_<N>, LEN_<N>}
// constants in declaration order. buildFlagTriggers cross-references
// TRIGGER_<N> with LEN_<N> after the full file is parsed so order is
// preserved regardless of which key appears first in the source.
type optFlagConsts struct {
	HasFlagsByteOffset bool
	FlagsByteOffset    int
	// triggerOrder lists trigger names in the order they were first
	// seen — used to keep advance ordering deterministic and aligned
	// with protocols where the optional fields are sequential (GRE).
	triggerOrder []string
	triggers     map[string]int // name → bit mask
	lengths      map[string]int // name → byte length
}

// varExtConsts is the raw form of <SELF>_VAREXT_LEN_* constants
// before they are validated as a complete five-tuple. Each set bit in
// `seen` corresponds to one of the required keys; loadVariableSuffix
// rejects partial declarations.
type varExtConsts struct {
	ByteOff int
	Mask    int
	Shift   int
	Scale   int
	Base    int
	seen    uint8
}

const (
	varExtByteOffBit uint8 = 1 << iota
	varExtMaskBit
	varExtShiftBit
	varExtScaleBit
	varExtBaseBit
)

const varExtAllBits = varExtByteOffBit | varExtMaskBit | varExtShiftBit | varExtScaleBit | varExtBaseBit

// setOptFlagsField parses one <SELF>_OPT_* key. Recognised forms:
//
//	OPT_FLAGS_BYTE_OFFSET — single declaration; flag-byte position
//	OPT_TRIGGER_<NAME>    — bit mask gating LEN_<NAME>
//	OPT_LEN_<NAME>        — byte length advanced when the trigger fires
//
// TRIGGER_<NAME> and LEN_<NAME> are paired by NAME (uppercase).
// Order is preserved via triggerOrder so codegen advances optional
// fields in the order GRE / future protocols expect.
func setOptFlagsField(of *optFlagConsts, key string, c *p4lite.Const, source string) error {
	if key == "FLAGS_BYTE_OFFSET" {
		if of.HasFlagsByteOffset {
			return fmt.Errorf("%s: duplicate OPT_FLAGS_BYTE_OFFSET declaration %q", source, c.Name)
		}
		of.HasFlagsByteOffset = true
		of.FlagsByteOffset = int(c.Int)
		return nil
	}
	if name, ok := strings.CutPrefix(key, "TRIGGER_"); ok {
		return recordOptField(of, &of.triggers, "TRIGGER", name, c, source)
	}
	if name, ok := strings.CutPrefix(key, "LEN_"); ok {
		return recordOptField(of, &of.lengths, "LEN", name, c, source)
	}
	return fmt.Errorf("%s: OPT const %q has unknown key %q (expected FLAGS_BYTE_OFFSET|TRIGGER_<NAME>|LEN_<NAME>)", source, c.Name, key)
}

// recordOptField stores one TRIGGER_<NAME> or LEN_<NAME> value into
// the named map and threads the name into triggerOrder so the
// builder later iterates declarations in source order.
func recordOptField(of *optFlagConsts, dst *map[string]int, kind, name string, c *p4lite.Const, source string) error {
	if name == "" {
		return fmt.Errorf("%s: OPT_%s_ const %q has empty name", source, kind, c.Name)
	}
	if *dst == nil {
		*dst = make(map[string]int)
	}
	if _, dup := (*dst)[name]; dup {
		return fmt.Errorf("%s: duplicate OPT_%s_%s declaration %q", source, kind, name, c.Name)
	}
	(*dst)[name] = int(c.Int)
	of.triggerOrder = appendIfNew(of.triggerOrder, name)
	return nil
}

func appendIfNew(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// buildFlagTriggers cross-references TRIGGER_<N> with LEN_<N> in
// declaration order, returning the flag byte offset and the resolved
// trigger list. Returns (0, nil, nil) when the .p4 declared no OPT_
// constants at all.
func buildFlagTriggers(of optFlagConsts, fields []Field, source string) (int, []FlagTrigger, error) {
	if !of.HasFlagsByteOffset && len(of.triggerOrder) == 0 {
		return 0, nil, nil
	}
	if !of.HasFlagsByteOffset {
		return 0, nil, fmt.Errorf("%s: OPT_TRIGGER_/OPT_LEN_ declared without OPT_FLAGS_BYTE_OFFSET", source)
	}
	headerBytes := SumBits(fields) / 8
	if of.FlagsByteOffset < 0 || of.FlagsByteOffset >= headerBytes {
		return 0, nil, fmt.Errorf("%s: OPT_FLAGS_BYTE_OFFSET %d is out of range for %d-byte primary header", source, of.FlagsByteOffset, headerBytes)
	}
	triggers := make([]FlagTrigger, 0, len(of.triggerOrder))
	for _, name := range of.triggerOrder {
		mask, hasT := of.triggers[name]
		length, hasL := of.lengths[name]
		switch {
		case hasT && !hasL:
			return 0, nil, fmt.Errorf("%s: OPT_TRIGGER_%s declared without matching OPT_LEN_%s", source, name, name)
		case !hasT && hasL:
			return 0, nil, fmt.Errorf("%s: OPT_LEN_%s declared without matching OPT_TRIGGER_%s", source, name, name)
		}
		if mask <= 0 || mask > 0xFF {
			return 0, nil, fmt.Errorf("%s: OPT_TRIGGER_%s mask %#x must be in (0, 0xFF]", source, name, mask)
		}
		if length <= 0 {
			return 0, nil, fmt.Errorf("%s: OPT_LEN_%s %d must be > 0", source, name, length)
		}
		triggers = append(triggers, FlagTrigger{Name: name, BitMask: mask, LenBytes: length})
	}
	return of.FlagsByteOffset, triggers, nil
}

// setVarExtField records one VAREXT_LEN_* key into ve, rejecting
// duplicates and unknown suffixes. Caller has already verified the
// const is bit<N>, not bool.
func setVarExtField(ve *varExtConsts, key string, c *p4lite.Const, source string) error {
	var bit uint8
	var dst *int
	switch key {
	case "BYTE_OFFSET":
		bit, dst = varExtByteOffBit, &ve.ByteOff
	case "MASK":
		bit, dst = varExtMaskBit, &ve.Mask
	case "SHIFT":
		bit, dst = varExtShiftBit, &ve.Shift
	case "SCALE":
		bit, dst = varExtScaleBit, &ve.Scale
	case "BASE":
		bit, dst = varExtBaseBit, &ve.Base
	default:
		return fmt.Errorf("%s: VAREXT_LEN const %q has unknown suffix %q (expected BYTE_OFFSET|MASK|SHIFT|SCALE|BASE)", source, c.Name, key)
	}
	if ve.seen&bit != 0 {
		return fmt.Errorf("%s: duplicate VAREXT_LEN_%s declaration %q", source, key, c.Name)
	}
	ve.seen |= bit
	*dst = int(c.Int)
	return nil
}

// buildVariableSuffix promotes the raw varExtConsts to a fully
// validated VariableSuffix, or returns nil when the .p4 declared no
// VAREXT keys at all. Partial declarations are rejected with a
// pointer at the missing keys.
func buildVariableSuffix(ve varExtConsts, fields []Field, source string) (*VariableSuffix, error) {
	if ve.seen == 0 {
		return nil, nil
	}
	if ve.seen != varExtAllBits {
		var missing []string
		for _, kv := range []struct {
			bit  uint8
			name string
		}{
			{varExtByteOffBit, "BYTE_OFFSET"},
			{varExtMaskBit, "MASK"},
			{varExtShiftBit, "SHIFT"},
			{varExtScaleBit, "SCALE"},
			{varExtBaseBit, "BASE"},
		} {
			if ve.seen&kv.bit == 0 {
				missing = append(missing, "VAREXT_LEN_"+kv.name)
			}
		}
		return nil, fmt.Errorf("%s: VAREXT_LEN declaration is incomplete (missing %s)", source, strings.Join(missing, ", "))
	}
	if ve.Mask == 0 || ve.Mask > 0xFF {
		return nil, fmt.Errorf("%s: VAREXT_LEN_MASK %#x must be in (0, 0xFF]", source, ve.Mask)
	}
	if ve.Shift < 0 || ve.Shift > 7 {
		return nil, fmt.Errorf("%s: VAREXT_LEN_SHIFT %d must be in [0, 7]", source, ve.Shift)
	}
	// Codegen lowers `* Scale` to a left-shift, so Scale must be a
	// power of two it knows how to encode (codegen.scaleShift table:
	// 1, 2, 4, 8, 16, 32, 64, 128). Capping at 128 also keeps the
	// worst-case computed advance ((mask >> shift) << log2(scale))
	// within 0xFFFF, well clear of int32 overflow.
	if ve.Scale <= 0 || ve.Scale > 128 || (ve.Scale&(ve.Scale-1)) != 0 {
		return nil, fmt.Errorf("%s: VAREXT_LEN_SCALE %d must be a power of two in [1, 128]", source, ve.Scale)
	}
	if ve.Base < 0 {
		return nil, fmt.Errorf("%s: VAREXT_LEN_BASE %d must be >= 0 (declared minimum header bytes)", source, ve.Base)
	}
	headerBytes := SumBits(fields) / 8
	if ve.ByteOff < 0 || ve.ByteOff >= headerBytes {
		return nil, fmt.Errorf("%s: VAREXT_LEN_BYTE_OFFSET %d is out of range for %d-byte primary header", source, ve.ByteOff, headerBytes)
	}
	if ve.Base != headerBytes {
		return nil, fmt.Errorf("%s: VAREXT_LEN_BASE %d must equal the primary header size (%d bytes)", source, ve.Base, headerBytes)
	}
	return &VariableSuffix{
		LenByteOff: ve.ByteOff,
		LenMask:    ve.Mask,
		LenShift:   ve.Shift,
		Scale:      ve.Scale,
		Base:       ve.Base,
	}, nil
}

func classifyConsts(cs []*p4lite.Const, protoName, source string) (classifyResult, error) {
	protoUpper := strings.ToUpper(protoName)
	res := classifyResult{Consts: make([]DispatchConst, 0, len(cs))}
	// Reject any duplicate const name regardless of family. Some
	// families (MAX_DEPTH, CHAIN_END, VAREXT_LEN_*, OPT_*) already
	// have purpose-specific dup checks, but plain Dispatch consts
	// (NO_CHECK / SANITY / Field) used to slip through silently —
	// `SelectDispatchConst` would just return whichever copy came
	// first, masking the typo. p4c-check catches identifier-level
	// dup in valid P4-16 anyway, but we double-gate here so kunai
	// can be vendored standalone (no p4c) and still fail loud.
	seenNames := make(map[string]bool, len(cs))
	for _, c := range cs {
		if seenNames[c.Name] {
			return classifyResult{}, fmt.Errorf("%s: duplicate const %q", source, c.Name)
		}
		seenNames[c.Name] = true
		if !strings.HasPrefix(c.Name, protoUpper+"_") {
			return classifyResult{}, fmt.Errorf("%s: const %q must begin with %q (self-prefix derived from filename)", source, c.Name, protoUpper+"_")
		}
		rest := c.Name[len(protoUpper)+1:]
		if rest == "MAX_DEPTH" {
			if c.IsBool {
				return classifyResult{}, fmt.Errorf("%s: MAX_DEPTH const %q must be bit<N>, got bool", source, c.Name)
			}
			if c.Int == 0 {
				return classifyResult{}, fmt.Errorf("%s: MAX_DEPTH const %q must be >= 1", source, c.Name)
			}
			if c.Int > maxDepthCap {
				return classifyResult{}, fmt.Errorf("%s: MAX_DEPTH const %q = %d exceeds cap %d", source, c.Name, c.Int, maxDepthCap)
			}
			if res.MaxDepth != 0 {
				return classifyResult{}, fmt.Errorf("%s: duplicate MAX_DEPTH declaration %q", source, c.Name)
			}
			res.MaxDepth = int(c.Int)
			continue
		}
		if strings.HasPrefix(rest, "OPT_") {
			if c.IsBool {
				return classifyResult{}, fmt.Errorf("%s: OPT const %q must be bit<N>, got bool", source, c.Name)
			}
			if err := setOptFlagsField(&res.OptFlags, rest[len("OPT_"):], c, source); err != nil {
				return classifyResult{}, err
			}
			continue
		}
		if strings.HasPrefix(rest, "VAREXT_LEN_") {
			if c.IsBool {
				return classifyResult{}, fmt.Errorf("%s: VAREXT_LEN const %q must be bit<N>, got bool", source, c.Name)
			}
			key := rest[len("VAREXT_LEN_"):]
			if err := setVarExtField(&res.VarExt, key, c, source); err != nil {
				return classifyResult{}, err
			}
			continue
		}
		if m := reChainEnd.FindStringSubmatch(rest); m != nil {
			if c.IsBool {
				return classifyResult{}, fmt.Errorf("%s: CHAIN_END const %q must be bit<N>, got bool", source, c.Name)
			}
			if res.ChainEnd != nil {
				return classifyResult{}, fmt.Errorf("%s: duplicate CHAIN_END declaration %q (only one chain-termination signal per protocol is supported)", source, c.Name)
			}
			res.ChainEnd = &ChainEndConst{
				Name:      c.Name,
				FieldName: strings.ToLower(m[1]),
				Value:     c.Int,
				Bits:      c.Bits,
			}
			continue
		}
		dc := DispatchConst{Name: c.Name}
		if m := reNoCheck.FindStringSubmatch(rest); m != nil {
			if !c.IsBool {
				return classifyResult{}, fmt.Errorf("%s: NO_CHECK const %q must be declared as bool", source, c.Name)
			}
			if !c.Bool {
				return classifyResult{}, fmt.Errorf("%s: NO_CHECK const %q must be true; false has no meaning", source, c.Name)
			}
			dc.Type = DispatchNoCheck
			dc.Parent = strings.ToLower(m[1])
			dc.Bool = true
		} else if m := reSanity.FindStringSubmatch(rest); m != nil {
			if c.IsBool {
				return classifyResult{}, fmt.Errorf("%s: SANITY const %q must be bit<N>, got bool", source, c.Name)
			}
			dc.Type = DispatchSanity
			dc.Parent = strings.ToLower(m[1])
			dc.SanityType = m[2]
			dc.Bits = c.Bits
			dc.Value = c.Int
		} else if m := reField.FindStringSubmatch(rest); m != nil {
			if c.IsBool {
				return classifyResult{}, fmt.Errorf("%s: field-dispatch const %q must be bit<N>, got bool", source, c.Name)
			}
			dc.Type = DispatchField
			dc.Parent = strings.ToLower(m[1])
			dc.FieldName = strings.ToLower(m[2])
			dc.Bits = c.Bits
			dc.Value = c.Int
		} else {
			return classifyResult{}, fmt.Errorf("%s: const %q does not match <SELF>_<PARENT>_{<FIELD>|SANITY_<TYPE>|NO_CHECK|MAX_DEPTH|CHAIN_END_<FIELD>}", source, c.Name)
		}
		res.Consts = append(res.Consts, dc)
	}
	return res, nil
}
