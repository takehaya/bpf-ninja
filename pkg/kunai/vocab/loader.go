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
	flagsOff, triggers, err := buildFlagTriggers(res.OptFlags, fields, p)
	if err != nil {
		return nil, err
	}
	walk, err := buildOptionWalk(res.OptFlags.optionsWalk, file, protoName, p)
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
		FlagTriggers:      triggers,
		FlagsByteOffset:   flagsOff,
		OptionWalk:        walk,
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
	spec.selfValidating = computeSelfValidating(spec)
	return spec, nil
}

// validateLayoutExclusivity rejects vocab files that combine the
// flag-triggered optional family with a non-trivial parser block.
// genLayerInner dispatches on ParseStateMachine first, so the
// FlagTriggers would silently never run — a real bug masquerading
// as success. Refuse it at load time.
func validateLayoutExclusivity(s *ProtocolSpec) error {
	if s.ParseStateMachine == nil {
		return nil
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
//
// reSanityName is here purely to surface a clear error if someone
// declares a legacy `<SELF>_<PARENT>_SANITY_<TYPE>` or `<SELF>_SANITY_<TYPE>`
// const. The SANITY family was removed in favour of parser-block
// self-validation (transition select with `default: reject`); without
// this check the name would fall through to reField and silently
// become a Field dispatch. The optional prefix accepts `[A-Z0-9_]+_`
// so multi-token parents (e.g. `FOO_BAR_SANITY_NIBBLE`) are caught
// alongside the single-token shapes — false positives like a const
// that happens to contain the substring `_SANITY_` are accepted as
// the cost of making the loud-fail exhaustive.
var (
	reNoCheck    = regexp.MustCompile(`^([A-Z0-9]+)_NO_CHECK$`)
	reSanityName = regexp.MustCompile(`^(?:[A-Z0-9_]+_)?SANITY_[A-Z0-9_]+$`)
	reChainEnd   = regexp.MustCompile(`^CHAIN_END_([A-Z0-9_]+)$`)
	reField      = regexp.MustCompile(`^([A-Z0-9]+)_([A-Z0-9_]+)$`)
)

// classifyResult bundles the per-protocol metadata classifyConsts
// peels out of the raw const list. Every field is optional; the
// loader fills in whatever the .p4 declared.
type classifyResult struct {
	Consts   []DispatchConst
	MaxDepth int
	ChainEnd *ChainEndConst
	OptFlags optFlagConsts
}

// optFlagConsts collects raw <SELF>_OPT_{FLAGS_BYTE_OFFSET, TRIGGER_<N>, LEN_<N>}
// constants in declaration order. buildFlagTriggers cross-references
// TRIGGER_<N> with LEN_<N> after the full file is parsed so order is
// preserved regardless of which key appears first in the source.
//
// The same OPT_ prefix is shared with TCP/IPv4 option-walk consts
// (TERMINATOR_KIND / PADDING_KIND / LENGTH_BYTE_OFF / <NAME>_KIND /
// <NAME>_SIZE) so this struct also collects them; they end up on a
// separate ProtocolSpec field after classification.
type optFlagConsts struct {
	HasFlagsByteOffset bool
	FlagsByteOffset    int
	// triggerOrder lists trigger names in the order they were first
	// seen — used to keep advance ordering deterministic and aligned
	// with protocols where the optional fields are sequential (GRE).
	triggerOrder []string
	triggers     map[string]int // name → bit mask
	lengths      map[string]int // name → byte length

	// TCP/IPv4 options walk: optionsWalk is non-nil when at least one
	// of the option-walk keys was declared.
	optionsWalk *optWalkConsts
}

// optWalkConsts holds the raw form of TCP/IPv4 option-walk consts
// before they are validated (terminator + padding + length-byte +
// per-option kind/size set).
type optWalkConsts struct {
	HasTerminator  bool
	TerminatorKind uint64
	HasPadding     bool
	PaddingKind    uint64
	HasLengthOff   bool
	LengthByteOff  int
	// optionOrder lists option names in declaration order so codegen
	// emits dispatch checks deterministically.
	optionOrder []string
	kinds       map[string]uint64
	sizes       map[string]int
}

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
	// Options-walk consts: <PROTO>_OPT_{TERMINATOR_KIND|PADDING_KIND|
	// LENGTH_BYTE_OFF|<NAME>_KIND|<NAME>_SIZE}.
	if of.optionsWalk == nil {
		of.optionsWalk = &optWalkConsts{kinds: map[string]uint64{}, sizes: map[string]int{}}
	}
	walk := of.optionsWalk
	switch key {
	case "TERMINATOR_KIND":
		if walk.HasTerminator {
			return fmt.Errorf("%s: duplicate OPT_TERMINATOR_KIND declaration %q", source, c.Name)
		}
		walk.HasTerminator = true
		walk.TerminatorKind = c.Int
		return nil
	case "PADDING_KIND":
		if walk.HasPadding {
			return fmt.Errorf("%s: duplicate OPT_PADDING_KIND declaration %q", source, c.Name)
		}
		walk.HasPadding = true
		walk.PaddingKind = c.Int
		return nil
	case "LENGTH_BYTE_OFF":
		if walk.HasLengthOff {
			return fmt.Errorf("%s: duplicate OPT_LENGTH_BYTE_OFF declaration %q", source, c.Name)
		}
		walk.HasLengthOff = true
		walk.LengthByteOff = int(c.Int)
		return nil
	}
	if name, ok := strings.CutSuffix(key, "_KIND"); ok && name != "" {
		if _, dup := walk.kinds[name]; dup {
			return fmt.Errorf("%s: duplicate OPT_%s_KIND declaration %q", source, name, c.Name)
		}
		walk.kinds[name] = c.Int
		walk.optionOrder = appendIfNew(walk.optionOrder, name)
		return nil
	}
	if name, ok := strings.CutSuffix(key, "_SIZE"); ok && name != "" {
		if _, dup := walk.sizes[name]; dup {
			return fmt.Errorf("%s: duplicate OPT_%s_SIZE declaration %q", source, name, c.Name)
		}
		walk.sizes[name] = int(c.Int)
		walk.optionOrder = appendIfNew(walk.optionOrder, name)
		return nil
	}
	return fmt.Errorf("%s: OPT const %q has unknown key %q (expected FLAGS_BYTE_OFFSET|TRIGGER_<NAME>|LEN_<NAME>|TERMINATOR_KIND|PADDING_KIND|LENGTH_BYTE_OFF|<NAME>_KIND|<NAME>_SIZE)", source, c.Name, key)
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

// buildOptionWalk validates the raw OPT_ option-walk consts and
// pairs each named option (TCP_OPT_<NAME>_KIND/SIZE) with its aux
// header type tcp_opt_<NAME>_h declared in the parser block. nil
// when the .p4 declared no option-walk consts.
//
// TerminatorKind / PaddingKind / LengthByteOff default to the RFC
// universal values (0 = EOL, 1 = NOP, length byte at offset 1) used
// by both TCP options (RFC 9293) and IPv4 options (RFC 791). A
// .p4 may either declare all three explicitly (override) or none
// (use defaults). Declaring some-but-not-all is a typo guard.
func buildOptionWalk(raw *optWalkConsts, file *p4lite.File, protoName, source string) (*OptionWalk, error) {
	if raw == nil {
		return nil, nil
	}
	hasAny := raw.HasTerminator || raw.HasPadding || raw.HasLengthOff
	hasAll := raw.HasTerminator && raw.HasPadding && raw.HasLengthOff
	if hasAny && !hasAll {
		return nil, fmt.Errorf("%s: protocol %q declares some OPT_ option-walk consts but missing one of TERMINATOR_KIND/PADDING_KIND/LENGTH_BYTE_OFF (declare all three to override the RFC defaults, or none to accept them)", source, protoName)
	}
	if len(raw.optionOrder) == 0 {
		return nil, fmt.Errorf("%s: protocol %q declares OPT_ option-walk skeleton but no <NAME>_KIND/SIZE entries", source, protoName)
	}
	out := &OptionWalk{TerminatorKind: 0, PaddingKind: 1, LengthByteOff: 1}
	if hasAll {
		out.TerminatorKind = raw.TerminatorKind
		out.PaddingKind = raw.PaddingKind
		out.LengthByteOff = raw.LengthByteOff
	}
	for _, name := range raw.optionOrder {
		kind, hasK := raw.kinds[name]
		size, hasS := raw.sizes[name]
		switch {
		case hasK && !hasS:
			return nil, fmt.Errorf("%s: OPT_%s_KIND declared without matching OPT_%s_SIZE", source, name, name)
		case !hasK && hasS:
			return nil, fmt.Errorf("%s: OPT_%s_SIZE declared without matching OPT_%s_KIND", source, name, name)
		}
		hdrName := strings.ToLower(protoName) + "_opt_" + strings.ToLower(name) + "_h"
		hdr := findHeader(file, hdrName)
		if hdr == nil {
			return nil, fmt.Errorf("%s: option %q has KIND/SIZE consts but no %q header declared", source, name, hdrName)
		}
		out.Options = append(out.Options, OptionEntry{
			Name:      name,
			Kind:      kind,
			Size:      size,
			HeaderRef: hdr,
		})
	}
	return out, nil
}


func classifyConsts(cs []*p4lite.Const, protoName, source string) (classifyResult, error) {
	protoUpper := strings.ToUpper(protoName)
	res := classifyResult{Consts: make([]DispatchConst, 0, len(cs))}
	// Reject any duplicate const name regardless of family. Some
	// families (MAX_DEPTH, CHAIN_END, OPT_*) already have purpose-
	// specific dup checks, but plain Dispatch consts (NO_CHECK /
	// SANITY / Field) used to slip through silently —
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
		if strings.HasPrefix(rest, "HDRLEN_") {
			return classifyResult{}, fmt.Errorf("%s: HDRLEN_* const family is no longer supported; express the variable trailer with `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` inside the parser block instead (const %q)", source, c.Name)
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
		} else if reSanityName.MatchString(rest) {
			return classifyResult{}, fmt.Errorf("%s: const %q uses the SANITY family, which has been removed — declare a parser-block `transition select(<field>) { ...; default: reject; }` to self-validate the protocol instead", source, c.Name)
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
			return classifyResult{}, fmt.Errorf("%s: const %q does not match <SELF>_{<PARENT>_<FIELD>|<PARENT>_NO_CHECK|MAX_DEPTH|CHAIN_END_<FIELD>}", source, c.Name)
		}
		res.Consts = append(res.Consts, dc)
	}
	return res, nil
}
