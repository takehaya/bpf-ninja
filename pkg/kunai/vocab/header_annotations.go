package vocab

import (
	"fmt"

	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab/p4lite"
)

// readHeaderAnnotations walks every header declaration in file and
// lowers kunai-recognised @-decorators into HeaderAnnotations entries
// keyed by header name. Unrecognised annotation names are tolerated so
// authors can pin future-reserved hints without a parser flag day; the
// keys of every recognised annotation are checked strictly so a typo
// fails loudly rather than silently no-op'ing.
//
// Cross-protocol field references inside @kunai_writeback are parsed
// but not resolved — the loader's pass-2 fills SourceByteOff /
// ParentByteOff once every spec is in scope.
func readHeaderAnnotations(file *p4lite.File, source string) (map[string]*HeaderAnnotations, error) {
	if file == nil {
		return nil, nil
	}
	out := make(map[string]*HeaderAnnotations)
	for _, h := range file.Headers {
		for _, ann := range h.Annotations {
			switch ann.Name {
			case "kunai_variable_tail":
				vt, err := lowerKunaiVariableTail(ann, h, source)
				if err != nil {
					return nil, err
				}
				entry := getOrCreateHeaderAnnotations(out, h.Name)
				if entry.VariableTail != nil {
					return nil, fmt.Errorf("%s:%s: header %q declares @kunai_variable_tail twice", source, ann.Pos, h.Name)
				}
				entry.VariableTail = vt
			case "kunai_writeback":
				wb, err := lowerKunaiWriteback(ann, h, source)
				if err != nil {
					return nil, err
				}
				entry := getOrCreateHeaderAnnotations(out, h.Name)
				if entry.WriteBack != nil {
					return nil, fmt.Errorf("%s:%s: header %q declares @kunai_writeback twice", source, ann.Pos, h.Name)
				}
				entry.WriteBack = wb
			default:
				continue
			}
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func getOrCreateHeaderAnnotations(m map[string]*HeaderAnnotations, name string) *HeaderAnnotations {
	if e, ok := m[name]; ok {
		return e
	}
	e := &HeaderAnnotations{}
	m[name] = e
	return e
}

// lowerKunaiVariableTail validates and projects an
// @kunai_variable_tail[len_field=F, scale=S, mask=M, shift=N, base=B]
// decorator into VariableTailSpec. Required keys: len_field, scale.
// Optional keys: mask (defaults to the full field extraction mask),
// shift (defaults to 0), base (defaults to 0). The named field's
// declared bit layout drives the LenFieldByteOff / LenShift /
// field-extraction-mask intersection so authors don't repeat what
// the header schema already states.
func lowerKunaiVariableTail(ann p4lite.Annotation, h *p4lite.Header, source string) (*VariableTailSpec, error) {
	allowed := map[string]bool{"len_field": true, "scale": true, "mask": true, "shift": true, "base": true}
	if err := requireKnownKeys(ann, allowed, source); err != nil {
		return nil, err
	}
	lenFieldVal, ok := ann.KVs["len_field"]
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail on header %q is missing required key `len_field`", source, ann.Pos, h.Name)
	}
	if lenFieldVal.Kind != p4lite.AnnotationIdent {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.len_field must be an identifier (got %v)", source, ann.Pos, lenFieldVal.Kind)
	}
	bitOff, fieldBits, ok := findHeaderFieldWindow(h, lenFieldVal.Ident)
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.len_field references unknown field %q in header %q", source, ann.Pos, lenFieldVal.Ident, h.Name)
	}
	if (bitOff%8)+fieldBits > 8 {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.len_field %q crosses a byte boundary (bits [%d,%d) — only single-byte fields are supported)", source, ann.Pos, lenFieldVal.Ident, bitOff, bitOff+fieldBits)
	}
	scale, err := readIntAnnotation(ann, "scale", source)
	if err != nil {
		return nil, err
	}
	if scale <= 0 {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.scale must be positive (got %d)", source, ann.Pos, scale)
	}
	if !isPowerOfTwo(scale) {
		return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.scale must be a power of two (got %d)", source, ann.Pos, scale)
	}
	bitInByte := bitOff % 8
	lsbShift := 8 - bitInByte - fieldBits
	fieldExtractionMask := ((1 << fieldBits) - 1) << lsbShift
	mask := fieldExtractionMask
	if mTok, ok := ann.KVs["mask"]; ok {
		if mTok.Kind != p4lite.AnnotationInt {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.mask must be an int literal", source, ann.Pos)
		}
		if mTok.Int == 0 {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.mask=0 makes the trail length always zero — unintended", source, ann.Pos)
		}
		if mTok.Int >= (1 << fieldBits) {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.mask=0x%x exceeds the %d-bit field %q (max 0x%x)", source, ann.Pos, mTok.Int, fieldBits, lenFieldVal.Ident, (1<<fieldBits)-1)
		}
		mask = int(mTok.Int) << lsbShift
	}
	shift := lsbShift
	if sTok, ok := ann.KVs["shift"]; ok {
		if sTok.Kind != p4lite.AnnotationInt {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.shift must be an int literal", source, ann.Pos)
		}
		shift = int(sTok.Int)
	}
	base := 0
	if bTok, ok := ann.KVs["base"]; ok {
		if bTok.Kind != p4lite.AnnotationInt {
			return nil, fmt.Errorf("%s:%s: @kunai_variable_tail.base must be an int literal", source, ann.Pos)
		}
		base = int(bTok.Int)
	}
	return &VariableTailSpec{
		LenFieldByteOff: bitOff / 8,
		LenMask:         mask,
		LenShift:        shift,
		Scale:           scale,
		Base:            base,
	}, nil
}

// lowerKunaiWriteback validates @kunai_writeback[source=F, parent=P.F]
// and resolves SourceByteOff against the chained header's layout.
// ParentByteOff is left zero — the loader's pass-2 fills it after
// every protocol's primary header is in scope.
func lowerKunaiWriteback(ann p4lite.Annotation, h *p4lite.Header, source string) (*WriteBackSpec, error) {
	allowed := map[string]bool{"source": true, "parent": true}
	if err := requireKnownKeys(ann, allowed, source); err != nil {
		return nil, err
	}
	srcVal, ok := ann.KVs["source"]
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback on header %q is missing required key `source`", source, ann.Pos, h.Name)
	}
	if srcVal.Kind != p4lite.AnnotationIdent {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback.source must be an identifier", source, ann.Pos)
	}
	bitOff, fieldBits, ok := findHeaderFieldWindow(h, srcVal.Ident)
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback.source references unknown field %q in header %q", source, ann.Pos, srcVal.Ident, h.Name)
	}
	if fieldBits != 8 || bitOff%8 != 0 {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback.source field %q is not a byte-aligned 8-bit field (writeback is a single byte copy)", source, ann.Pos, srcVal.Ident)
	}
	parentVal, ok := ann.KVs["parent"]
	if !ok {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback on header %q is missing required key `parent`", source, ann.Pos, h.Name)
	}
	if parentVal.Kind != p4lite.AnnotationFieldRef {
		return nil, fmt.Errorf("%s:%s: @kunai_writeback.parent must be a `proto.field` reference (e.g. `ipv6.next_header`)", source, ann.Pos)
	}
	return &WriteBackSpec{
		SourceField:   srcVal.Ident,
		ParentProto:   parentVal.Proto,
		ParentField:   parentVal.Field,
		SourceByteOff: bitOff / 8,
	}, nil
}

// requireKnownKeys errors when an annotation carries a key the
// recognised set doesn't accept. This catches `@kunai_writeback[srce=...]`
// typos at load time instead of silently no-op'ing them.
func requireKnownKeys(ann p4lite.Annotation, allowed map[string]bool, source string) error {
	for k := range ann.KVs {
		if !allowed[k] {
			return fmt.Errorf("%s:%s: @%s does not accept key %q", source, ann.Pos, ann.Name, k)
		}
	}
	return nil
}

func readIntAnnotation(ann p4lite.Annotation, key string, source string) (int, error) {
	v, ok := ann.KVs[key]
	if !ok {
		return 0, fmt.Errorf("%s:%s: @%s is missing required int key %q", source, ann.Pos, ann.Name, key)
	}
	if v.Kind != p4lite.AnnotationInt {
		return 0, fmt.Errorf("%s:%s: @%s.%s must be an int literal", source, ann.Pos, ann.Name, key)
	}
	return int(v.Int), nil
}

func findHeaderFieldWindow(h *p4lite.Header, name string) (bitOff, bits int, ok bool) {
	off := 0
	for _, f := range h.Fields {
		if f.Name == name {
			return off, f.Bits, true
		}
		off += f.Bits
	}
	return 0, 0, false
}

func isPowerOfTwo(n int) bool {
	if n <= 0 {
		return false
	}
	return n&(n-1) == 0
}

// resolveHeaderWritebackTargets fills ParentByteOff on every
// WriteBackSpec across the spec set. Run after every protocol's
// primary header is loaded so cross-protocol field references can be
// satisfied. The field must live in the parent's primary header and
// be a byte-aligned 8-bit slot for the codegen byte copy to land
// without extra masking.
func resolveHeaderWritebackTargets(specs map[string]*ProtocolSpec) error {
	for _, spec := range specs {
		for hname, hann := range spec.HeaderAnnotations {
			wb := hann.WriteBack
			if wb == nil {
				continue
			}
			parent, ok := specs[wb.ParentProto]
			if !ok {
				return fmt.Errorf("%s: @kunai_writeback on %q references unknown protocol %q", spec.Source, hname, wb.ParentProto)
			}
			bitOff, found := bitOffsetInFields(parent.Fields, wb.ParentField)
			if !found {
				return fmt.Errorf("%s: @kunai_writeback on %q references unknown field %q in protocol %q", spec.Source, hname, wb.ParentField, wb.ParentProto)
			}
			if bitOff%8 != 0 {
				return fmt.Errorf("%s: @kunai_writeback on %q targets non-byte-aligned field %s.%s (bit offset %d)", spec.Source, hname, wb.ParentProto, wb.ParentField, bitOff)
			}
			wb.ParentByteOff = bitOff / 8
		}
	}
	return nil
}

func bitOffsetInFields(fields []Field, name string) (int, bool) {
	off := 0
	for _, f := range fields {
		if f.Name == name {
			return off, true
		}
		off += f.Bits
	}
	return 0, false
}

