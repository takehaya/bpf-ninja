// Package filter provides argument filter parsing and validation for fentry/fexit probes.
package filter

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/takehaya/bpf-ninja/internal/attach"
)

// ArgFilterOp represents the comparison operator for an argument filter.
type ArgFilterOp int

const (
	OpEqual        ArgFilterOp = iota // param=value (exact match)
	OpGreaterEqual                    // param>=value
	OpLessEqual                       // param<=value
	OpRange                           // param=min..max
	OpNotEqual                        // param!=value
)

// ArgFilter represents a single argument filter condition.
type ArgFilter struct {
	ParamName  string      // Parameter name from BTF
	ParamIndex int         // 0-based index in fentry args array (BTF index)
	ParamSize  uint32      // Size in bytes (1, 2, 4, 8)
	Signed     bool        // Whether the parameter is signed
	Pointer    bool        // Compare the pointer itself with NULL, without reading memory
	Deref      bool        // Read a member through the pointer argument
	Offset     uint32      // Member byte offset
	Op         ArgFilterOp // Comparison operator
	Value      uint64      // Value for exact/comparison (or min for range)
	MaxValue   uint64      // Max value for range operator
}

// String returns a human-readable representation of the filter.
func (f *ArgFilter) String() string {
	fmtVal := func(v uint64) string {
		if f.Pointer {
			return "null"
		}
		if f.Signed {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%d", v)
	}
	switch f.Op {
	case OpEqual:
		return fmt.Sprintf("%s=%s", f.ParamName, fmtVal(f.Value))
	case OpNotEqual:
		return fmt.Sprintf("%s!=%s", f.ParamName, fmtVal(f.Value))
	case OpGreaterEqual:
		return fmt.Sprintf("%s>=%s", f.ParamName, fmtVal(f.Value))
	case OpLessEqual:
		return fmt.Sprintf("%s<=%s", f.ParamName, fmtVal(f.Value))
	case OpRange:
		return fmt.Sprintf("%s=%s..%s", f.ParamName, fmtVal(f.Value), fmtVal(f.MaxValue))
	default:
		return fmt.Sprintf("%s=?", f.ParamName)
	}
}

// ParsedFilter holds the result of parsing a filter expression (before BTF validation).
type ParsedFilter struct {
	ParamName string
	Null      bool
	BigEndian uint32 // Explicit network-order width in bytes
	Op        ArgFilterOp
	Value     uint64
	MaxValue  uint64 // only used for OpRange
}

// filterPattern accepts integer parameters or param->member.member expressions.
var filterPattern = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*(?:->[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*|\[0\])?)(==|!=|>=|<=|=)(.+)$`)
var networkValuePattern = regexp.MustCompile(`^be(16|32|64)\((.+)\)$`)

// ParseArgFilter parses an integer/member/scalar-pointee comparison or a
// pointer NULL test. Network-order literals are only meaningful for equality.
func ParseArgFilter(expr string) (ParsedFilter, error) {
	m := filterPattern.FindStringSubmatch(expr)
	if m == nil {
		return ParsedFilter{}, fmt.Errorf("invalid filter expression: %q (expected param=value, param!=value, param>=value, param<=value, or param=min..max)", expr)
	}
	pf := ParsedFilter{ParamName: m[1]}
	switch m[2] {
	case "=", "==":
		pf.Op = OpEqual
	case "!=":
		pf.Op = OpNotEqual
	case ">=":
		pf.Op = OpGreaterEqual
	case "<=":
		pf.Op = OpLessEqual
	}
	rhs := strings.TrimSpace(m[3])
	if rhs == "null" {
		if pf.Op != OpEqual && pf.Op != OpNotEqual {
			return pf, fmt.Errorf("%q: null only supports =, ==, or !=", expr)
		}
		pf.Null = true
		return pf, nil
	}
	parts := strings.Split(rhs, "..")
	if len(parts) > 1 {
		if pf.Op != OpEqual || len(parts) != 2 {
			return pf, fmt.Errorf("invalid range in %q: use =min..max", expr)
		}
		pf.Op = OpRange
	}
	for i, part := range parts {
		v, width, err := parseFilterValue(strings.TrimSpace(part))
		if err != nil {
			return pf, fmt.Errorf("invalid value in %q: %w", expr, err)
		}
		if width != 0 && pf.Op != OpEqual && pf.Op != OpNotEqual {
			return pf, fmt.Errorf("%q: beNN literals only support equality (=, ==, !=); network byte order does not preserve numeric ordering for ranges or >=/<=", expr)
		}
		if i == 0 {
			pf.Value, pf.BigEndian = v, width
		} else {
			pf.MaxValue = v
		}
	}
	if pf.Op == OpRange && pf.Value > pf.MaxValue && int64(pf.Value) > int64(pf.MaxValue) {
		return pf, fmt.Errorf("invalid range in %q: min > max", expr)
	}
	return pf, nil
}

func parseFilterValue(s string) (uint64, uint32, error) {
	m := networkValuePattern.FindStringSubmatch(s)
	if m == nil {
		v, err := parseValue(s)
		return v, 0, err
	}
	n, _ := strconv.Atoi(m[1])
	width := uint32(n / 8)
	literal := strings.TrimSpace(m[2])
	if strings.HasPrefix(literal, "-") {
		return 0, 0, fmt.Errorf("%s requires an unsigned value", s)
	}
	v, err := parseValue(literal)
	if err != nil {
		return 0, 0, err
	}
	if err := validateValueRange(v, width, false, s); err != nil {
		return 0, 0, err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	switch width {
	case 2:
		v = uint64(binary.NativeEndian.Uint16(buf[6:]))
	case 4:
		v = uint64(binary.NativeEndian.Uint32(buf[4:]))
	case 8:
		v = binary.NativeEndian.Uint64(buf[:])
	}
	return v, width, nil
}

// parseValue parses a string as uint64, supporting hex (0x), decimal, and
// negative values. Negative values are stored as their two's complement
// bit pattern (e.g. -1 → 0xFFFFFFFFFFFFFFFF), which is the representation
// used by the eBPF signed comparison instructions.
func parseValue(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	if strings.HasPrefix(s, "-") {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return uint64(v), nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// ParseAndValidateFilters parses filter expressions and validates them against BTF parameters.
func ParseAndValidateFilters(exprs []string, params []attach.FuncParamInfo) ([]ArgFilter, error) {
	if len(exprs) == 0 {
		return nil, nil
	}

	var filters []ArgFilter
	for _, expr := range exprs {
		pf, err := ParseArgFilter(expr)
		if err != nil {
			return nil, err
		}

		var param attach.FuncParamInfo
		if pf.Null {
			param, err = attach.ResolvePointerArg(pf.ParamName, params)
		} else {
			param, err = attach.ResolveArg(pf.ParamName, params)
		}
		if err != nil {
			return nil, err
		}

		if pf.BigEndian != 0 {
			if pf.BigEndian != param.Size {
				return nil, fmt.Errorf("%q: be%d width must equal the %d-bit argument/member width", expr, pf.BigEndian*8, param.Size*8)
			}
			// Compare the stored bit pattern, including a signed leaf's sign extension.
			if param.Signed && param.Size < 8 {
				shift := 64 - param.Size*8
				pf.Value = uint64(int64(pf.Value<<shift) >> shift)
			}
		}
		// Validate that filter values fit within the parameter's bit width.
		if err := validateValueRange(pf.Value, param.Size, param.Signed, expr); err != nil {
			return nil, err
		}
		if pf.Op == OpRange {
			if err := validateValueRange(pf.MaxValue, param.Size, param.Signed, expr); err != nil {
				return nil, err
			}
			// Re-check min <= max under the resolved signedness.
			if param.Signed {
				if int64(pf.Value) > int64(pf.MaxValue) {
					return nil, fmt.Errorf("invalid range in %q: min (%d) > max (%d) for signed parameter", expr, int64(pf.Value), int64(pf.MaxValue))
				}
			} else {
				if pf.Value > pf.MaxValue {
					return nil, fmt.Errorf("invalid range in %q: min (%d) > max (%d)", expr, pf.Value, pf.MaxValue)
				}
			}
		}

		filters = append(filters, ArgFilter{
			ParamName:  pf.ParamName,
			Pointer:    pf.Null,
			ParamIndex: param.Index,
			ParamSize:  param.Size,
			Signed:     param.Signed,
			Deref:      param.Deref,
			Offset:     param.Offset,
			Op:         pf.Op,
			Value:      pf.Value,
			MaxValue:   pf.MaxValue,
		})
	}

	return filters, nil
}

// validateValueRange checks that value fits within the given parameter size and signedness.
func validateValueRange(value uint64, size uint32, signed bool, expr string) error {
	if size >= 8 {
		// 64-bit values always fit. For signed parameters, parseValue encodes
		// negatives as two's complement (e.g. -1 → 0xFFFFFFFFFFFFFFFF) which
		// is a valid int64 bit pattern.
		return nil
	}
	bits := size * 8
	if signed {
		min := -(int64(1) << (bits - 1)) // e.g. -128 for int8
		max := int64(1)<<(bits-1) - 1    // e.g. 127 for int8
		sv := int64(value)
		if sv < min || sv > max {
			return fmt.Errorf("value %d in %q is out of range for %d-bit signed parameter [%d, %d]", sv, expr, bits, min, max)
		}
	} else {
		max := uint64(1)<<bits - 1 // e.g. 255 for uint8
		if value > max {
			return fmt.Errorf("value %d in %q is out of range for %d-bit unsigned parameter [0, %d]", value, expr, bits, max)
		}
	}
	return nil
}
