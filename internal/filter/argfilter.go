// Package filter provides argument filter parsing and validation for fentry/fexit probes.
package filter

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/takehaya/xdp-ninja/internal/attach"
)

// ArgFilterOp represents the comparison operator for an argument filter.
type ArgFilterOp int

const (
	OpEqual        ArgFilterOp = iota // param=value (exact match)
	OpGreaterEqual                    // param>=value
	OpLessEqual                       // param<=value
	OpRange                           // param=min..max
)

// ArgFilter represents a single argument filter condition.
type ArgFilter struct {
	ParamName  string      // Parameter name from BTF
	ParamIndex int         // 0-based index in fentry args array (BTF index)
	ParamSize  uint32      // Size in bytes (1, 2, 4, 8)
	Signed     bool        // Whether the parameter is signed
	Op         ArgFilterOp // Comparison operator
	Value      uint64      // Value for exact/comparison (or min for range)
	MaxValue   uint64      // Max value for range operator
}

// String returns a human-readable representation of the filter.
func (f *ArgFilter) String() string {
	fmtVal := func(v uint64) string {
		if f.Signed {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%d", v)
	}
	switch f.Op {
	case OpEqual:
		return fmt.Sprintf("%s=%s", f.ParamName, fmtVal(f.Value))
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
	Op        ArgFilterOp
	Value     uint64
	MaxValue  uint64 // only used for OpRange
}

// filterPattern matches: param=value, param>=value, param<=value, param=min..max
var filterPattern = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)(=|>=|<=)(.+)$`)

// ParseArgFilter parses a single filter expression string.
// Supported formats:
//   - "param=value"     - exact match
//   - "param>=value"    - greater than or equal
//   - "param<=value"    - less than or equal
//   - "param=min..max"  - range (inclusive)
func ParseArgFilter(expr string) (ParsedFilter, error) {
	matches := filterPattern.FindStringSubmatch(expr)
	if matches == nil {
		return ParsedFilter{}, fmt.Errorf("invalid filter expression: %q (expected: param=value, param>=value, param<=value, or param=min..max)", expr)
	}

	pf := ParsedFilter{ParamName: matches[1]}
	opStr := matches[2]
	valueStr := matches[3]

	switch opStr {
	case ">=", "<=":
		if opStr == ">=" {
			pf.Op = OpGreaterEqual
		} else {
			pf.Op = OpLessEqual
		}
		v, err := parseValue(valueStr)
		if err != nil {
			return ParsedFilter{}, fmt.Errorf("invalid value in %q: %w", expr, err)
		}
		pf.Value = v
	case "=":
		if strings.Contains(valueStr, "..") {
			parts := strings.SplitN(valueStr, "..", 2)
			if len(parts) != 2 {
				return ParsedFilter{}, fmt.Errorf("invalid range in %q: expected min..max", expr)
			}
			pf.Op = OpRange
			v, err := parseValue(parts[0])
			if err != nil {
				return ParsedFilter{}, fmt.Errorf("invalid min value in %q: %w", expr, err)
			}
			pf.Value = v
			mv, err := parseValue(parts[1])
			if err != nil {
				return ParsedFilter{}, fmt.Errorf("invalid max value in %q: %w", expr, err)
			}
			pf.MaxValue = mv
			// Reject if min > max under both unsigned and signed interpretation.
			// The correct signedness is resolved later in ParseAndValidateFilters.
			if pf.Value > pf.MaxValue && int64(pf.Value) > int64(pf.MaxValue) {
				return ParsedFilter{}, fmt.Errorf("invalid range in %q: min > max", expr)
			}
		} else {
			pf.Op = OpEqual
			v, err := parseValue(valueStr)
			if err != nil {
				return ParsedFilter{}, fmt.Errorf("invalid value in %q: %w", expr, err)
			}
			pf.Value = v
		}
	}

	return pf, nil
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

	// Build a map from parameter name to its info
	paramMap := make(map[string]attach.FuncParamInfo)
	for _, p := range params {
		paramMap[p.Name] = p
	}

	var filters []ArgFilter
	for _, expr := range exprs {
		pf, err := ParseArgFilter(expr)
		if err != nil {
			return nil, err
		}

		param, ok := paramMap[pf.ParamName]
		if !ok {
			var available []string
			for _, p := range params {
				available = append(available, p.Name)
			}
			if len(available) == 0 {
				return nil, fmt.Errorf("parameter %q not found; function has no filterable parameters (only integer types after the first argument are supported)", pf.ParamName)
			}
			return nil, fmt.Errorf("parameter %q not found; available parameters: %v", pf.ParamName, available)
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
			ParamIndex: param.Index,
			ParamSize:  param.Size,
			Signed:     param.Signed,
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
		min := -(int64(1) << (bits - 1))          // e.g. -128 for int8
		max := int64(1)<<(bits-1) - 1              // e.g. 127 for int8
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
