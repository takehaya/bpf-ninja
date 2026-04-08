package filter

import (
	"testing"

	"github.com/takehaya/xdp-ninja/internal/attach"
)

func TestParseArgFilter(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantParam string
		wantOp    ArgFilterOp
		wantVal   uint64
		wantMax   uint64
		wantErr   bool
	}{
		{
			name:      "exact match decimal",
			expr:      "id=42",
			wantParam: "id",
			wantOp:    OpEqual,
			wantVal:   42,
		},
		{
			name:      "exact match hex",
			expr:      "teid=0x1234",
			wantParam: "teid",
			wantOp:    OpEqual,
			wantVal:   0x1234,
		},
		{
			name:      "greater equal",
			expr:      "flags>=100",
			wantParam: "flags",
			wantOp:    OpGreaterEqual,
			wantVal:   100,
		},
		{
			name:      "less equal",
			expr:      "count<=1000",
			wantParam: "count",
			wantOp:    OpLessEqual,
			wantVal:   1000,
		},
		{
			name:      "range",
			expr:      "port=1024..65535",
			wantParam: "port",
			wantOp:    OpRange,
			wantVal:   1024,
			wantMax:   65535,
		},
		{
			name:      "range with hex",
			expr:      "id=0x10..0xFF",
			wantParam: "id",
			wantOp:    OpRange,
			wantVal:   0x10,
			wantMax:   0xFF,
		},
		{
			name:      "underscore in name",
			expr:      "my_param=123",
			wantParam: "my_param",
			wantOp:    OpEqual,
			wantVal:   123,
		},
		{
			name:      "negative value",
			expr:      "temp>=-10",
			wantParam: "temp",
			wantOp:    OpGreaterEqual,
			wantVal:   ^uint64(9), // two's complement of -10
		},
		{
			name:      "negative range",
			expr:      "offset=-100..100",
			wantParam: "offset",
			wantOp:    OpRange,
			wantVal:   ^uint64(99), // two's complement of -100
			wantMax:   100,
		},
		{
			name:    "invalid: no value",
			expr:    "id=",
			wantErr: true,
		},
		{
			name:    "invalid: no operator",
			expr:    "id123",
			wantErr: true,
		},
		{
			name:    "invalid: bad value",
			expr:    "id=abc",
			wantErr: true,
		},
		{
			name:    "invalid: range min > max",
			expr:    "id=100..50",
			wantErr: true,
		},
		{
			name:    "invalid: incomplete range",
			expr:    "id=100..",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf, err := ParseArgFilter(tt.expr)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseArgFilter(%q) expected error, got nil", tt.expr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseArgFilter(%q) unexpected error: %v", tt.expr, err)
			}

			if pf.ParamName != tt.wantParam {
				t.Errorf("ParamName = %q, want %q", pf.ParamName, tt.wantParam)
			}
			if pf.Op != tt.wantOp {
				t.Errorf("Op = %v, want %v", pf.Op, tt.wantOp)
			}
			if pf.Value != tt.wantVal {
				t.Errorf("Value = %d, want %d", pf.Value, tt.wantVal)
			}
			if pf.MaxValue != tt.wantMax {
				t.Errorf("MaxValue = %d, want %d", pf.MaxValue, tt.wantMax)
			}
		})
	}
}

func TestParseAndValidateFilters(t *testing.T) {
	params := []attach.FuncParamInfo{
		{Name: "id", Index: 1, Size: 4, Signed: false},
		{Name: "flags", Index: 2, Size: 8, Signed: false},
		{Name: "count", Index: 3, Size: 4, Signed: true},
	}

	tests := []struct {
		name    string
		exprs   []string
		want    int // expected number of filters
		wantErr bool
	}{
		{
			name:  "empty",
			exprs: nil,
			want:  0,
		},
		{
			name:  "single filter",
			exprs: []string{"id=42"},
			want:  1,
		},
		{
			name:  "multiple filters",
			exprs: []string{"id=42", "flags>=100"},
			want:  2,
		},
		{
			name:    "unknown parameter",
			exprs:   []string{"unknown=42"},
			wantErr: true,
		},
		{
			name:    "invalid expression",
			exprs:   []string{"invalid"},
			wantErr: true,
		},
		{
			name:    "value out of range for u32",
			exprs:   []string{"id=4294967296"}, // 2^32, exceeds u32 max
			wantErr: true,
		},
		{
			name:  "signed negative value in range",
			exprs: []string{"count>=-100"},
			want:  1,
		},
		{
			name:    "signed value out of range",
			exprs:   []string{"count>=3000000000"}, // exceeds int32 max
			wantErr: true,
		},
		{
			name:    "signed range inverted",
			exprs:   []string{"count=10..-10"}, // min > max in signed domain
			wantErr: true,
		},
		{
			name:  "signed range valid negative",
			exprs: []string{"count=-10..10"},
			want:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters, err := ParseAndValidateFilters(tt.exprs, params)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseAndValidateFilters() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseAndValidateFilters() unexpected error: %v", err)
			}

			if len(filters) != tt.want {
				t.Errorf("got %d filters, want %d", len(filters), tt.want)
			}
		})
	}
}

func TestArgFilterString(t *testing.T) {
	tests := []struct {
		filter ArgFilter
		want   string
	}{
		{
			filter: ArgFilter{ParamName: "id", Op: OpEqual, Value: 42},
			want:   "id=42",
		},
		{
			filter: ArgFilter{ParamName: "flags", Op: OpGreaterEqual, Value: 100},
			want:   "flags>=100",
		},
		{
			filter: ArgFilter{ParamName: "count", Op: OpLessEqual, Value: 1000},
			want:   "count<=1000",
		},
		{
			filter: ArgFilter{ParamName: "port", Op: OpRange, Value: 1024, MaxValue: 65535},
			want:   "port=1024..65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.filter.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
