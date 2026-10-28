package filter

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
)

func TestArgumentComparisons(t *testing.T) {
	u16 := &btf.Int{Size: 2}
	params := []attach.FuncParamInfo{
		{Name: "n", Index: 1, Size: 2},
		{Name: "wide", Index: 2, Size: 8},
		{Name: "ip", Index: 3, Size: 4},
		{Name: "q", Index: 4, Kind: "ptr-struct", Type: &btf.Pointer{Target: &btf.Struct{Size: 2, Members: []btf.Member{{Name: "port", Type: u16}}}}},
		{Name: "value", Index: 5, Kind: "ptr", Type: &btf.Pointer{Target: &btf.Const{Type: u16}}},
		{Name: "opaque", Index: 6, Kind: "ptr", Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}}},
		{Name: "signed", Index: 7, Size: 2, Signed: true},
	}
	be16 := uint64(binary.NativeEndian.Uint16([]byte{1, 187}))
	be32 := uint64(binary.NativeEndian.Uint32([]byte{10, 0, 0, 1}))
	be64 := binary.NativeEndian.Uint64([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	for _, tt := range []struct {
		expr           string
		op             ArgFilterOp
		value          uint64
		deref, pointer bool
	}{
		{"n==443", OpEqual, 443, false, false}, {"n!=443", OpNotEqual, 443, false, false},
		{"q->port==443", OpEqual, 443, true, false}, {"q->port!=443", OpNotEqual, 443, true, false},
		{"q->port==be16(443)", OpEqual, be16, true, false}, {"n!=be16(443)", OpNotEqual, be16, false, false},
		{"ip=be32(0x0a000001)", OpEqual, be32, false, false}, {"wide==be64(0x0102030405060708)", OpEqual, be64, false, false},
		{"signed=be16(443)", OpEqual, uint64(int64(int16(be16))), false, false},
		{"q=null", OpEqual, 0, false, true}, {"q==null", OpEqual, 0, false, true}, {"q!=null", OpNotEqual, 0, false, true},
		{"value==null", OpEqual, 0, false, true}, {"opaque!=null", OpNotEqual, 0, false, true},
		{"value[0]==64", OpEqual, 64, true, false}, {"value[0]!=0", OpNotEqual, 0, true, false},
		{"value[0]=be16(443)", OpEqual, be16, true, false},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			fs, err := ParseAndValidateFilters([]string{tt.expr}, params)
			if err != nil {
				t.Fatal(err)
			}
			f := fs[0]
			if f.Op != tt.op || f.Value != tt.value || f.Deref != tt.deref || f.Pointer != tt.pointer {
				t.Fatalf("filter: %+v", f)
			}
			if tt.pointer && f.String() != strings.Replace(tt.expr, "==", "=", 1) {
				t.Fatalf("string: %s", f.String())
			}
		})
	}
	for _, tt := range []struct{ expr, want string }{
		{"n=be32(443)", "width must equal"}, {"q->port=be64(443)", "width must equal"},
		{"n>=be16(1)", "does not preserve numeric ordering"}, {"q->port<=be16(2)", "does not preserve numeric ordering"},
		{"n=be16(1)..be16(2)", "does not preserve numeric ordering"}, {"n=1..be16(2)", "does not preserve numeric ordering"},
		{"n!=1..2", "invalid range"}, {"n=be16(65536)", "out of range"}, {"wide=be64(-1)", "unsigned value"},
		{"n=null", "requires a pointer"}, {"q->port==null", "requires a pointer"},
		{"q>=null", "null only supports"}, {"q=0", "pointer"}, {"opaque[0]=0", "integer or enum"},
		{"value[1]=0", "invalid filter expression"}, {"q[0]=0", "integer or enum"},
		{"value[0]->port=0", "invalid filter expression"}, {"n=be8(1)", "invalid value"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			_, err := ParseAndValidateFilters([]string{tt.expr}, params)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v, want %q", err, tt.want)
			}
		})
	}
	fs, err := ParseAndValidateFilters([]string{"n==443", "q->port!=0", "value[0]>=1", "value[0]<=1000", "q!=null"}, params)
	if err != nil || len(fs) != 5 {
		t.Fatalf("AND filters: %+v %v", fs, err)
	}
}
