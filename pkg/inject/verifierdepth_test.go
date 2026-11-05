package inject

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestParseStackDepths(t *testing.T) {
	for _, tc := range []struct {
		log  string
		want []int
	}{
		{"processed 4 insns\nstack depth 8+24+160\n", []int{8, 24, 160}},
		{"stack depth 504 max 512\n", []int{504}},
	} {
		got, err := ParseStackDepths(tc.log)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("ParseStackDepths(%q) = %v, %v; want %v", tc.log, got, err, tc.want)
		}
	}
	for _, log := range []string{"", "processed 4 insns\n"} {
		if _, err := ParseStackDepths(log); err == nil {
			t.Fatalf("ParseStackDepths(%q) succeeded", log)
		}
	}
}

func TestFrameFloorsUseDirectAccessAfterFastcallShrink(t *testing.T) {
	fn := &btf.Func{Name: "entry", Type: &btf.FuncProto{}}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.StoreMem(asm.RFP, -160, asm.R1, asm.DWord).WithSymbol("entry"), fn),
		asm.Return(),
	}
	report, err := FrameFloors([]int{152}, []string{"entry"}, insns, KernelInfo{Major: 6, Minor: 12})
	if err != nil {
		t.Fatal(err)
	}
	f := report.Functions[0]
	if f.VerifiedDepth != 152 || f.TextDepth != 160 || f.Floor != -160 || f.Source != "text" {
		t.Fatalf("floor = %+v", f)
	}
}

func TestFrameFloorsMarkDeadFunctions(t *testing.T) {
	fn := func(name string) *btf.Func { return &btf.Func{Name: name, Type: &btf.FuncProto{}} }
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("entry"), fn("entry")), asm.Return(),
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol("dead"), fn("dead")), asm.Return(),
	}
	report, err := FrameFloors([]int{8}, []string{"entry"}, insns, KernelInfo{Major: 7})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Functions) != 2 || !report.Functions[1].Dead || report.Functions[1].Source != "dead" {
		t.Fatalf("functions = %+v", report.Functions)
	}
}

func TestFrameFloorsPre68SkipInexactFunction(t *testing.T) {
	fn := &btf.Func{Name: "entry", Type: &btf.FuncProto{}}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Reg(asm.R2, asm.RFP).WithSymbol("entry"), fn),
		asm.Add.Reg(asm.R2, asm.R1),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		asm.Return(),
	}
	report, err := FrameFloors([]int{8}, []string{"entry"}, insns, KernelInfo{Major: 6, Minor: 6})
	if err != nil {
		t.Fatal(err)
	}
	f := report.Functions[0]
	if f.SkipReason == "" || !strings.Contains(f.SkipReason, "before 6.8") {
		t.Fatalf("floor = %+v", f)
	}
	if len(report.Frames()) != 0 {
		t.Fatalf("frames = %v", report.Frames())
	}
}
