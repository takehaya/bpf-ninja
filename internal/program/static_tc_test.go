package program

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

func TestBpfStaticTCCapture(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	integer := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	ctx := &btf.Pointer{Target: &btf.Struct{Name: "__sk_buff", Size: 192}}
	entry := &btf.Func{Name: "tc_target", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{{Name: "ctx", Type: ctx}}}}
	fn := &btf.Func{Name: "static_hook", Linkage: btf.StaticFunc, Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{
		{Name: "ctx", Type: ctx}, {Name: "value", Type: &btf.Pointer{Target: integer}},
	}}}
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -8, 7, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.Call.Label(fn.Name),
		asm.Mov.Imm(asm.R0, 0), asm.Return(),
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(fn.Name), fn), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(entry.Name), entry)
	target, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "tc_static_test", Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
	if err != nil {
		t.Fatalf("target load: %+v", err)
	}
	defer func() { _ = target.Close() }()
	input := untaggedIPv4TCP()
	for _, mode := range []string{"entry", "exit", "gated"} {
		t.Run(mode, func(t *testing.T) {
			stages := []Stage{{Expr: "eth", IsFexit: mode == "exit"}}
			if mode == "gated" {
				stages = append(stages, Stage{Expr: "eth", IsFexit: true})
			}
			probe, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: fn.Name, Type: ebpf.SchedCLS}}, stages, nil, true, nil, EmitBoth)
			if err != nil {
				t.Fatalf("capture load: %+v", err)
			}
			defer func() { _ = probe.Close() }()
			ret, output, err := target.Test(input)
			if err != nil || ret != 0 || !bytes.Equal(output, input) {
				t.Fatalf("target ret=%d err=%v output=%x", ret, err, output)
			}
			if err := probe.Quiesce(); err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, m := range probe.InnerMaps {
				rd, err := fastrb.New(m.FD(), int(m.MaxEntries()))
				if err != nil {
					t.Fatal(err)
				}
				rd.ReadBatch(func(rec []byte) {
					pkt, err := capture.ParseRawSample(rec)
					if err != nil {
						t.Error(err)
						return
					}
					count++
					if !bytes.Equal(pkt.Data, input) {
						t.Errorf("captured %x, want %x", pkt.Data, input)
					}
				})
				_ = rd.Close()
			}
			want := 1
			if mode == "gated" {
				want = 2
			}
			t.Logf("captured %d/%d records; each matches %d input bytes", count, want, len(input))
			if count != want {
				t.Fatalf("captures=%d, want %d", count, want)
			}
		})
	}
	old := TCVlanReinsert
	TCVlanReinsert = true
	defer func() { TCVlanReinsert = old }()
	probe, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: fn.Name, Type: ebpf.SchedCLS}}, []Stage{{Expr: "eth"}}, nil, true, nil, EmitBoth)
	if probe != nil {
		_ = probe.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "static TC probe-read does not support VLAN reinsertion") {
		t.Fatalf("VLAN reinsertion: %v", err)
	}
}
