//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// deadRegisterProgram has an instruction with register field reg in a branch
// the verifier prunes, so the kernel accepts the load.
func deadRegisterProgram(t *testing.T, reg asm.Register) inject.RawProgram {
	t.Helper()
	ctx := &btf.Pointer{Target: &btf.Struct{Name: "xdp_md"}}
	fn := &btf.Func{Name: "p", Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{Name: "ctx", Type: ctx}}}, Linkage: btf.GlobalFunc}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R1, 0), fn),
		asm.JEq.Imm(asm.R1, 0, "out"),
		asm.Mov.Imm(reg, 0),
		asm.FnKtimeGetNs.Call().WithSymbol("out"),
		asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}
	builder := new(btf.Builder)
	fi, li, err := btf.MarshalExtInfos(insns, builder)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := builder.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	types, err := btf.LoadSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := insns.Marshal(&buf, wire); err != nil {
		t.Fatal(err)
	}
	raw, err := asm.AppendInstructions(nil, &buf, wire, "linux")
	if err != nil {
		t.Fatal(err)
	}
	return inject.RawProgram{Instructions: raw, Type: ebpf.XDP, BTF: types, FuncInfo: fi, LineInfo: li, Maps: map[int32]inject.RawMap{}}
}

// A panic in the analysis of one load is an error on the fallback path, not
// the end of the supervisor: the listing, the rewrite and the stack
// accounting of a program with a register field above 10 return errors.
func TestAnalysisPanicIsError(t *testing.T) {
	s := &supervisor{probeTailCallReachability: func() error { return nil }}
	for reg := asm.Register(11); reg <= 15; reg++ {
		raw := deadRegisterProgram(t, reg)
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("r%d: panic escaped: %v", reg, p)
				}
			}()
			if _, _, err = listing(raw); err == nil {
				t.Errorf("r%d: listing accepted the program", reg)
			}
			for _, rule := range []Rule{{Program: "p", HookPrefix: "h", Entry: true}, {Program: "p", HookPrefix: "h", Calls: []string{"bpf_ktime_get_ns"}}} {
				if _, _, err = s.rewrite(raw, raw, "p", rule, HookForm{}, inject.StackReport{Source: "verifier"}, false, nil); err == nil {
					t.Errorf("r%d %+v: rewrite accepted the program", reg, rule)
				}
			}
			if _, err = frameFloors([]int{8}, []string{"p"}, raw, inject.KernelInfo{Major: 7}); err == nil {
				t.Errorf("r%d: stack accounting accepted the program", reg)
			}
		}()
	}
	if err := guard("x", func() error { panic("boom") }); !errors.Is(err, errAnalysisPanic) {
		t.Fatalf("guard: %v", err)
	}
}
