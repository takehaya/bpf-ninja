//go:build linux && amd64

package syscallhook

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
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

// A program with a register field above 10 is refused by the analyses
// themselves (inject.ErrRefused): the listing, the rewrite and the stack
// accounting return the ordinary refusal, not a panic the guard caught.
func TestAnalysisRefusesDeadRegister(t *testing.T) {
	var logs bytes.Buffer
	s := &supervisor{probeTailCallReachability: func() error { return nil }, options: Options{Log: &logs}}
	for reg := asm.Register(11); reg <= 15; reg++ {
		raw := deadRegisterProgram(t, reg)
		ordinary := func(what string, err error) {
			t.Helper()
			if !errors.Is(err, inject.ErrRefused) || errors.Is(err, errAnalysisPanic) {
				t.Errorf("r%d %s: %v, want an ordinary refusal", reg, what, err)
			}
		}
		_, _, err := listing(raw)
		ordinary("listing", err)
		for _, rule := range []Rule{{Program: "p", HookPrefix: "h", Entry: true}, {Program: "p", HookPrefix: "h", Calls: []string{"bpf_ktime_get_ns"}}} {
			_, _, err = s.rewrite(raw, raw, "p", rule, HookForm{}, inject.StackReport{Source: "verifier"}, false, nil)
			ordinary(fmt.Sprintf("rewrite %+v", rule), err)
		}
		_, err = frameFloors([]int{8}, []string{"p"}, raw, inject.KernelInfo{Major: 7})
		ordinary("stack accounting", err)
	}
}

// A panic in the analysis of one load is an error on the fallback path, not
// the end of the supervisor: each guarded step returns errAnalysisPanic when
// the analysis it runs panics.
func TestAnalysisPanicIsError(t *testing.T) {
	var logs bytes.Buffer
	s := &supervisor{probeTailCallReachability: func() error { return nil }, options: Options{Log: &logs}}
	raw := deadRegisterProgram(t, asm.R9)
	boom := func() { panic("boom") }
	for _, tc := range []struct {
		name   string
		inject func() func() // replaces one analysis with a panic, returns the undo
		run    func() error
	}{
		{"parse", func() func() {
			old := parseStackDepths
			parseStackDepths = func(string) ([]int, error) { boom(); return nil, nil }
			return func() { parseStackDepths = old }
		}, func() error { _, err := stackDepths("stack depth 8"); return err }},
		{"frames", func() func() {
			old := frameFloorsRaw
			frameFloorsRaw = func([]int, []string, inject.RawProgram, inject.KernelInfo) (inject.StackReport, error) {
				boom()
				return inject.StackReport{}, nil
			}
			return func() { frameFloorsRaw = old }
		}, func() error {
			_, err := frameFloors([]int{8}, []string{"p"}, raw, inject.KernelInfo{Major: 7})
			return err
		}},
		{"listing", func() func() {
			old := discoverMapCallsRaw
			discoverMapCallsRaw = func(inject.RawProgram) ([]inject.LookupSite, error) { boom(); return nil, nil }
			return func() { discoverMapCallsRaw = old }
		}, func() error { _, _, err := listing(raw); return err }},
		{"rewrite", func() func() {
			old := transformLookupRaw
			transformLookupRaw = func(inject.RawProgram, inject.LookupRequestRaw, func() error) (*inject.LookupResultRaw, error) {
				boom()
				return nil, nil
			}
			return func() { transformLookupRaw = old }
		}, func() error {
			_, _, err := s.rewrite(raw, raw, "p", Rule{Program: "p", HookPrefix: "h", Entry: true}, HookForm{}, inject.StackReport{Source: "verifier"}, false, nil)
			return err
		}},
	} {
		if err := tc.run(); errors.Is(err, errAnalysisPanic) {
			t.Fatalf("%s: panics without an injected panic: %v", tc.name, err)
		}
		undo := tc.inject()
		var err error
		func() {
			defer undo()
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("%s: panic escaped: %v", tc.name, p)
				}
			}()
			err = tc.run()
		}()
		if !errors.Is(err, errAnalysisPanic) || !strings.Contains(err.Error(), "boom") {
			t.Errorf("%s: %v, want errAnalysisPanic", tc.name, err)
		}
	}
}
