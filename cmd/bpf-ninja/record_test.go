package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hookabi"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// TestRecordFlagValidation runs the root command against an interface that
// does not exist: each case must fail on the --record check before any
// target is looked up.
func TestRecordFlagValidation(t *testing.T) {
	for _, tc := range []struct{ args []string }{
		{[]string{"--record", "all"}},
		{[]string{"--record-max", "8"}},
		{[]string{"--record", "entry", "--record-max", "4097"}},
		{[]string{"--record", "entry", "--mode", "xdp"}},
		{[]string{"--record", "filter", "--dump-asm", "full"}},
	} {
		argv := append([]string{"bpf-ninja", "-i", "nonexist0"}, tc.args...)
		err := newRootCommand().Run(context.Background(), argv)
		if err == nil || !strings.Contains(err.Error(), "--record") {
			t.Fatalf("run %v: %v", tc.args, err)
		}
	}
	// The default turns itself off where nothing can be recorded.
	argv := []string{"bpf-ninja", "-i", "nonexist0", "--mode", "xdp"}
	if err := newRootCommand().Run(context.Background(), argv); err == nil || strings.Contains(err.Error(), "--record") {
		t.Fatalf("default --record refused --mode xdp: %v", err)
	}
}

func hookTarget(name string, progID uint32) attach.Target {
	return attach.Target{FuncName: name, ProgID: progID, Generated: true, Params: []attach.FuncParamInfo{
		{Name: "site", Index: 1, Size: 4},
		{Name: "value", Index: 2, Size: 8, Kind: "ptr-struct",
			Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Struct{Name: "pol", Size: 4,
				Members: []btf.Member{{Name: "rc", Type: &btf.Int{Name: "u32", Size: 4}}}}}}},
	}}
}

func TestRecordLayouts(t *testing.T) {
	hook := hookTarget("ninja_pol", 1)
	ordinary := attach.Target{FuncName: "classify", ProgID: 1, Params: []attach.FuncParamInfo{{Name: "q", Index: 1, Size: 8, Kind: "ptr-struct"}}}
	tf := []filter.TargetFilters{{Args: []filter.ArgFilter{{ParamName: "value->rc", ParamIndex: 2, ParamSize: 4, Deref: true, Op: filter.OpEqual, Value: 2}}}, {}}

	// Default filter mode records only the hook-shaped target.
	def := recordRequest{recordbuild.Options{Mode: record.ModeFilter}}
	ls, err := def.layouts([]attach.Target{hook, ordinary}, tf)
	if err != nil || ls == nil || ls[0] == nil || ls[1] != nil {
		t.Fatalf("default layouts %+v %v", ls, err)
	}
	// No field referenced anywhere turns the default off (nil, no error).
	ls, err = def.layouts([]attach.Target{hook}, []filter.TargetFilters{{}})
	if err != nil || ls != nil {
		t.Fatalf("empty default %+v %v", ls, err)
	}
	// Explicit filter mode records at every target, hook-shaped or not.
	ent := recordRequest{recordbuild.Options{Mode: record.ModeFilter, Explicit: true}}
	ordFilter := filter.TargetFilters{Args: []filter.ArgFilter{{ParamName: "q->rc", ParamIndex: 1, ParamSize: 4, Deref: true, Op: filter.OpEqual, Value: 1}}}
	ls, err = ent.layouts([]attach.Target{hook, ordinary}, []filter.TargetFilters{tf[0], ordFilter})
	if err != nil || ls[0] == nil || ls[1] == nil {
		t.Fatalf("explicit filter layouts %+v %v", ls, err)
	}
	// More than 255 targets: default turns off, explicit refuses.
	many := make([]attach.Target, 256)
	for i := range many {
		many[i] = hook
	}
	if ls, err := def.layouts(many, nil); err != nil || ls != nil {
		t.Fatalf("256 default: %+v %v", ls, err)
	}
	if _, err := ent.layouts(many, nil); err == nil {
		t.Fatal("256 explicit accepted")
	}
}

func TestRecordOutput(t *testing.T) {
	targets := []attach.Target{hookTarget("ninja_pol", 7), hookTarget("ninja_pol", 9), hookTarget("other", 7)}
	layouts := []*record.Layout{{Mode: record.ModeEntry}, {Mode: record.ModeEntry}, {Mode: record.ModeEntry}}
	cfg := output.Config{IsFexit: true, Actions: []output.ActionName{{Name: "x"}}, MultiPoint: true}
	recordOutput(&cfg, targets, layouts, true)
	if cfg.IsFexit || cfg.MultiPoint || cfg.Actions != nil || cfg.RawReturn {
		t.Fatalf("verdict layout not cleared: %+v", cfg)
	}
	// An exit capture keeps the return value, as the first comment pair.
	if !cfg.RecordReturn {
		t.Fatal("exit capture drops the return value")
	}
	entry := output.Config{}
	recordOutput(&entry, targets, layouts, false)
	if entry.RecordReturn {
		t.Fatal("entry capture records a return value")
	}
	if !cfg.NoRunIDs || len(cfg.Hooks) != 3 || len(cfg.Records) != 3 {
		t.Fatalf("hooks/records: %+v", cfg)
	}
	// Duplicate function names are disambiguated by program id.
	if cfg.Hooks[0] != "ninja_pol@7" || cfg.Hooks[1] != "ninja_pol@9" || cfg.Hooks[2] != "other" {
		t.Fatalf("names %q", cfg.Hooks)
	}
}

// inject's exported HookTag must stay equal to the hookabi leaf it comes from.
func TestHookTagMatchesInject(t *testing.T) {
	if inject.HookTag != hookabi.HookTag {
		t.Fatalf("inject.HookTag %q != hookabi.HookTag %q", inject.HookTag, hookabi.HookTag)
	}
}

// -v names each condition the default filter layout tests but does not
// record; explicit, entry and ordinary-function captures log none.
func TestRecordOmitted(t *testing.T) {
	hook := hookTarget("ninja_pol", 1)
	ordinary := attach.Target{FuncName: "classify", ProgID: 2}
	tf := filter.TargetFilters{Args: []filter.ArgFilter{
		{ParamName: "value->rc", ParamIndex: 2, ParamSize: 4, Deref: true},
		{ParamName: "value->tw.__opaque", ParamIndex: 2, ParamSize: 8, Deref: true, Offset: 8, ThroughOpaque: true}},
		Sets: []filter.SetFilter{{Fields: []filter.SetKeyField{
			{ParamName: "value->rc", ParamIdx: 2, ParamSize: 4, Deref: true},
			{ParamName: "value->tw.lock", ParamIdx: 2, ParamSize: 4, Deref: true, Offset: 12, ThroughOpaque: true}}}}}
	filters := []filter.TargetFilters{tf, tf}
	def := recordRequest{recordbuild.Options{Mode: record.ModeFilter}}
	got := def.omitted([]attach.Target{hook, ordinary}, filters)
	want := []string{
		"record filter at ninja_pol (id=1): value->tw.__opaque is tested but not recorded (inside a bpf_* struct)",
		"record filter at ninja_pol (id=1): value->tw.lock is tested but not recorded (inside a bpf_* struct)",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("default: %q", got)
	}
	for _, opt := range []recordbuild.Options{{Mode: record.ModeFilter, Explicit: true}, {Mode: record.ModeEntry}} {
		if got := (recordRequest{opt}).omitted([]attach.Target{hook}, filters[:1]); got != nil {
			t.Fatalf("%+v: %q", opt, got)
		}
	}
}
