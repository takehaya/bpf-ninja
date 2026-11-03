package program

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/record"
	"github.com/takehaya/bpf-ninja/internal/recordbuild"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

// TestRecordEpilogue pins that a capture without a layout emits the same
// epilogue, and that a layout moves the packet behind its block.
func TestRecordEpilogue(t *testing.T) {
	id := asm.Instructions{asm.Mov.Imm(asm.R1, 0)}
	plain, legacy := captureWithRecord(3, 4, true, 64, id, origLenFromR8, nil, 0, nil), captureWithRingbuf(3, 4, true, 64, id, origLenFromR8)
	if len(plain) != len(legacy) {
		t.Fatal("nil layout changed the epilogue")
	}
	for i := range plain {
		if fmt.Sprint(plain[i]) != fmt.Sprint(legacy[i]) {
			t.Fatalf("insn %d: %v != %v", i, plain[i], legacy[i])
		}
	}
	l := &record.Layout{Mode: record.ModeFilter, Fields: []record.Field{{Name: "site", ParamIndex: 1, Size: 4}}}
	insns := captureWithRecord(3, 4, false, 64, id, origLenFromR8, l, 7, &fieldSnap{fd: 5, layout: l})
	want := map[string]bool{
		fmt.Sprint(asm.Mov.Imm(asm.R2, int32(metadataSize+l.Size()+64))):              false, // reserve size
		fmt.Sprint(asm.StoreImm(asm.R0, 12, int64(capture.ModeRecordFlag), asm.Byte)): false,
		fmt.Sprint(asm.StoreImm(asm.R0, 13, 7, asm.Byte)):                             false,
		fmt.Sprint(asm.Add.Imm(asm.R1, int32(metadataSize+l.Size()))):                 false, // packet copy
	}
	for _, ins := range insns {
		if _, ok := want[fmt.Sprint(ins)]; ok {
			want[fmt.Sprint(ins)] = true
		}
	}
	for s, seen := range want {
		if !seen {
			t.Fatalf("missing %s", s)
		}
	}
}

// TestNilRecordProgramsByteIdentical pins the non-recording tracing programs
// to the hashes their instructions had at 5d2c83d (before --record), so the
// record changes cannot alter a capture that does not record. The golden
// hashes were generated from a build at 5d2c83d, then regenerated from
// b2dba63 plus the orig_len change: the prologue leaves the packet length
// in R8, the metadata grows from 28 to 32 bytes (reserve size and data
// offset +4) and the epilogue stores R8 into it. The PR that made the
// change lists the instruction diff. They moved again when the submit
// flag began to follow the ring's backlog (emitWakeFlag).
func TestNilRecordProgramsByteIdentical(t *testing.T) {
	golden := map[string]string{
		"entry-nofilter": "25f2fde88018dffbe0631b6e8329a95ee42e272a15dd20bd3c21ea8665d8096b",
		"entry-int":      "a5eb55fb3dc072af119fcb773b5719b9168c8e9a731985dfbbfbea9b7c31c9a4",
		"entry-int2":     "796f34fd837594604f4ed3f6f3a000db23e376f5e93339050510870bbff3022f",
		"entry-member":   "f4f910d043eb19ee122300c090d5b2b9d501ad0cc4a4f2812f35d28b38c7a92c",
		"entry-ptr":      "c6fc19df82838d5bebd4fb6f1d2457bca052bac7f6a05f239a4d4e8821b3ae1a",
		"exit-int":       "e425709195a68a9b72e083aed4473c134bc5d878342c6af72696c58ee15f9dd5",
	}
	cases := []struct {
		name  string
		fexit bool
		ret   int16
		tf    filter.TargetFilters
	}{
		{"entry-nofilter", false, 0, filter.TargetFilters{}},
		{"entry-int", false, 0, filter.TargetFilters{Args: []filter.ArgFilter{{ParamIndex: 1, ParamSize: 4, Op: filter.OpGreaterEqual, Value: 3}}}},
		{"entry-int2", false, 0, filter.TargetFilters{Args: []filter.ArgFilter{{ParamIndex: 1, ParamSize: 4, Op: filter.OpGreaterEqual, Value: 3}, {ParamIndex: 1, ParamSize: 4, Op: filter.OpLessEqual, Value: 9}}}},
		{"entry-member", false, 0, filter.TargetFilters{Args: []filter.ArgFilter{{ParamIndex: 2, ParamSize: 4, Deref: true, Offset: 8, Op: filter.OpEqual, Value: 2}}}},
		{"entry-ptr", false, 0, filter.TargetFilters{Args: []filter.ArgFilter{{ParamIndex: 2, ParamSize: 8, Pointer: true, Op: filter.OpNotEqual}}}},
		{"exit-int", true, 48, filter.TargetFilters{Args: []filter.ArgFilter{{ParamIndex: 1, ParamSize: 4, Op: filter.OpEqual, Value: 7}}}},
	}
	h, _ := hook.ByName(hook.KindXDP)
	for _, c := range cases {
		insns, err := buildTracingInsnsForHook(h, codegen.Output{}, c.tf, 1, 2, 3, c.fexit, c.ret, nil, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%+v", insns)))
		if got := hex.EncodeToString(sum[:]); got != golden[c.name] {
			t.Errorf("%s: program changed from the pin: got %s want %s", c.name, got, golden[c.name])
		}
	}
}

// TestRecordReadsFieldOnce builds a recording filter with two conditions on
// one member plus a NULL test, and asserts the member is read once: the
// second condition reuses the first read (its snapshot).
func TestRecordReadsFieldOnce(t *testing.T) {
	u32 := &btf.Int{Name: "__u32", Size: 4}
	value := &btf.Struct{Name: "pol", Size: 4, Members: []btf.Member{{Name: "pol_rc", Type: u32}}}
	target := attach.Target{Generated: true, Params: []attach.FuncParamInfo{
		{Name: "site", Index: 1, Size: 4},
		{Name: "value", Index: 2, Size: 8, Kind: "ptr-struct", Type: &btf.Pointer{Target: &btf.Const{Type: value}}},
	}}
	tf := filter.TargetFilters{Args: []filter.ArgFilter{
		{ParamName: "value->pol_rc", ParamIndex: 2, ParamSize: 4, Deref: true, Op: filter.OpGreaterEqual, Value: 3},
		{ParamName: "value->pol_rc", ParamIndex: 2, ParamSize: 4, Deref: true, Op: filter.OpLessEqual, Value: 9},
		{ParamName: "value", ParamIndex: 2, ParamSize: 8, Pointer: true, Op: filter.OpNotEqual},
	}}
	layout, err := recordbuild.Build(target, tf, recordbuild.Options{Mode: record.ModeFilter})
	if err != nil || layout == nil || len(layout.Fields) != 2 {
		t.Fatalf("layout %+v %v", layout, err)
	}
	h, _ := hook.ByName(hook.KindXDP)
	// A layout without the fields gives both slot -1; they must stay two
	// reads, not share one.
	for _, l := range []*record.Layout{layout, {Mode: record.ModeFilter}} {
		insns, err := buildFilterGate(h, codegen.Output{}, tf, 2, nil, nil, false, 0, &fieldSnap{fd: 9, layout: l})
		if err != nil {
			t.Fatal(err)
		}
		var getArg, probeRead int
		for _, ins := range insns {
			switch {
			case ins == asm.FnGetFuncArg.Call():
				getArg++
			case ins == asm.FnProbeReadKernel.Call():
				probeRead++
			}
		}
		// value->pol_rc: one member read (get_func_arg + probe_read) for both
		// comparisons; value: one get_func_arg for the NULL test, no deref.
		if getArg != 2 || probeRead != 1 {
			t.Fatalf("%d fields: get_func_arg=%d probe_read=%d", len(l.Fields), getArg, probeRead)
		}
	}
}

// testSetMaps returns placeholder --set maps whose setMapFD is the given FD.
func testSetMaps(t *testing.T, fds ...int) []*ebpf.Map {
	t.Helper()
	maps, byMap := make([]*ebpf.Map, len(fds)), map[*ebpf.Map]int{}
	for i, fd := range fds {
		maps[i] = new(ebpf.Map)
		byMap[maps[i]] = fd
	}
	old := setMapFD
	setMapFD = func(m *ebpf.Map) int { return byMap[m] }
	t.Cleanup(func() { setMapFD = old })
	return maps
}

// TestRecordSetReusesRead: a set key on a field that an argument filter or
// an earlier set already read takes the snapshot instead of a second read.
func TestRecordSetReusesRead(t *testing.T) {
	maps := testSetMaps(t, 77, 78)
	u32 := &btf.Int{Name: "__u32", Size: 4}
	value := &btf.Struct{Name: "pol", Size: 4, Members: []btf.Member{{Name: "pol_rc", Type: u32}}}
	target := attach.Target{Generated: true, Params: []attach.FuncParamInfo{
		{Name: "site", Index: 1, Size: 4},
		{Name: "value", Index: 2, Size: 8, Kind: "ptr-struct", Type: &btf.Pointer{Target: &btf.Const{Type: value}}},
	}}
	set := func(m *ebpf.Map) filter.SetFilter {
		return filter.SetFilter{Map: m, KeySize: 4, StateOff: -1, TagWidth: 1, Fields: []filter.SetKeyField{{
			FieldName: "pol_rc", FieldSize: 4, ParamName: "value->pol_rc", ParamIdx: 2, ParamSize: 4, Deref: true}}}
	}
	arg := filter.ArgFilter{ParamName: "value->pol_rc", ParamIndex: 2, ParamSize: 4, Deref: true, Op: filter.OpGreaterEqual, Value: 3}
	h, _ := hook.ByName(hook.KindXDP)
	for _, c := range []struct {
		name string
		tf   filter.TargetFilters
	}{
		{"arg+set", filter.TargetFilters{Args: []filter.ArgFilter{arg}, Sets: []filter.SetFilter{set(maps[0])}}},
		{"two-sets", filter.TargetFilters{Sets: []filter.SetFilter{set(maps[0]), set(maps[1])}}},
	} {
		l, err := recordbuild.Build(target, c.tf, recordbuild.Options{Mode: record.ModeFilter})
		if err != nil || l == nil || len(l.Fields) != 1 {
			t.Fatalf("%s: layout %+v %v", c.name, l, err)
		}
		count := func(snap *fieldSnap) (probeRead, snapRefs int) {
			insns, err := buildFilterGate(h, codegen.Output{}, c.tf, 2, nil, nil, false, 0, snap)
			if err != nil {
				t.Fatal(err)
			}
			for _, ins := range insns {
				switch {
				case ins == asm.FnProbeReadKernel.Call():
					probeRead++
				case ins.OpCode.IsDWordLoad() && ins.Src == asm.PseudoMapFD && ins.Constant == 9:
					snapRefs++
				}
			}
			return
		}
		// Recording: one member read, stored once and loaded once by the
		// later set. Without a layout the program reads the member twice.
		if p, s := count(&fieldSnap{fd: 9, layout: l}); p != 1 || s != 2 {
			t.Errorf("%s: probe_read=%d snapshot refs=%d, want 1 and 2", c.name, p, s)
		}
		if p, s := count(nil); p != 2 || s != 0 {
			t.Errorf("%s without a layout: probe_read=%d snapshot refs=%d, want 2 and 0", c.name, p, s)
		}
	}
}

// TestNilRecordSetProgramsByteIdentical pins --set, gated and arg-echo
// programs built without a record layout to their 5d2c83d instructions,
// regenerated for orig_len as above (a gated entry parks it at -72 after
// its filter and keeps it in the hold).
// The arg-echo program captures no packet and is unchanged.
func TestNilRecordSetProgramsByteIdentical(t *testing.T) {
	golden := map[string]string{
		"tracing-scalar-set-fexit=false": "0bfa42ee6639266a1966819478500d4655afac58272369404fa3a191d48b9573",
		"tracing-scalar-set-fexit=true":  "037692d1c1bebf89b782f74fb0110e4fb352097fc41578f3bde163444a1978b7",
		"gated-scalar-set":               "c33773e6ad02178fa608a8dc31dda123c62c125d56197fee297cab6912ec4a22",
		"tracing-deref-set-fexit=false":  "200d6624128879422af8e9cb0bd2494d23000ba01567cf3a3ba1546020063a76",
		"tracing-deref-set-fexit=true":   "c12201b54c769cb8f2c03bfb7899dd230679e5fe425f7aa7377c54d1ac25682a",
		"gated-deref-set":                "636937c1bf8874344ef6b77e07bba84ace83f36f7f19c45203f07952303bcfde",
		"tracing-two-sets-fexit=false":   "4f2701f46eac7e4b5d8feb3ed17c97004f37a6714ed0f7fde7d83878801f3e20",
		"tracing-two-sets-fexit=true":    "2bebdb1cf0b190f73854d12d2c8e0b02a9f32579ba9d8f8b01d881454d0fdf27",
		"gated-two-sets":                 "a2e168d38c3715c020a327d2e47ad8143fd64fd7f807cba4017e0c3f73851fdd",
		"tracing-arg+set-fexit=false":    "79b6641d6cedc8dbb0ec2f8c225f5c03cb864bfc57f6e3bad82f21de4ceabae2",
		"tracing-arg+set-fexit=true":     "dc1191ed8f35bee97e29c5e8aa1c205dafd82eb216baaa081f0d0f54aa8dc065",
		"gated-arg+set":                  "1c8e117112a2120e156f0cbcf4dce0cf5a334d957a044c8aad1279614e83117e",
		"argecho":                        "0dd44a0c2fbf4fdb4bef3035c6056e53697e0f21d787ad5003b13cd53488da1f",
	}
	maps := testSetMaps(t, 77, 78)
	scalarSet := filter.SetFilter{Map: maps[0], KeySize: 4, StateOff: -1, TagWidth: 1,
		Fields: []filter.SetKeyField{{FieldName: "site", FieldSize: 4, ParamName: "site", ParamIdx: 1, ParamSize: 4}}}
	derefSet := filter.SetFilter{Map: maps[1], KeySize: 8, StateOff: 4, TagWidth: 4,
		Fields: []filter.SetKeyField{
			{FieldName: "a", FieldSize: 4, ParamName: "key->a", ParamIdx: 2, ParamSize: 4, Deref: true},
			{FieldName: "b", FieldOff: 4, FieldSize: 2, ParamName: "key->b", ParamIdx: 2, ParamSize: 2, Deref: true, Offset: 4, ParamSigned: true}}}
	arg := filter.ArgFilter{ParamName: "key->a", ParamIndex: 2, ParamSize: 4, Deref: true, Op: filter.OpLessEqual, Value: 9}
	sum := func(name string, insns asm.Instructions) {
		s := sha256.Sum256([]byte(fmt.Sprintf("%+v", insns)))
		if got := hex.EncodeToString(s[:]); got != golden[name] {
			t.Errorf("%s: program changed from the pin: got %s want %s", name, got, golden[name])
		}
	}
	h, _ := hook.ByName(hook.KindXDP)
	for _, c := range []struct {
		name string
		tf   filter.TargetFilters
	}{
		{"scalar-set", filter.TargetFilters{Sets: []filter.SetFilter{scalarSet}}},
		{"deref-set", filter.TargetFilters{Sets: []filter.SetFilter{derefSet}}},
		{"two-sets", filter.TargetFilters{Sets: []filter.SetFilter{scalarSet, derefSet}}},
		{"arg+set", filter.TargetFilters{Args: []filter.ArgFilter{arg}, Sets: []filter.SetFilter{derefSet}}},
	} {
		for _, fexit := range []bool{false, true} {
			insns, err := buildTracingInsnsForHook(h, codegen.Output{}, c.tf, 1, 2, 3, fexit, 48, nil, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			sum(fmt.Sprintf("tracing-%s-fexit=%v", c.name, fexit), insns)
		}
		g, err := buildGatedEntryInsns(h, codegen.Output{}, c.tf, 4, 5, 3, 2, nil, nil, EmitBoth, 128, 0)
		if err != nil {
			t.Fatal(err)
		}
		sum("gated-"+c.name, g)
	}
	params := []attach.FuncParamInfo{{Name: "site", Index: 1, Size: 4}, {Name: "key", Index: 2, Size: 8, Kind: "ptr-struct"}}
	sum("argecho", buildArgEchoInsns(6, []filter.ArgFilter{arg, {ParamName: "site", ParamIndex: 1, ParamSize: 4, Op: filter.OpEqual, Value: 3}}, params))
}
