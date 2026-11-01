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
	plain, legacy := captureWithRecord(3, 4, true, 64, id, nil, 0, nil), captureWithRingbuf(3, 4, true, 64, id)
	if len(plain) != len(legacy) {
		t.Fatal("nil layout changed the epilogue")
	}
	for i := range plain {
		if fmt.Sprint(plain[i]) != fmt.Sprint(legacy[i]) {
			t.Fatalf("insn %d: %v != %v", i, plain[i], legacy[i])
		}
	}
	l := &record.Layout{Mode: record.ModeFilter, Fields: []record.Field{{Name: "site", ParamIndex: 1, Size: 4}}}
	insns := captureWithRecord(3, 4, false, 64, id, l, 7, &fieldSnap{fd: 5, layout: l})
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
// hashes were generated from a build at 5d2c83d.
func TestNilRecordProgramsByteIdentical(t *testing.T) {
	golden := map[string]string{
		"entry-nofilter": "868ebed4a718e14b9a1c58114d844123f1a43dc301d05f02b5013f2eae9f3919",
		"entry-int":      "c3f68bcf65d82eabed8e3e9561a716aa4f80ac2caca45907eada0c0ab96b307d",
		"entry-int2":     "1f497398fe2e46ba668decc90db859f4e1557094972be570fbe368dc145c5935",
		"entry-member":   "2844606119fac2b1a5375181a2846b9408c955ff715e960b2cafdcdee635a874",
		"entry-ptr":      "7f54a75a8efc01faab8fd5bbf62fabf3e18244e7ecf6e950b2d2aad5f3dd3240",
		"exit-int":       "95c73583778e54e893a40e43b3e7e237ec4709b66ce2bbad22d23f105b3fe354",
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
			t.Errorf("%s: program changed from 5d2c83d: got %s want %s", c.name, got, golden[c.name])
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
// programs built without a record layout to their 5d2c83d instructions.
func TestNilRecordSetProgramsByteIdentical(t *testing.T) {
	golden := map[string]string{
		"tracing-scalar-set-fexit=false": "ffa040c61875de28b845149574a692e530ed035af736e4cac7e9aae6efba221d",
		"tracing-scalar-set-fexit=true":  "c61a87c6d959bb4cc80c2ac57ae7a92ed08686148e8949d086904121d8aceadd",
		"gated-scalar-set":               "97c9a82e13fcff146b1c4a4e3915cdbf57c774d6388534b81636d5c908d1b6ce",
		"tracing-deref-set-fexit=false":  "c7c5a6b1d7b78bc6f373f9f7be5ddf482c6187cc3ec5bb4b9cdb36181fffa4c1",
		"tracing-deref-set-fexit=true":   "e77aabe2f43136e7bc85e57d124fdfaf8aaf1562714bb5b7937d080257e3c742",
		"gated-deref-set":                "3c7223f1d905c7c7118369c35709655bcf65d7224df5176bae78714188abd57d",
		"tracing-two-sets-fexit=false":   "56166a1826f77dfef15810903d1fded8ab51982ad6c43c917e58e884a7310c36",
		"tracing-two-sets-fexit=true":    "786313496ae835cb9258e9b9b27c11fc288cc12af606041b68b2c74fe6c28682",
		"gated-two-sets":                 "40f4360b07b854c4b0414bbdbc39362c93b170b2fac54f3c545e556072c8106f",
		"tracing-arg+set-fexit=false":    "64044378eb8e65d63cd22c941869a56432bcaf77c621d34a759302fa7b99fb88",
		"tracing-arg+set-fexit=true":     "3203d6fe0ca224d655cc3ec22a433cda9d6e55a083efdcbb26e1d5b0e7965b0c",
		"gated-arg+set":                  "3ea79465adfc79d65ef71b5a7f09d943b5dec37fc7e2c1fbee3f45bf6ad138ba",
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
			t.Errorf("%s: program changed from 5d2c83d: got %s want %s", name, got, golden[name])
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
