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
// change lists the instruction diff.
func TestNilRecordProgramsByteIdentical(t *testing.T) {
	golden := map[string]string{
		"entry-nofilter": "987b1849100b954d7cef99221b8b6025809ad73af4f850080f38bab3c6713b21",
		"entry-int":      "82e77f7790c13b351080e630687d8ac9e2cb0c7bd660274c7bbcbcbdd90d11c9",
		"entry-int2":     "c28713483b5c02315df1fd9b9c3ff2f9582bee6be705cb1ca1a1e3b24b7ef73c",
		"entry-member":   "005292e8e309ddce507bb12964cfafda59df90e31440ca7632a78ec5194453ba",
		"entry-ptr":      "d6da7ec1f0e3c13b959ee6718c87d3849fe987bdc4959738cca4419116f26fa9",
		"exit-int":       "25cc8494506f941971008977cce64522ee436c815d7497324a4988c93806756a",
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
		"tracing-scalar-set-fexit=false": "ff6961ac9eb321b865142964e70ff9330e8068d28e30d440f65a39d060cf1764",
		"tracing-scalar-set-fexit=true":  "39bfc55df0986877a129be394a8bd0196c5b0d9eff845266645ae0d9b01e170c",
		"gated-scalar-set":               "c33773e6ad02178fa608a8dc31dda123c62c125d56197fee297cab6912ec4a22",
		"tracing-deref-set-fexit=false":  "6483ba25575a3569d3494b8a47bd8f1de24141dcc580b0e5e3e2b9710261d3d3",
		"tracing-deref-set-fexit=true":   "d051ae1767d856993c6809e9cc3185a1368604324f41cc7a1e1ec9558719b93c",
		"gated-deref-set":                "636937c1bf8874344ef6b77e07bba84ace83f36f7f19c45203f07952303bcfde",
		"tracing-two-sets-fexit=false":   "8731597d85a71e56da56e8eb6aca7270c4e311bbae89aba40a9c88f664f62f56",
		"tracing-two-sets-fexit=true":    "33516cea4399aed150d8a91e243364d6e92469424d5ad4d30bb7078a6debe6d9",
		"gated-two-sets":                 "a2e168d38c3715c020a327d2e47ad8143fd64fd7f807cba4017e0c3f73851fdd",
		"tracing-arg+set-fexit=false":    "b60e6189535e58665088205844a613d876ff740147bee94efb5cd82cdd475561",
		"tracing-arg+set-fexit=true":     "b8e0784633f0300b0104c3d15fe102a9c59600f3894a72a1f030cfdfb2082eab",
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
