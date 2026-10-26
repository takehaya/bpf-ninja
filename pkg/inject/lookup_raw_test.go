package inject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Every bool option of LookupRequestRaw reaches LookupRequest, so a new flag
// cannot be silently dropped when the raw request is converted.
func TestRawRequestForwardsOptions(t *testing.T) {
	var raw LookupRequestRaw
	v := reflect.ValueOf(&raw).Elem()
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.Bool {
			f.SetBool(true)
		}
	}
	got := reflect.ValueOf(raw.request())
	for i := range v.NumField() {
		if name := v.Type().Field(i).Name; v.Field(i).Kind() == reflect.Bool && !got.FieldByName(name).Bool() {
			t.Errorf("%s is not forwarded", name)
		}
	}
}

// Convert the already-linked ProgramSpec to load inputs without loading BPF.
// Keeping symbols tests checksum parity; numeric strips all instruction metadata
// via a marshal/unmarshal, as a syscall front end would receive it.
func rawLookupFixture(t *testing.T, spec *ebpf.CollectionSpec, name string, numeric bool) RawProgram {
	t.Helper()
	insns := append(asm.Instructions(nil), spec.Programs[name].Instructions...)
	builder := new(btf.Builder)
	var err error
	if spec.Types != nil {
		builder, err = rawBTFBuilder(spec.Types)
		if err != nil {
			t.Fatal(err)
		}
	}
	fi, li, err := btf.MarshalExtInfos(insns, builder)
	if err != nil {
		t.Fatal(err)
	}
	var blob []byte
	if spec.Types != nil {
		blob, err = marshalRawBTF(builder, spec.Types)
	} else {
		blob, err = builder.Marshal(nil, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	types, err := btf.LoadSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	maps := make(map[int32]RawMap)
	fds := make(map[string]int32)
	for i := range insns {
		ins := &insns[i]
		if !ins.IsLoadFromMap() {
			continue
		}
		m := spec.Maps[ins.Reference()]
		if m == nil {
			t.Fatalf("missing fixture map %s", ins.Reference())
		}
		fd := int32(ins.Constant)
		if numeric {
			var ok bool
			fd, ok = fds[ins.Reference()]
			if !ok {
				fd = int32(40 + len(fds))
				fds[ins.Reference()] = fd
			}
			ins.Constant = int64(fd)
		}
		maps[fd] = RawMap{Name: ins.Reference(), Type: m.Type, KeySize: m.KeySize, ValueSize: m.ValueSize, Key: m.Key, Value: m.Value}
	}
	if numeric {
		var wire bytes.Buffer
		if err := insns.Marshal(&wire, rawByteOrder()); err != nil {
			t.Fatal(err)
		}
		insns, err = asm.AppendInstructions(nil, &wire, rawByteOrder(), "linux")
		if err != nil {
			t.Fatal(err)
		}
	}
	return RawProgram{Instructions: insns, Type: spec.Programs[name].Type, BTF: types, FuncInfo: fi, LineInfo: li, Maps: maps}
}

func rawLookupRequest(req LookupRequest) LookupRequestRaw {
	return LookupRequestRaw{Site: req.Site, Auto: req.Auto, HookName: req.HookName, Stack: req.Stack}
}

func assertRawLookupParity(t *testing.T, src *ebpf.CollectionSpec, req LookupRequest, want *LookupResult) {
	t.Helper()
	p := rawLookupFixture(t, src, req.ProgramName, false)
	got, err := TransformLookupRaw(p, rawLookupRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceChecksum != want.SourceChecksum || got.TransformedChecksum != want.TransformedChecksum ||
		got.InsertedSlots != want.InsertedSlots || got.AddedBytes != want.AddedBytes || got.InsertedAt != want.InsertedAt ||
		!reflect.DeepEqual(got.Sites, want.Sites) || got.Site != want.Site || !reflect.DeepEqual(got.Skipped, want.Skipped) ||
		len(got.Hooks) != len(want.Hooks) {
		t.Fatalf("raw/ELF result mismatch: raw=%+v ELF=%+v", got, want)
	}
	for i, hook := range want.Hooks {
		if got.Hooks[i].Name != hook.Name || got.Hooks[i].MapName != hook.MapName || !reflect.DeepEqual(got.Hooks[i].Sites, hook.Sites) {
			t.Fatalf("raw/ELF hook %d mismatch: raw=%+v ELF=%+v", i, got.Hooks[i], hook)
		}
	}
	out := want.Spec.Programs[req.ProgramName].Instructions
	if len(got.Instructions) != len(out) {
		t.Fatal("instruction lengths differ")
	}
	for i, ins := range out {
		if !sameInstr(ins, got.Instructions[i]) || ins.Reference() != got.Instructions[i].Reference() || ins.Symbol() != got.Instructions[i].Symbol() {
			t.Fatalf("instruction/relocation %d differs: %v vs %v", i, ins, got.Instructions[i])
		}
	}
	assertRawMetadata(t, p, got)
}

func assertRawMetadata(t *testing.T, p RawProgram, got *LookupResultRaw) {
	t.Helper()
	funcs, err := btf.LoadFuncInfos(bytes.NewReader(got.FuncInfo), binary.NativeEndian, uint32(len(got.FuncInfo)/8), got.BTF)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := btf.LoadLineInfos(bytes.NewReader(got.LineInfo), binary.NativeEndian, uint32(len(got.LineInfo)/16), got.BTF)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hooks) == 0 || len(funcs) != len(p.FuncInfo)/8+len(got.Hooks) || len(got.HookFuncInfo) != 8 ||
		binary.NativeEndian.Uint32(got.HookFuncInfo[4:]) != uint32(got.HookTypeID) ||
		got.HookName != got.Hooks[0].Name || got.HookTypeID != got.Hooks[0].TypeID {
		t.Fatal("missing hook func_info")
	}
	if funcs[0].Offset != 0 {
		t.Fatal("entry func_info is not at offset 0")
	}
	for i, hook := range got.Hooks {
		if len(hook.FuncInfo) != 8 || binary.NativeEndian.Uint32(hook.FuncInfo[4:]) != uint32(hook.TypeID) ||
			funcs[1+i].Func.Name != hook.Name || uint32(funcs[1+i].Offset) != binary.NativeEndian.Uint32(hook.FuncInfo) {
			t.Fatalf("hook %s is not in order right after entry", hook.Name)
		}
	}
	byPC := rawOffsets(got.Instructions)
	for _, fn := range funcs {
		ins := byPC[int(fn.Offset)]
		if btf.FuncMetadata(&ins).Name != fn.Func.Name {
			t.Fatal("func_info offset mismatch")
		}
		found := false
		for _, line := range lines {
			if line.Offset == fn.Offset {
				found = true
			}
		}
		if !found {
			t.Fatal("function lacks line_info")
		}
	}
	for _, line := range lines {
		if byPC[int(line.Offset)].Source().String() != line.Line.String() {
			t.Fatal("line_info offset mismatch")
		}
	}
	for id := btf.TypeID(1); ; id++ {
		old, err := p.BTF.TypeByID(id)
		if errors.Is(err, btf.ErrNotFound) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		newType, err := got.BTF.TypeByID(id)
		if err != nil || !reflect.DeepEqual(old, newType) {
			t.Fatalf("original type ID %d changed: %v", id, err)
		}
		for _, hook := range got.Hooks {
			if hook.TypeID <= id {
				t.Fatal("hook ID overlaps original types")
			}
		}
	}
}

func TestLookupRawMapIdentity(t *testing.T) {
	p := rawLookupFixture(t, lookupFixture(), "p", true)
	m := p.Maps[40]
	m.Name = "fd_resolved_sessions"
	p.Maps[40] = m
	sites, err := DiscoverLookupsRaw(p)
	if err != nil || len(sites) != 1 || sites[0].MapName != m.Name || sites[0].Reason != "" || sites[0].FuncName != "p" {
		t.Fatalf("fd discovery: %+v, %v", sites, err)
	}
	req := rawLookupRequest(lookupReq())
	req.Site.MapName = m.Name
	got, err := TransformLookupRaw(p, req)
	if err != nil {
		t.Fatal(err)
	}
	assertRawMetadata(t, p, got)
	var maps int
	for _, ins := range got.Instructions {
		if ins.IsLoadFromMap() {
			maps++
			if ins.Constant != 40 || ins.Reference() != "" {
				t.Fatal("map fd changed")
			}
		}
	}
	if maps != 1 {
		t.Fatal("map load lost")
	}
	// An unnamed map has no hook name to give; Auto falls back to a number.
	m.Name = ""
	p.Maps[40] = m
	auto, err := TransformLookupRaw(p, LookupRequestRaw{Auto: true, Entry: true, HookName: req.HookName, Stack: req.Stack})
	if err != nil {
		t.Fatal(err)
	}
	if len(auto.Hooks) != 2 || auto.Hooks[0].Name != req.HookName+"_0" || auto.Hooks[0].MapName != "" {
		t.Fatalf("unnamed map hooks: %+v", auto.Hooks)
	}
	delete(p.Maps, 40)
	sites, err = DiscoverLookupsRaw(p)
	if err != nil || len(sites) != 1 || sites[0].Reason == "" {
		t.Fatalf("missing map discovery: %+v, %v", sites, err)
	}
	if _, err := TransformLookupRaw(p, req); !errors.Is(err, ErrRefused) {
		t.Fatalf("missing map transform: %v", err)
	}
}

func TestLookupRawBTFExtension(t *testing.T) {
	p := rawLookupFixture(t, lookupFixture(), "p", true)
	m := p.Maps[40]
	m.Key = &btf.Typedef{Name: "session_key", Type: m.Key}
	p.Maps[40] = m
	before := p.BTF.Copy()
	got, err := TransformLookupRaw(p, rawLookupRequest(lookupReq()))
	if err != nil {
		t.Fatal(err)
	}
	assertRawMetadata(t, p, got)
	blobSpec, err := btf.LoadSpecFromReader(bytes.NewReader(got.BTFBytes))
	if err != nil {
		t.Fatal(err)
	}
	typ, err := blobSpec.TypeByID(got.HookTypeID)
	if err != nil {
		t.Fatal(err)
	}
	fn := typ.(*btf.Func)
	proto := fn.Type.(*btf.FuncProto)
	ret := proto.Return.(*btf.Int)
	if fn.Name != got.HookName || fn.Linkage != btf.GlobalFunc || len(proto.Params) != 3 || ret.Size != 4 || ret.Encoding != btf.Signed {
		t.Fatalf("hook ABI: %+v", fn)
	}
	ctx := proto.Params[0].Type.(*btf.Pointer).Target.(*btf.Struct)
	if ctx.Name != "xdp_md" {
		t.Fatal("context type changed")
	}
	for i, want := range []btf.Type{p.Maps[40].Key, p.Maps[40].Value} {
		actual := proto.Params[i+1].Type.(*btf.Pointer).Target.(*btf.Const).Type
		if !reflect.DeepEqual(actual, want) {
			t.Fatalf("map argument %d changed", i)
		}
	}
	// The generated metadata and external map types must not alias caller BTF.
	btf.FuncMetadata(&got.Instructions[0]).Name = "changed"
	if _, err := p.BTF.AnyTypeByName("changed"); err == nil {
		t.Fatal("input BTF mutated")
	}
	old, _ := before.AnyTypeByName("p")
	current, _ := p.BTF.AnyTypeByName("p")
	if !reflect.DeepEqual(old, current) {
		t.Fatal("input function changed")
	}
	if _, err := p.BTF.AnyTypeByName(got.HookName); err == nil {
		t.Fatal("hook added to input BTF")
	}
}

func TestLookupRawMultipleCallbacks(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *ebpf.CollectionSpec
	}{
		{"multiple", multiLookupFixture()},
		{"multiple-with-callback", func() *ebpf.CollectionSpec {
			spec := multiLookupFixture()
			prog := spec.Programs["p"]
			prog.Instructions = append(prog.Instructions, callbackLoad(asm.R2, 2, ""), asm.Return(), callbackHead("callback"), asm.Return())
			return spec
		}()},
		{"symbolic-callback", callbackLookupFixture(true)},
		{"numeric-callback", callbackLookupFixture(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := lookupReq()
			req.Site.AllMatches = true
			// The callback fixture's counters reach fp-24.
			req.Stack.LowestOffset = -24
			p := rawLookupFixture(t, tc.spec, "p", true)
			before := append(asm.Instructions(nil), p.Instructions...)
			got, err := TransformLookupRaw(p, rawLookupRequest(req))
			if err != nil {
				t.Fatal(err)
			}
			assertRawMetadata(t, p, got)
			if !reflect.DeepEqual(before, p.Instructions) {
				t.Fatal("input instructions changed")
			}
			// Resolve the ELF output's symbols and fds, then compare actual load bytes.
			work := tc.spec.Copy()
			if _, err := transformLookup(work, req); err != nil {
				t.Fatal(err)
			}
			want := work.Programs["p"].Instructions
			for i := range want {
				if want[i].IsLoadFromMap() {
					want[i].Constant = 40
				}
			}
			var elfWire, rawWire bytes.Buffer
			if err := want.Marshal(&elfWire, rawByteOrder()); err != nil {
				t.Fatal(err)
			}
			if err := got.Instructions.Marshal(&rawWire, rawByteOrder()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(elfWire.Bytes(), rawWire.Bytes()) {
				t.Fatal("raw callback/branch relocation differs from ELF")
			}
		})
	}
}

func TestLookupRawDifferentMapIdentities(t *testing.T) {
	p := rawLookupFixture(t, multiLookupFixture(), "p", true)
	p.Maps[41] = p.Maps[40] // Same name and types, but a different fd identity.
	// Locate the second map load without assuming a slice/raw-PC equivalence.
	count := 0
	for i := range p.Instructions {
		if p.Instructions[i].IsLoadFromMap() {
			count++
			if count == 2 {
				p.Instructions[i].Constant = 41
			}
		}
	}
	req := rawLookupRequest(lookupReq())
	req.Site.AllMatches = true
	if _, err := TransformLookupRaw(p, req); !errors.Is(err, ErrRefused) {
		t.Fatalf("mixed map identities: %v", err)
	}
	sites, err := DiscoverLookupsRaw(p)
	if err != nil {
		t.Fatal(err)
	}
	req.Site.AllMatches, req.Site.SitePCs = false, []uint32{sites[1].SitePC}
	if _, err := TransformLookupRaw(p, req); err != nil {
		t.Fatalf("explicit one-map selection: %v", err)
	}
}

func TestLookupRawRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*RawProgram, *LookupRequestRaw)
	}{
		{"non-xdp", func(p *RawProgram, r *LookupRequestRaw) { p.Type = ebpf.SocketFilter }},
		{"missing-btf", func(p *RawProgram, r *LookupRequestRaw) { p.BTF = nil }},
		{"missing-functions", func(p *RawProgram, r *LookupRequestRaw) { p.FuncInfo = nil }},
		{"missing-lines", func(p *RawProgram, r *LookupRequestRaw) { p.LineInfo = nil }},
		{"short-function-record", func(p *RawProgram, r *LookupRequestRaw) { p.FuncInfo = p.FuncInfo[:7] }},
		{"short-line-record", func(p *RawProgram, r *LookupRequestRaw) { p.LineInfo = p.LineInfo[:15] }},
		{"function-continuation", func(p *RawProgram, r *LookupRequestRaw) { binary.NativeEndian.PutUint32(p.FuncInfo, 10) }},
		{"line-past-end", func(p *RawProgram, r *LookupRequestRaw) { binary.NativeEndian.PutUint32(p.LineInfo, 999) }},
		{"duplicate-functions", func(p *RawProgram, r *LookupRequestRaw) { p.FuncInfo = append(p.FuncInfo, p.FuncInfo...) }},
		{"duplicate-lines", func(p *RawProgram, r *LookupRequestRaw) { p.LineInfo = append(p.LineInfo, p.LineInfo...) }},
		{"bad-function-id", func(p *RawProgram, r *LookupRequestRaw) { binary.NativeEndian.PutUint32(p.FuncInfo[4:], 99999) }},
		{"non-function-id", func(p *RawProgram, r *LookupRequestRaw) { binary.NativeEndian.PutUint32(p.FuncInfo[4:], 0) }},
		{"bad-line-string", func(p *RawProgram, r *LookupRequestRaw) { binary.NativeEndian.PutUint32(p.LineInfo[4:], 99999) }},
		{"missing-map", func(p *RawProgram, r *LookupRequestRaw) { delete(p.Maps, 40) }},
		{"bad-map-kind", func(p *RawProgram, r *LookupRequestRaw) { m := p.Maps[40]; m.Type = ebpf.HashOfMaps; p.Maps[40] = m }},
		{"key-size", func(p *RawProgram, r *LookupRequestRaw) { m := p.Maps[40]; m.KeySize++; p.Maps[40] = m }},
		{"wrong-ctx", func(p *RawProgram, r *LookupRequestRaw) {
			typ, _ := p.BTF.AnyTypeByName("p")
			typ.(*btf.Func).Type.(*btf.FuncProto).Params[0].Type = &btf.Int{Size: 4}
		}},
		{"collision", func(p *RawProgram, r *LookupRequestRaw) { r.HookName = "p" }},
		{"invalid-hook", func(p *RawProgram, r *LookupRequestRaw) { r.HookName = "9bad" }},
		{"stack-direct", func(p *RawProgram, r *LookupRequestRaw) { r.Stack.LowestOffset = 0 }},
		{"stack-room", func(p *RawProgram, r *LookupRequestRaw) { r.Stack.LowestOffset = -489 }},
		{"stack-positive", func(p *RawProgram, r *LookupRequestRaw) { r.Stack.LowestOffset = 8 }},
		{"empty-map", func(p *RawProgram, r *LookupRequestRaw) { r.Site.MapName = "" }},
		{"selector-modes", func(p *RawProgram, r *LookupRequestRaw) { r.Site.AllMatches = true; r.Site.SitePCs = []uint32{11} }},
		{"duplicate-pcs", func(p *RawProgram, r *LookupRequestRaw) { r.Site.SitePCs = []uint32{11, 11} }},
		{"wrong-function", func(p *RawProgram, r *LookupRequestRaw) { r.Site.FuncName = "absent" }},
		{"branch-continuation", func(p *RawProgram, r *LookupRequestRaw) { p.Instructions[4].Offset = 5 }},
		{"entry-call", func(p *RawProgram, r *LookupRequestRaw) {
			p.Instructions = append(p.Instructions, asm.Call.Label(""))
			p.Instructions[len(p.Instructions)-1].Constant = -18
		}},
		{"bad-callback", func(p *RawProgram, r *LookupRequestRaw) {
			p.Instructions = append(p.Instructions, callbackLoad(asm.R2, 0, ""))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rawLookupFixture(t, lookupFixture(), "p", true)
			req := rawLookupRequest(lookupReq())
			tc.change(&p, &req)
			insns := append(asm.Instructions(nil), p.Instructions...)
			fi, li := bytes.Clone(p.FuncInfo), bytes.Clone(p.LineInfo)
			got, err := TransformLookupRaw(p, req)
			if got != nil || !errors.Is(err, ErrRefused) {
				t.Fatalf("want refusal, got %v, %v", got, err)
			}
			if !reflect.DeepEqual(insns, p.Instructions) || !bytes.Equal(fi, p.FuncInfo) || !bytes.Equal(li, p.LineInfo) {
				t.Fatal("refusal mutated input")
			}
		})
	}
}

func TestLookupRawBTFOriginalIDs(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		t.Run(fmt.Sprint(tagged), func(t *testing.T) {
			spec := lookupFixture()
			fn := btf.FuncMetadata(&spec.Programs["p"].Instructions[0])
			if tagged {
				fn.Tags = []string{"original-function"}
				fn.ParamTags = [][]string{{"original-parameter"}}
				ctx := fn.Type.(*btf.FuncProto).Params[0].Type.(*btf.Pointer).Target.(*btf.Struct)
				ctx.Tags = []string{"original-struct"}
				ctx.Members[0].Tags = []string{"original-member"}
			}
			p := rawLookupFixture(t, spec, "p", true)
			got, err := TransformLookupRaw(p, rawLookupRequest(lookupReq()))
			if err != nil {
				t.Fatal(err)
			}
			assertRawMetadata(t, p, got)
		})
	}
}

func TestLookupRawSubprogramRefusal(t *testing.T) {
	spec := lookupFixture()
	ins := &spec.Programs["p"].Instructions[9]
	head := callbackHead("subprogram")
	*ins = btf.WithFuncMetadata(ins.WithSource(head.Source()), btf.FuncMetadata(&head))
	p := rawLookupFixture(t, spec, "p", true)
	sites, err := DiscoverLookupsRaw(p)
	if err != nil || len(sites) != 1 || sites[0].Reason == "" || sites[0].FuncName != "subprogram" {
		t.Fatalf("subprogram discovery: %+v, %v", sites, err)
	}
	if _, err := TransformLookupRaw(p, rawLookupRequest(lookupReq())); !errors.Is(err, ErrRefused) {
		t.Fatalf("subprogram transform: %v", err)
	}
}
