package inject

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const (
	testHook = "obs_hook"
	testOff  = 0
)

// shapeReq returns a Request describing the fixed R2 = *(u32 *)(R0+0) shape
// with R1 as the redefined site register and an audited stack floor of -4.
func shapeReq(site uint32) Request {
	return Request{
		ELFSHA256:   strings.Repeat("0", 64),
		ProgramName: "p",
		SitePC:      site,
		HookName:    testHook,
		Load:        LoadShape{PtrReg: asm.R0, Offset: testOff},
		Stack:       StackAudit{LowestOffset: -4},
	}
}

// siteLoad is the audited load; redef writes R1 right after it.
func siteLoad() asm.Instruction  { return asm.LoadMem(asm.R2, asm.R0, testOff, asm.Word) }
func siteRedef() asm.Instruction { return asm.Mov.Imm(asm.R1, 0) }

func rawOffsets(insns asm.Instructions) map[int]asm.Instruction {
	m := map[int]asm.Instruction{}
	it := insns.Iterate()
	for it.Next() {
		m[int(it.Offset)] = *it.Ins
	}
	return m
}

func sameInstr(a, b asm.Instruction) bool {
	return a.OpCode == b.OpCode && a.Dst == b.Dst && a.Src == b.Src &&
		a.Offset == b.Offset && a.Constant == b.Constant &&
		a.Reference() == b.Reference() && a.Symbol() == b.Symbol()
}

func TestSpliceSuccessShapeAndGrowth(t *testing.T) {
	// Site at raw slot 1 (non-zero), so the inserted site immediate R1 = 1 is
	// distinguishable from a zero redefinition and from slot indices.
	in := asm.Instructions{
		asm.Mov.Imm(asm.R9, 0), // 0
		siteLoad(),             // 1 (site)
		siteRedef(),            // 2
		asm.Mov.Imm(asm.R0, 0), // 3
		asm.Return(),           // 4
	}
	out, err := splice(in, shapeReq(1))
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if len(out) != len(in)+insertSlots {
		t.Fatalf("length %d, want %d", len(out), len(in)+insertSlots)
	}
	off := rawOffsets(out)
	// The six spliced slots follow the site load (raw slot 1).
	want := asm.Instructions{
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		asm.StoreMem(asm.RFP, -24, asm.R2, asm.DWord),
		asm.Mov.Imm32(asm.R1, 1), // zero-extended u32 site immediate
		asm.Call.Label(testHook),
		asm.LoadMem(asm.R0, asm.RFP, -16, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, -24, asm.DWord),
	}
	for i, w := range want {
		g := off[2+i]
		if !sameInstr(g, w) {
			t.Fatalf("spliced slot %d = %v, want %v", i, g, w)
		}
	}
	// The site immediate must not be byte-identical to the zero redefinition.
	if sameInstr(off[4], siteRedef()) {
		t.Fatal("site immediate is indistinguishable from the redefinition")
	}
	// The original load keeps its metadata and remains at slot 1.
	if off[1].OpCode != siteLoad().OpCode {
		t.Fatal("site load moved")
	}
}

func TestAppendHookMetadataAndABI(t *testing.T) {
	out := appendHook(asm.Instructions{asm.Return()}, shapeReq(0))
	head := out[len(out)-3]
	if head.Symbol() != testHook {
		t.Fatalf("missing hook symbol, got %q", head.Symbol())
	}
	// The kernel requires line info for every function, so the generated
	// function carries a source line as well as func metadata.
	if head.Source() == nil {
		t.Fatal("generated function requires source line info")
	}
	fn := btf.FuncMetadata(&out[len(out)-3])
	if fn == nil || fn.Name != testHook || fn.Linkage != btf.GlobalFunc {
		t.Fatalf("missing typed global function metadata: %+v", fn)
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok || len(proto.Params) != 2 {
		t.Fatalf("unexpected proto %+v", fn.Type)
	}
	if proto.Params[0].Name != "site" || proto.Params[1].Name != "value" {
		t.Fatalf("ABI = (%s,%s), want (site,value)", proto.Params[0].Name, proto.Params[1].Name)
	}
	if ret, ok := proto.Return.(*btf.Int); !ok || ret.Size != 4 {
		t.Fatalf("return type = %v, want 4-byte int", proto.Return)
	}
	for _, p := range proto.Params {
		if i, ok := p.Type.(*btf.Int); !ok || i.Size != 4 || i.Encoding != btf.Unsigned {
			t.Fatalf("param %s is not u32: %v", p.Name, p.Type)
		}
	}
	if out[len(out)-1].OpCode != asm.Return().OpCode {
		t.Fatal("generated function must end in exit")
	}
}

// relocation: forward branch that bypasses the insertion keeps landing on the
// original next instruction; a back edge crossing the call is widened.
func TestSpliceBranchRelocation(t *testing.T) {
	// site=2; branch at slot 0 targets slot 3 (= site+1, the redef), so it must
	// bypass the six inserted slots after relocation.
	fwd := asm.Instructions{
		asm.JEq.Imm(asm.R9, 0, ""), // 0
		asm.Mov.Imm(asm.R0, 0),     // 1
		siteLoad(),                 // 2
		siteRedef(),                // 3
		asm.Return(),               // 4
	}
	fwd[0].Offset = 2 // 0 -> 0+1+2 = slot 3
	out, err := splice(fwd, shapeReq(2))
	if err != nil {
		t.Fatalf("splice fwd: %v", err)
	}
	if got := rawOffsets(out)[0].Offset; got != 2+insertSlots {
		t.Fatalf("bypass branch offset = %d, want %d", got, 2+insertSlots)
	}

	// Back edge: branch at slot 4 jumps to slot 0 (before the site), crossing
	// the insertion, so its negative offset must grow by insertSlots.
	back := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),     // 0
		asm.Mov.Imm(asm.R9, 0),     // 1
		siteLoad(),                 // 2
		siteRedef(),                // 3
		asm.JEq.Imm(asm.R9, 0, ""), // 4
		asm.Return(),               // 5
	}
	back[4].Offset = -5 // 4 -> 4+1-5 = slot 0
	out, err = splice(back, shapeReq(2))
	if err != nil {
		t.Fatalf("splice back: %v", err)
	}
	if got := rawOffsets(out)[4+insertSlots].Offset; got != -5-insertSlots {
		t.Fatalf("back-edge offset = %d, want %d", got, -5-insertSlots)
	}
}

func TestSpliceNumericAndSymbolicCalls(t *testing.T) {
	// Numeric bpf2bpf call (Reference == "") after the site is relocated via
	// its constant; a symbolic call is left for the loader to resolve.
	numeric := asm.Call.Label("")
	numeric.Constant = 1 // slot 3 -> 3+1+1 = slot 5
	sym := asm.Call.Label("subprog")

	in := asm.Instructions{
		siteLoad(),             // 0 (site)
		siteRedef(),            // 1
		sym,                    // 2 symbolic
		numeric,                // 3 numeric -> 5
		asm.Mov.Imm(asm.R0, 0), // 4
		asm.Return(),           // 5
	}
	out, err := splice(in, shapeReq(0))
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	off := rawOffsets(out)
	gotSym := off[2+insertSlots]
	if gotSym.Reference() != "subprog" || gotSym.Constant != -1 {
		t.Fatalf("symbolic call changed: ref=%q const=%d", gotSym.Reference(), gotSym.Constant)
	}
	// Both call and target shifted by insertSlots, so the delta is unchanged.
	gotNum := off[3+insertSlots]
	if gotNum.Constant != 1 {
		t.Fatalf("numeric call constant = %d, want 1", gotNum.Constant)
	}

	// A numeric call BEFORE the site that targets past it crosses the
	// insertion, so its constant must grow by insertSlots.
	cross := asm.Call.Label("")
	cross.Constant = 4 // slot 0 -> 0+1+4 = slot 5
	in2 := asm.Instructions{
		cross,                  // 0 (numeric call -> 5)
		asm.Mov.Imm(asm.R9, 0), // 1
		asm.Mov.Imm(asm.R8, 0), // 2
		siteLoad(),             // 3 (site)
		siteRedef(),            // 4
		asm.Return(),           // 5
	}
	out2, err := splice(in2, shapeReq(3))
	if err != nil {
		t.Fatalf("splice crossing: %v", err)
	}
	if got := rawOffsets(out2)[0].Constant; got != 4+insertSlots {
		t.Fatalf("crossing numeric call constant = %d, want %d", got, 4+insertSlots)
	}
}

// A numeric call whose target is not an instruction boundary is refused.
func TestSpliceNumericCallOffBoundaryRefused(t *testing.T) {
	bad := asm.Call.Label("")
	bad.Constant = 40 // far past the end of the stream
	in := asm.Instructions{siteLoad(), siteRedef(), bad, asm.Return()}
	if _, err := splice(in, shapeReq(0)); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("off-boundary numeric call must be refused, got %v", err)
	}

	// A negative numeric call target that lands before the stream start is also
	// refused.
	neg := asm.Call.Label("")
	neg.Constant = -10
	in2 := asm.Instructions{siteLoad(), siteRedef(), neg, asm.Return()}
	if _, err := splice(in2, shapeReq(0)); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("negative numeric call target must be refused, got %v", err)
	}
}

func TestSplicePreservesMapRef(t *testing.T) {
	mapLoad := asm.LoadMapPtr(asm.R3, 0).WithReference("mymap")
	in := asm.Instructions{siteLoad(), siteRedef(), mapLoad, asm.Return()}
	out, err := splice(in, shapeReq(0))
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	// mapLoad is an LDIMM64 (two raw slots); after the insertion it starts at
	// raw slot 2+insertSlots and must keep its reference and width.
	g := rawOffsets(out)[2+insertSlots]
	if !g.IsLoadFromMap() || g.Reference() != "mymap" {
		t.Fatalf("map ref not preserved: %v", g)
	}
}

// An LDIMM64 BEFORE the site makes the raw SitePC differ from the slice index;
// splice must still locate and splice the correct instruction.
func TestSpliceLDIMM64BeforeSite(t *testing.T) {
	mapLoad := asm.LoadMapPtr(asm.R3, 0).WithReference("mymap") // slots 0-1
	in := asm.Instructions{
		mapLoad,      // raw slot 0 (slice index 0), occupies slots 0 and 1
		siteLoad(),   // raw slot 2 (slice index 1)
		siteRedef(),  // raw slot 3 (slice index 2)
		asm.Return(), // raw slot 4 (slice index 3)
	}
	out, err := splice(in, shapeReq(2)) // SitePC is the raw slot, not the index
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	off := rawOffsets(out)
	// The spill store (first inserted slot) must follow the site at raw slot 2.
	if g := off[3]; g.OpCode != asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord).OpCode {
		t.Fatalf("insertion not placed after the raw site slot: %v", g)
	}
	// The map load is untouched at raw slot 0.
	if g := off[0]; !g.IsLoadFromMap() || g.Reference() != "mymap" {
		t.Fatalf("map load before site was disturbed: %v", g)
	}
}

func TestSpliceRefusals(t *testing.T) {
	cases := []struct {
		name string
		in   asm.Instructions
		req  Request
	}{
		{"site-not-boundary", asm.Instructions{siteLoad(), siteRedef(), asm.Return()}, shapeReq(99)},
		{"wrong-load-shape", asm.Instructions{asm.Mov.Imm(asm.R2, 0), siteRedef(), asm.Return()}, shapeReq(0)},
		{"wrong-dst-reg", asm.Instructions{asm.LoadMem(asm.R3, asm.R0, 0, asm.Word), siteRedef(), asm.Return()}, shapeReq(0)},
		{"no-following", asm.Instructions{siteLoad()}, shapeReq(0)},
		{"unknown-ref", asm.Instructions{siteLoad(), siteRedef(), asm.LoadImm(asm.R3, 0, asm.DWord).WithReference("fp"), asm.Return()}, shapeReq(0)},
		{"branch-off-boundary", func() asm.Instructions {
			j := asm.JEq.Imm(asm.R9, 0, "")
			j.Offset = 40
			return asm.Instructions{siteLoad(), siteRedef(), j, asm.Return()}
		}(), shapeReq(0)},
		{"symbolic-branch", func() asm.Instructions {
			return asm.Instructions{siteLoad(), siteRedef(), asm.JEq.Imm(asm.R9, 0, "lbl"), asm.Return()}
		}(), shapeReq(0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append(asm.Instructions{}, tc.in...)
			if _, err := splice(tc.in, tc.req); err == nil {
				t.Fatal("expected refusal")
			} else if !errors.Is(err, ErrRefused) {
				t.Fatalf("not ErrRefused: %v", err)
			}
			if len(tc.in) != len(before) {
				t.Fatal("input mutated on refusal")
			}
			for i := range before {
				if !sameInstr(tc.in[i], before[i]) {
					t.Fatalf("input instruction %d mutated on refusal", i)
				}
			}
		})
	}
}

// The instruction after the site must cleanly redefine R1 without reading it.
func TestSpliceRedefinitionRefusals(t *testing.T) {
	bad := []struct {
		name string
		next asm.Instruction
	}{
		{"jump-reads-r1", asm.JEq.Imm(asm.R1, 0, "")},
		{"alu-rmw-reads-r1", asm.Add.Imm(asm.R1, 1)},
		{"mov-r1-r1", asm.Mov.Reg(asm.R1, asm.R1)},
		{"load-through-r1", asm.LoadMem(asm.R1, asm.R1, 0, asm.Word)},
		{"store-not-def", asm.StoreMem(asm.R1, 0, asm.R2, asm.Word)},
		{"wrong-dst", asm.Mov.Imm(asm.R3, 0)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			in := asm.Instructions{siteLoad(), tc.next, asm.Return()}
			if _, err := splice(in, shapeReq(0)); err == nil || !errors.Is(err, ErrRefused) {
				t.Fatalf("expected refusal, got %v", err)
			}
		})
	}

	good := []struct {
		name string
		next asm.Instruction
	}{
		{"mov-imm", asm.Mov.Imm(asm.R1, 7)},
		{"mov-reg-other", asm.Mov.Reg(asm.R1, asm.R6)},
		{"ldimm64", asm.LoadImm(asm.R1, 0, asm.DWord)},
		{"ldx-other-ptr", asm.LoadMem(asm.R1, asm.R6, 0, asm.Word)},
	}
	for _, tc := range good {
		t.Run(tc.name, func(t *testing.T) {
			in := asm.Instructions{siteLoad(), tc.next, asm.Return()}
			if _, err := splice(in, shapeReq(0)); err != nil {
				t.Fatalf("expected success, got %v", err)
			}
		})
	}
}

func TestSpliceInvalidFuncPtrLoadRefused(t *testing.T) {
	fp := asm.LoadImm(asm.R3, 0, asm.DWord)
	fp.Src = asm.PseudoFunc
	in := asm.Instructions{siteLoad(), siteRedef(), fp, asm.Return()}
	if _, err := splice(in, shapeReq(0)); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("off-boundary function-pointer load must be refused, got %v", err)
	}
}

func TestStackBoundAndSpills(t *testing.T) {
	// A direct reference below the audited floor is refused.
	deep := asm.Instructions{asm.StoreMem(asm.RFP, -512, asm.R0, asm.DWord)}
	if err := checkStackBound(deep, -8); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("deep stack ref must be refused, got %v", err)
	}
	// A reference at or above the floor is allowed.
	if err := checkStackBound(asm.Instructions{asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord)}, -8); err != nil {
		t.Fatalf("in-bound ref refused: %v", err)
	}
}

// spillSlots must use widened arithmetic so a very negative mark cannot wrap
// through int16 into a wrongly accepted positive offset.
func TestSpillSlotsBoundaries(t *testing.T) {
	cases := []struct {
		lowest          int16
		wantOK          bool
		wantR0, wantVal int16
	}{
		{0, true, -8, -16},
		{-1, true, -16, -24},
		{-4, true, -16, -24},
		{-495, true, -504, -512},
		{-496, true, -504, -512},
		{-497, false, 0, 0},
		{-512, false, 0, 0},
		{-32768, false, 0, 0}, // most-negative int16 must not wrap positive
	}
	for _, tc := range cases {
		r0, val, err := spillSlots(tc.lowest)
		if tc.wantOK {
			if err != nil {
				t.Fatalf("spillSlots(%d) refused: %v", tc.lowest, err)
			}
			if r0 != tc.wantR0 || val != tc.wantVal {
				t.Fatalf("spillSlots(%d) = %d,%d, want %d,%d", tc.lowest, r0, val, tc.wantR0, tc.wantVal)
			}
			if val < -512 || r0 < -512 {
				t.Fatalf("spillSlots(%d) accepted an out-of-range slot: %d,%d", tc.lowest, r0, val)
			}
		} else {
			if err == nil || !errors.Is(err, ErrRefused) {
				t.Fatalf("spillSlots(%d) must be refused, got %d,%d,%v", tc.lowest, r0, val, err)
			}
		}
	}
}

func TestCollisionDetection(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"p": {Instructions: asm.Instructions{asm.Return().WithSymbol(testHook)}},
	}}
	if err := checkNoCollision(spec, testHook); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("symbol collision must be refused, got %v", err)
	}
	if err := checkNoCollision(spec, "other"); err != nil {
		t.Fatalf("non-colliding name refused: %v", err)
	}
}

func TestCheckReferences(t *testing.T) {
	mkCall := func(ref string) asm.Instruction { return asm.Call.Label(ref) }

	// Resolved symbolic call plus a defined map load: accepted.
	okSpec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{"m": {}},
		Programs: map[string]*ebpf.ProgramSpec{
			"p":   {Instructions: asm.Instructions{mkCall("sub"), asm.LoadMapPtr(asm.R1, 0).WithReference("m"), asm.Return(), asm.Return().WithSymbol("sub")}},
			"sub": {Instructions: asm.Instructions{asm.Return().WithSymbol("sub")}},
		},
	}
	if err := checkReferences(okSpec, okSpec.Programs["p"], testHook); err != nil {
		t.Fatalf("valid references refused: %v", err)
	}
	// Each entry may contain its own copy of a shared linked subprogram.
	// Symbols in a different program do not participate in this program's
	// relocation and cannot resolve a call missing from its own stream.
	unlinked := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"p":   {Instructions: asm.Instructions{mkCall("sub"), asm.Return()}},
		"sub": okSpec.Programs["sub"],
	}}
	if err := checkReferences(unlinked, unlinked.Programs["p"], testHook); !errors.Is(err, ErrRefused) {
		t.Fatalf("call outside the flattened stream must be refused, got %v", err)
	}

	// Unresolved symbolic call.
	badCall := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"p": {Instructions: asm.Instructions{mkCall("missing"), asm.Return()}},
	}}
	if err := checkReferences(badCall, badCall.Programs["p"], testHook); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("unresolved call must be refused, got %v", err)
	}

	// Missing map.
	badMap := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"p": {Instructions: asm.Instructions{asm.LoadMapPtr(asm.R1, 0).WithReference("gone"), asm.Return()}},
	}}
	if err := checkReferences(badMap, badMap.Programs["p"], testHook); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("missing map must be refused, got %v", err)
	}

	// Ambiguous: the same symbol defined twice.
	ambiguous := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"p":  {Instructions: asm.Instructions{mkCall("dup"), asm.Return().WithSymbol("dup"), asm.Return().WithSymbol("dup")}},
		"q":  {Instructions: asm.Instructions{asm.Return().WithSymbol("dup")}},
		"q2": {Instructions: asm.Instructions{asm.Return().WithSymbol("dup")}},
	}}
	if err := checkReferences(ambiguous, ambiguous.Programs["p"], testHook); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("ambiguous symbol must be refused, got %v", err)
	}

	// An original reference equal to the hook name is refused so the appended
	// hook cannot silently satisfy a previously unresolved call.
	refHook := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"p": {Instructions: asm.Instructions{mkCall(testHook), asm.Return()}},
	}}
	if err := checkReferences(refHook, refHook.Programs["p"], testHook); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("reference to the hook name must be refused, got %v", err)
	}
}

func TestCheckExtInfo(t *testing.T) {
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	fn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: i32}}

	// Missing func metadata on the first instruction.
	noFunc := asm.Instructions{siteLoad(), asm.Return()}
	if err := checkExtInfo(noFunc); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("missing func info must be refused, got %v", err)
	}

	// Func metadata but no source line on the function start.
	noSrc := asm.Instructions{btf.WithFuncMetadata(siteLoad(), fn), asm.Return()}
	if err := checkExtInfo(noSrc); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("missing source line must be refused, got %v", err)
	}

	// Complete: func metadata and source line.
	ok := asm.Instructions{btf.WithFuncMetadata(siteLoad().WithSource(asm.Comment("p")), fn), asm.Return()}
	if err := checkExtInfo(ok); err != nil {
		t.Fatalf("complete ext-info refused: %v", err)
	}
}

func TestValidateRequest(t *testing.T) {
	bad := []struct {
		name string
		mut  func(*Request)
	}{
		{"empty-sha", func(r *Request) { r.ELFSHA256 = "" }},
		{"short-sha", func(r *Request) { r.ELFSHA256 = "abcd" }},
		{"non-hex-sha", func(r *Request) { r.ELFSHA256 = strings.Repeat("g", 64) }},
		{"empty-prog", func(r *Request) { r.ProgramName = "" }},
		{"empty-hook", func(r *Request) { r.HookName = "" }},
		{"bad-hook-char", func(r *Request) { r.HookName = "bad name" }},
		{"bad-hook-digit", func(r *Request) { r.HookName = "9hook" }},
		{"long-hook", func(r *Request) { r.HookName = strings.Repeat("a", MaxHookName+1) }},
		{"ptr-not-r0", func(r *Request) { r.Load.PtrReg = asm.R3 }},
		{"stack-positive", func(r *Request) { r.Stack.LowestOffset = 8 }},
		{"stack-too-deep", func(r *Request) { r.Stack.LowestOffset = -513 }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			req := shapeReq(0)
			tc.mut(&req)
			if err := validateRequest(req); err == nil || !errors.Is(err, ErrRefused) {
				t.Fatalf("expected refusal, got %v", err)
			}
		})
	}
	if err := validateRequest(shapeReq(0)); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
}

func TestValidateRequestAndHashMismatch(t *testing.T) {
	// Missing fields are refused before any parse.
	if _, err := Transform([]byte("x"), Request{}); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("empty request must be refused, got %v", err)
	}
	// A well-formed request whose hash does not match the bytes is refused,
	// and the refusal names the hash boundary.
	req := shapeReq(0)
	req.ELFSHA256 = hex.EncodeToString(sha256.New().Sum(nil)) // hash of empty input
	_, err := Transform([]byte("not the audited bytes"), req)
	if err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("hash mismatch must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Fatalf("refusal should mention the hash: %v", err)
	}
	// Matching hash but non-ELF bytes: a parse error, not a refusal.
	blob := []byte("still not an ELF")
	sum := sha256.Sum256(blob)
	req.ELFSHA256 = hex.EncodeToString(sum[:])
	if _, err := Transform(blob, req); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("non-ELF with matching hash should be a parse error, got %v", err)
	}
	// An uppercase hex digest of the same bytes is still accepted at the gate
	// (it fails later as a parse error, not a hash refusal).
	req.ELFSHA256 = strings.ToUpper(hex.EncodeToString(sum[:]))
	if _, err := Transform(blob, req); err != nil && strings.Contains(err.Error(), "does not match") {
		t.Fatalf("uppercase digest should pass the hash gate: %v", err)
	}
}

// goSpec builds an isolated synthetic XDP collection whose program "p" carries
// the audited load shape plus the BTF func and source metadata the transform
// requires, used to exercise the transform core and Copy() isolation without a
// kernel or compiler.
func goSpec() *ebpf.CollectionSpec {
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	fn := &btf.Func{Name: "p", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: i32}}
	insns := asm.Instructions{siteLoad(), siteRedef(), asm.Mov.Imm(asm.R0, 0), asm.Return()}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSource(asm.Comment("p")), fn)
	return &ebpf.CollectionSpec{
		ByteOrder: binary.LittleEndian,
		Programs: map[string]*ebpf.ProgramSpec{
			"p": {Name: "p", Type: ebpf.XDP, Instructions: insns},
		},
	}
}

func TestTransformCoreCloneAndMetadata(t *testing.T) {
	src := goSpec()
	origLen := len(src.Programs["p"].Instructions)
	original := append(asm.Instructions(nil), src.Programs["p"].Instructions...)

	work := src.Copy()
	if err := transform(work, shapeReq(0)); err != nil {
		t.Fatalf("transform: %v", err)
	}

	// The clone grew by the full splice; the source was not touched.
	if got := len(work.Programs["p"].Instructions); got != origLen+insertSlots+genSlots {
		t.Fatalf("clone length %d, want %d", got, origLen+insertSlots+genSlots)
	}
	if len(src.Programs["p"].Instructions) != origLen {
		t.Fatal("Copy() did not isolate: source instructions changed")
	}
	// The clone carries the generated typed function; the source does not.
	out := work.Programs["p"].Instructions
	for i, ins := range original {
		j := i
		if i > 0 {
			j += insertSlots
		}
		if out[j] != ins || src.Programs["p"].Instructions[i] != ins {
			t.Fatalf("original instruction or metadata changed at %d", i)
		}
	}
	if btf.FuncMetadata(&out[len(out)-3]) == nil {
		t.Fatal("clone missing generated function metadata")
	}
}

func TestTransformRefusesNonXDP(t *testing.T) {
	work := goSpec()
	work.Programs["p"].Type = ebpf.SocketFilter
	if err := transform(work, shapeReq(0)); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("non-XDP program must be refused, got %v", err)
	}
}

func TestTransformNoMutationOnRefusal(t *testing.T) {
	work := goSpec()

	// Snapshot after fixture setup so metadata identity is comparable.
	req := shapeReq(0)
	work.Programs["p"].Instructions[0] = work.Programs["p"].Instructions[0].WithSymbol(req.HookName)
	before := append(asm.Instructions{}, work.Programs["p"].Instructions...)

	if err := transform(work, req); err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("collision must refuse, got %v", err)
	}
	got := work.Programs["p"].Instructions
	if len(got) != len(before) {
		t.Fatalf("instruction count changed on refusal: %d, want %d", len(got), len(before))
	}
	// Compare the full instructions, not just the length: a refusal must not
	// corrupt any operand or metadata.
	for i := range before {
		if !sameInstr(got[i], before[i]) || got[i].Metadata != before[i].Metadata {
			t.Fatalf("instruction %d mutated on refusal", i)
		}
	}
}

// The single-site Transform puts its two slots in the site's frame, which
// calls the hook: with the hook's 32-byte frame, -464 fits the kernel's
// 512-byte combined limit and -472 does not, and the refusal leaves work as
// it was.
func TestTransformStackLimit(t *testing.T) {
	for _, tc := range []struct {
		bound  int16
		refuse bool
	}{{-464, false}, {-472, true}} {
		work := goSpec()
		before := append(asm.Instructions(nil), work.Programs["p"].Instructions...)
		req := shapeReq(0)
		req.Stack.LowestOffset = tc.bound
		err := transform(work, req)
		if !tc.refuse {
			if err != nil {
				t.Fatalf("bound %d: %v", tc.bound, err)
			}
			continue
		}
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "512-byte combined limit") {
			t.Fatalf("bound %d: want the combined-limit refusal, got %v", tc.bound, err)
		}
		got := work.Programs["p"].Instructions
		if len(got) != len(before) {
			t.Fatalf("bound %d: refusal changed the instruction count", tc.bound)
		}
		for i := range before {
			if !sameInstr(got[i], before[i]) || got[i].Metadata != before[i].Metadata {
				t.Fatalf("bound %d: instruction %d mutated on refusal", tc.bound, i)
			}
		}
	}
}

func TestChecksumStableAndDistinct(t *testing.T) {
	a := asm.Instructions{siteLoad(), asm.Return()}
	c1, err := checksum(a, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := checksum(a, binary.LittleEndian)
	if c1 != c2 {
		t.Fatal("checksum not stable")
	}
	b := asm.Instructions{siteLoad(), asm.Mov.Imm(asm.R0, 1), asm.Return()}
	c3, _ := checksum(b, binary.LittleEndian)
	if c1 == c3 {
		t.Fatal("distinct streams share a checksum")
	}
}
