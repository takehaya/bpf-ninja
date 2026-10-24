package inject

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// kernelSitePC is the raw slot of the audited load in buildTarget.
const kernelSitePC = 3

// Observation record layout in the array map value (16 bytes):
//
//	[0:8]   seen   (u64)  how many times the hook was observed
//	[8:12]  site   (u32)  the SitePC the hook reported
//	[12:16] value  (u32)  the observed u32
const (
	obsSeenOff  = 0
	obsSiteOff  = 8
	obsValueOff = 12
	obsValueLen = 16
)

// buildTarget returns an isolated XDP CollectionSpec whose program "p" carries
// the audited load shape R2 = *(u32 *)(R0+0) at raw slot kernelSitePC, with the
// following instruction redefining R1. The post-site code reuses R0 (as the
// load pointer) and R2 (the observed value) so a missing spill/restore around
// the injected call would change the program's result, not just fail silently.
// The first instruction carries BTF func and source metadata, which the
// transform requires and the appended hook mirrors.
func buildTarget(value uint32) *ebpf.CollectionSpec {
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	u32 := &btf.Int{Name: "__u32", Size: 4, Encoding: btf.Unsigned}
	xdpMD := &btf.Struct{Name: "xdp_md", Size: 20, Members: []btf.Member{
		{Name: "data", Type: u32, Offset: 0},
		{Name: "data_end", Type: u32, Offset: 32},
	}}
	mainFn := &btf.Func{
		Name:    "p",
		Linkage: btf.GlobalFunc,
		Type: &btf.FuncProto{
			Return: i32,
			Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: xdpMD}}},
		},
	}

	matched := asm.JEq.Reg(asm.R0, asm.R2, "")
	matched.Offset = 2
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, int64(int32(value)), asm.Word), // 0: *(u32 *)(r10-4) = value
		asm.Mov.Reg(asm.R0, asm.RFP),                             // 1: r0 = r10
		asm.Add.Imm(asm.R0, -4),                                  // 2: r0 += -4 (pointer alias; caller-audited)
		asm.LoadMem(asm.R2, asm.R0, 0, asm.Word),                 // 3: SITE  r2 = *(u32 *)(r0+0) = value
		asm.Mov.Imm(asm.R1, 0),                                   // 4: r1 = 0 (redefines the site reg)
		// (the typed observation call is spliced in here)
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word), // 5: reuses the restored pointer
		matched,                                  // 6: compares with the restored value
		asm.Mov.Imm(asm.R0, 1),                   // 7: XDP_DROP on a value mismatch
		asm.Return(),                             // 8
		asm.Mov.Imm(asm.R0, 2),                   // 9: XDP_PASS on a match
		asm.Return(),                             // 10
	}
	insns[0] = btf.WithFuncMetadata(
		insns[0].WithSource(asm.Comment("synthetic XDP target")),
		mainFn,
	)

	return &ebpf.CollectionSpec{
		ByteOrder: binary.LittleEndian,
		Programs: map[string]*ebpf.ProgramSpec{
			"p": {Name: "p", Type: ebpf.XDP, Instructions: insns, License: "GPL"},
		},
	}
}

func kernelReq() Request {
	return Request{
		ProgramName: "p",
		SitePC:      kernelSitePC,
		HookName:    "obs_hook",
		Load:        LoadShape{PtrReg: asm.R0, Offset: 0},
		Stack:       StackAudit{LowestOffset: -4},
	}
}

// observerSpec builds a standalone fentry observer (pure asm, no clang/ELF) that
// attaches to targetProg's generated hook function and records the hook's two
// u32 arguments plus a seen counter into a one-entry array map. The observer
// reads the arguments from the fentry context (ctx[0]=site, ctx[1]=value).
func observerSpec(hook string, targetProg *ebpf.Program) *ebpf.CollectionSpec {
	observe := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord), // r6 = ctx[0] = site
		asm.LoadMem(asm.R7, asm.R1, 8, asm.DWord), // r7 = ctx[1] = value
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),    // key = 0
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4), // r2 = &key
		asm.LoadMapPtr(asm.R1, 0).WithReference("obs"),
		asm.FnMapLookupElem.Call(),     // r0 = lookup(obs, &key)
		asm.JEq.Imm(asm.R0, 0, "done"), // null → skip (verifier requires the check)
		asm.LoadMem(asm.R1, asm.R0, obsSeenOff, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, obsSeenOff, asm.R1, asm.DWord), // seen++
		asm.StoreMem(asm.R0, obsSiteOff, asm.R6, asm.Word),  // site
		asm.StoreMem(asm.R0, obsValueOff, asm.R7, asm.Word), // value
		asm.Mov.Imm(asm.R0, 0).WithSymbol("done"),
		asm.Return(),
	}
	return &ebpf.CollectionSpec{
		ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{
			"obs": {Type: ebpf.Array, KeySize: 4, ValueSize: obsValueLen, MaxEntries: 1},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"observe": {
				Name:         "observe",
				Type:         ebpf.Tracing,
				AttachType:   ebpf.AttachTraceFEntry,
				AttachTo:     hook,
				AttachTarget: targetProg,
				Instructions: observe,
				License:      "GPL",
			},
		},
	}
}

// loadOrSkip loads a collection, failing on a verifier rejection (a real defect
// on a capable machine) but skipping on a known permission or feature gap.
func loadOrSkip(t *testing.T, spec *ebpf.CollectionSpec) *ebpf.Collection {
	t.Helper()
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err == nil {
		return coll
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		t.Fatalf("verifier rejected a program that should load: %+v", ve)
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("skipping: BPF unsupported or insufficient privileges: %v", err)
	}
	t.Fatalf("loading collection: %v", err)
	return nil
}

func runXDP(t *testing.T, prog *ebpf.Program) (uint32, []byte) {
	t.Helper()
	in := make([]byte, 64)
	out := make([]byte, 64)
	ret, err := prog.Run(&ebpf.RunOptions{Data: in, DataOut: out})
	if err != nil {
		t.Fatalf("test-run: %v", err)
	}
	return ret, out
}

func readObs(t *testing.T, m *ebpf.Map) (seen uint64, site, value uint32) {
	t.Helper()
	var rec [obsValueLen]byte
	if err := m.Lookup(uint32(0), &rec); err != nil {
		t.Fatalf("map lookup: %v", err)
	}
	seen = binary.LittleEndian.Uint64(rec[obsSeenOff:])
	site = binary.LittleEndian.Uint32(rec[obsSiteOff:])
	value = binary.LittleEndian.Uint32(rec[obsValueOff:])
	return seen, site, value
}

// TestBpfTypedInjectionObservesSiteAndValue loads a tiny synthetic XDP target
// plain and injected, over a finite set of observed u32 values, confirms the
// injection does not change the program's action or output, attaches an fentry
// observer to the generated hook and reads back both the site and the u32 value
// with an explicit seen counter, then detaches and confirms observation stops.
// Everything is built from asm fixtures: there is no clang, ELF file, or other
// external runtime dependency. This test exercises the transform core and the
// loaded result, without parsing an ELF. It skips
// cleanly without BPF privileges or features and fails on a verifier rejection.
func TestBpfTypedInjectionObservesSiteAndValue(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	for _, value := range []uint32{0, 1, 0xffffffff} {
		value := value
		t.Run(hexName(value), func(t *testing.T) {
			runObservationCase(t, value)
		})
	}
}

func hexName(v uint32) string {
	switch v {
	case 0:
		return "value_0"
	case 1:
		return "value_1"
	default:
		return "value_max"
	}
}

func runObservationCase(t *testing.T, value uint32) {
	// Plain target: baseline action and output.
	plain := loadOrSkip(t, buildTarget(value))
	t.Cleanup(func() { plain.Close() })
	plainRet, plainOut := runXDP(t, plain.Programs["p"])
	if plainRet != 2 {
		t.Fatalf("plain action %d, want XDP_PASS (2)", plainRet)
	}

	// Injected target: drive the real transform core on the controlled,
	// verifiable clone, then load.
	work := buildTarget(value)
	if err := transform(work, kernelReq()); err != nil {
		t.Fatalf("transform: %v", err)
	}
	injected := loadOrSkip(t, work)
	t.Cleanup(func() { injected.Close() })
	injProg := injected.Programs["p"]

	// Injected but unobserved (no fentry attached yet): the hook is called but
	// does nothing visible, so the action and output must match the plain run.
	// A broken R0 or R2 restore would show up here as a different result.
	injRet, injOut := runXDP(t, injProg)
	if injRet != plainRet {
		t.Fatalf("injected action %d != plain %d", injRet, plainRet)
	}
	if string(injOut) != string(plainOut) {
		t.Fatal("injected output differs from plain")
	}

	// Attach an fentry observer to the generated hook.
	obsColl := loadOrSkip(t, observerSpec(kernelReq().HookName, injProg))
	t.Cleanup(func() { obsColl.Close() })

	obsLink, err := link.AttachTracing(link.TracingOptions{
		Program:    obsColl.Programs["observe"],
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("skipping: fentry attach unsupported: %v", err)
		}
		t.Fatalf("attach fentry: %v", err)
	}
	// Register cleanup immediately so a later t.Fatal cannot leak the link.
	t.Cleanup(func() { _ = obsLink.Close() })

	// Attached: the action is still unchanged and the observer records the site,
	// the loaded u32 value, and a non-zero seen count.
	attRet, attOut := runXDP(t, injProg)
	if attRet != plainRet || string(attOut) != string(plainOut) {
		t.Fatal("attached run changed action or output")
	}
	seen, gotSite, gotVal := readObs(t, obsColl.Maps["obs"])
	if seen != 1 {
		t.Fatalf("observed %d calls, want exactly one", seen)
	}
	if gotSite != kernelSitePC || gotVal != value {
		t.Fatalf("observed (site=%d,value=%#x), want (site=%d,value=%#x)",
			gotSite, gotVal, kernelSitePC, value)
	}

	// Detached: reset the record and confirm no further observation. The seen
	// counter distinguishes "reset to zero" from "no event".
	if err := obsLink.Close(); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if err := obsColl.Maps["obs"].Put(uint32(0), make([]byte, obsValueLen)); err != nil {
		t.Fatalf("reset map: %v", err)
	}
	detRet, detOut := runXDP(t, injProg)
	if detRet != plainRet || string(detOut) != string(plainOut) {
		t.Fatal("detached run changed action or output")
	}
	if seen, _, _ := readObs(t, obsColl.Maps["obs"]); seen != 0 {
		t.Fatalf("observation after detach: seen=%d", seen)
	}
}
