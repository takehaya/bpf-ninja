package attach

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

func TestFindXDPProgramNoInterface(t *testing.T) {
	_, err := FindXDPProgram("nonexistent_iface_xyz")
	if err == nil {
		t.Fatal("expected error for nonexistent interface, got nil")
	}
}

func TestListFuncs(t *testing.T) {
	prog := loadTestXDP(t)
	funcs, err := ListFuncs(prog)
	if err != nil {
		t.Fatalf("ListFuncs: %v", err)
	}

	found := map[string]bool{}
	for _, f := range funcs {
		found[f.Name] = true
	}

	if !found["xdp_subfunc_test"] {
		t.Error("expected xdp_subfunc_test in function list")
	}
	if !found["process_packet"] {
		t.Error("expected process_packet in function list")
	}
}

func TestValidateSubfuncValid(t *testing.T) {
	prog := loadTestXDP(t)
	if err := ValidateSubfunc(prog, 0, "process_packet"); err != nil {
		t.Fatalf("ValidateSubfunc for valid func: %v", err)
	}
}

func TestValidateSubfuncNotFound(t *testing.T) {
	prog := loadTestXDP(t)
	err := ValidateSubfunc(prog, 0, "nonexistent_func")
	if err == nil {
		t.Fatal("expected error for nonexistent function, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
	if !strings.Contains(err.Error(), "process_packet") {
		t.Errorf("error should list available functions, got: %v", err)
	}
}

// loadCPUMapProg loads an XDP program eligible to be attached to a CPUMAP
// entry (expected_attach_type BPF_XDP_CPUMAP).
func loadCPUMapProg(t *testing.T) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, testutil.XDPSubfuncSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}
	spec.Programs["xdp_subfunc_test"].AttachType = ebpf.AttachXDPCPUMap

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_subfunc_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Skipf("loading CPUMAP XDP program (kernel may lack BPF_XDP_CPUMAP): %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })
	return objs.Prog
}

// TestScanRedirectMapCPUMap verifies that a downstream XDP program
// attached to a CPUMAP entry is discovered via the redirect_map path.
func TestScanRedirectMapCPUMap(t *testing.T) {
	prog := loadCPUMapProg(t)

	progInfo, err := prog.Info()
	if err != nil {
		t.Fatalf("prog info: %v", err)
	}
	wantID, ok := progInfo.ID()
	if !ok {
		t.Fatal("program has no ID")
	}

	// value layout: struct bpf_cpumap_val { u32 qsize; u32 bpf_prog.fd }
	cpumap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.CPUMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("creating CPUMAP (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = cpumap.Close() })

	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], 192) // qsize
	binary.NativeEndian.PutUint32(val[4:8], uint32(prog.FD()))
	if err := cpumap.Put(uint32(0), val); err != nil {
		t.Skipf("populating CPUMAP with program (kernel may lack support): %v", err)
	}

	targets, err := scanMapForPrograms(cpumap, 0)
	if err != nil {
		t.Fatalf("scanMapForPrograms: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Via != "cpumap" {
		t.Errorf("Via = %q, want cpumap", got.Via)
	}
	if got.Key != 0 {
		t.Errorf("Key = %d, want 0", got.Key)
	}
	if got.ProgID != uint32(wantID) {
		t.Errorf("ProgID = %d, want %d", got.ProgID, uint32(wantID))
	}
}

// TestScanRedirectMapSkipsEmptyEntry verifies that a CPUMAP entry with no
// attached program (prog id 0) yields no target.
func TestScanRedirectMapSkipsEmptyEntry(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	cpumap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.CPUMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("creating CPUMAP (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = cpumap.Close() })

	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], 192) // qsize, no program
	if err := cpumap.Put(uint32(0), val); err != nil {
		t.Skipf("populating CPUMAP: %v", err)
	}

	targets, err := scanMapForPrograms(cpumap, 0)
	if err != nil {
		t.Fatalf("scanMapForPrograms: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets for empty entry, got %d: %+v", len(targets), targets)
	}
}

// TestListReachableProgramsCPUMap exercises the full discovery path: a
// dispatcher XDP program references a CPUMAP, and ListReachablePrograms
// walks prog.Info().MapIDs() to surface the downstream program attached
// to that CPUMAP entry.
func TestListReachableProgramsCPUMap(t *testing.T) {
	down := loadCPUMapProg(t)
	downInfo, err := down.Info()
	if err != nil {
		t.Fatalf("downstream prog info: %v", err)
	}
	wantID, ok := downInfo.ID()
	if !ok {
		t.Fatal("downstream program has no ID")
	}

	cpumap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.CPUMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("creating CPUMAP (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = cpumap.Close() })

	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], 192) // qsize
	binary.NativeEndian.PutUint32(val[4:8], uint32(down.FD()))
	if err := cpumap.Put(uint32(0), val); err != nil {
		t.Skipf("populating CPUMAP with program: %v", err)
	}

	// Minimal dispatcher: load the CPUMAP pointer (creating the used_map
	// relationship that surfaces it in MapIDs), then XDP_PASS.
	dispatcher, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, cpumap.FD()),
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("loading dispatcher program: %v", err)
	}
	t.Cleanup(func() { _ = dispatcher.Close() })

	targets, err := ListReachablePrograms(dispatcher)
	if err != nil {
		t.Fatalf("ListReachablePrograms: %v", err)
	}

	var found *ProgTarget
	for i := range targets {
		if targets[i].Via == "cpumap" && targets[i].ProgID == uint32(wantID) {
			found = &targets[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("downstream cpumap program (id=%d) not discovered; got %+v", uint32(wantID), targets)
	}
	if found.Key != 0 {
		t.Errorf("Key = %d, want 0", found.Key)
	}
}

// loadDevMapProg loads an XDP program eligible to be attached to a DEVMAP
// entry (expected_attach_type BPF_XDP_DEVMAP).
func loadDevMapProg(t *testing.T) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, testutil.XDPSubfuncSource))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}
	spec.Programs["xdp_subfunc_test"].AttachType = ebpf.AttachXDPDevMap

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_subfunc_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Skipf("loading DEVMAP XDP program (kernel may lack BPF_XDP_DEVMAP): %v", err)
	}
	t.Cleanup(func() { _ = objs.Prog.Close() })
	return objs.Prog
}

// TestScanRedirectMapDevMap verifies that a downstream XDP program attached
// to a DEVMAP entry is discovered. The value layout (bpf_devmap_val) puts
// the program id at the same offset 4 as CPUMAP; the entry targets the
// loopback interface.
func TestScanRedirectMapDevMap(t *testing.T) {
	prog := loadDevMapProg(t)

	progInfo, err := prog.Info()
	if err != nil {
		t.Fatalf("prog info: %v", err)
	}
	wantID, ok := progInfo.ID()
	if !ok {
		t.Fatal("program has no ID")
	}

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("looking up loopback: %v", err)
	}

	devmap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.DevMap,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("creating DEVMAP (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = devmap.Close() })

	// value layout: struct bpf_devmap_val { u32 ifindex; u32 bpf_prog.fd }
	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], uint32(lo.Index))
	binary.NativeEndian.PutUint32(val[4:8], uint32(prog.FD()))
	if err := devmap.Put(uint32(0), val); err != nil {
		t.Skipf("populating DEVMAP with program (device may not support XDP): %v", err)
	}

	targets, err := scanMapForPrograms(devmap, 0)
	if err != nil {
		t.Fatalf("scanMapForPrograms: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Via != "devmap" {
		t.Errorf("Via = %q, want devmap", got.Via)
	}
	if got.ProgID != uint32(wantID) {
		t.Errorf("ProgID = %d, want %d", got.ProgID, uint32(wantID))
	}
}

// TestScanRedirectMapDevMapHash covers the DEVMAP_HASH routing branch.
// Like DEVMAP and CPUMAP, DEVMAP_HASH requires key_size == 4 (u32 keys),
// so the shared uint32 iteration in scanRedirectMap applies. The value
// layout (bpf_devmap_val) is identical to DEVMAP.
func TestScanRedirectMapDevMapHash(t *testing.T) {
	prog := loadDevMapProg(t)

	progInfo, err := prog.Info()
	if err != nil {
		t.Fatalf("prog info: %v", err)
	}
	wantID, ok := progInfo.ID()
	if !ok {
		t.Fatal("program has no ID")
	}

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("looking up loopback: %v", err)
	}

	devmap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.DevMapHash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("creating DEVMAP_HASH (kernel may lack support): %v", err)
	}
	t.Cleanup(func() { _ = devmap.Close() })

	val := make([]byte, 8)
	binary.NativeEndian.PutUint32(val[0:4], uint32(lo.Index))
	binary.NativeEndian.PutUint32(val[4:8], uint32(prog.FD()))
	// DEVMAP_HASH keys are arbitrary u32; use a non-zero sparse key.
	const key = uint32(42)
	if err := devmap.Put(key, val); err != nil {
		t.Skipf("populating DEVMAP_HASH with program (device may not support XDP): %v", err)
	}

	targets, err := scanMapForPrograms(devmap, 0)
	if err != nil {
		t.Fatalf("scanMapForPrograms: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Via != "devmap_hash" {
		t.Errorf("Via = %q, want devmap_hash", got.Via)
	}
	if got.Key != key {
		t.Errorf("Key = %d, want %d", got.Key, key)
	}
	if got.ProgID != uint32(wantID) {
		t.Errorf("ProgID = %d, want %d", got.ProgID, uint32(wantID))
	}
}
