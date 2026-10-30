package program

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/google/gopacket/pcapgo"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/output"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

// Explicit object/directory overrides let VM jobs retain every input, raw shard
// and failed attempt without requiring a compiler in the VM.
func hookFixture(t *testing.T) (*ebpf.Collection, []attach.Target, string) {
	t.Helper()
	obj := os.Getenv("BPF_NINJA_HOOK_TEST_OBJECT")
	dir := os.Getenv("BPF_NINJA_HOOK_TEST_DIR")
	testutil.SkipIfNotRoot(t)
	if obj == "" {
		source, err := os.ReadFile("testdata/hookpoints.c")
		if err != nil {
			t.Fatal(err)
		}
		obj = testutil.CompileBPFSource(t, string(source))
	}
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	elf, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(elf)
	result, err := inject.TransformLookup(elf, inject.LookupRequest{ELFSHA256: fmt.Sprintf("%x", sum), ProgramName: "hook_root", Auto: true, HookName: "hook", Stack: inject.StackAudit{LowestOffset: -8}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hooks) != 3 || len(result.Skipped) != 0 {
		t.Fatalf("hooks=%+v skipped=%+v", result.Hooks, result.Skipped)
	}
	coll, err := ebpf.NewCollection(result.Spec)
	if err != nil {
		t.Fatalf("load injected fixture: %+v", err)
	}
	t.Cleanup(coll.Close)
	prog := coll.Programs["hook_root"]
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("missing program id")
	}
	root, err := attach.FindBPFProgramByID(uint32(id))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Program.Close() })
	names := make([]string, len(result.Hooks))
	for i, h := range result.Hooks {
		names[i] = h.Name
	}
	targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{root}, names, false)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := json.MarshalIndent(result.Hooks, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "injection-hooks.json"), plan, 0644); err != nil {
		t.Fatal(err)
	}
	return coll, targets, dir
}

type hookRecord struct {
	Interface uint32
	PacketID  uint64
	Marker    byte
	Mutated   byte
}

func checkHookPcap(t *testing.T, path string, names []string, wantMarkers []byte) []hookRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := pcapgo.NewNgReader(bytes.NewReader(b), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	packets := 0
	for {
		_, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packets++
	}
	if r.NInterfaces() != len(names) {
		t.Fatalf("interfaces=%d want %d", r.NInterfaces(), len(names))
	}
	for i, name := range names {
		intf, err := r.Interface(i)
		if err != nil {
			t.Fatal(err)
		}
		if intf.Name != name || intf.Description != fmt.Sprintf("bpf-ninja capture site_id=%d", i+1) {
			t.Fatalf("interface %d: %+v", i, intf)
		}
	}
	var records []hookRecord
	for off := 0; off < len(b); {
		if off+12 > len(b) {
			t.Fatal("short block")
		}
		size := int(binary.LittleEndian.Uint32(b[off+4:]))
		if size < 12 || off+size > len(b) || binary.LittleEndian.Uint32(b[off+size-4:]) != uint32(size) {
			t.Fatal("bad block framing")
		}
		if binary.LittleEndian.Uint32(b[off:]) == 6 {
			caplen := int(binary.LittleEndian.Uint32(b[off+20:]))
			opt := off + 28 + (caplen+3)&^3
			if caplen < 2 || opt+20 != off+size || binary.LittleEndian.Uint16(b[opt:]) != 5 || binary.LittleEndian.Uint16(b[opt+2:]) != 8 {
				t.Fatal("missing epb_packetid")
			}
			rec := hookRecord{Interface: binary.LittleEndian.Uint32(b[off+8:]), PacketID: binary.LittleEndian.Uint64(b[opt+4:]), Marker: b[off+28], Mutated: b[off+29]}
			if rec.PacketID == 0 {
				t.Fatal("zero packet id")
			}
			records = append(records, rec)
		}
		off += size
	}
	if packets != len(records) {
		t.Fatal("packet count disagrees")
	}
	if err := checkHookRecords(records, wantMarkers); err != nil {
		t.Fatal(err)
	}
	parsed, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".json", parsed, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("pcap=%s interfaces=%v records=%d groups=%d", path, names, len(records), len(wantMarkers))
	return records
}

// The fixture skips hook_c only for marker 1. Markers repeat across runs,
// so check their multiplicities as well as each packet ID's hook sequence.
func checkHookRecords(records []hookRecord, wantMarkers []byte) error {
	groups := map[uint64][]hookRecord{}
	for _, rec := range records {
		groups[rec.PacketID] = append(groups[rec.PacketID], rec)
	}
	if len(groups) != len(wantMarkers) {
		return fmt.Errorf("groups=%d want %d; records=%+v", len(groups), len(wantMarkers), records)
	}
	counts := map[byte]int{}
	for _, g := range groups {
		marker := g[0].Marker
		counts[marker]++
		wantHooks := 3
		if marker == 1 {
			wantHooks = 2
		}
		if len(g) != wantHooks {
			return fmt.Errorf("marker %d: hooks=%d want %d; records=%+v", marker, len(g), wantHooks, g)
		}
		for i, rec := range g {
			if rec.Marker != marker {
				return fmt.Errorf("packet id %d mixes markers: %+v", rec.PacketID, g)
			}
			if rec.Interface != uint32(i) || (i > 0 && rec.Mutated != 42) || (i == 0 && rec.Mutated != 0) {
				return fmt.Errorf("route/mutation mismatch: %+v", g)
			}
		}
	}
	for _, marker := range wantMarkers {
		counts[marker]--
	}
	for marker, count := range counts {
		if count != 0 {
			return fmt.Errorf("marker %d group count mismatch %d", marker, count)
		}
	}
	return nil
}

func TestBpfHookPcapng(t *testing.T) {
	coll, targets, dir := hookFixture(t)
	old := RingbufSize
	RingbufSize = 1 << 20
	t.Cleanup(func() { RingbufSize = old })
	p, err := LoadHookPoints(targets, "", nil, true, nil)
	if err != nil {
		t.Fatalf("load hook capture: %+v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.FuncName
	}
	cfg := output.Config{Hooks: names}
	base := filepath.Join(dir, "api.pcapng")
	readers := make([]*fastrb.Reader, len(p.InnerMaps))
	writers := make([]*output.Writer, len(p.InnerMaps))
	for cpu, m := range p.InnerMaps {
		rd, err := fastrb.New(m.FD(), int(m.MaxEntries()))
		if err != nil {
			t.Fatal(err)
		}
		readers[cpu] = rd
		t.Cleanup(func() { _ = rd.Close() })
		w, err := output.NewWriter(fmt.Sprintf("%s.cpu%d", base, cpu), cfg)
		if err != nil {
			t.Fatal(err)
		}
		writers[cpu] = w
		t.Cleanup(func() { _ = w.Close() })
	}
	drain := func() int {
		n := 0
		for cpu, rd := range readers {
			rd.ReadBatch(func(raw []byte) {
				pkt, err := capture.ParseRawSample(raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := writers[cpu].Write(pkt); err != nil {
					t.Fatal(err)
				}
				n++
			})
		}
		return n
	}
	cpus := affinityCPUs(t)
	if len(cpus) < 2 {
		t.Fatal("test needs two CPUs")
	}
	for _, cpu := range cpus[:2] {
		unpin, err := pinThread(cpu)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []byte{0, 0, 1, 2} {
			frame := make([]byte, 64)
			frame[0] = marker
			ret, _, err := coll.Programs["hook_root"].Test(frame)
			want := uint32(2)
			if marker == 2 {
				want = 4
			}
			if err != nil || ret != want {
				t.Fatalf("TEST_RUN marker=%d ret=%d err=%v", marker, ret, err)
			}
		}
		if err := unpin(); err != nil {
			t.Fatal(err)
		}
	}
	if n := drain(); n != 22 {
		t.Fatalf("records=%d want22", n)
	}
	if err := p.Quiesce(); err != nil {
		t.Fatal(err)
	}
	for _, w := range writers {
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := output.MergeShardFiles(base, len(writers), cfg); err != nil {
		t.Fatal(err)
	}
	records := checkHookPcap(t, base, names, []byte{0, 0, 1, 2, 0, 0, 1, 2})
	seenCPUs := map[uint64]bool{}
	for _, r := range records {
		seenCPUs[r.PacketID>>48] = true
	}
	if len(seenCPUs) != 2 {
		t.Fatalf("id CPUs=%v", seenCPUs)
	}
}

func TestBpfHookPcapngCLI(t *testing.T) {
	coll, targets, dir := hookFixture(t)
	binaryPath := os.Getenv("BPF_NINJA_HOOK_TEST_BINARY")
	if binaryPath == "" {
		binaryPath = filepath.Join(dir, "bpf-ninja")
		build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/bpf-ninja")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build CLI: %v\n%s", err, out)
		}
	}
	info, err := coll.Programs["hook_root"].Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	path := filepath.Join(dir, "cli.pcapng")
	args := []string{"-p", strconv.Itoa(int(id)), "--hook-pcapng", "--ringbuf-size", "1", "--fast-reader", "--no-cpu-affinity", "-w", path}
	names := make([]string, len(targets))
	for i, target := range targets {
		args = append(args, "--func", target.FuncName)
		names[i] = target.FuncName
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "cli.stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	ready := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			line := s.Text()
			if _, err := fmt.Fprintln(log, line); err != nil {
				t.Error(err)
			}
			if strings.Contains(line, "capturing (") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
	}()
	select {
	case <-ready:
	case <-done:
		t.Fatal("CLI exited before ready; see cli.stderr.log")
	case <-ctx.Done():
		t.Fatal("CLI readiness timeout")
	}
	for _, marker := range []byte{0, 0, 1, 2} {
		frame := make([]byte, 64)
		frame[0] = marker
		if _, _, err := coll.Programs["hook_root"].Test(frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	<-done
	if err := cmd.Wait(); err != nil {
		t.Fatalf("CLI exit: %v; see cli.stderr.log", err)
	}
	checkHookPcap(t, path, names, []byte{0, 0, 1, 2})
}

func TestBpfHookPcapngRejects(t *testing.T) {
	coll, targets, _ := hookFixture(t)
	cases := [][]attach.Target{{targets[0], targets[0]}}
	root := targets[0]
	root.FuncName = "hook_root"
	cases = append(cases, []attach.Target{root})
	other, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "other", Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	different := targets[0]
	different.Program = other
	cases = append(cases, []attach.Target{targets[0], different})
	for _, targets := range cases {
		p, err := LoadHookPoints(targets, "", nil, true, nil)
		if p != nil {
			_ = p.Close()
		}
		if err == nil {
			t.Fatalf("accepted unsupported targets %+v", targets)
		}
		t.Logf("refused: %v", err)
	}
	// No attach is attempted on a tail-calling program (including kernel 7.0).
	array, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = array.Close() }()
	tail, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "tail_root", Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{
		asm.LoadMapPtr(asm.R2, array.FD()), asm.Mov.Imm(asm.R3, 0), asm.FnTailCall.Call(), asm.Mov.Imm(asm.R0, 2), asm.Return(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tail.Close() }()
	p, err := LoadHookPoints([]attach.Target{{Program: tail, Type: ebpf.XDP, FuncName: "unused"}}, "", nil, true, nil)
	if p != nil {
		_ = p.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "tail calls") {
		t.Fatalf("tail-call refusal: %v", err)
	}
	t.Logf("refused before attach: %v; fixture root=%s", err, coll.Programs["hook_root"])
}

// Exercise both direct and fault-handled context reads in the same run.
func TestBpfHookPcapngStaticPointer(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	obj := os.Getenv("BPF_NINJA_MEMBER_OBJECT")
	if obj == "" {
		obj = testutil.CompileBPFSource(t, argMemberSource)
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	prog := coll.Programs["member_target"]
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	root, err := attach.FindBPFProgramByID(uint32(id))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Program.Close() }()
	names := []string{"scalar_capture", "scalar_hook"}
	targets, _, err := attach.ResolveTargets([]*attach.ProgInfo{root}, names, false)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := staticXDPNeedsProbeRead(prog, "scalar_hook", ebpf.AttachTraceFEntry, root.FuncAvailability("scalar_hook"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("static scalar_hook probe_read=%v", fallback)
	if !fallback {
		t.Skip("kernel preserves the static prototype; probe-read fallback is not exercised")
	}
	for _, match := range []bool{true, false} {
		t.Run(fmt.Sprintf("match=%v", match), func(t *testing.T) {
			expr := "value[0]=64"
			if !match {
				expr = "value[0]=65"
			}
			filters := make([]filter.TargetFilters, len(targets))
			for i, target := range targets {
				args, err := filter.ParseAndValidateFilters([]string{expr}, target.Params)
				if err != nil {
					t.Fatal(err)
				}
				filters[i].Args = args
			}
			p, err := LoadHookPoints(targets, "", filters, true, nil)
			if err != nil {
				t.Fatalf("load hook capture: %+v", err)
			}
			defer func() { _ = p.Close() }()
			unpin, err := pinThread(affinityCPUs(t)[0])
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := unpin(); err != nil {
					t.Error(err)
				}
			}()
			// The middle run has null pointer arguments. Identical matching inputs
			// on either side must still receive different run ids.
			for _, marker := range []byte{0, 1, 0} {
				frame := make([]byte, 64)
				frame[0] = marker
				ret, out, err := prog.Test(frame)
				if err != nil || ret != 2 || !bytes.Equal(out, frame) {
					t.Fatalf("TEST_RUN marker=%d ret=%d out=%x err=%v", marker, ret, out, err)
				}
			}
			if err := p.Quiesce(); err != nil {
				t.Fatal(err)
			}
			groups := map[uint64][]uint8{}
			for _, m := range p.InnerMaps {
				rd, err := fastrb.New(m.FD(), int(m.MaxEntries()))
				if err != nil {
					t.Fatal(err)
				}
				rd.ReadBatch(func(raw []byte) {
					pkt, err := capture.ParseRawSample(raw)
					if err != nil {
						t.Fatal(err)
					}
					if pkt.PacketID == 0 || len(pkt.Data) != 64 || pkt.Data[0] != 0 {
						t.Fatalf("invalid correlated packet: %+v", pkt)
					}
					groups[pkt.PacketID] = append(groups[pkt.PacketID], pkt.SiteID)
				})
				if err := rd.Close(); err != nil {
					t.Fatal(err)
				}
			}
			want := 0
			if match {
				want = 2
			}
			if len(groups) != want {
				t.Fatalf("groups=%v want %d", groups, want)
			}
			for id, sites := range groups {
				if len(sites) != 2 || sites[0] != 1 || sites[1] != 2 {
					t.Fatalf("run %d: sites=%v want [1 2]", id, sites)
				}
			}
			stats, err := p.ExportStats()
			if err != nil || stats.ReserveFail != 0 || stats.CopyFail != 0 || stats.LookupMiss != 0 {
				t.Fatalf("export stats=%+v err=%v", stats, err)
			}
			t.Logf("match=%v groups=%v", match, groups)
		})
	}
}

// LoadHookPoints correlates entry observations of subfunctions in one XDP
// or tc (SchedCLS) program. The root entry allocates an id even if no hook matches a filter.
// IDs identify runs in this capture session, never packet contents or addresses.
func LoadHookPoints(targets []attach.Target, expr string, filters []filter.TargetFilters, useDSL bool, sets []*setmap.Set) (*Probe, error) {
	return LoadHookCapture(targets, expr, filters, useDSL, sets, HookCaptureOptions{EntryStart: expr != ""})
}
