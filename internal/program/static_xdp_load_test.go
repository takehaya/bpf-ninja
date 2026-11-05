package program

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/codegen"
)

var xdpTestHook, _ = hook.ByName(hook.KindXDP)

func TestBpfStaticXDPContextSelection(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	for _, tc := range []struct{ name, source, entry, fn string }{
		{"ctx_only", strings.Replace(testutil.XDPSubfuncSource, "int process_packet", "static int process_packet", 1), "xdp_subfunc_test", "process_packet"},
		{"pointer_args", argMemberSource, "member_target", "scalar_hook"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, tc.source))
			if err != nil {
				t.Fatal(err)
			}
			coll, err := ebpf.NewCollection(spec)
			if err != nil {
				t.Fatal(err)
			}
			defer coll.Close()
			target := coll.Programs[tc.entry]
			for _, exit := range []bool{false, true} {
				_, at := tracingLabel(exit)
				fallback, err := staticNeedsProbeRead(xdpTestHook, target, tc.fn, at, attach.FuncAvailability{})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s exit=%v probe_read=%v", tc.fn, exit, fallback)
				if tc.name == "ctx_only" {
					if fallback {
						t.Fatal("ctx-only static helper lost direct loads")
					}
				}
			}
			if tc.name == "ctx_only" {
				assertOriginMainStaticXDPCodegen(t, target, tc.fn)
				for _, stages := range [][]Stage{{{}}, {{IsFexit: true}}, {{}, {IsFexit: true}}} {
					p, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: tc.fn, Type: ebpf.XDP}}, stages, nil, true, nil, EmitBoth)
					if err != nil {
						t.Fatal(err)
					}
					for _, prog := range p.progs {
						info, err := prog.Info()
						if err != nil {
							t.Fatal(err)
						}
						insns, err := info.Instructions()
						if err != nil {
							t.Fatal(err)
						}
						found := false
						for _, in := range insns {
							if in.OpCode == asm.LoadMemOp(asm.DWord) && in.Dst == asm.R7 && in.Src == asm.R6 && in.Offset == 0 {
								found = true
							}
						}
						if !found {
							t.Fatal("capture replaced direct ctx load with probe_read")
						}
					}
					if err := p.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := staticNeedsProbeRead(xdpTestHook, target, "missing_function", ebpf.AttachTraceFEntry, attach.FuncAvailability{}); err == nil {
				t.Fatal("unrelated load failure must propagate")
			}
		})
	}
}

func assertOriginMainStaticXDPCodegen(t *testing.T, target *ebpf.Program, fn string) {
	t.Helper()
	// Full instruction-stream hashes generated from origin/main (060811d),
	// with map FDs 10..13, an integer filter and a packet DSL filter. This
	// includes gated exit, whose direct-load instruction order must not move.
	// Regenerated from b2dba63 plus the orig_len change, which adds moves
	// and stores around the direct loads and moves none of them, and again
	// for emitWakeFlag, which adds instructions after each shard lookup.
	for _, tc := range []struct{ mode, hash string }{
		{"entry", "56190adc6c672acc8bdfaaba402964a25e171963356aa6af7b0a676db2a4f348"},
		{"exit", "0917d6da0fd966c2175fcf0c4cb9266a0753c5c96db8610f5ea4eda10aed90b4"},
		{"gated", "45fba07fe07e1f079a14b0783e65523ee090b831eaf28eb44bf25507f02863f5"},
	} {
		_, at := tracingLabel(tc.mode != "entry")
		fallback, err := staticNeedsProbeRead(xdpTestHook, target, fn, at, attach.FuncAvailability{})
		if err != nil {
			t.Fatal(err)
		}
		h, _ := hook.ByName(hook.KindXDP)
		if fallback {
			h = staticXDPHook(h, tc.mode != "entry")
		}
		out, err := compileFilter("eth", true, tc.mode != "entry", ebpf.XDP)
		if err != nil {
			t.Fatal(err)
		}
		tf := filter.TargetFilters{Args: []filter.ArgFilter{{ParamIndex: 1, ParamSize: 4, Op: filter.OpEqual, Value: 7}}}
		insns, err := buildTracingInsnsForHook(h, out, tf, 10, 11, 12, tc.mode != "entry", 16, nil, nil, 0)
		if tc.mode == "gated" {
			insns, err = buildGatedExitInsns(h, out, tf, 10, 13, 12, 11, nil, nil, EmitBoth, 64, 16, 0, fallback)
		}
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := insns.Marshal(&b, binary.LittleEndian); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b.Bytes())); got != tc.hash {
			t.Fatalf("%s codegen differs from origin/main: got %s want %s", tc.mode, got, tc.hash)
		}
	}
}

func TestBpfStaticXDPGatedContextReadFailure(t *testing.T) {
	h, _ := hook.ByName(hook.KindXDP)
	testGatedContextReadFailure(t, loadDummyXDP(t), xdpFuncName, h, staticXDPHook(h, true), 0)
}

// testGatedContextReadFailure forces the read-th fault-handled ctx read of
// safe's prologue to fail at a gated exit and checks that no hold leaks.
func testGatedContextReadFailure(t *testing.T, target *ebpf.Program, fn string, entryHook, safe *hook.Hook, read int) {
	t.Helper()
	if err := gatedContextReadLeak(t, target, fn, entryHook, safe, read, true); err != nil {
		t.Fatal(err)
	}
}

// gatedContextReadLeak is testGatedContextReadFailure returning the leak it
// finds. deferPrologue=false runs the prologue before the hold is returned,
// the order that leaks, so a test can show the check fails.
func gatedContextReadLeak(t *testing.T, target *ebpf.Program, fn string, entryHook, safe *hook.Hook, read int, deferPrologue bool) error {
	t.Helper()
	hold, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: holdHdr + 64, MaxEntries: uint32(holdSlots)})
	if err != nil {
		t.Fatal(err)
	}
	p := &Probe{maps: []*ebpf.Map{hold}, holdMap: hold}
	defer func() { _ = p.Close() }()
	var out codegen.Output
	out.Capture.MaxCapLen = 64
	insns, err := buildGatedExitInsns(safe, out, filter.TargetFilters{}, 0, hold.FD(), 0, 0, nil, nil, EmitBoth, 64, 8, 0, deferPrologue)
	if err != nil {
		t.Fatal(err)
	}
	// Force the prologue's ctx read to fault, after an entry wrote a hold.
	injected := false
	for i, in := range insns {
		if in == asm.FnProbeReadKernel.Call() && read > 0 {
			read--
		} else if in == asm.FnProbeReadKernel.Call() {
			insns = append(insns[:i], append(asm.Instructions{asm.Mov.Imm(asm.R3, 0)}, insns[i:]...)...)
			// No output maps are needed: all paths after this read must exit.
			insns = append(insns[:i+3], asm.Ja.Label("exit"))
			// The identity read comes after a jump to hold_unpaired; send
			// every label the cut removed to exit as well.
			defined := map[string]bool{}
			for _, in := range insns {
				defined[in.Symbol()] = true
			}
			for _, in := range insns {
				if ref := in.Reference(); ref != "" && ref != "exit" && !defined[ref] {
					insns = append(insns, asm.Ja.Label("exit").WithSymbol(ref))
					defined[ref] = true
				}
			}
			insns = finishProgram(insns, out, 0)
			injected = true
			break
		}
	}
	if !injected {
		t.Fatal("missing ctx read")
	}
	if err := attachTracingProbe(p, target, "ctx_fail_exit", fn, ebpf.AttachTraceFExit, insns, false, attach.FuncAvailability{}); err != nil {
		t.Fatal(err)
	}
	entry, err := buildGatedEntryInsns(entryHook, out, filter.TargetFilters{}, hold.FD(), 0, 0, 0, nil, nil, EmitBoth, 64, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachTracingProbe(p, target, "ctx_fail_entry", fn, ebpf.AttachTraceFEntry, entry, false, attach.FuncAvailability{}); err != nil {
		t.Fatal(err)
	}
	for range maxHoldSlots + 1 {
		if _, err := target.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Quiesce(); err != nil {
		t.Fatal(err)
	}
	var values [][]byte
	if err := hold.Lookup(uint32(0), &values); err != nil {
		t.Fatal(err)
	}
	for cpu, value := range values {
		if depth := binary.NativeEndian.Uint32(value[holdDepth:]); depth != 0 {
			return fmt.Errorf("CPU %d leaked depth=%d", cpu, depth)
		}
		if valid := binary.NativeEndian.Uint16(value[holdValid:]); valid != 0 {
			return fmt.Errorf("CPU %d retained hold=%d", cpu, valid)
		}
	}
	return nil
}
