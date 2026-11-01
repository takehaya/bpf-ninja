package program

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/hook"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/inject"
)

var tcTestHook, _ = hook.ByName(hook.KindTC)

// loadStaticTCTarget loads tc_target, which calls static_hook(ctx, &value).
// The int * argument makes the static prototype unreliable on every matrix
// kernel; static_hook returns TC_ACT_SHOT while the target returns 0.
func loadStaticTCTarget(t *testing.T) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)
	integer := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	ctx := &btf.Pointer{Target: &btf.Struct{Name: "__sk_buff", Size: 192}}
	entry := &btf.Func{Name: "tc_target", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{{Name: "ctx", Type: ctx}}}}
	fn := &btf.Func{Name: "static_hook", Linkage: btf.StaticFunc, Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{
		{Name: "ctx", Type: ctx}, {Name: "value", Type: &btf.Pointer{Target: integer}},
	}}}
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -8, 7, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.Call.Label(fn.Name),
		asm.Mov.Imm(asm.R0, 0), asm.Return(),
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 2).WithSymbol(fn.Name), fn), asm.Return(),
	}
	insns[0] = btf.WithFuncMetadata(insns[0].WithSymbol(entry.Name), entry)
	target, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "tc_static_test", Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
	if err != nil {
		t.Fatalf("target load: %+v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	return target
}

// runCapture runs target once on input and returns the records by mode.
func runCapture(t *testing.T, probe *Probe, target *ebpf.Program, input []byte) [2][]capture.Packet {
	t.Helper()
	ret, output, err := target.Test(input)
	if err != nil || ret != 0 || !bytes.Equal(output, input) {
		t.Fatalf("target ret=%d err=%v output=%x", ret, err, output)
	}
	if err := probe.Quiesce(); err != nil {
		t.Fatal(err)
	}
	var got [2][]capture.Packet
	for _, m := range probe.InnerMaps {
		rd, err := fastrb.New(m.FD(), int(m.MaxEntries()))
		if err != nil {
			t.Fatal(err)
		}
		rd.ReadBatch(func(rec []byte) {
			pkt, err := capture.ParseRawSample(rec)
			if err != nil || pkt.Mode > 1 {
				t.Errorf("record %x: %v", rec, err)
				return
			}
			pkt.Data = bytes.Clone(pkt.Data) // the ring is unmapped on Close
			got[pkt.Mode] = append(got[pkt.Mode], pkt)
		})
		_ = rd.Close()
	}
	return got
}

func TestBpfStaticTCCapture(t *testing.T) {
	target := loadStaticTCTarget(t)
	if fallback, err := staticNeedsProbeRead(tcTestHook, target, "static_hook", ebpf.AttachTraceFEntry, attach.FuncAvailability{}); err != nil || !fallback {
		t.Fatalf("fixture must reject direct sk_buff reads: probe_read=%v err=%v", fallback, err)
	}
	input := untaggedIPv4TCP()
	for _, mode := range []string{"entry", "exit", "gated"} {
		exprs := []string{"eth", "eth where action == TC_ACT_SHOT", "eth where action == TC_ACT_OK"}
		if mode == "entry" {
			exprs = exprs[:1]
		}
		for _, expr := range exprs {
			t.Run(mode+"/"+expr, func(t *testing.T) {
				stages := []Stage{{Expr: expr, IsFexit: mode == "exit"}}
				if mode == "gated" {
					stages = []Stage{{Expr: "eth"}, {Expr: expr, IsFexit: true}}
				}
				probe, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: "static_hook", Type: ebpf.SchedCLS}}, stages, nil, true, nil, EmitBoth)
				if err != nil {
					t.Fatalf("capture load: %+v", err)
				}
				defer func() { _ = probe.Close() }()
				got := runCapture(t, probe, target, input)
				want := [2]int{1, 0}
				switch mode {
				case "exit":
					want = [2]int{0, 1}
				case "gated":
					want = [2]int{1, 1}
				}
				if strings.HasSuffix(expr, "TC_ACT_OK") {
					want = [2]int{}
				}
				for m, pkts := range got {
					for _, pkt := range pkts {
						if !bytes.Equal(pkt.Data, input) || m == 1 && pkt.Action != 2 {
							t.Errorf("mode %d: action=%d data=%x, want TC_ACT_SHOT and %x", m, pkt.Action, pkt.Data, input)
						}
					}
				}
				t.Logf("entry/exit records %d/%d of %d input bytes", len(got[0]), len(got[1]), len(input))
				if [2]int{len(got[0]), len(got[1])} != want {
					t.Fatalf("entry/exit records=%d/%d, want %v", len(got[0]), len(got[1]), want)
				}
			})
		}
	}
	old := TCVlanReinsert
	TCVlanReinsert = true
	defer func() { TCVlanReinsert = old }()
	for _, expr := range []string{"", "eth/vlan[tci==100]/ipv4/tcp"} {
		t.Run("vlan-reinsert/"+expr, func(t *testing.T) {
			probe, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: "static_hook", Type: ebpf.SchedCLS}}, []Stage{{Expr: expr}}, nil, true, nil, EmitBoth)
			if probe != nil {
				_ = probe.Close()
			}
			refused := err != nil && strings.Contains(err.Error(), `--tc-vlan-reinsert is not supported at static tc function "static_hook"`)
			if refused != (expr != "") || expr == "" && err != nil {
				t.Fatalf("expr %q: %v", expr, err)
			}
		})
	}
}

func TestBpfStaticTCGatedContextReadFailure(t *testing.T) {
	target := loadStaticTCTarget(t)
	for read := range 3 {
		t.Run(fmt.Sprint("read", read), func(t *testing.T) {
			safe := staticTCHook(tcTestHook, "static_hook")
			testGatedContextReadFailure(t, target, "static_hook", safe, safe, read)
		})
	}
}

const staticTCCtxOnlySource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
__attribute__((noinline))
static int classify(struct __sk_buff *skb) {
    asm volatile("" : : "r"(skb));
    return skb->len > 20 ? 2 : 0;
}
SEC("tc")
int tc_ctx_only(struct __sk_buff *skb) {
    return classify(skb) == 2 ? 0 : 2;
}
char _license[] SEC("license") = "GPL";
`

// Without KEEP, clang drops the unused ctx and passes a stack pointer in R1,
// while BTF still lists classify(skb, value).
const staticDeadCtxSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
volatile int g = 3;
__attribute__((noinline))
static int classify(CTX *ctx, int *value) {
    KEEP
    return *value == 7 ? 2 : 0;
}
SEC(SECTION)
int dead_ctx(CTX *ctx) {
    int v = g;
    return classify(ctx, &v) == 2 ? 0 : 2;
}
char _license[] SEC("license") = "GPL";
`

func TestBpfStaticContextArgument(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	load := func(t *testing.T, source, prog string) *ebpf.Program {
		spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, source))
		if err != nil {
			t.Fatal(err)
		}
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(coll.Close)
		return coll.Programs[prog]
	}
	t.Run("tc ctx only keeps direct reads", func(t *testing.T) {
		target := load(t, staticTCCtxOnlySource, "tc_ctx_only")
		for _, exit := range []bool{false, true} {
			_, at := tracingLabel(exit)
			if fallback, err := staticNeedsProbeRead(tcTestHook, target, "classify", at, attach.FuncAvailability{}); err != nil || fallback {
				t.Fatalf("exit=%v: probe_read=%v err=%v", exit, fallback, err)
			}
		}
		dataOff, _, _, err := hook.SkBuffPacketOffsets()
		if err != nil {
			t.Fatal(err)
		}
		old := TCVlanReinsert
		TCVlanReinsert = true
		defer func() { TCVlanReinsert = old }()
		vlan := "eth/vlan[tci==100]/ipv4/tcp"
		for _, stages := range [][]Stage{{{Expr: vlan}}, {{Expr: vlan, IsFexit: true}}, {{Expr: vlan}, {Expr: vlan, IsFexit: true}}} {
			p, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: "classify", Type: ebpf.SchedCLS}}, stages, nil, true, nil, EmitBoth)
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
					found = found || in.OpCode == asm.LoadMemOp(asm.DWord) && in.Dst == asm.R7 && in.Src == asm.R6 && in.Offset == int16(dataOff)
				}
				if !found {
					t.Fatal("capture replaced the direct sk_buff load with probe_read")
				}
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
		}
	})
	for _, tc := range []struct {
		name, ctx, section string
		typ                ebpf.ProgramType
	}{{"tc", "struct __sk_buff", "tc", ebpf.SchedCLS}, {"xdp", "struct xdp_md", "xdp", ebpf.XDP}} {
		for _, live := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s live ctx=%v", tc.name, live), func(t *testing.T) {
				keep := map[bool]string{true: `asm volatile("" : : "r"(ctx));`}[live]
				source := strings.NewReplacer("CTX", tc.ctx, "SECTION", `"`+tc.section+`"`, "KEEP", keep).Replace(staticDeadCtxSource)
				target := load(t, source, "dead_ctx")
				h, _ := hook.ByProgramType(tc.typ)
				if fallback, err := staticNeedsProbeRead(h, target, "classify", ebpf.AttachTraceFEntry, attach.FuncAvailability{}); err != nil || !fallback {
					t.Fatalf("probe_read=%v err=%v", fallback, err)
				}
				p, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: "classify", Type: tc.typ}}, []Stage{{Expr: "eth"}}, nil, true, nil, EmitBoth)
				if p != nil {
					_ = p.Close()
				}
				refused := err != nil && strings.Contains(err.Error(), "cannot show that every call passes the program context")
				if refused == live || live && err != nil {
					t.Fatalf("load: %v", err)
				}
				t.Log(err)
			})
		}
	}
}

// A static hook generated by the lookup transform gets its ctx from the
// entry's spill slot; the context check must follow that reload.
func TestBpfStaticTCInjectedHook(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	elf, err := os.ReadFile(testutil.CompileBPFSource(t, `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hits SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} cfg SEC(".maps");
SEC("tc")
int p(struct __sk_buff *skb) {
    __u32 k = 0;
    __u64 *n = bpf_map_lookup_elem(&hits, &k);
    if (n) __sync_fetch_and_add(n, 1);
    __u32 *v = bpf_map_lookup_elem(&cfg, &k);
    return v && *v ? 2 : 0;
}
char _license[] SEC("license") = "GPL";
`))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(elf)
	res, err := inject.TransformLookup(elf, inject.LookupRequest{ELFSHA256: hex.EncodeToString(sum[:]), ProgramName: "p", Auto: true,
		Entry: true, StaticUntrusted: true, HookName: "obs", Stack: inject.StackAudit{LowestOffset: -16}})
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, h := range res.Hooks {
		if h.Static {
			name = h.Name
		}
	}
	if name == "" {
		t.Fatalf("no static hook in %+v", res.Hooks)
	}
	coll, err := ebpf.NewCollection(res.Spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	target := coll.Programs["p"]
	fallback, err := staticNeedsProbeRead(tcTestHook, target, name, ebpf.AttachTraceFEntry, attach.FuncAvailability{})
	if err != nil || !fallback {
		t.Fatalf("%s must take the probe-read path: probe_read=%v err=%v", name, fallback, err)
	}
	if err := checkStaticCtxArg(target, name); err != nil {
		t.Fatal(err)
	}
	probe, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: name, Type: ebpf.SchedCLS}}, []Stage{{Expr: "eth"}}, nil, true, nil, EmitBoth)
	if err != nil {
		t.Fatalf("capture at %s (probe_read=%v): %+v", name, fallback, err)
	}
	defer func() { _ = probe.Close() }()
	input := untaggedIPv4TCP()
	got := runCapture(t, probe, target, input)
	t.Logf("%s probe_read=%v records=%d", name, fallback, len(got[0]))
	if len(got[0]) != 1 || !bytes.Equal(got[0][0].Data, input) {
		t.Fatalf("records %+v", got)
	}
}
