package program

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/setmap"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

const argMemberSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct classifier_target { __s32 pdr_id; __u16 port; __s8 small; };
struct classifier_query { __u64 seid; __u64 imsi; struct classifier_target target; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct classifier_query);
} queries SEC(".maps");

__attribute__((noinline))
int sdf_classify(struct xdp_md *ctx, struct classifier_query *q, __u32 n) {
    asm volatile("" : : "r"(ctx), "r"(q), "r"(n));
    return 0;
}
__attribute__((noinline))
int scalar_capture(struct xdp_md *ctx, const __u32 *value, __u32 n) {
    asm volatile("" : : "r"(ctx), "r"(value), "r"(n));
    return 0;
}
union scalar_choice { __u64 number; };
__attribute__((noinline))
static int scalar_hook(struct xdp_md *ctx, const __u32 *value, const void *opaque, union scalar_choice *choice, __u64 n) {
    asm volatile("" : : "r"(ctx), "r"(value), "r"(opaque), "r"(choice), "r"(n));
    return 0;
}
SEC("xdp")
int member_target(struct xdp_md *ctx) {
    __u32 key = 0;
    struct classifier_query *q = bpf_map_lookup_elem(&queries, &key);
    if (!q) return XDP_ABORTED;
    q->seid = 5;
    q->imsi = 262010000000001ULL;
    q->target.pdr_id = -3;
    q->target.port = 65530;
    q->target.small = -7;
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    if (data + 1 > end) return XDP_ABORTED;
    if (*(__u8 *)data) q = 0;
    __u32 value = 64;
    union scalar_choice choice = { .number = 64 };
    scalar_capture(ctx, q ? &value : 0, 64);
    scalar_hook(ctx, q ? &value : 0, q, q ? &choice : 0, 0x0102030405060708ULL + *(__u8 *)data);
    sdf_classify(ctx, q, 7);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
`

// This test only uses test-run; it never attaches to an interface or pins a map.
func TestBpfArgMember(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, argMemberSource))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	target := coll.Programs["member_target"]
	params, err := attach.GetFuncParams(target, "sdf_classify")
	if err != nil {
		t.Fatal(err)
	}
	echo, err := attach.ResolveEchoArgs([]string{"q->imsi", "n", "q->target.pdr_id", "q->target.port", "q->target.small"}, params)
	if err != nil {
		t.Fatal(err)
	}
	for _, exit := range []bool{false, true} {
		t.Run(fmt.Sprintf("exit=%v/plain_echo", exit), func(t *testing.T) {
			plain, err := attach.ResolveEchoArgs(nil, params)
			if err != nil {
				t.Fatal(err)
			}
			probe, err := LoadArgEcho(target, "sdf_classify", nil, plain, exit, false, attach.FuncAvailability{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = probe.Close() }()
			rd, err := fastrb.New(probe.EchoRing.FD(), EchoRingSize)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = rd.Close() }()
			if _, err := target.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
				t.Fatal(err)
			}
			count := 0
			rd.ReadBatch(func(rec []byte) {
				count++
				if len(rec) != 8 || binary.NativeEndian.Uint64(rec) != 7 {
					t.Fatalf("plain echo: %x", rec)
				}
			})
			if count != 1 {
				t.Fatalf("plain echo records=%d", count)
			}
		})
		for _, tt := range []struct {
			name       string
			exprs      []string
			null, want bool
		}{
			{"equal", []string{"q->imsi=262010000000001"}, false, true},
			{"equal_alias", []string{"q->imsi==262010000000001"}, false, true},
			{"not_equal", []string{"q->imsi!=262010000000002", "n!=8"}, false, true},
			{"not_equal_miss", []string{"q->imsi!=262010000000001"}, false, false},
			{"be16", []string{"q->target.port==be16(64255)"}, false, true},
			{"be32", []string{"n==be32(0x07000000)"}, false, true},
			{"nonnull", []string{"q!=null"}, false, true},
			{"null_miss", []string{"q==null"}, false, false},
			{"null_not_equal_member", []string{"q->imsi!=0"}, true, false},
			{"miss", []string{"q->imsi=262010000000002"}, false, false},
			{"range", []string{"q->seid=1..9"}, false, true},
			{"range_miss", []string{"q->seid=6..9"}, false, false},
			{"mixed", []string{"n=7", "q->target.pdr_id>=-3", "q->imsi>=262010000000001", "n<=7", "q->target.small=-7", "q->target.port=65530"}, false, true},
			{"signed_miss", []string{"q->target.pdr_id<=-4"}, false, false},
			{"null_gate", []string{"q->seid=0"}, true, false},
			{"null_echo", nil, true, false},
		} {
			t.Run(fmt.Sprintf("exit=%v/%s", exit, tt.name), func(t *testing.T) {
				fs, err := filter.ParseAndValidateFilters(tt.exprs, params)
				if err != nil {
					t.Fatal(err)
				}
				probe, err := LoadArgEcho(target, "sdf_classify", fs, echo, exit, false, attach.FuncAvailability{})
				if err != nil {
					t.Fatalf("load echo: %+v", err)
				}
				defer func() { _ = probe.Close() }()
				rd, err := fastrb.New(probe.EchoRing.FD(), EchoRingSize)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rd.Close() }()
				data := make([]byte, 64)
				if tt.null {
					data[0] = 1
				}
				if _, err := target.Run(&ebpf.RunOptions{Data: data}); err != nil {
					t.Fatal(err)
				}
				count := 0
				rd.ReadBatch(func(rec []byte) {
					count++
					want := []uint64{262010000000001, 7, ^uint64(2), 65530, ^uint64(6)}
					if len(rec) != len(want)*8 {
						t.Fatalf("record size: %d", len(rec))
					}
					for i, v := range want {
						if got := binary.NativeEndian.Uint64(rec[i*8:]); got != v {
							t.Errorf("echo[%d]=%d, want %d", i, got, v)
						}
					}
				})
				want := 0
				if tt.want {
					want = 1
				}
				if count != want {
					t.Fatalf("records=%d, want %d", count, want)
				}
			})
		}
	}
	// Exercise the capture wrapper too, where R6-R9 and the saved ctx are live.
	fs, err := filter.ParseAndValidateFilters([]string{"q->imsi=262010000000001", "q->target.pdr_id=-3", "n=7"}, params)
	if err != nil {
		t.Fatal(err)
	}
	if got := countEventsTestRun(t, target, "sdf_classify", fs, 1); got != 1 {
		t.Fatalf("capture records=%d, want 1", got)
	}
}

// NULL comparisons must work without reading the pointee, including void*,
// union*, and scalar*. Echo only n here so a NULL match can emit a record.
func TestBpfArgMemberPointers(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, argMemberSource))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	target := coll.Programs["member_target"]
	for _, fn := range []string{"sdf_classify", "scalar_hook"} {
		params, err := attach.GetFuncParams(target, fn)
		if err != nil {
			t.Fatal(err)
		}
		echo, err := attach.ResolveEchoArgs([]string{"n"}, params)
		if err != nil {
			t.Fatal(err)
		}
		type pointerCase struct {
			expr       string
			null, want bool
		}
		cases := []pointerCase{}
		for _, p := range params {
			if p.Kind == "" {
				continue
			}
			for _, null := range []bool{false, true} {
				cases = append(cases, pointerCase{p.Name + "==null", null, null}, pointerCase{p.Name + "!=null", null, !null}, pointerCase{p.Name + "=null", null, null})
			}
		}
		if fn == "scalar_hook" {
			cases = append(cases,
				pointerCase{"value[0]==64", false, true}, pointerCase{"value[0]!=63", false, true},
				pointerCase{"value[0]!=64", false, false}, pointerCase{"value[0]=63..65", false, true},
				pointerCase{"value[0]>=64", false, true}, pointerCase{"value[0]<=63", false, false},
				pointerCase{"value[0]!=0", true, false}, pointerCase{"value[0]=0", true, false},
				pointerCase{"n==be64(0x0807060504030201)", false, true},
			)
		}
		for _, exit := range []bool{false, true} {
			for _, tc := range cases {
				t.Run(fmt.Sprintf("%s/exit=%v/%s/null=%v", fn, exit, tc.expr, tc.null), func(t *testing.T) {
					fs, err := filter.ParseAndValidateFilters([]string{tc.expr}, params)
					if err != nil {
						t.Fatal(err)
					}
					probe, err := LoadArgEcho(target, fn, fs, echo, exit, false, attach.FuncAvailability{})
					if err != nil {
						t.Fatalf("load: %+v", err)
					}
					defer func() { _ = probe.Close() }()
					rd, err := fastrb.New(probe.EchoRing.FD(), EchoRingSize)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = rd.Close() }()
					data := make([]byte, 64)
					if tc.null {
						data[0] = 1
					}
					if _, err := target.Run(&ebpf.RunOptions{Data: data}); err != nil {
						t.Fatal(err)
					}
					count := 0
					rd.ReadBatch(func(rec []byte) { count++ })
					want := 0
					if tc.want {
						want = 1
					}
					if count != want {
						t.Fatalf("records=%d want=%d", count, want)
					}
				})
			}
		}
		if fn == "scalar_hook" {
			t.Run("scalar_echo", func(t *testing.T) {
				selected, err := attach.ResolveEchoArgs([]string{"value[0]", "choice->number"}, params)
				if err != nil {
					t.Fatal(err)
				}
				probe, err := LoadArgEcho(target, fn, nil, selected, false, false, attach.FuncAvailability{})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = probe.Close() }()
				rd, err := fastrb.New(probe.EchoRing.FD(), EchoRingSize)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rd.Close() }()
				if _, err := target.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
					t.Fatal(err)
				}
				count := 0
				rd.ReadBatch(func(rec []byte) {
					count++
					if len(rec) != 16 || binary.NativeEndian.Uint64(rec) != 64 || binary.NativeEndian.Uint64(rec[8:]) != 64 {
						t.Fatalf("record: %x", rec)
					}
				})
				if count != 1 {
					t.Fatalf("records=%d", count)
				}
			})
		}
	}
}

// Exercise member set keys in the full capture pipeline, where the set key,
// NULL-read scratch, packet filter and gated hold occupy the same stack frame.
func TestBpfArgMemberSetAndGated(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, argMemberSource))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	target := coll.Programs["member_target"]
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 16, ValueSize: 4, MaxEntries: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	// A signed 32-bit member widens into a 64-bit field, followed by an
	// ordinary integer arg. Padding must remain zero across helper calls.
	key := make([]byte, 16)
	binary.NativeEndian.PutUint64(key, ^uint64(2))
	binary.NativeEndian.PutUint32(key[8:], 7)
	for _, mode := range []string{"entry", "exit", "gated"} {
		for _, kind := range []string{"member", "member_set", "implicit_set", "scalar_set", "static_null", "static_nonnull", "static_member", "null", "null_miss", "member_null_miss", "set_null_miss", "set_miss", "and_miss", "dsl_miss"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				fn := "sdf_classify"
				if kind == "scalar_set" {
					fn = "scalar_capture"
				}
				if kind == "static_null" || kind == "static_nonnull" || kind == "static_member" {
					fn = "scalar_hook"
				}
				params, err := attach.GetFuncParams(target, fn)
				if err != nil {
					t.Fatal(err)
				}
				exprs := []string{"q->imsi==262010000000001", "q->target.pdr_id!=0", "n==7"}
				null := false
				want := 1
				var sets []filter.SetFilter
				switch kind {
				case "static_null":
					exprs = []string{"opaque==null"}
					null = true
				case "static_nonnull":
					exprs = []string{"opaque!=null"}
				case "static_member":
					exprs = []string{"value[0]==64", "choice->number!=0"}
				case "null":
					exprs = []string{"q==null", "n!=0"}
					null = true
				case "null_miss":
					exprs = []string{"q!=null"}
					null = true
					want = 0
				case "member_null_miss":
					null = true
					want = 0
				case "and_miss":
					exprs = append(exprs, "n!=7")
					want = 0
				case "dsl_miss":
					want = 0
				case "member_set", "implicit_set", "scalar_set", "set_null_miss", "set_miss":
					set := &setmap.Set{SpecRef: setmap.SpecRef{Name: "members", Mapping: []setmap.MapEntry{{Field: "pdr_id", Source: "arg:q->target.pdr_id"}, {Field: "n", Source: "arg:n"}}}, Def: &setmap.Definition{Map: m, KeySize: 16, Fields: []setmap.KeyField{{Name: "pdr_id", Size: 8}, {Name: "n", Off: 8, Size: 4}}}}
					switch kind {
					case "implicit_set":
						// q->imsi is a unique promoted field, and n is an ordinary arg.
						set.Mapping = nil
						set.Def.Fields[0].Name = "imsi"
						binary.NativeEndian.PutUint64(key, 262010000000001)
						binary.NativeEndian.PutUint32(key[8:], 7)
					case "scalar_set":
						set.Mapping[0].Source = "arg:value[0]"
						exprs = []string{"value!=null"}
						// Mix a scalar pointee with an ordinary integer arg.
						set.Mapping[1].Source = "arg:n"
						binary.NativeEndian.PutUint64(key, 64)
						binary.NativeEndian.PutUint32(key[8:], 64)
					default:
						binary.NativeEndian.PutUint64(key, ^uint64(2))
						binary.NativeEndian.PutUint32(key[8:], 7)
					}
					if kind == "set_miss" {
						binary.NativeEndian.PutUint32(key[8:], 8)
						want = 0
					}
					if err := m.Put(key, uint32(1)); err != nil {
						t.Fatal(err)
					}
					defer func() { _ = m.Delete(key) }()
					if kind == "set_null_miss" {
						null = true
						want = 0
						exprs = nil
					}
					sets, err = filter.ResolveSetFilters([]*setmap.Set{set}, []string{"members"}, params)
					if err != nil {
						t.Fatal(err)
					}
				}
				args, err := filter.ParseAndValidateFilters(exprs, params)
				if err != nil {
					t.Fatal(err)
				}
				stages := []Stage{{Expr: "eth"}}
				if kind == "dsl_miss" {
					stages[0].Expr = "eth/ipv4/tcp"
				}
				if mode == "exit" {
					stages[0].IsFexit = true
				}
				if mode == "gated" {
					stages = append(stages, Stage{Expr: "eth", IsFexit: true})
					want *= 2
				}
				probe, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: fn, Type: ebpf.XDP}}, stages, []filter.TargetFilters{{Args: args, Sets: sets}}, true, nil, EmitBoth)
				if err != nil {
					t.Fatalf("load capture: %+v", err)
				}
				defer func() { _ = probe.Close() }()
				data := make([]byte, 64)
				if null {
					data[0] = 1
				}
				if _, err := target.Run(&ebpf.RunOptions{Data: data}); err != nil {
					t.Fatal(err)
				}
				if err := probe.Quiesce(); err != nil {
					t.Fatal(err)
				}
				count := 0
				for _, m := range probe.InnerMaps {
					rd, err := fastrb.New(m.FD(), int(m.MaxEntries()))
					if err != nil {
						t.Fatal(err)
					}
					rd.ReadBatch(func(rec []byte) { count++ })
					_ = rd.Close()
				}
				if count != want {
					t.Fatalf("records=%d want=%d", count, want)
				}
			})
		}
	}
}
