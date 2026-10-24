package program

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/filter"
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
			probe, err := LoadArgEcho(target, "sdf_classify", nil, plain, exit, false)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			rd, err := fastrb.New(probe.EchoRing.FD(), EchoRingSize)
			if err != nil {
				t.Fatal(err)
			}
			defer rd.Close()
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
				probe, err := LoadArgEcho(target, "sdf_classify", fs, echo, exit, false)
				if err != nil {
					t.Fatalf("load echo: %+v", err)
				}
				defer probe.Close()
				rd, err := fastrb.New(probe.EchoRing.FD(), EchoRingSize)
				if err != nil {
					t.Fatal(err)
				}
				defer rd.Close()
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
