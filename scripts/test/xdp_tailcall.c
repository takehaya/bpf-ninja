// Two-program tail call chain for testing -p (prog ID) attach.
//
// xdp_dispatcher (attached to interface) → tail call → xdp_prog_a (XDP_PASS)
//
// Loaded via: bpftool prog loadall xdp_tailcall.o /sys/fs/bpf/tc_test
// Both programs are type XDP. The section names use "xdp" prefix so
// libbpf/bpftool recognizes them as XDP programs.

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} prog_array SEC(".maps");

SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx) {
  bpf_tail_call(ctx, &prog_array, 0);
  return 2; /* XDP_PASS fallback */
}

SEC("xdp")
int xdp_prog_a(struct xdp_md *ctx) { return 2; /* XDP_PASS */ }

char _license[] SEC("license") = "GPL";
