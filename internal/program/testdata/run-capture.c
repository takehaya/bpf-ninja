// The long bpf_loop and same-CPU pinned test-run threads reproduce the
// preemptible normal test-run path. Hooks add packet markers to that workload.
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
static long busy(__u32 i, void *p) {
  volatile __u64 *v = p;
  *v += i;
  return 0;
}
static long busy_slow(__u32 i, void *p) {
  volatile __u64 *v = p;
#pragma unroll
  for (int j = 0; j < 64; j++)
    *v += i + j;
  return 0;
}
static __always_inline void workload(void) {
  __u64 v = 0;
  bpf_loop(4000000, busy, &v, 0);
}
__attribute__((noinline)) int run_hook_xdp(struct xdp_md *ctx) {
  return ctx->data_end - ctx->data;
}
__attribute__((noinline)) int run_hook_tc(struct __sk_buff *ctx) {
  return ctx->len;
}
__attribute__((noinline)) int run_begin_xdp(struct xdp_md *ctx) {
  return ctx->data_end - ctx->data;
}
__attribute__((noinline)) int run_begin_tc(struct __sk_buff *ctx) {
  return ctx->len;
}
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} seen SEC(".maps");
static __always_inline void remember(void *ctx) {
  __u32 k = 0;
  __u64 v = (__u64)ctx;
  bpf_map_update_elem(&seen, &k, &v, 0);
}
SEC("xdp") int run_stress_xdp(struct xdp_md *ctx) {
  remember(ctx);
  if (run_begin_xdp(ctx) <= 0)
    return XDP_DROP;
  workload();
  return run_hook_xdp(ctx) > 0 ? XDP_PASS : XDP_DROP;
}
SEC("xdp") int run_stress_slow_xdp(struct xdp_md *ctx) {
  remember(ctx);
  if (run_begin_xdp(ctx) <= 0)
    return XDP_DROP;
  __u64 v = 0;
  bpf_loop(4000000, busy_slow, &v, 0);
  return run_hook_xdp(ctx) > 0 ? XDP_PASS : XDP_DROP;
}
SEC("tc") int run_stress_tc(struct __sk_buff *ctx) {
  remember(ctx);
  if (run_begin_tc(ctx) <= 0)
    return 2;
  workload();
  return run_hook_tc(ctx) > 0 ? 0 : 2;
}
SEC("xdp") int run_adjust_xdp(struct xdp_md *ctx) {
  remember(ctx);
  if (bpf_xdp_adjust_head(ctx, 4))
    return XDP_ABORTED;
  return run_hook_xdp(ctx) > 0 ? XDP_PASS : XDP_DROP;
}
SEC("tc") int run_adjust_tc(struct __sk_buff *ctx) {
  remember(ctx);
  if (bpf_skb_change_head(ctx, 32, 0))
    return 2;
  return run_hook_tc(ctx) > 0 ? 0 : 2;
}
char LICENSE[] SEC("license") = "GPL";
