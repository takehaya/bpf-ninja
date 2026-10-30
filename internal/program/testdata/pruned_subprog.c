#define SEC(name) __attribute__((section(name), used))
#define NOINLINE __attribute__((noinline))
struct xdp_md {
  unsigned data, data_end, data_meta, ingress_ifindex, rx_queue_index,
      egress_ifindex;
};
const volatile unsigned enabled = 0;
NOINLINE int global_dead(struct xdp_md *ctx) {
  return ctx->ingress_ifindex + 1;
}
static NOINLINE int static_dead(struct xdp_md *ctx) {
  return ctx->rx_queue_index + 2;
}
static NOINLINE int static_dead_other(struct xdp_md *ctx) {
  return ctx->ingress_ifindex + 4;
}
NOINLINE int live_hook(struct xdp_md *ctx) { return ctx->ingress_ifindex + 3; }
SEC("xdp") int entry(struct xdp_md *ctx) {
  if (enabled)
    return global_dead(ctx) + static_dead(ctx) + static_dead_other(ctx);
  return live_hook(ctx);
}
char _license[] SEC("license") = "GPL";
