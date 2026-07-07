// XDP program with a __noinline capture point, used to test xdp-ninja's
// --func subfunction attach + --arg-filter argument reading.
//
// capture_point(ctx, pkt_len) mirrors a real datapath capture point: the
// first argument is the context pointer (which xdp-ninja treats as the
// implicit ctx and does not expose), and pkt_len is the filterable arg that
// --arg-filter reads. pkt_len is otherwise unused, so KEEP_ARGS (keep_args.h)
// is what keeps it on the ABI — without it the compiler would drop the dead
// argument and xdp-ninja could not read it.

#include <linux/bpf.h>

#include "keep_args.h"

#define SEC(NAME) __attribute__((section(NAME), used))

__attribute__((noinline)) int capture_point(struct xdp_md *ctx, __u32 pkt_len) {
  KEEP_ARGS(ctx, pkt_len);
  return 0;
}

SEC("xdp")
int xdp_argcap(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  // char* (not void*) subtraction: a byte-sized ptrdiff in standard C,
  // avoiding the void*-arithmetic GNU extension (-Wpointer-arith).
  capture_point(ctx, (__u32)((char *)data_end - (char *)data));
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
