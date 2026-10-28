#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct event {
  __u32 op;
  __u32 site;
  __u64 value;
  __u64 status;
};
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} events SEC(".maps");

/* Every typed push, pop and peek hook is
 * int HOOK_MAP_OP(struct xdp_md *ctx, u32 site, const VALUE *value, u64
 * status). The arguments are read with bpf_get_func_arg, as raw u64 values. */
static int report(void *ctx, __u32 op) {
  __u64 site = 0, value = 0, status = 0;
  struct event *e;

  bpf_get_func_arg(ctx, 1, &site);
  bpf_get_func_arg(ctx, 2, &value);
  bpf_get_func_arg(ctx, 3, &status);
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  e->op = op;
  e->site = site;
  e->value = 0;
  /* The bloom filter holds __u32 values, the queue __u64 ones. */
  bpf_probe_read_kernel(&e->value, op == 2 ? sizeof(__u32) : sizeof(__u64),
                        (void *)value);
  e->status = status;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fentry/ninja_recent_push")
int on_push(void *ctx) { return report(ctx, 0); }

SEC("fentry/ninja_recent_pop")
int on_pop(void *ctx) { return report(ctx, 1); }

SEC("fentry/ninja_seen_peek")
int on_peek(void *ctx) { return report(ctx, 2); }

char LICENSE[] SEC("license") = "GPL";
