#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct event {
  __u32 op;
  __u32 site;
  __u64 value;
  __u64 status;
  __u32 cpu;
  __u32 pad;
};
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} events SEC(".maps");

static int report(void *ctx, __u32 op) {
  __u64 site = 0, value = 0, status = 0;
  bpf_get_func_arg(ctx, 3, &status);
  if ((__s32)status == 0)
    return 0;
  bpf_get_func_arg(ctx, 1, &site);
  bpf_get_func_arg(ctx, 2, &value);
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  e->op = op;
  e->site = site;
  e->value = 0;
  bpf_probe_read_kernel(&e->value, op == 2 ? sizeof(__u32) : sizeof(__u64),
                        (void *)value);
  e->status = status;
  e->cpu = bpf_get_smp_processor_id();
  e->pad = 0;
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
