#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} start SEC(".maps");
struct event {
  __u32 site;
  __u32 op;
  __u64 status;
  __u64 ns;
};
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} events SEC(".maps");

SEC("fentry/ninja_entry")
int on_entry(void *ctx) {
  __u32 key = 0;
  __u64 *t = bpf_map_lookup_elem(&start, &key);
  if (t)
    *t = bpf_ktime_get_ns();
  return 0;
}

static int report(void *ctx, __u32 op) {
  __u64 now = bpf_ktime_get_ns(), site = 0, status = 0;
  __u32 key = 0;
  __u64 *t = bpf_map_lookup_elem(&start, &key);
  if (!t || !*t)
    return 0;
  __u64 elapsed = now - *t;
  bpf_get_func_arg(ctx, 1, &site);
  bpf_get_func_arg(ctx, 3, &status);
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  e->site = site;
  e->op = op;
  e->status = status;
  e->ns = elapsed;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fentry/ninja_recent_push")
int on_push(void *ctx) { return report(ctx, 0); }

SEC("fentry/ninja_seen_push")
int on_seen_push(void *ctx) { return report(ctx, 1); }

char LICENSE[] SEC("license") = "GPL";
