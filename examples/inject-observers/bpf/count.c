#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct key {
  __u32 op;
  __u32 site;
};
struct counter {
  __u64 calls;
  __u64 failures;
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 128);
  __type(key, struct key);
  __type(value, struct counter);
} counters SEC(".maps");

static int count(void *ctx, __u32 op) {
  __u64 site = 0, status = 0;
  bpf_get_func_arg(ctx, 1, &site);
  bpf_get_func_arg(ctx, 3, &status);
  struct key key = {.op = op, .site = site};
  struct counter zero = {}, *c = bpf_map_lookup_elem(&counters, &key);
  if (!c) {
    bpf_map_update_elem(&counters, &key, &zero, BPF_NOEXIST);
    c = bpf_map_lookup_elem(&counters, &key);
  }
  if (c) {
    c->calls++;
    /* The upper half holds push flags, not the helper's return value. */
    c->failures += (__s32)status != 0;
  }
  return 0;
}

SEC("fentry/ninja_recent_push")
int on_push(void *ctx) { return count(ctx, 0); }

SEC("fentry/ninja_recent_pop")
int on_pop(void *ctx) { return count(ctx, 1); }

SEC("fentry/ninja_seen_peek")
int on_peek(void *ctx) { return count(ctx, 2); }

char LICENSE[] SEC("license") = "GPL";
