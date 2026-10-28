#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(max_entries, 2);
  __type(value, __u64);
} recent SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
  __uint(max_entries, 16);
  __type(value, __u32);
} seen SEC(".maps");
struct stat {
  __u64 pkts;
  __u64 bytes;
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct stat);
} stats SEC(".maps");

SEC("xdp")
int entry(struct xdp_md *ctx) {
  __u32 len = ctx->data_end - ctx->data;
  __u64 v = len;
  __u32 k = 0;
  struct stat *st;

  if (bpf_map_peek_elem(&seen, &len))
    bpf_map_push_elem(&seen, &len, BPF_ANY);
  if (bpf_map_push_elem(&recent, &v, BPF_ANY))
    bpf_map_pop_elem(&recent, &v);
  st = bpf_map_lookup_percpu_elem(&stats, &k, 0);
  if (st)
    return st->pkts ? XDP_DROP : XDP_PASS;
  return XDP_ABORTED;
}
char LICENSE[] SEC("license") = "GPL";
