#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct flow_key {
  __u16 dport;
  __u16 pad;
};
struct pol {
  __u32 action;
  __u16 port;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4);
  __type(key, struct flow_key);
  __type(value, struct pol);
} policies SEC(".maps");

SEC("xdp")
int entry(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *end = (void *)(long)ctx->data_end;
  if (data + 38 > end)
    return XDP_ABORTED;
  struct flow_key key = {.dport = *(__u16 *)(data + 36)};
  struct pol *value = bpf_map_lookup_elem(&policies, &key);
  return value ? value->action : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
