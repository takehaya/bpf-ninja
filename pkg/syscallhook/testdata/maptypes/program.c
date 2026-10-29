#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
typedef unsigned int u32;
struct xdp_md {
  u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index,
      egress_ifindex;
};
struct record {
  u32 identity, action;
};
struct {
  __uint(type, 1);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct record);
} sessions SEC(".maps");
static void *(*lookup)(void *, const void *) = (void *)1;
SEC("xdp") int ingress(struct xdp_md *ctx) {
  u32 key = 0;
  struct record *value = lookup(&sessions, &key);
  return value ? value->action : 1;
}
char _license[] SEC("license") = "GPL";
