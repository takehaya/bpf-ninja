typedef unsigned int __u32;
struct xdp_md {
  __u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index,
      egress_ifindex;
};
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define MAP(name)                                                              \
  struct {                                                                     \
    __uint(type, 2);                                                           \
    __uint(max_entries, 1);                                                    \
    __type(key, __u32);                                                        \
    __type(value, __u32);                                                      \
  } name SEC(".maps")
MAP(a);
MAP(b);
MAP(c);
static void *(*lookup)(void *, const void *) = (void *)1;

SEC("xdp") int hook_root(struct xdp_md *ctx) {
  unsigned char *data = (void *)(long)ctx->data;
  unsigned char *end = (void *)(long)ctx->data_end;
  if (data + 14 > end)
    return 1;
  __u32 key = 0;
  __u32 *v = lookup(&a, &key);
  if (!v || *v)
    return 1;
  data[1] = 42;
  v = lookup(&b, &key);
  if (!v || *v)
    return 1;
  if (data[0] == 1)
    return 2;
  v = lookup(&c, &key);
  if (!v || *v)
    return 1;
  return data[0] == 2 ? 4 : 2;
}
char _license[] SEC("license") = "GPL";
