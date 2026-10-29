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
// Legacy map definitions carry sizes but no key/value BTF association.
// Keep this named type in the ELF BTF even when debug optimization drops
// locals.
struct record retained_type SEC(".bss");
struct map_def {
  u32 type, key_size, value_size, max_entries, flags;
};
struct map_def sessions SEC("maps") = {1, 4, 8, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
SEC("xdp") int ingress(struct xdp_md *ctx) {
  u32 key = 0;
  struct record *value = lookup(&sessions, &key);
  return value ? value->action : 1;
}
char _license[] SEC("license") = "GPL";
