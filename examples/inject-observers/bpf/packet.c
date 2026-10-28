#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

/* Filled from the running kernel's xdp_buff BTF before loading. */
const volatile __u32 data_offset = 0;
const volatile __u32 data_end_offset = 0;

struct event {
  __u32 site;
  __u32 length;
  __u64 status;
  __u8 first[8];
};
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} events SEC(".maps");

SEC("fentry/ninja_recent_push")
int on_push(void *ctx) {
  __u64 xdp = 0, data = 0, end = 0, site = 0, status = 0;
  bpf_get_func_arg(ctx, 0, &xdp);
  /* fentry receives xdp_buff, not the user-facing xdp_md layout. */
  if (bpf_probe_read_kernel(&data, sizeof(data), (void *)(xdp + data_offset)) ||
      bpf_probe_read_kernel(&end, sizeof(end), (void *)(xdp + data_end_offset)))
    return 0;
  if (end < data || end - data < 8)
    return 0;
  bpf_get_func_arg(ctx, 1, &site);
  bpf_get_func_arg(ctx, 3, &status);
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  e->site = site;
  e->length = end - data;
  e->status = status;
  if (bpf_probe_read_kernel(e->first, sizeof(e->first), (void *)data)) {
    bpf_ringbuf_discard(e, 0);
    return 0;
  }
  bpf_ringbuf_submit(e, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
