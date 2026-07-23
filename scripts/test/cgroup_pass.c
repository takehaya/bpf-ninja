// Minimal cgroup-skb filter used by integration tests as the
// fentry/fexit attach target for `bpf-ninja --cgroup / -p` on a
// BPF_PROG_TYPE_CGROUP_SKB program. Returns SK_PASS (1)
// unconditionally — bpf-ninja attaches as a tracing observer, the
// dummy never gates real traffic.
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("cgroup_skb/ingress")
int cgroup_pass(struct __sk_buff *skb) { return 1; }

char _license[] SEC("license") = "GPL";
