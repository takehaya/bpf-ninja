// Minimal tc clsact classifier used by integration tests as the
// fentry/fexit attach target for `bpf-ninja --mode tc-{entry,exit}`.
// Returns TC_ACT_OK unconditionally — bpf-ninja attaches as a tracing
// observer, the dummy never gates real traffic.
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("classifier")
int tc_pass(struct __sk_buff *skb) { return TC_ACT_OK; }

char _license[] SEC("license") = "GPL";
