// XDP program that decapsulates a UDP-encapsulated Ethernet frame and
// then drops or passes it on the inner header. Used by the multi-point
// (--entry + --exit) integration test: the entry record must show the
// outer header, the exit record the inner header, and only DROP'd
// packets must appear at exit.
//
//   outer: Ethernet / IPv4 / UDP dport 6081 / inner Ethernet / IPv4 / TCP
//   decap: bpf_xdp_adjust_head(+42) so the inner Ethernet header is at head
//   verdict: inner TCP dport 80 -> XDP_DROP, otherwise XDP_PASS
//   anything else (no outer UDP 6081) -> XDP_PASS untouched

#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static long (*bpf_xdp_adjust_head)(void *ctx, int delta) = (void *)44;

#define ETH_HLEN 14
#define IPV4_HLEN 20
#define UDP_HLEN 8
#define OUTER_LEN (ETH_HLEN + IPV4_HLEN + UDP_HLEN)
#define ENCAP_PORT 6081
#define DROP_PORT 80

static __always_inline __u16 be16(const unsigned char *p) {
  return (__u16)((p[0] << 8) | p[1]);
}

SEC("xdp")
int decap_drop(struct xdp_md *ctx) {
  unsigned char *data = (void *)(long)ctx->data;
  unsigned char *data_end = (void *)(long)ctx->data_end;

  if (data + OUTER_LEN > data_end)
    return XDP_PASS;
  if (be16(data + 12) != 0x0800) /* outer ethertype IPv4 */
    return XDP_PASS;
  if ((data[ETH_HLEN] & 0xf0) != 0x40 || (data[ETH_HLEN] & 0x0f) != 5)
    return XDP_PASS;
  if (data[ETH_HLEN + 9] != 17) /* outer proto UDP */
    return XDP_PASS;
  if (be16(data + ETH_HLEN + IPV4_HLEN + 2) != ENCAP_PORT)
    return XDP_PASS;

  if (bpf_xdp_adjust_head(ctx, OUTER_LEN) < 0)
    return XDP_ABORTED;

  data = (void *)(long)ctx->data;
  data_end = (void *)(long)ctx->data_end;
  if (data + ETH_HLEN + IPV4_HLEN + 4 > data_end)
    return XDP_PASS;
  if (be16(data + 12) != 0x0800) /* inner ethertype IPv4 */
    return XDP_PASS;
  if (data[ETH_HLEN + 9] != 6) /* inner proto TCP */
    return XDP_PASS;
  if (be16(data + ETH_HLEN + IPV4_HLEN + 2) == DROP_PORT)
    return XDP_DROP;
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
