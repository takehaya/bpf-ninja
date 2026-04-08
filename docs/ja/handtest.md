# ハンドテスト: xdp-ninja パケットキャプチャ

xdp-ninja の各機能を手動で検証する手順書。
シンプルな XDP プログラムへの fentry/fexit から始め、
`--func` によるサブ関数プローブ、tail call 環境での動作まで段階的に確認する。

## 前提条件

- Linux kernel 6.x 以上（bpf2bpf call と tail call の共存をサポート）
- root 権限
- clang, bpftool, tcpdump

## 0. ビルド

```bash
cd /path/to/xdp-ninja
go build -o xdp-ninja ./cmd/xdp-ninja/
```

---

## Part 1: エントリ関数への fentry/fexit

最もシンプルなケース。XDP プログラムのエントリ関数にアタッチしてパケットをキャプチャする。

### 1.1 テスト用プログラムの作成

```bash
cat > /tmp/xdp_simple.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return 2; /* XDP_PASS */
}

char _license[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_simple.c -o /tmp/xdp_simple.o
```

### 1.2 環境構築

```bash
sudo ip netns add nstest
sudo ip link add vtest0 type veth peer name vtest1
sudo ip link set vtest1 netns nstest
sudo ip addr add 10.77.0.1/24 dev vtest0
sudo ip netns exec nstest ip addr add 10.77.0.2/24 dev vtest1
sudo ip link set vtest0 up
sudo ip netns exec nstest ip link set vtest1 up
sudo ip netns exec nstest ip link set lo up

# XDP プログラムをアタッチ
sudo ip link set dev vtest0 xdp obj /tmp/xdp_simple.o sec xdp
```

疎通確認:

```bash
sudo ip netns exec nstest ping -c 3 10.77.0.1
```

### 1.3 fentry（XDP 処理前のキャプチャ）

ターミナル 1:

```bash
sudo ./xdp-ninja -i vtest0 -v | tcpdump -n -r -
```

ターミナル 2:

```bash
sudo ip netns exec nstest ping -c 5 10.77.0.1
```

期待: ICMP パケットがキャプチャされる。

### 1.4 fexit（XDP 処理後のキャプチャ）

```bash
sudo ./xdp-ninja -i vtest0 --mode exit -v | tcpdump -n -r -
```

期待: ICMP パケットがキャプチャされる。

### 1.5 フィルタ付き

```bash
# マッチするフィルタ
sudo ./xdp-ninja -i vtest0 "icmp" -v | tcpdump -n -r -

# マッチしないフィルタ
sudo ./xdp-ninja -i vtest0 "tcp port 80" -v -c 3 | tcpdump -n -r -
```

期待: icmp フィルタではキャプチャされ、tcp port 80 では `0 packets captured`。

### 1.6 pcap ファイル出力

```bash
sudo ./xdp-ninja -i vtest0 -w /tmp/capture.pcap -c 5 &
sudo ip netns exec nstest ping -c 5 10.77.0.1
wait
tcpdump -n -r /tmp/capture.pcap
```

期待: pcap ファイルが生成され、tcpdump で読める。

### 1.7 クリーンアップ

```bash
sudo ip link set dev vtest0 xdp off
sudo ip link delete vtest0 2>/dev/null
sudo ip netns delete nstest 2>/dev/null
```

---

## Part 2: `--func` によるサブ関数プローブ

`__noinline` サブ関数にアタッチしてキャプチャする。
global と static の両方を含むプログラムで動作を確認する。

### 2.1 テスト用プログラムの作成

```
xdp_main
  └─ classify_packet  [global __noinline]
      └─ parse_headers  [static __noinline]
```

```bash
cat > /tmp/xdp_subfunc.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP     0x0800
#define IPPROTO_ICMP 1

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16        h_proto;
} __attribute__((packed));

struct iphdr {
    __u8   ihl_ver;
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

/* static __noinline: verifier が呼び出し元のコンテキストで検証する */
static __attribute__((noinline))
int parse_headers(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    return ip->protocol;
}

/* global __noinline: verifier が独立して検証する */
__attribute__((noinline))
int classify_packet(struct xdp_md *ctx) {
    int proto = parse_headers(ctx);
    if (proto == IPPROTO_ICMP)
        return 2; /* XDP_PASS */
    return 2; /* XDP_PASS */
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
    return classify_packet(ctx);
}

char _license[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_subfunc.c -o /tmp/xdp_subfunc.o
```

> **注意:** `__noinline` サブ関数の body は `ctx->data` 等にアクセスする非自明な処理が必要。
> `return 2;` だけの trivial な body は `clang -O2` で定数畳み込みされ、bpf2bpf call ごと消える。

### 2.2 環境構築

```bash
sudo ip netns add nstest
sudo ip link add vtest0 type veth peer name vtest1
sudo ip link set vtest1 netns nstest
sudo ip addr add 10.77.0.1/24 dev vtest0
sudo ip netns exec nstest ip addr add 10.77.0.2/24 dev vtest1
sudo ip link set vtest0 up
sudo ip netns exec nstest ip link set vtest1 up
sudo ip netns exec nstest ip link set lo up

sudo ip link set dev vtest0 xdp obj /tmp/xdp_subfunc.o sec xdp
```

疎通確認:

```bash
sudo ip netns exec nstest ping -c 3 10.77.0.1
```

### 2.3 `--list-funcs` で関数一覧を確認

```bash
sudo ./xdp-ninja -i vtest0 --list-funcs
```

期待出力:

```
BTF functions in program (id=XXXX):
  parse_headers                              [static]
  classify_packet                            [global]
  xdp_main                                   [global]
```

### 2.4 fentry on `classify_packet`（global）

```bash
sudo ./xdp-ninja -i vtest0 --func classify_packet -v | tcpdump -n -r -
```

期待: ICMP パケットがキャプチャされる。

### 2.5 fentry on `parse_headers`（static）

```bash
sudo ./xdp-ninja -i vtest0 --func parse_headers -v | tcpdump -n -r -
```

期待: 同様にキャプチャされる。

### 2.6 fexit on サブ関数

```bash
sudo ./xdp-ninja -i vtest0 --func classify_packet --mode exit -v | tcpdump -n -r -
```

期待: キャプチャされる。

### 2.7 存在しない関数名（エラー）

```bash
sudo ./xdp-ninja -i vtest0 --func no_such_func
```

期待: 利用可能な関数名を含むエラーメッセージ。

### 2.8 クリーンアップ

```bash
sudo ip link set dev vtest0 xdp off
sudo ip link delete vtest0 2>/dev/null
sudo ip netns delete nstest 2>/dev/null
```

---

## Part 3: tail call 環境でのサブ関数プローブ

dispatcher が tail call で leaf を呼び出す構成で、
leaf 内のサブ関数に fentry/fexit をアタッチできることを確認する。

### 3.1 テスト用プログラムの作成

```
xdp_dispatcher
  └─ tail call ─→ xdp_leaf
                    └─ classify_packet  [global]
                        └─ parse_headers  [static]
```

```bash
cat > /tmp/xdp_tc_subfunc.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP     0x0800
#define IPPROTO_ICMP 1

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16        h_proto;
} __attribute__((packed));

struct iphdr {
    __u8   ihl_ver;
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} prog_array SEC(".maps");

/* static __noinline */
static __attribute__((noinline))
int parse_headers(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    return ip->protocol;
}

/* global __noinline */
__attribute__((noinline))
int classify_packet(struct xdp_md *ctx) {
    int proto = parse_headers(ctx);
    if (proto == IPPROTO_ICMP)
        return 2;
    return 2;
}

SEC("xdp")
int xdp_leaf(struct xdp_md *ctx) {
    return classify_packet(ctx);
}

SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx) {
    bpf_tail_call(ctx, &prog_array, 0);
    return 2;
}

char _license[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_tc_subfunc.c -o /tmp/xdp_tc_subfunc.o
```

### 3.2 環境構築

```bash
sudo ip netns add nstest
sudo ip link add vtest0 type veth peer name vtest1
sudo ip link set vtest1 netns nstest
sudo ip addr add 10.77.0.1/24 dev vtest0
sudo ip netns exec nstest ip addr add 10.77.0.2/24 dev vtest1
sudo ip link set vtest0 up
sudo ip netns exec nstest ip link set vtest1 up
sudo ip netns exec nstest ip link set lo up

# bpftool でロード（dispatcher と leaf を別プログラムとしてロード）
sudo rm -rf /sys/fs/bpf/tctest
sudo mkdir -p /sys/fs/bpf/tctest
sudo bpftool prog loadall /tmp/xdp_tc_subfunc.o /sys/fs/bpf/tctest

# プログラム ID を取得
DISP_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/tctest/xdp_dispatcher | head -1 | awk '{print $1}' | tr -d ':')
LEAF_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/tctest/xdp_leaf | head -1 | awk '{print $1}' | tr -d ':')
echo "DISP_ID=$DISP_ID LEAF_ID=$LEAF_ID"

# dispatcher をインターフェースにアタッチ
sudo bpftool net attach xdp id "$DISP_ID" dev vtest0

# prog_array を pin して tail call を設定
MAP_ID=$(sudo bpftool prog show id "$DISP_ID" | grep -oP 'map_ids \K\d+')
sudo bpftool map pin id "$MAP_ID" /sys/fs/bpf/tctest/prog_array
sudo bpftool map update pinned /sys/fs/bpf/tctest/prog_array key 0 0 0 0 value id "$LEAF_ID"
```

疎通確認:

```bash
sudo ip netns exec nstest ping -c 3 10.77.0.1
```

### 3.3 `--list-progs` で tail call ツリーを確認

```bash
sudo ./xdp-ninja -i vtest0 --list-progs
```

期待出力:

```
id=XXXX   xdp_dispatcher
id=YYYY   xdp_leaf (tailcall[0])
```

### 3.4 leaf のサブ関数一覧

```bash
sudo ./xdp-ninja -p $LEAF_ID --list-funcs
```

### 3.5 fentry on サブ関数（tail call 経由で発火するか）

```bash
sudo ./xdp-ninja -p $LEAF_ID --func classify_packet -v | tcpdump -n -r -
```

期待: ICMP パケットがキャプチャされる。
tail call 先プログラム内の bpf2bpf call はトランポリンが正常に動作する。

### 3.6 fexit on サブ関数

```bash
sudo ./xdp-ninja -p $LEAF_ID --func classify_packet --mode exit -v | tcpdump -n -r -
```

期待: キャプチャされる。

### 3.7 tail call 先エントリ関数への直接アタッチ（発火しないケース）

```bash
sudo ./xdp-ninja -p $LEAF_ID -v -c 3 | tcpdump -n -r -
```

期待: `0 packets captured`。
tail call は `jmp` でエントリのトランポリンをバイパスするため、
エントリ関数への fentry は発火しない。
一方、内部の bpf2bpf call は通常の関数呼び出しなのでトランポリンが動作する。

### 3.8 クリーンアップ

```bash
sudo bpftool net detach xdp dev vtest0
sudo rm -rf /sys/fs/bpf/tctest
sudo ip link delete vtest0 2>/dev/null
sudo ip netns delete nstest 2>/dev/null
```

---

## Part 4: `--arg-filter` による引数フィルタリング

`--func` で指定したサブ関数の引数値でフィルタリングする。
整数型の引数（最初の xdp_md ポインタを除く）が対象。

### 4.1 テスト用プログラムの作成

```
xdp_entry
  └─ process_packet(ctx, tunnel_id)  [global __noinline, u32 引数付き]
```

```bash
cat > /tmp/xdp_argfilter.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__attribute__((noinline))
int process_packet(struct xdp_md *ctx, __u32 tunnel_id) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return 1;
    volatile __u32 id = tunnel_id; /* 最適化で引数が消えるのを防止 */
    return (id > 0) ? 2 : 1;
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx) {
    return process_packet(ctx, 42);
}

char _license[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_argfilter.c -o /tmp/xdp_argfilter.o
```

### 4.2 環境構築

```bash
sudo ip netns add nstest
sudo ip link add vtest0 type veth peer name vtest1
sudo ip link set vtest1 netns nstest
sudo ip addr add 10.77.0.1/24 dev vtest0
sudo ip netns exec nstest ip addr add 10.77.0.2/24 dev vtest1
sudo ip link set vtest0 up
sudo ip netns exec nstest ip link set vtest1 up
sudo ip netns exec nstest ip link set lo up

sudo ip link set dev vtest0 xdp obj /tmp/xdp_argfilter.o sec xdp
```

疎通確認:

```bash
sudo ip netns exec nstest ping -c 3 10.77.0.1
```

### 4.3 `--list-params` でフィルタ可能なパラメータを確認

```bash
sudo ./xdp-ninja -i vtest0 --func process_packet --list-params
```

期待出力:

```
Filterable parameters for process_packet (id=XXXX):
  tunnel_id            [4 bytes, unsigned, arg index 1]
```

### 4.4 `--list-params` を `--func` なしで実行（エラー）

```bash
sudo ./xdp-ninja -i vtest0 --list-params
```

期待: `--list-params requires --func` エラー。

### 4.5 完全一致フィルタ（マッチ）

```bash
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id=42" -v | tcpdump -n -r -
```

期待: tunnel_id=42 なのでパケットがキャプチャされる。

### 4.6 完全一致フィルタ（不一致）

```bash
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id=99" -v -c 3 | tcpdump -n -r -
```

期待: `0 packets captured`。

### 4.7 範囲フィルタ

```bash
# マッチ (42 は 40..50 の範囲内)
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id=40..50" -v | tcpdump -n -r -

# 不一致 (42 は 100..200 の範囲外)
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id=100..200" -v -c 3 | tcpdump -n -r -
```

### 4.8 比較フィルタ

```bash
# >= (42 >= 40 → マッチ)
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id>=40" -v | tcpdump -n -r -

# <= (42 <= 50 → マッチ)
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id<=50" -v | tcpdump -n -r -

# >= (42 >= 100 → 不一致)
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id>=100" -v -c 3 | tcpdump -n -r -
```

### 4.9 16進数値

```bash
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id=0x2a" -v | tcpdump -n -r -
```

期待: 0x2a = 42 なのでキャプチャされる。

### 4.10 パケットフィルタとの併用

```bash
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "tunnel_id=42" "icmp" -v | tcpdump -n -r -
```

期待: 引数フィルタとパケットフィルタの両方を満たすパケットのみキャプチャされる。

### 4.11 存在しないパラメータ名（エラー）

```bash
sudo ./xdp-ninja -i vtest0 --func process_packet --arg-filter "no_such=42"
```

期待: 利用可能なパラメータ名を含むエラーメッセージ。

### 4.12 `--arg-filter` を `--func` なしで実行（エラー）

```bash
sudo ./xdp-ninja -i vtest0 --arg-filter "tunnel_id=42"
```

期待: `--arg-filter requires --func` エラー。

### 4.13 クリーンアップ

```bash
sudo ip link set dev vtest0 xdp off
sudo ip link delete vtest0 2>/dev/null
sudo ip netns delete nstest 2>/dev/null
```
