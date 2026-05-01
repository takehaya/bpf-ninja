# xdp-ninja DSL 利用ガイド

`--dsl` フラグを付けると、フィルタ式は tcpdump 構文ではなく **xdp-ninja DSL** として解釈される。tcpdump/cbpfc では書きにくい多段カプセル化 (GTP-U over UDP, MPLS label stack, VXLAN inner Ethernet, …) を「プロトコルスタックの形」のまま記述できるのがゴール。

このドキュメントは利用者向け。formal な EBNF と例文表は [dsl-grammar.md](./dsl-grammar.md) にある。新しいプロトコル vocab を書きたい場合は [`pkg/kunai/protocols/`](../../pkg/kunai/protocols/) の既存 .p4 と [`pkg/kunai/vocab/loader.go`](../../pkg/kunai/vocab/loader.go) を参考にする。

## クイックスタート

```bash
sudo xdp-ninja --dsl -i veth0 "eth/ipv4/tcp[dport==443]"
```

- `--dsl` を付けないと従来どおり tcpdump 式扱い (cbpfc にコンパイル) になる。
- フィルタ式は **位置引数** として末尾に渡す。
- 既存の `-w pcap`, `-c count`, `--mode exit` などはすべて DSL でも使える。

## 文法

### Layer chain

レイヤをスラッシュで連結する。

```
eth/ipv4/tcp
eth/ipv6/icmp6
eth/ipv4/udp/vxlan/eth/ipv4/tcp     # 内側 Ethernet を再度展開
eth/ipv4/udp/gtp/ipv4/tcp           # GTP-U の内側 IP
```

各レイヤは vocab で定義された protocol 名 (lowercase)。バンドル済み vocab:

| 名前 | 用途 | 補足 |
|---|---|---|
| `eth` | Ethernet II | DIX 形式、14 byte |
| `ipv4`, `ipv6` | L3 |
| `tcp`, `udp` | L4 |
| `icmp`, `icmp6` | type/code フィルタに使える |
| `vlan`, `qinq` | 802.1Q / 802.1ad |
| `cw` | EoMPLS Control Word |
| `mpls` | label stack (詳細は後述) |
| `gre`, `vxlan`, `geneve` | encapsulation |
| `gtp` | GTP-U |
| `srv6` | SRH (segment list は MVP 範囲外) |

### Quantifier

レイヤの後ろに付ける。連続出現を表す。

| 構文 | 意味 |
|---|---|
| (なし) | 必ず 1 回 |
| `?` | 0 または 1 回 (optional) |
| `+` | 1 回以上 (bpf_loop で展開) |
| `*` | 0 回以上 (bpf_loop、先頭の peek でスキップ) |
| `{n}` | ちょうど n 回 (静的アンロール、`{n,n}` と等価) |
| `{n,m}` | n〜m 回。m≤4 は静的アンロール、それ以上は bpf_loop |

例:

```
eth/vlan?/ipv4/tcp                  # 任意 VLAN 1 段
eth/vlan{1,3}/ipv4/tcp              # VLAN 1〜3 段
eth/mpls+/ipv4/tcp                  # MPLS label stack (s-bit で終端)
eth/mpls{2,8}/ipv4/tcp              # MPLS 2〜8 段、8 段で打切
eth/vlan*/ipv4/tcp                  # VLAN 0〜N 段
```

### Predicate

`[field==value]` で同レイヤのヘッダフィールドに条件を付ける。カンマ区切りで複数条件を書くと AND。

```
eth/ipv4/tcp[dport==443]
eth/ipv4[src==10.0.0.1, dst==192.168.1.0/24]/tcp   # 複数フィールド (AND)
eth/ipv4/tcp[sport==12345, dport==443]              # port の両端を指定
eth/ipv4[ttl==64]/icmp[type==8]                     # 異なるレイヤに別々の predicate
eth/ipv6/tcp[sport==80]
eth/ipv6[src==2001:db8::/32]/tcp                   # IPv6 CIDR
eth/ipv6[dst==fe80::1]/udp                         # IPv6 アドレス
eth[dst==de:ad:be:ef:00:01]/ipv4/tcp               # MAC アドレス
```

サポート演算子: `==`, `!=`, `<`, `<=`, `>`, `>=`。

値は整数リテラル (10進 / `0x` 16進)、IPv4 (`10.0.0.1`)、IPv4 CIDR (`10.0.0.0/8`)、IPv6 (`fe80::1`)、IPv6 CIDR (`2001:db8::/32`)、MAC (`de:ad:be:ef:00:01`)。

すべてのリテラルで `==` / `!=` が使える。整数リテラルのみ ordered (`<`, `<=`, `>`, `>=`) も可。

### Where 節

レイヤチェーンの後に `where <expr>` を付けて、より広い条件を書く。

```
eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80
eth/ipv4/tcp where ipv4.total_length > 100 and tcp.dport == 443
eth/ipv4/tcp where action == XDP_DROP            # exit mode 限定
```

#### 演算子

| 種類 | 演算子 |
|---|---|
| 比較 | `==`, `!=`, `<`, `<=`, `>`, `>=` |
| 算術 | `+`, `-`, `*`, `/`, `%` |
| 論理 | `or`, `and`, `not` (`&&`/`\|\|` も可) |
| カッコ | `(`, `)` |

算術ネストは MVP で **3 段まで** (それを超えると `ErrNotImplemented`)。

#### フィールド参照

- `proto.field` — チェーン内に同名 protocol が 1 つしかないとき。
- `@label.field` — `eth/ipv4@outer/udp/gtp/ipv4@inner/tcp` のように `@label` 付与しておく。
- 同じ protocol が 2 つ以上あって `@label` が無い場合は resolve エラー。

#### action atom

`action == XDP_*` は **exit mode (`--mode exit`)** でのみ使える。`fentry` 段階では XDP がまだ実行されていないので、リジェクトされる。

サポート: `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT`。

### Capture 節

`capture` でパケットを perf ring に送る量・条件を細かく制御できる。

```
eth/ipv4/tcp                                # 既定 (snaplen 1500)
eth/ipv4/tcp capture all                    # 既定と同じ
eth/ipv4/tcp capture headers                # chain 全レイヤのヘッダ合計バイトのみ
eth/ipv4/tcp capture headers+64             # ヘッダ + 64 byte ペイロード
eth/ipv4/tcp capture headers+128 where tcp.dport > 1024

# 特定 layer まで (label / proto 名で指定)
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp capture inner       # @inner の末尾まで
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp capture inner+64    # +64 byte
eth/ipv4/tcp capture ipv4                                  # chain に 1 つだけなら proto 名でも可

# 先頭からの絶対バイト数
eth/ipv4/tcp capture absolute 96
```

per-capture の `where` はトップレベルの `where` と **AND** 合成される。

MVP 制限:
- フィールド列指定 (`capture tcp.flags, ipv4.dst`) は未対応。
- chain (`+`/`*`/`{n,m}`) を含むフィルタは静的に長さを確定できないので、`headers (+N)?` / `<label> (+N)?` は使えない (resolve エラー)。`absolute N` は chain 形に依存しないので使用可能。
- proto 名で指定するとき chain 内に複数 instance があると ambiguous error。`@label` で一意化する。
- `absolute` は capture 内の contextual keyword。label が `absolute` という名前と衝突する稀ケースは `absolute+0` で label 解釈を強制可能。

### Alternation

`(a|b|c)` でカッコ区切りの選択肢を書ける。

```
eth/(vlan|qinq)
eth/(vlan|qinq)/ipv4/tcp
```

MVP 制約 (codegen が enforce):
- 2〜4 alt
- すべての alt が **同じ header size** (uniform advance のため)
- `?`/`+`/`*` 等の quantifier は alt 全体に付けられない (= QuantOne のみ)
- ネスト不可
- 先頭 layer 不可
- alt 後の layer は **すべての alt が同一の dispatch を提供** している必要 (例: VLAN/QinQ → IPv4 はどちらも `ethertype=0x0800` で揃うので OK。IPv4/IPv6 → TCP は `protocol` vs `next_header` で異なるので resolve エラー)。

### Label

同じ protocol が 2 段以上出てくると `proto.field` で曖昧。`@name` で明示できる。

```
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.dst == 0xc0a80101 and inner.dport == 443
```

ラベル名: 英数字 + `_`。`XDP_*` 等の予約語は不可。1 つの protocol あたり最大 2 ラベル (MVP)。

## 実例

### 基本

```bash
# ICMP echo request だけ
sudo xdp-ninja --dsl -i veth0 "eth/ipv4/icmp[type==8]"

# IPv6 TCP に絞って snaplen 256
sudo xdp-ninja --dsl -i veth0 "eth/ipv6/tcp capture headers+128"

# fexit 観測で XDP が DROP したものだけ
sudo xdp-ninja --dsl -i veth0 --mode exit "eth/ipv4/tcp where action == XDP_DROP"
```

### encapsulation

```bash
# VLAN 任意 1 段の TCP/443
sudo xdp-ninja --dsl -i veth0 "eth/vlan?/ipv4/tcp[dport==443]"

# QinQ + VLAN いずれか
sudo xdp-ninja --dsl -i veth0 "eth/(vlan|qinq)/ipv4/tcp"

# MPLS スタック (s-bit で終端、IPv4 ペイロード)
sudo xdp-ninja --dsl -i veth0 "eth/mpls+/ipv4/tcp"

# VXLAN inner Ethernet/IP/TCP
sudo xdp-ninja --dsl -i veth0 "eth/ipv4/udp/vxlan/eth/ipv4/tcp"

# GTP-U inner IP, ラベル付き outer/inner
sudo xdp-ninja --dsl -i veth0 \
  "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.src == 0xc0a80001"
```

### where と capture の組合せ

```bash
# total_length 100 byte 超の TCP のみ、ヘッダ + 64 byte 取得
sudo xdp-ninja --dsl -i veth0 \
  "eth/ipv4/tcp where ipv4.total_length > 100 capture headers+64"

# TCP/443 か TCP/80
sudo xdp-ninja --dsl -i veth0 \
  "eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80"
```

## MVP 制限まとめ

実装中だが今は使えないもの:

| 機能 | 状態 | 代替 |
|---|---|---|
| `field in [v1, v2, ...]` | 未対応 | `where` で `or` 連結 |
| `field has FLAG` | 未対応 | bitmask 比較を `where` で |
| `flow.is_new` 等 flow 状態 | 未対応 | — |
| `capture f1, f2` フィールド列 | 未対応 | `capture headers+N` |
| chain 内 hs を含む `headers+N` | 未対応 | quantifier 確定後のチェーンに使う |
| Sanity self-dispatch 連鎖 | 未対応 | NO_CHECK / Field self-dispatch を使う |
| alt のネスト / 異種サイズ | 未対応 | 同サイズ alt のみ |
| alt 後の layer 異種 dispatch | 未対応 | vocab で揃えるか filter を分割 |
| 算術ネスト 4 段以上 | 未対応 | 中間値を別 filter 起動で計算 |

## 仕組みのざっくり

1. one-liner を **AST → IR** に解決 (vocab に照らして protocol/field/dispatch をバインド)
2. IR を **eBPF 命令** に codegen
   - 静的チェーンや predicate は素直に展開
   - chain (`+`/`*`/大きい `{n,m}`) は **bpf_loop + bpf2bpf callback** で BTF func_info 付きで emit
   - alternation は uniform-size 制約のもとで sequence 展開
3. 既存の runFilter / capture / fentry-fexit ラッパに乗せて kernel に load
4. verifier が通ればそのまま動く。MVP 範囲は **kernel 5.17+** (bpf_loop 必須) で動作確認

## 参考

- [dsl-overview.md](./dsl-overview.md) — DSL ドキュメント index
- [dsl-grammar.md](./dsl-grammar.md) — formal EBNF + 例文
- [dsl-followups.md](./dsl-followups.md) — 残作業
- vocab 一覧: `pkg/kunai/protocols/*.p4`
