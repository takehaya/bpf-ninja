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
| `gtp` | GTP-U (固定 8 B + E/S/PN flag で optional 4 B + ext header 列) |
| `srv6` | SRH (固定 8 B + segment list)。segment list は `srv6.segments[N]` で aux header stack として access |

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

**Aux header field** にも bracket 内でアクセスできる (例: GTP-U の opt block):

```
eth/ipv4/udp/gtp[opt.next_ext == 0]/ipv4/tcp     # GTP の auxiliary header opt の next_ext field
```

ただし aux header stack (`gtp.exts`, `srv6.segments` 等) は index または `where any/all(...)` 必要。詳細は §Where 節 を参照。

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

| 形 | 例 | 用途 |
|---|---|---|
| `proto.field` | `tcp.dport` | primary header の field (チェーン内 1 個のとき) |
| `@label.field` | `outer.src` | 同 protocol が複数あるときラベルで識別 |
| `proto.aux.field` | `gtp.opt.next_ext` | 単発 auxiliary header の field |
| `proto.stack[N].field` | `srv6.segments[0].addr` | aux header stack の N 番目 (静的 index) |
| `proto.stack[expr].field` | `srv6.segments[srv6.last_entry].addr` | 動的 index (parent header field 由来) |
| `proto.options.NAME.field` | `tcp.options.MSS.value` | TCP/IPv4 option lookup |

#### Aux header / stack / options アクセスの実例

```
# GTP-U の opt block の next_ext (gating 自動)
eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.next_ext == 0

# SRv6 segment list の特定位置
eth/ipv6/srv6/tcp where srv6.segments[0].addr == fc00::1            # 最終 dest (wire 先頭)
eth/ipv6/srv6/tcp where srv6.segments[srv6.last_entry].addr == X    # 最後の hop
eth/ipv6/srv6/tcp where srv6.segments[srv6.segments_left].addr == X # 現 active hop

# IPv6 / GTP-U extension headers
eth/ipv6/tcp where ipv6.exts[0].next_header == 44                    # 最初の ext type
eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts[0].ext_type == 1            # 最初の GTP ext type

# TCP option lookup (走査して match)
eth/ipv4/tcp where tcp.options.MSS.value == 1460
eth/ipv4/tcp where tcp.options.WS.shift > 5
eth/ipv4/tcp where tcp.options.TS.val > 0
```

#### Quantifier (`any` / `all`)

aux header stack 全 entry に対する量化:

```
# どれかの segment が一致 (∃)
eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)

# 全 segment が一致 (∀)
eth/ipv6/srv6/tcp where all(srv6.segments.addr == fc00::1)
```

`any/all` 内では aux header stack 名を **index 無し** で書く (= iteration 変数)。EXPR 内に stack 参照は **1 個まで** (複数あると parse error)。

SRv6 segments のような parent-count 系には自動 count guard が入る (= `srv6.last_entry+1` を超えた walk は無視)。

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

実装中だが今は使えないもの (✅ 完了済み項目は詳細を [`dsl-followups.md`](./dsl-followups.md) §F1-F13 参照):

| 機能 | 状態 | 代替 / 備考 |
|---|---|---|
| `field in [v1, v2, ...]` | ✅ 整数値で実装済 (F7) | IPv4/IPv6/MAC/CIDR alternatives は scope outside、`where` で `or` 連結 |
| `field has FLAG` | ✅ F6 bitwise で代替 | `tcp.flags & 0x12 == 0x12` のように書く |
| `capture f1, f2` フィールド列 | 未対応 | `capture headers+N` |
| chain 内 hs を含む `headers+N` | 未対応 | quantifier 確定後のチェーンに使う |
| Sanity self-dispatch 連鎖 | 未対応 | NO_CHECK / Field self-dispatch を使う |
| alt のネスト (grouping のみ) | ✅ P3-13 で実装 | `((a\|b)\|(c\|d))` は resolver で `(a\|b\|c\|d)` に平坦化される (alt member 数は altCountCap = 4 まで) |
| alt のネストに quantifier (`(a\|b)?`) | 未対応 | optional な内側 alt は意味が違うので flatten 不可。当面 reject |
| alt 異種サイズ | ✅ P3-12 で実装 | `(ipv4\|ipv6)/tcp` のように size の違う alt が動く |
| alt 後の layer 異種 dispatch | ✅ P3-12 で実装 | `(ipv4\|ipv6)/tcp` で `protocol` vs `next_header` の field 違いを per-alt JNE で吸収 |
| where / capture が異種サイズ alt を跨ぐ | ✅ PR-A/B で実装 | `(ipv4\|ipv6)/tcp where tcp.dport == 443` も `capture headers+64` も `where tcp.options.MSS.value == 1460` も per-layer entry slot で動く |
| where が alt member を直接参照 (`where ipv6.src == ...`) | 未対応 | alt 別の field なのでどちらの alt が match したか区別不可。bracket predicate `(ipv4\|ipv6[src==fe80::1])/tcp` で書く |
| 算術ネスト 4 段以上 | 未対応 | 中間値を別 filter 起動で計算 |
| `Int<128>` の `+`/`-` | ✅ 完了 (F4) | `field == field` / `field op const == field` / `field op field == field` 全形が動く |
| `Int<128>` ordered cmp (`<`/`>`) | ✅ bracket / where-arith 両方 (F3) | `ipv6[dst < fe80::ffff]` も `where ipv6.src < ipv6.dst` も両方動く |

## 型エラーの例

resolver / parser が出す主要なエラーパターン (詳しくは [`dsl-types.md`](./dsl-types.md))。

### 値が field 幅に収まらない

```
$ xdp-ninja -i eth0 --dsl 'eth/ipv4/tcp where tcp.dport > 99999'
1:30: value 99999 does not fit in bit<16> (in arithmetic context)
```

`tcp.dport` は `bit<16>` field なので、99999 は narrow できない。`> 65535` に書き直すか、より広い field を使う。

### CIDR の host bits が立っている

```
$ xdp-ninja -i eth0 --dsl 'eth/ipv4[src==10.0.0.5/24]/tcp'
1:14: CIDR "10.0.0.5/24" has host bits set; network would be 10.0.0.0/24
  (suggestion: 10.0.0.0/24 for the subnet, or 10.0.0.5/32 for the single host)
```

CIDR は network address (boundary 整列) を要求する。`10.0.0.0/24` で subnet match、`10.0.0.5/32` で host match の使い分けを明示する。

### division / modulo by zero (静的)

```
$ xdp-ninja -i eth0 --dsl 'eth/ipv4/tcp where tcp.dport / 0 == 1'
1:33: division by zero
```

書き間違いを防ぐため resolver が reject。runtime に divisor が 0 の場合は BPF の既定で `0` が返る。

### Bool に対する ordered cmp

```
$ xdp-ninja -i eth0 --dsl 'eth/ipv4/tcp where true < false'
1:25: ordered comparison < not allowed for Bool (Bool supports only == and !=)
```

Bool には自然順序がないので `<`, `>` 等は禁止。`==` (iff) / `!=` (xor) を使う。

## Bool atom の使い方

`where` 直下に bool atom を書ける ([`dsl-types.md` §5.4](./dsl-types.md#54-intn--bool-coercion-bool-文脈))。

```
where true                              # 常に match (where 省略と等価)
where false                             # 常に no-match
where gtp.opt.exists                    # GTP-U の opt block が抽出されたか
where tcp.dport                         # tcp.dport != 0 の縮約 (Int<N> -> Bool decay)
where (tcp.dport == 443) == gtp.opt.exists   # iff (両方真 or 両方偽)
where (tcp.dport == 443) != gtp.opt.exists   # xor (片方だけ真)
```

## 仕組みのざっくり

1. one-liner を **AST → IR** に解決 (vocab に照らして protocol/field/dispatch をバインド)
   - 同時に **型システム** が異幅 cmp の widening、リテラルの fit-check、Bool/Action/CIDR の文脈チェックを行う ([`dsl-types.md`](./dsl-types.md))
2. IR を **eBPF 命令** に codegen
   - 静的チェーンや predicate は素直に展開
   - chain (`+`/`*`/大きい `{n,m}`) は **bpf_loop + bpf2bpf callback** で BTF func_info 付きで emit
   - alternation は uniform-size 制約のもとで sequence 展開
3. 既存の runFilter / capture / fentry-fexit ラッパに乗せて kernel に load
4. verifier が通ればそのまま動く。MVP 範囲は **kernel 5.17+** (bpf_loop 必須) で動作確認

## 参考

- [dsl-overview.md](./dsl-overview.md) — DSL ドキュメント index
- [dsl-grammar.md](./dsl-grammar.md) — formal EBNF + 例文
- [dsl-types.md](./dsl-types.md) — 型システム (型・暗黙変換・widening・fit check・エラーカタログ)
- [dsl-followups.md](./dsl-followups.md) — 残作業
- vocab 一覧: `pkg/kunai/protocols/*.p4`
