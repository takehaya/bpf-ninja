# xdp-ninja DSL 利用ガイド

フィルタ式は **xdp-ninja DSL** としてコンパイルされる (default)。tcpdump/cbpfc では書きにくい多段カプセル化 (GTP-U over UDP, MPLS label stack, VXLAN inner Ethernet, …) を「プロトコルスタックの形」のまま記述できるのがゴール。

このドキュメントは利用者向け。formal な EBNF と例文表は [dsl-grammar.md](./dsl-grammar.md) にある。新しいプロトコル vocab を書きたい場合は [`pkg/kunai/protocols/`](../../pkg/kunai/protocols/) の既存 .p4 と [`pkg/kunai/vocab/loader.go`](../../pkg/kunai/vocab/loader.go) を参考にする。

## クイックスタート

```bash
sudo xdp-ninja -i veth0 "eth/ipv4/tcp[dport==443]"
```

- DSL は **default**。tcpdump/cBPF 構文を使いたいときだけ `--cbpf` を付ける (legacy、deprecation notice 出る)。
- フィルタ式は **位置引数** として末尾に渡す。
- 既存の `-w pcap`, `-c count`, `--mode entry/exit/xdp/tc-entry/tc-exit` などはすべて DSL でも使える。

#### `--mode` 一覧

| Mode | Attach 方法 | 既存プログラム | XDP/TC return action 観測 | 主用途 |
|---|---|---|---|---|
| `entry` (default) | XDP fentry trampoline | 必須 (BTF 付) | × (packet only) | production XDP に来る前のパケットを観測 |
| `exit` | XDP fexit trampoline | 必須 (BTF 付) | ○ (`XDP_PASS`/`DROP`/...) | XDP の判断結果を観測。`where action == XDP_DROP` 等で絞れる |
| `xdp` | netdev に直接 attach | 不要 (既に attach されてるとエラー) | n/a (常に `XDP_PASS`) | XDP が attach されてない netdev の standalone capture |
| `tc-entry` | TC clsact fentry trampoline | 必須 (TC clsact filter; `tc filter add ... direction ingress/egress`) | × (skb の pre-state) | tc-bpf が来る前の skb を観測 |
| `tc-exit` | TC clsact fexit trampoline | 必須 (同上) | ○ (`TC_ACT_OK/SHOT/...`) | tc-bpf の verdict を観測。`where action == TC_ACT_SHOT` 等 |

`tc-entry`/`tc-exit` は XDP 不要 (TC 層の clsact filter に対する fentry/fexit)。target 指定は `-p <progID>` のみ (TC clsact qdisc の interface walk は未配線)。

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

算術ネストは MVP で **16 段まで** (それを超えると `ErrNotImplemented`、`maxArithDepth` 定数で管理)。

#### フィールド参照

| 形 | 例 | 用途 |
|---|---|---|
| `proto.field` | `tcp.dport` | primary header の field (チェーン内 1 個のとき) |
| `@label.field` | `outer.src` | 同 protocol が複数あるときラベルで識別 |
| `proto.aux.field` | `gtp.opt.next_ext` | 単発 auxiliary header の field |
| `proto.stack[N].field` | `srv6.segments[0].addr` | aux header stack の N 番目 (静的 index) |
| `proto.stack[expr].field` | `srv6.segments[srv6.last_entry].addr` | 動的 index (parent header field 由来) |
| `proto.options.NAME.field` | `tcp.options.MSS.value` | TCP/IPv4 option lookup |

あるプロトコルにどんな aux / stack / options が露出してるか調べたいときは `xdp-ninja --dsl-help <proto>` で full reference を出せる (例: `--dsl-help srv6` で `segments[0..7]` stack の field と access pattern が、`--dsl-help gtp` で `opt` aux + `exts[0..7]` stack が、`--dsl-help tcp` で options walk の named entries が一覧される)。

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
eth/ipv4/tcp where tcp.options.TS.tsval > 0
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

`action == <NAME>` は **fexit 系の mode** (`--mode exit` / `--mode tc-exit`) でのみ使える。fentry 系 (`entry` / `tc-entry`) では下流プログラムの戻り値がまだ存在せず、`--mode xdp` は xdp-ninja 自身が常に `XDP_PASS` を返す立場で観測対象がないので、いずれも resolver で reject される。

| Mode | サポートされる定数 |
|---|---|
| `--mode exit` (XDP fexit) | `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT` |
| `--mode tc-exit` (TC fexit) | `TC_ACT_UNSPEC` (-1), `TC_ACT_OK`, `TC_ACT_RECLASSIFY`, `TC_ACT_SHOT`, `TC_ACT_PIPE`, `TC_ACT_STOLEN`, `TC_ACT_QUEUED`, `TC_ACT_REPEAT`, `TC_ACT_REDIRECT`, `TC_ACT_TRAP` |

(host adapter ごとの定数表は `pkg/kunai/host/xdp/xdp.go` / `pkg/kunai/host/tc/tc.go` の `Capabilities()` を参照。新 host を足すときは同 shape の `Action map[string]int32` + `ActionFetcher` を提供する。)

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

#### snaplen トレードオフ (重要)

`capture` 句を **書かない** = `capture all` の sugar。 **既定で full packet を取る**
(host 側 `DefaultCapLen=1500` にフォールバック、 libpcap / tcpdump の `-s 0`
相当)。 これは「`tcp where dport==443` と書いたら payload まで取れる」 という
tcpdump 互換の UX を優先した設計。

高 rate capture (>1 Mpps 級) で ringbuf 予約サイズを縮めて throughput を上げ
たい場合は **明示的に `capture headers` (or `headers+N`)** を書く。 paper §6
の R32 数字 (filter+payload 14+ Mpps) はこの opt-in 状態で測定している:

| 書き方 | ringbuf 予約 | 用途 |
|---|---|---|
| `tcp where dport==443` (= `capture all` 暗黙) | 1500 B | tcpdump 相当、 payload 完全保存 |
| `tcp where dport==443 capture headers` | 54 B | 高 rate、 header 解析だけしたい |
| `tcp where dport==443 capture headers+64` | 118 B | header + L7 先頭 64 B |
| `--snaplen N` (CLI 上書き) | N B | 上記全てを N で clamp |

なお **filter 評価コスト** (in-kernel scratch read) は `capture` 句に関係なく
常に `inferFilterMinPrefix` で動的に縮められている (R32 の filter cost
14×→0× win)。 縮まらないのは ringbuf 予約 / pcap 出力サイズだけ。

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
sudo xdp-ninja -i veth0 "eth/ipv4/icmp[type==8]"

# IPv6 TCP に絞って snaplen 256
sudo xdp-ninja -i veth0 "eth/ipv6/tcp capture headers+128"

# fexit 観測で XDP が DROP したものだけ
sudo xdp-ninja -i veth0 --mode exit "eth/ipv4/tcp where action == XDP_DROP"
```

### encapsulation

```bash
# VLAN 任意 1 段の TCP/443
sudo xdp-ninja -i veth0 "eth/vlan?/ipv4/tcp[dport==443]"

# QinQ + VLAN いずれか
sudo xdp-ninja -i veth0 "eth/(vlan|qinq)/ipv4/tcp"

# MPLS スタック (s-bit で終端、IPv4 ペイロード)
sudo xdp-ninja -i veth0 "eth/mpls+/ipv4/tcp"

# VXLAN inner Ethernet/IP/TCP
sudo xdp-ninja -i veth0 "eth/ipv4/udp/vxlan/eth/ipv4/tcp"

# GTP-U inner IP, ラベル付き outer/inner
sudo xdp-ninja -i veth0 \
  "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.src == 0xc0a80001"
```

### where と capture の組合せ

```bash
# total_length 100 byte 超の TCP のみ、ヘッダ + 64 byte 取得
sudo xdp-ninja -i veth0 \
  "eth/ipv4/tcp where ipv4.total_length > 100 capture headers+64"

# TCP/443 か TCP/80
sudo xdp-ninja -i veth0 \
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
$ xdp-ninja -i eth0 'eth/ipv4/tcp where tcp.dport > 99999'
1:30: value 99999 does not fit in bit<16> (in arithmetic context)
```

`tcp.dport` は `bit<16>` field なので、99999 は narrow できない。`> 65535` に書き直すか、より広い field を使う。

### CIDR の host bits が立っている

```
$ xdp-ninja -i eth0 'eth/ipv4[src==10.0.0.5/24]/tcp'
1:14: CIDR "10.0.0.5/24" has host bits set; network would be 10.0.0.0/24
  (suggestion: 10.0.0.0/24 for the subnet, or 10.0.0.5/32 for the single host)
```

CIDR は network address (boundary 整列) を要求する。`10.0.0.0/24` で subnet match、`10.0.0.5/32` で host match の使い分けを明示する。

### division / modulo by zero (静的)

```
$ xdp-ninja -i eth0 'eth/ipv4/tcp where tcp.dport / 0 == 1'
1:33: division by zero
```

書き間違いを防ぐため resolver が reject。runtime に divisor が 0 の場合は BPF の既定で `0` が返る。

### Bool に対する ordered cmp

```
$ xdp-ninja -i eth0 'eth/ipv4/tcp where true < false'
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

## `--mode xdp`: native XDP として直接 attach

通常の xdp-ninja は **既存の XDP プログラム** に fentry/fexit で trampoline attach する観測ツール (=「他人の XDP を覗く」モード)。一方 `--mode xdp` を付けると **xdp-ninja 自身が XDP として interface に直接 attach** する。「interface に何も XDP が attach されていない、けど filter したい」場合に便利。

```bash
# DSL で TCP/443 だけ capture, それ以外は素通し (XDP_PASS)
sudo xdp-ninja --mode xdp -i eth0 "eth/ipv4/tcp[dport==443]"

# DSL filter (UDP は全部 capture)
sudo xdp-ninja --mode xdp -i eth0 "eth/ipv4/udp"

# 旧 pcap syntax を使いたい時は --cbpf 必須 (legacy)
sudo xdp-ninja --cbpf --mode xdp -i eth0 "tcp port 443"

# 既存 XDP がある interface では fail (production XDP を意図せず壊さない設計)
sudo xdp-ninja --mode xdp -i eth0 "eth/ipv4/tcp[dport==443]"
# → error: interface eth0 already has XDP program (id=42, mode=driver);
#          use --mode entry to observe it via fentry, or detach the existing program first
```

挙動:
- マッチしたパケットは `bpf_perf_event_output` で perf ring に capture
- どのパケットも常に `XDP_PASS` を返す (drop モードは v2 follow-up)
- mode metadata 値は `2` (= xdp-native; 既存 entry=0, exit=1)

DSL / tcpdump 両方とも `--mode xdp` で完全 load 可能 (kunai codegen が packet-pointer-safe な bound check を emit する設計、F14 完了済)。IPv4 / IPv6 / alternation / 各種 quantifier / capture / where すべて verifier 通過確認 (`internal/program/program_xdp_test.go::xdpNativeDSLExprs` 参照)。

## 出力ファイルレイアウト (per-CPU sharded)

R22 以降、 ringbuf は per-CPU shard (`BPF_MAP_TYPE_ARRAY_OF_MAPS` の inner =
個別 `BPF_MAP_TYPE_RINGBUF`) で構成される。 user-space 側も shard ごとに
1 goroutine + 1 file で受けるので、 `-w path.pcap` を指定したとき出力は:

```
path.pcap         ← SHB+IDB のみの marker file (0 packets)
path.pcap.cpu0    ← CPU 0 が受けた packets
path.pcap.cpu1    ← CPU 1 が受けた packets
...
path.pcap.cpuN    ← (N = nproc - 1)
```

`tcpdump -r path.pcap` は marker を読むだけで packets は出ない。 各 `cpuN` ファイル
は独立した valid pcap-ng として開ける:

```bash
# CPU 12 が受けた分だけ読む
tcpdump -r path.pcap.cpu12

# 全 shard を mergecap でまとめる
mergecap -w merged.pcap path.pcap.cpu*

# 確認: shard ごとの packet count
for f in path.pcap.cpu*; do echo "$(basename $f): $(tcpdump -r $f 2>/dev/null | wc -l)"; done
```

**注意**: `xdp-ninja convert` は `--raw-dump` 用の `.raw` を pcap-ng に変換する
サブコマンドで、 **`.cpuN` pcap-ng shards は処理しない**。 shards をまとめたい
場合は wireshark 同梱の `mergecap` を使う。 raw-dump path
(`--raw-dump -w foo.raw`) を使う場合は `.cpuN` 分割が同じ命名規則で起こり、
`xdp-ninja convert -i foo.raw.cpu0 ...` で 1 個ずつ pcap-ng に変換できる。

## Performance flags

高 rate capture (>1 Mpps 級) で使う flag 群。 通常用途では既定値で十分。

| Flag | 既定 | 効果 / 注意 |
|---|---|---|
| `--snaplen N` | 0 (= MaxCapLen or DefaultCapLen=1500) | 1 packet あたりの保存 byte 数を CLI から強制上書き。 DSL の `capture` 句より優先 |
| `--ringbuf-size MB` | 16 | per-CPU ringbuf 1 個あたりの size。 storage 帯域が追いつかない時は増やす |
| `--fast-reader` | off | mmap+atomic 直叩きの fastrb reader を使う。 cilium/ebpf の generic reader より低 CPU、 高 throughput |
| `--no-wakeup` | off | `BPF_RB_NO_WAKEUP` を全 submit に立てる。 reader 側 epoll wake が無くなり throughput up、 **代わりに p50 latency が 100µs → ~2.6ms に悪化** (1ms polling 床)。 `--fast-reader` 必須 |
| `--observer-prefetch` | off | filter scratch を 512 B 強制。 R12 の ice driver で L1-dcache prefetch が効くケースに opt-in |
| `--in-memory-buffer MB` | 0 (off) | raw-dump 出力先を mmap 上の `MAP_POPULATE` バッファに置く。 NVMe write が bottleneck な時に隠せる |
| `--null-output` | off | bench 用。 出力 file を一切開かず、 reader の CPU コストだけ測る |
| `--latency-sample-period N` | 0 (off) | N packet ごとに 1 サンプル、 BPF→reader latency (ns 単位) を tsv に蓄積 |
| `--latency-sample-output PATH` | (stderr) | 上の sample tsv の出力先 |
| `--raw-dump` | off | pcap-ng 経由を bypass。 packet bytes + header をそのまま raw に追記。 後で `xdp-ninja convert` で pcap-ng 化 |
| `--rx-hwts` | off | `bpf_xdp_metadata_rx_timestamp` kfunc を使って NIC の HW timestamp を埋め込む。 ice 等 6.8+ driver 対応のみ |

flag 同士の組合せメモ:

- `--no-wakeup` は必ず `--fast-reader` と一緒に。 cilium/ebpf reader は missing
  wake で永久ブロックする
- `--in-memory-buffer` は `--raw-dump` の時のみ意味あり (pcap-ng path には未対応)
- `--rx-hwts` は `--mode xdp` only。 entry/exit (fentry/fexit) では使えない
- `--snaplen 0` (CLI 既定) はバイパスを意味する。 強制 0B にしたい場合は
  `capture absolute 0` を DSL 側で書く

## Hand-test: `--dump-asm` で eBPF asm を覗く

`--dump-asm` を付けると、フィルタをコンパイルした結果の eBPF 命令列を **load せずに** stdout に print して exit する。`-i` / `-p` 不要。色々な式を試して codegen の挙動を確認したいときに便利。

2 段階のスコープがある:

| 値 | 範囲 |
|---|---|
| `--dump-asm filter` | kunai (DSL) または cbpfc (tcpdump) が出した **filter Main + Callbacks + CaptureInfo** だけ。target-agnostic ABI (R0=pkt_start, R1=pkt_end → R2=accept/reject @ filter_result) |
| `--dump-asm full` | 上記を `loadProbe` の wrapper (xdp_buff load + scratch コピー + bpf_xdp_output + return) で囲んだ完全な tracing program。map FD は 0 placeholder (load しないので無問題) |

```bash
# DSL filter のみ
xdp-ninja --dump-asm filter "eth/ipv4/tcp where tcp.dport == 443"

# tcpdump filter のみ (cbpfc 出力、 --cbpf 必須)
xdp-ninja --cbpf --dump-asm filter "tcp port 443"

# 完全な tracing program (mode 別に shape が変わる)
xdp-ninja --dump-asm full --mode entry "eth/ipv4/tcp[dport==443]"
xdp-ninja --dump-asm full --mode exit "eth/ipv4/tcp where action == XDP_DROP"
```

DSL の parse error / type error も同じ経路を通るので、`--dump-asm filter` は **構文/型のサニティチェック** にも使える (load 前に stderr で error 出して exit 1)。

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
