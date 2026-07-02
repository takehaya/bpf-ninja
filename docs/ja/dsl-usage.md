# xdp-ninja DSL 利用ガイド

フィルタ式は default で xdp-ninja DSL としてコンパイルされます。tcpdump/cbpfc では書きにくい多段カプセル化 (GTP-U over UDP、MPLS label stack、VXLAN inner Ethernet など) をプロトコルスタックの形のまま記述できることがゴールです。

このドキュメントは利用者向けです。formal な EBNF と例文表は [dsl-grammar.md](./dsl-grammar.md) にあります。新しいプロトコル vocab を書きたい場合は [`pkg/kunai/protocols/`](../../pkg/kunai/protocols/) の既存 .p4 と [`pkg/kunai/vocab/loader.go`](../../pkg/kunai/vocab/loader.go) を参考にしてください。

## クイックスタート

```bash
sudo xdp-ninja -i veth0 "eth/ipv4/tcp[dport==443]"
```

- DSL が default です。tcpdump/cBPF 構文を使いたいときだけ `--cbpf` を付けますが、これは legacy 扱いで deprecation notice が出ます。
- フィルタ式は位置引数として末尾に渡します。
- 既存の `-w pcap`、`-c count`、`--mode entry/exit/xdp/tc-entry/tc-exit` などはすべて DSL でも使えます。

#### `--mode` 一覧

| Mode | Attach 方法 | 既存プログラム | XDP/TC return action 観測 | 主用途 |
|---|---|---|---|---|
| `entry` (default) | XDP fentry trampoline | 必須 (BTF 付) | × (packet only) | production XDP に来る前のパケットを観測 |
| `exit` | XDP fexit trampoline | 必須 (BTF 付) | ○ (`XDP_PASS`/`DROP`/...) | XDP の判断結果を観測する。`where action == XDP_DROP` 等で絞れる |
| `xdp` | netdev に直接 attach | 不要 (既に attach されているとエラー) | n/a (常に `XDP_PASS`) | XDP が attach されていない netdev の standalone capture |
| `tc-entry` | TC clsact fentry trampoline | 必須 (TC clsact filter; `tc filter add ... direction ingress/egress`) | × (skb の pre-state) | tc-bpf が来る前の skb を観測 |
| `tc-exit` | TC clsact fexit trampoline | 必須 (同上) | ○ (`TC_ACT_OK/SHOT/...`) | tc-bpf の verdict を観測する。`where action == TC_ACT_SHOT` 等 |

`tc-entry`/`tc-exit` は TC 層の clsact filter に対する fentry/fexit なので、XDP は不要です。TC clsact qdisc の interface walk は未配線のため、target 指定は `-p <progID>` のみです。

## 文法

### Layer chain

レイヤをスラッシュで連結します。

```
eth/ipv4/tcp
eth/ipv6/icmp6
eth/ipv4/udp/vxlan/eth/ipv4/tcp     # 内側 Ethernet を再度展開
eth/ipv4/udp/gtp/ipv4/tcp           # GTP-U の内側 IP
```

各レイヤは vocab で定義された lowercase の protocol 名です。バンドル済みの vocab は次のとおりです。

| 名前 | 用途 | 補足 |
|---|---|---|
| `eth` | Ethernet II | DIX 形式、14 byte |
| `ipv4`、`ipv6` | L3 |
| `tcp`、`udp` | L4 |
| `icmp`、`icmp6` | type/code フィルタに使える |
| `vlan`、`qinq` | 802.1Q / 802.1ad |
| `cw` | EoMPLS Control Word |
| `mpls` | label stack (詳細は後述) |
| `gre`、`vxlan`、`geneve` | encapsulation |
| `gtp` | GTP-U (固定 8 B + E/S/PN flag で optional 4 B + ext header 列) |
| `srv6` | SRH (固定 8 B + segment list)。segment list は `srv6.segments[N]` で aux header stack として access できる |

### Quantifier

レイヤの後ろに付けます。連続出現を表します。

| 構文 | 意味 |
|---|---|
| (なし) | 必ず 1 回 |
| `?` | 0 または 1 回 (optional) |
| `+` | 1 回以上 (bpf_loop で展開) |
| `*` | 0 回以上 (bpf_loop、先頭の peek でスキップ) |
| `{n}` | ちょうど n 回 (静的アンロール、`{n,n}` と等価) |
| `{n,m}` | n〜m 回。m≤4 は静的アンロール、それ以上は bpf_loop |
| `{n,}` | n 回以上 (上限省略、bpf_loop で展開) |

例を示します。

```
eth/vlan?/ipv4/tcp                  # 任意 VLAN 1 段
eth/vlan{1,3}/ipv4/tcp              # VLAN 1〜3 段
eth/mpls+/ipv4/tcp                  # MPLS label stack (s-bit で終端)
eth/mpls{2,8}/ipv4/tcp              # MPLS 2〜8 段、8 段で打切
eth/vlan*/ipv4/tcp                  # VLAN 0〜N 段
```

### Predicate

`[field==value]` で同レイヤのヘッダフィールドに条件を付けます。カンマ区切りで複数条件を書くと AND になります。

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

サポートする演算子は `==`、`!=`、`<`、`<=`、`>`、`>=` です。

値は整数リテラル (10進 / `0x` 16進)、IPv4 (`10.0.0.1`)、IPv4 CIDR (`10.0.0.0/8`)、IPv6 (`fe80::1`)、IPv6 CIDR (`2001:db8::/32`)、MAC (`de:ad:be:ef:00:01`) です。

すべてのリテラルで `==` / `!=` が使えます。整数リテラルに限り ordered な比較 (`<`、`<=`、`>`、`>=`) も使えます。

Aux header field にも bracket 内でアクセスできます。GTP-U の opt block を例に示します。

```
eth/ipv4/udp/gtp[opt.next_ext == 0]/ipv4/tcp     # GTP の auxiliary header opt の next_ext field
```

ただし `gtp.exts` や `srv6.segments` などの aux header stack には index または `where any/all(...)` が必要です。詳細は §Where 節を参照してください。

### Where 節

レイヤチェーンの後に `where <expr>` を付けて、より広い条件を書きます。

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

算術ネストは MVP では 16 段までです。それを超えると `ErrNotImplemented` になります。上限は `maxArithDepth` 定数で管理されています。

#### フィールド参照

| 形 | 例 | 用途 |
|---|---|---|
| `proto.field` | `tcp.dport` | primary header の field (チェーン内 1 個のとき) |
| `@label.field` | `outer.src` | 同 protocol が複数あるときラベルで識別 |
| `proto.aux.field` | `gtp.opt.next_ext` | 単発 auxiliary header の field |
| `proto.stack[N].field` | `srv6.segments[0].addr` | aux header stack の N 番目 (静的 index) |
| `proto.stack[expr].field` | `srv6.segments[srv6.last_entry].addr` | 動的 index (parent header field 由来) |
| `proto.options.NAME.field` | `tcp.options.MSS.value` | TCP/IPv4 option lookup |

あるプロトコルにどんな aux / stack / options が露出しているか調べたいときは、`xdp-ninja --dsl-help <proto>` で full reference を出せます。たとえば `--dsl-help srv6` では `segments[0..7]` stack の field と access pattern が、`--dsl-help gtp` では `opt` aux + `exts[0..7]` stack が、`--dsl-help tcp` では options walk の named entries が一覧されます。

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

aux header stack の全 entry に対して量化できます。

```
# どれかの segment が一致 (∃)
eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)

# 全 segment が一致 (∀)
eth/ipv6/srv6/tcp where all(srv6.segments.addr == fc00::1)
```

`any/all` 内では aux header stack 名を index 無しで書きます。これが iteration 変数になります。EXPR 内に書ける stack 参照は 1 個までで、複数あると parse error になります。

SRv6 segments のような parent-count 系には自動 count guard が入り、`srv6.last_entry+1` を超えた walk は無視されます。

#### action atom

`action == <NAME>` は fexit 系の mode (`--mode exit` / `--mode tc-exit`) でのみ使えます。fentry 系 (`entry` / `tc-entry`) では下流プログラムの戻り値がまだ存在せず、`--mode xdp` は xdp-ninja 自身が常に `XDP_PASS` を返す立場で観測対象がないため、いずれも resolver で reject されます。

| Mode | サポートされる定数 |
|---|---|
| `--mode exit` (XDP fexit) | `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT` |
| `--mode tc-exit` (TC fexit) | `TC_ACT_UNSPEC` (-1), `TC_ACT_OK`, `TC_ACT_RECLASSIFY`, `TC_ACT_SHOT`, `TC_ACT_PIPE`, `TC_ACT_STOLEN`, `TC_ACT_QUEUED`, `TC_ACT_REPEAT`, `TC_ACT_REDIRECT`, `TC_ACT_TRAP` |

host adapter ごとの定数表は `pkg/kunai/host/xdp/xdp.go` / `pkg/kunai/host/tc/tc.go` の `FexitCapabilities()` を参照してください。新 host を足すときは `Capabilities.Lang` に同 shape の `Action map[string]int32` + `ActionFetcher` を提供します。

### Capture 節

`capture` でパケットを perf ring に送る量・条件を細かく制御できます。

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

per-capture の `where` はトップレベルの `where` と AND で合成されます。

MVP では次の制限があります。

- フィールド列指定 (`capture tcp.flags, ipv4.dst`) は未対応です。
- chain (`+`/`*`/`{n,m}`) を含むフィルタは静的に長さを確定できないので、`headers (+N)?` / `<label> (+N)?` は使えず resolve エラーになります。`absolute N` は chain 形に依存しないので使用可能です。
- proto 名で指定するとき chain 内に複数 instance があると ambiguous error になります。`@label` で一意化します。
- `absolute` は capture 内の contextual keyword です。label が `absolute` という名前と衝突する稀なケースでは `absolute+0` で label 解釈を強制できます。

#### snaplen トレードオフ (重要)

`capture` 句を書かない場合は `capture all` の sugar として扱われ、既定で full packet を取ります。host 側の `DefaultCapLen=1500` にフォールバックし、libpcap / tcpdump の `-s 0` 相当です。これは `tcp where dport==443` と書いたら payload まで取れるという tcpdump 互換の UX を優先した設計です。

高 rate capture (>1 Mpps 級) で ringbuf 予約サイズを縮めて throughput を上げたい場合は、明示的に `capture headers` または `headers+N` を書きます。paper §6 の R32 数字 (filter+payload 14+ Mpps) はこの opt-in 状態で測定しています。

| 書き方 | ringbuf 予約 | 用途 |
|---|---|---|
| `tcp where dport==443` (= `capture all` 暗黙) | 1500 B | tcpdump 相当、payload 完全保存 |
| `tcp where dport==443 capture headers` | 54 B | 高 rate、header 解析だけしたい |
| `tcp where dport==443 capture headers+64` | 118 B | header + L7 先頭 64 B |
| `--snaplen N` (CLI 上書き) | N B | 上記全てを N で clamp |

なお filter 評価コスト (in-kernel scratch read) は `capture` 句に関係なく常に `inferFilterMinPrefix` で動的に縮められており、これが R32 の filter cost 14×→0× の win です。縮まらないのは ringbuf 予約 / pcap 出力サイズだけです。

### Alternation

`(a|b|c)` でカッコ区切りの選択肢を書けます。

```
eth/(vlan|qinq)
eth/(vlan|qinq)/ipv4/tcp
```

codegen が enforce する MVP 制約は次のとおりです。

- 2〜4 alt
- `?`/`+`/`*` 等の quantifier は alt 全体には付けられず、QuantOne のみ
- 先頭 layer 不可
- 各 alt は親からの Field dispatch const が必要です (NoCheck dispatch の alt は不可)
- ネストした alt group は flatten され、`(a|b|c|d)` と等価に扱われます
- header size は alt 間で異なっていても構いません。サイズが異なる場合、後続 layer の field 参照は実行時 offset 経由になります
- alt 後の layer は、各 alt に対する dispatch const を持っている必要があります。VLAN/QinQ → IPv4 のように全 alt で揃っていれば単一チェック、IPv4/IPv6 → TCP のように field が異なる場合も、alt ごとの dispatch (diverged dispatch) として動きます。

### Label

同じ protocol が 2 段以上出てくると `proto.field` では曖昧になります。`@name` で明示できます。

```
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.dst == 0xc0a80101 and inner.dport == 443
```

ラベル名は英数字と `_` です。`XDP_*` 等の予約語は使えません。MVP では 1 つの protocol あたり最大 2 ラベルです。

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

## 型エラーの例

resolver / parser が出す主要なエラーパターンを示します。詳しくは [`dsl-types.md`](./dsl-types.md) を参照してください。

### 値が field 幅に収まらない

```
$ xdp-ninja -i eth0 'eth/ipv4/tcp where tcp.dport > 99999'
1:30: value 99999 does not fit in bit<16> (in arithmetic context)
```

`tcp.dport` は `bit<16>` field なので、99999 は narrow できません。`> 65535` に書き直すか、より広い field を使います。

### CIDR の host bits が立っている

```
$ xdp-ninja -i eth0 'eth/ipv4[src==10.0.0.5/24]/tcp'
1:14: CIDR "10.0.0.5/24" has host bits set; network would be 10.0.0.0/24
  (suggestion: 10.0.0.0/24 for the subnet, or 10.0.0.5/32 for the single host)
```

CIDR は boundary 整列した network address を要求します。`10.0.0.0/24` で subnet match、`10.0.0.5/32` で host match の使い分けを明示します。

### division / modulo by zero (静的)

```
$ xdp-ninja -i eth0 'eth/ipv4/tcp where tcp.dport / 0 == 1'
1:33: division by zero
```

書き間違いを防ぐため resolver が reject します。runtime に divisor が 0 の場合は BPF の既定で `0` が返ります。

### Bool に対する ordered cmp

```
$ xdp-ninja -i eth0 'eth/ipv4/tcp where true < false'
1:25: ordered comparison < not allowed for Bool (Bool supports only == and !=)
```

Bool には自然順序がないので `<`、`>` 等は禁止です。`==` (iff) / `!=` (xor) を使います。

## Bool atom の使い方

`where` 直下に bool atom を書けます ([`dsl-types.md` §5.4](./dsl-types.md#54-intn--bool-coercion-bool-文脈))。

```
where true                              # 常に match (where 省略と等価)
where false                             # 常に no-match
where gtp.opt.exists                    # GTP-U の opt block が抽出されたか
where tcp.dport                         # tcp.dport != 0 の縮約 (Int<N> -> Bool decay)
where (tcp.dport == 443) == gtp.opt.exists   # iff (両方真 or 両方偽)
where (tcp.dport == 443) != gtp.opt.exists   # xor (片方だけ真)
```

## `--mode xdp` で native XDP として直接 attach する

通常の xdp-ninja は、既存の XDP プログラムに fentry/fexit で trampoline attach する観測ツールであり、他人の XDP を覗くモードです。一方 `--mode xdp` を付けると、xdp-ninja 自身が XDP として interface に直接 attach します。interface に何も XDP が attach されていないが filter したい場合に便利です。

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

挙動は次のとおりです。

- マッチしたパケットは `bpf_perf_event_output` で perf ring に capture されます。
- どのパケットも常に `XDP_PASS` を返します。drop モードは v2 follow-up です。
- mode metadata 値は xdp-native を表す 2 です。既存は entry=0、exit=1 です。

DSL / tcpdump の両方とも `--mode xdp` で完全に load 可能です。kunai codegen が packet-pointer-safe な bound check を emit する設計で、F14 として完了済みです。IPv4 / IPv6 / alternation / 各種 quantifier / capture / where のすべてで verifier 通過を確認しています。詳細は `internal/program/program_xdp_test.go::xdpNativeDSLExprs` を参照してください。

## 出力ファイルレイアウト (per-CPU sharded)

R22 以降、ringbuf は per-CPU shard (`BPF_MAP_TYPE_ARRAY_OF_MAPS` の inner は個別の `BPF_MAP_TYPE_RINGBUF`) で構成されます。user-space 側も shard ごとに 1 goroutine + 1 file で受けるので、`-w path.pcap` を指定したときの出力は次のようになります。

```
path.pcap         ← 全 shard を時刻順にマージした単一 pcap-ng (そのまま使える)
path.pcap.cpu0    ← CPU 0 が受けた packets (残置)
path.pcap.cpu1    ← CPU 1 が受けた packets (残置)
...
path.pcap.cpuN    ← (N = nproc - 1)
```

キャプチャ停止時 (Ctrl-C または `-c`) に、xdp-ninja は per-CPU shard を時刻順に k-way マージして base の `path.pcap` を単一 pcap-ng として書き出します。停止直後に `merging N shard(s) into path.pcap ...` と表示されるので、そこがマージ中です。`tcpdump -r path.pcap` でそのまま全パケットを時刻順に読めます。`.cpuN` は残るので、個別に読む・自分で mergecap することもできます。

```bash
# base をそのまま読む (全 CPU 分・時刻順)
tcpdump -r path.pcap

# CPU 12 が受けた分だけ読む
tcpdump -r path.pcap.cpu12

# 自分で mergecap したい場合 (base と同等)
mergecap -w merged.pcap path.pcap.cpu*
```

`-w` を付けない場合 (stdout ストリーミング) は、全 CPU を 1 本の pcap-ng ストリームに直列化してマージするので、`sudo xdp-ninja ... | tcpdump -r -` で全コア分が見えます。高レートでは `-w` を使ってください (stdout 直列化はインタラクティブ経路向け)。

注意点として、`xdp-ninja convert` は `--raw-dump` 用の `.raw` を pcap-ng に変換するサブコマンドで、`.cpuN` pcap-ng shards は処理しません。raw-dump path (`--raw-dump -w foo.raw`) を使う場合は `.cpuN` 分割が同じ命名規則で起こり、`xdp-ninja convert -i foo.raw.cpu0 ...` で 1 個ずつ pcap-ng に変換できます (raw-dump は自動マージの対象外)。

## 複数の (プログラム, 関数) に同時アタッチする

`-p` と `--func` はどちらも繰り返し指定できます。各 `--func` は、指定した全プログラムのうち **BTF にその関数を持つものすべて**にアタッチされます (無いプログラムはスキップ。どのプログラムにも無い関数名はエラー)。`--func` を省略した場合は各プログラムの entry 関数が対象です。

多段 dispatcher (cpu_dispatch → CPUMAP → 方向別ハンドラ) では capture point が方向ごとに別プログラムへ散り、さらに noinline サブ関数は呼び出し元プログラムごとに実体を持ちます (例: `pgwu_capture_point_dl` が v4/v6 ハンドラ両方に入る)。UL + DL v4 + DL v6 の全網羅は従来3回の起動が必要でしたが、1回で張れます。

```bash
# --list-progs で dispatcher から末端の prog ID を洗い出し
sudo xdp-ninja -i ens2f0 --list-progs

# UL + DL (v4/v6 両実体) を1回でアタッチ。--func pgwu_capture_point_dl は
# 1610/1611 の両方に、_ul は 1614 だけにマッチする
sudo xdp-ninja -p 1610 -p 1611 -p 1614 \
  --func pgwu_capture_point_ul --func pgwu_capture_point_dl \
  --arg-filter "imsi=999990000000001" -w all.pcap
```

- 全アタッチポイントが **1本の共有 ringbuf** に emit するので、出力は通常どおり 1 つの pcap に時刻順で入ります (`-w` なら終了時マージ、stdout なら直列化ストリーム)。
- `--arg-filter` は関数ごとに BTF を引いて検証・解決されます。同じ param 名が関数によって別の引数位置にあっても正しく効きます。指定した param を持たない関数が混ざるとエラーになります。
- XDP と tc のターゲット混在は不可 (別々に起動してください)。`--arg-echo` は単一 (プログラム, 関数) のみ。

## 関数引数の値を覗く (`--arg-echo`)

`--func` で狙ったサブ関数の整数引数が、実際にどんな値で呼ばれているかを見る診断モードです。`--arg-filter "imsi=..."` が当たらないとき、「そもそも引数にどんな値が乗っているか」を確認するのに使います (例: IMSI が 10 進なのか TBCD なのか)。パケットキャプチャはせず、引数だけを専用 ringbuf に流して表示します。

```bash
# 対象関数の絞り込み可能な整数引数を確認
sudo xdp-ninja -p 1661 --func pgwu_capture_point_ul --list-params
#   imsi  [8 bytes, unsigned, arg index 1]
#   teid  [4 bytes, unsigned, arg index 2]

# 1 回だけ観測して終了 (-c 1)
sudo xdp-ninja -p 1661 --func pgwu_capture_point_ul --arg-echo -c 1
#   pgwu_capture_point_ul: imsi=999990000000001 (0x38d7c50ba9c01) teid=12345 (0x3039)
```

- `--func` 必須。表示対象は `--list-params` が挙げる整数引数 (10 進と 16 進を併記)。
- `--arg-filter` と併用すると、その述語に**マッチした呼び出しだけ**を表示します。値の当たりを付けてから絞り込む、という使い方ができます。
- 連続して同じ引数タプルが来た場合は 1 行に畳んで `(xN)` と表示します。`-c N` で N 件表示したら終了、無指定なら Ctrl-C まで。
- リーダは capture path と同じ in-tree の `fastrb` (mmap + epoll) を使います。

## Performance flags

高 rate capture (>1 Mpps 級) で使う flag 群です。通常用途では既定値で十分です。

| Flag | 既定 | 効果 / 注意 |
|---|---|---|
| `--snaplen N` | 0 (= MaxCapLen or DefaultCapLen=1500) | 1 packet あたりの保存 byte 数を CLI から強制上書きする。DSL の `capture` 句より優先 |
| `--ringbuf-size MB` | 16 | per-CPU ringbuf 1 個あたりの size を指定する。storage 帯域が追いつかない時は増やす |
| `--fast-reader` | off | mmap+atomic 直叩きの fastrb reader を使う。cilium/ebpf の generic reader より低 CPU かつ高 throughput |
| `--no-wakeup` | off | `BPF_RB_NO_WAKEUP` を全 submit に立てる。reader 側の epoll wake が無くなり throughput が上がるが、1ms polling 床により p50 latency が 100µs → ~2.6ms に悪化する。`--fast-reader` 必須 |
| `--observer-prefetch` | off | filter scratch を 512 B に強制する。R12 の ice driver で L1-dcache prefetch が効くケース向けの opt-in |
| `--rx-cores N` | 0 (off) | split-core capture を行う。利用者が `ethtool -L combined N` で NIC queue 数を N にし、RX/capture が core `0..N-1` に閉じている前提で、consumer goroutine を core `N..2N-1` に pin して RX softirq から分離する。`-w` 出力時の producer-consumer 結合を断ち、32/32 split で capture rate が 30% 向上する。`--fast-reader` 必須、`--busy-poll --no-wakeup` と併用 |
| `--busy-poll` | off | fastrb shard を `epoll_wait` で寝かさず `ReadBatch` で spin させる。consumer が常時 drain するので wake が不要になる。shard ごとに 1 core を消費する。`--fast-reader` 必須、`--no-wakeup` と対 |
| `--in-memory-buffer MB` | 0 (off) | raw-dump 出力先を mmap 上の `MAP_POPULATE` バッファに置く。NVMe write が bottleneck な時に隠せる |
| `--null-output` | off | bench 用に、出力 file を一切開かず reader の CPU コストだけ測る |
| `--latency-sample-period N` | 0 (off) | N packet ごとに 1 サンプル、BPF→reader latency を ns 単位で tsv に蓄積する |
| `--latency-sample-output PATH` | (stderr) | 上の sample tsv の出力先 |
| `--raw-dump` | off | pcap-ng 経由を bypass する。packet bytes + header をそのまま raw に追記し、後で `xdp-ninja convert` で pcap-ng 化できる |
| `--rx-hwts` | off | `bpf_xdp_metadata_rx_timestamp` kfunc を使って NIC の HW timestamp を埋め込む。ice 等の 6.8+ driver 対応のみ |

flag 同士の組合せについて補足します。

- `--no-wakeup` は必ず `--fast-reader` と一緒に使います。cilium/ebpf reader は missing wake で永久ブロックします。
- `--in-memory-buffer` は `--raw-dump` の時のみ意味があります。pcap-ng path には未対応です。
- `--rx-hwts` は `--mode xdp` 限定です。entry/exit (fentry/fexit) では使えません。
- `--rx-cores` は NIC queue 数を手で変える運用が前提です。`ethtool -L combined N` はドライバが安定してから実行してください。初期化が未完了の `modprobe` 直後に叩くと、ice 等が RTNL を握ったまま D-state デッドロックし、udev / dmesg など box 全体に波及して reboot が必須になります。split-core を使わないなら queue 数は変更不要です。
- CLI 既定の `--snaplen 0` はバイパスを意味します。強制的に 0 B にしたい場合は `capture absolute 0` を DSL 側で書きます。

## Hand-test として `--dump-asm` で eBPF asm を覗く

`--dump-asm` を付けると、フィルタをコンパイルした結果の eBPF 命令列を load せずに stdout に print して exit します。`-i` / `-p` は不要です。さまざまな式を試して codegen の挙動を確認したいときに便利です。

スコープは 2 段階あります。

| 値 | 範囲 |
|---|---|
| `--dump-asm filter` | kunai (DSL) または cbpfc (tcpdump) が出した filter Main + Callbacks + CaptureInfo だけを print する。target-agnostic ABI (R0=pkt_start, R1=pkt_end → R2=accept/reject @ filter_result) |
| `--dump-asm full` | 上記を `loadProbe` の wrapper (xdp_buff load + scratch コピー + bpf_xdp_output + return) で囲んだ完全な tracing program を print する。load しないので map FD は 0 placeholder のままで問題ない |

```bash
# DSL filter のみ
xdp-ninja --dump-asm filter "eth/ipv4/tcp where tcp.dport == 443"

# tcpdump filter のみ (cbpfc 出力、 --cbpf 必須)
xdp-ninja --cbpf --dump-asm filter "tcp port 443"

# 完全な tracing program (mode 別に shape が変わる)
xdp-ninja --dump-asm full --mode entry "eth/ipv4/tcp[dport==443]"
xdp-ninja --dump-asm full --mode exit "eth/ipv4/tcp where action == XDP_DROP"
```

DSL の parse error / type error も同じ経路を通るので、`--dump-asm filter` は構文/型のサニティチェックにも使えます。load 前に stderr に error を出して exit 1 します。

## 仕組みのざっくり

1. one-liner を AST → IR に解決します。vocab に照らして protocol/field/dispatch をバインドします。
   - 同時に型システムが異幅 cmp の widening、リテラルの fit-check、Bool/Action/CIDR の文脈チェックを行います ([`dsl-types.md`](./dsl-types.md))。
2. IR を eBPF 命令に codegen します。
   - 静的チェーンや predicate は素直に展開します。
   - chain (`+`/`*`/大きい `{n,m}`) は bpf_loop + bpf2bpf callback で、BTF func_info 付きで emit します。
   - alternation は uniform-size 制約のもとで sequence 展開します。
3. 既存の runFilter / capture / fentry-fexit ラッパに乗せて kernel に load します。
4. verifier が通ればそのまま動きます。MVP 範囲は bpf_loop が必須のため kernel 5.17+ で動作確認しています。

## 参考

- [dsl-overview.md](./dsl-overview.md): DSL ドキュメント index
- [dsl-grammar.md](./dsl-grammar.md): formal EBNF + 例文
- [dsl-types.md](./dsl-types.md): 型システム (型・暗黙変換・widening・fit check・エラーカタログ)
- [dsl-followups.md](./dsl-followups.md): 残作業
- vocab 一覧: `pkg/kunai/protocols/*.p4`
