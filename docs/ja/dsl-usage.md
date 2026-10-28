# bpf-ninja DSL 利用ガイド

フィルタ式は default で bpf-ninja DSL としてコンパイルされます。tcpdump/cbpfc では書きにくい多段カプセル化 (GTP-U over UDP、MPLS label stack、VXLAN inner Ethernet など) をプロトコルスタックの形のまま記述できることがゴールです。

このドキュメントは利用者向けです。formal な EBNF と例文表は [dsl-grammar.md](./dsl-grammar.md) にあります。新しいプロトコル vocab を書きたい場合は [`pkg/kunai/protocols/`](../../pkg/kunai/protocols/) の既存 .p4 と [`pkg/kunai/vocab/loader.go`](../../pkg/kunai/vocab/loader.go) を参考にしてください。

[capture の選択](cli/capture.md)、[出力と完了](cli/output.md)、[set の操作](cli/sets.md)、[capture recipes](examples/capture-recipes.md) は別のガイドです。
このページはフィルタ式の構文と意味を説明します。
問題の切り分けは [Troubleshooting](troubleshooting.md)、トンネル式の確認は [tunnel recipe](examples/tunnel-filters.md) を参照してください。

## クイックスタート

```bash
sudo bpf-ninja -i veth0 "eth/ipv4/tcp[dport==443]"
```

- DSL が default です。tcpdump/cBPF 構文を使いたいときだけ `--cbpf` を付けますが、これは legacy 扱いで deprecation notice が出ます。
- フィルタ式は位置引数として末尾に渡します。
- 既存の `-w pcap`、`-c count`、`--mode entry/exit/xdp` などはすべて DSL でも使えます。

#### `--mode` 一覧

| Mode | Attach 方法 | 既存プログラム | return action 観測 | 主用途 |
|---|---|---|---|---|
| `entry` (default) | fentry trampoline | 必須 (BTF 付) | × (packet only) | production プログラムに来る前のパケットを観測 |
| `exit` | fexit trampoline | 必須 (BTF 付) | ○ (`XDP_PASS`/`TC_ACT_OK`/...) | 判断結果を観測する。`where action == XDP_DROP` 等で絞れる |
| `xdp` | netdev に直接 attach | 不要 (既に attach されているとエラー) | n/a (常に `XDP_PASS`) | XDP が attach されていない netdev の standalone capture |

hook 種別 (XDP / TC clsact / cgroup-skb / netfilter) は指定不要です。ターゲットプログラムの型から自動判別されます。`-p <progID>` はどの対応型でも受け付け、`-i <iface>` は interface の XDP プログラムを引き、`--cgroup <path>` は cgroup v2 パスに attach された cgroup-skb プログラムを列挙します (BPF_PROG_QUERY、ingress + egress)。TC clsact filter (`tc filter add ... direction ingress/egress` で張ったもの) も fentry/fexit の対象にできますが、TC clsact qdisc の interface walk は未配線のため、target 指定は `-p <progID>` のみです。

attach 済みの freplace (`BPF_PROG_TYPE_EXT`) も `-p <EXT_ID>` で指定できます。
`-p <dispatcher_ID> --list-progs` は `freplace` の子プログラムを表示します。
packet の読み方と action 名は置換元の型から選び、probe と BTF の参照先は EXT 自身です。
未 attach の EXT は拒否します。

```sh
sudo bpf-ninja -p <EXT_ID> --mode entry 'eth/ipv4' --mode exit 'eth/ipv4' --emit both -w ext.pcap
sudo bpf-ninja -p <EXT_ID> --list-params
```

EXT の entry が ctx の後に `orig_ret` などの整数引数を持つ場合、`--func` なしで
`--arg-filter` / `--list-params` / `--arg-echo` を使えます。
置換済みの stub への probe は拒否し、指定すべき EXT ID をエラーに表示します。
freplace link を持つプログラムの他の global subfunction も既定では保護します。
`--allow-dispatcher-slot` で解除できますが、その probe が後の freplace を `EBUSY` にする可能性があります。
link 一覧は snapshot のため、並行して attach が変わると kernel の attach エラーになる場合があります。その場合は一覧を取り直してください。


cgroup-skb ターゲットには注意点が 2 つあります。パケットは network header (L3) 始まりで Ethernet ヘッダを含まないため、DSL チェインは `ipv4/...` または `ipv6/...` を起点にします (`eth/...` は警告付きで誤 parse になります)。pcap-ng 出力も LINKTYPE_RAW になり、Wireshark / tcpdump はバージョン nibble から v4/v6 を自動判定します。

netfilter ターゲット (BPF_PROG_TYPE_NETFILTER、カーネル 6.4+) も同じく L3 始まりで、cgroup-skb と同じ注意点が当てはまります。target 指定は `-p <progID>` のみで、exit mode の verdict は `where action == NF_DROP` または `where action == NF_ACCEPT` で絞れます (両方拾うなら `or` でつなぎます) (カーネルが netfilter BPF の返り値をこの 2 値に制限しているため、これで全 verdict です)。

旧 `--mode tc-entry` / `tc-exit` は `entry` / `exit` の deprecated alias として残っています (stderr に警告が出ます)。

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
| `+` | 1 回以上。固定長 layer は bpf_loop で展開し、self edge を持つ parser-machine の layer (ipv4、ipv6) は `<PROTO>_MAX_DEPTH` 個 (ipv4 は 8、ipv6 は 4) まで instance ごとに parser を展開する |
| `*` | 0 回以上 (先頭の peek でスキップ)。上限は `+` と同じ |
| `{n}` | ちょうど n 回 (静的アンロール、`{n,n}` と等価。`{1,1}` ≡ `1` は chain-end 信号を持たない proto で Lean 保証済: `spec/lean/Kunai/Laws.lean: one_eq_range_layer`。mpls では `{1,1}` がスタックの終端も要求する) |
| `{n,m}` | n〜m 回。固定長 layer は m≤4 を静的アンロールし、それ以上は bpf_loop。self edge を持つ parser-machine の layer (ipv4、ipv6) は m≤8 まで書け、instance ごとに parser が走る。`where` でその layer を参照するには `@label` を付け、最後に match した header を指す |
| `{n,}` | n 回以上。上限は `+` と同じで、n が `<PROTO>_MAX_DEPTH` を超える式は型エラー |

例を示します。

```
eth/vlan?/ipv4/tcp                  # 任意 VLAN 1 段
eth/vlan{1,3}/ipv4/tcp              # VLAN 1〜3 段
eth/mpls+/ipv4/tcp                  # MPLS label stack (s-bit で終端)
eth/mpls{2,8}/ipv4/tcp              # MPLS 2〜8 段 (9 段以上のスタックには match しない)
eth/vlan*/ipv4/tcp                  # VLAN 0〜N 段
```

MPLS の s-bit のように、スタックの終端を示す印を持つ protocol では、quantifier の上限に達した header がその印を持っていないと、スタックが上限より深いとみなして packet を reject します。この規則は [`spec/lean/DECISIONS.md`](../../spec/lean/DECISIONS.md) の D-024 で決めたものです。`eth/mpls{1,2}/ipv4/tcp` は 3 段以上のスタックに match せず、`mpls?` は MPLS が無いパケットと、1 段で終わるスタックにだけ match します。`mpls+` と `mpls*` の上限は `MPLS_MAX_DEPTH` の 8 段です。終端の印を持たない `vlan` などでは、上限に達したところで次の layer に進みます。quantifier は欲張りで後戻りしないので、終端の印を持つ protocol で `mpls?/mpls` や `mpls{1,4}/mpls` のように quantifier の直後に同じ protocol を書くと、後ろの `mpls` は match しません。`vlan+/vlan` のように上限の無い quantifier の後ろに同じ protocol を書いた形も、上限の段数より深いスタックにしか match しません。resolver はこれらの形に warning を出し、`mpls{1,2}` や `mpls{2,5}` のように 1 つの quantifier にまとめた書き方を示します。

#### tc での VLAN tag

tc では多くの場合、kernel が外側の VLAN tag を 1 枚 skb metadata に移してから program が動くので、filter が見る byte 列にその tag はありません。既定では filter はこの byte 列に当たるので、`eth/ipv4/tcp` は tag 付きのフレームにも match し、外側の tag を必須にした形 (`eth/vlan/…`、`eth/vlan[tci==100]/…`) は tag 付きのフレームに match しえないので compile 時の型エラーになります。optional にした `eth/vlan?/ipv4/tcp` は書けます。optional な外側の tag の field を bracket や `where` で読むこともできますが、読めるのは byte 列に残っている tag だけです。1 枚だけ tag の付いたフレームでは `vlan?` は不在になり、`vlan[tci==100]?` は評価されず、`where vlan.tci == 100` は false になります。`--tc-vlan-reinsert` を付けると、bpf-ninja は metadata の tag を filter に渡す byte 列の MAC アドレスの直後に戻し、filter は回線上のフレームどおりに書けます: `eth/vlan[tci==100]/ipv4/tcp` は 802.1Q のフレーム、`eth/qinq/vlan/ipv4/tcp` は QinQ のフレームに match し、`eth/ipv4/tcp` は tag 付きのフレームに match しなくなります。どちらでも capture される byte 列は kernel が持っているもので、metadata にある tag は含みません。option を付けたとき `capture vlan` のように layer で長さを決める capture は 4 byte 多めに取ります。`--cbpf` の pcap 形式のフィルタは option に関係なく kernel が持つ byte 列に当たります。cgroup-skb と netfilter は L3 から始まるので VLAN は関係しません。

ingress では tag が常に metadata に移ります。egress では、既定の `reorder_hdr on` の VLAN デバイスから送られたフレームの tag は metadata にありますが、packet socket に tag 付きで書き込まれたフレームは tag が byte 列に残ります。`--tc-vlan-reinsert` を付けると、後者は byte 列をそのまま使うので、filter からはどちらも同じフレームに見えます。metadata に移るのは外側の tag 1 枚だけです。この制約がかかるのは root の `eth` の直後に続く `vlan` / `qinq` だけで、トンネルの内側の tag は既定のままでも byte 列から読めます。たとえば `eth/ipv4/udp/vxlan/eth/vlan[tci==100]/ipv4/tcp` はそのまま書けます。QinQ のフレームでは外側の S-tag だけが metadata に移り、内側の C-tag は byte 列に残ります。そのため既定のままでは `eth/vlan?/ipv4/tcp` の `vlan` が C-tag にマッチし、`eth/ipv4/tcp` は QinQ のフレームに match しません。`eth/vlan[tci==100]?/ipv4/tcp` や `where vlan.tci == 100` が読むのもこの C-tag です。S-tag を含めて回線上のフレームどおりに判定したいときは `--tc-vlan-reinsert` を付けます。tag の有無や種類を問わず match させたいとき、既定の tc では必須の `(vlan|qinq)` が compile 時のエラーになり、alternation には `?` を付けられないので、`eth/qinq?/vlan?/ipv4/tcp` のように書きます。

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

すべてのリテラルで `==` / `!=` が使えます。ordered な比較 (`<`、`<=`、`>`、`>=`) は整数リテラルと、IPv4 / IPv6 / MAC のアドレスリテラルで使えます。アドレスはワイヤ上のバイト列を符号なし整数として読んだ値で比べるので、`ipv4[src >= 128.0.0.0]` は最上位ビットが立つアドレスに一致します。CIDR は `==` / `!=` だけです。`where` 句のアドレスリテラルは引き続き `==` / `!=` だけで、順序比較は `int<128>(n)` のような整数リテラルで書きます。

`field in [...]` は候補のどれかに一致すれば真になる OR です。候補には整数、範囲 `lo..hi`、アドレス、CIDR を書けます。アドレスと CIDR は `==` と同じ比較で、CIDR は prefix の一致です。

```
eth/ipv4/tcp[dport in [80, 443, 8000..8080]]       # 整数と範囲
eth/ipv4[dst in [10.0.0.1, 10.0.0.2]]/tcp           # IPv4 アドレスの列
eth/ipv4[src in [10.0.0.0/8, 192.168.1.1]]/tcp      # CIDR とアドレスの混在
eth/ipv6[src in [fc00::1, fc00::/16]]/tcp           # IPv6
eth[src in [aa:bb:cc:dd:ee:01, 11:22:33:44:55:66]]/ipv4/tcp
eth/ipv6/srv6[segments[1].addr in [fc00::1, fc00::2]]/tcp
```

bit-slice した field にも使えます。`ipv6[dst[96:128] in [10.0.0.1, 10.0.0.2]]` は下位 32 bit を IPv4 アドレスの列と比べます。128 bit や 48 bit の field の整数は、その整数を値とするアドレスとして比べます。`eth[src in [11:22:33:44:55:66, 5]]` や `eth[src == 5]` の `5` は 00:00:00:00:00:05 と同じです。範囲の候補も同じく、field のバイト列を big endian の数として比べます。`eth[src in [0x667788990000..0x66778899ffff]]` は 66:77:88:99:00:00 から 66:77:88:99:ff:ff までに一致します。範囲の端は 2^64-1 までの整数なので、128 bit の field では上位 64 bit が 0 のアドレスだけが範囲に入ります。byte 境界で始まらない、または終わらない slice は数として読み、アドレスの値と比べます。`ipv6[dst[92:124] == 10.0.0.1]` は dst の 92 bit 目から 32 bit を 10.0.0.1 と比べます。64 bit 以下の slice は、`ipv6[dst[60:124] == 0xa00000]` のように 9 byte にまたがっていても読めます。byte 境界で始まらないフィールドも slice でき、IPv6 の DSCP は `ipv6[traffic_class[0:6] == 46]` や `ipv6[traffic_class[0:6] in [40..47]]` と書けます。option のフィールドも同じで、Geneve の OVN option の 15 bit の `ingress_port` は `geneve[ovn.ingress_port == 7]` や `geneve[ovn.ingress_port in [1, 7]]` と書けます。

Aux header field にも bracket 内でアクセスできます。GTP-U の opt block を例に示します。

```
eth/ipv4/udp/gtp[opt.next_ext == 0]/ipv4/tcp     # GTP の auxiliary header opt の next_ext field
```

ただし `gtp.exts` や `srv6.segments` などの aux header stack には index または `where any/all(...)` が必要です。詳細は §Where 節を参照してください。

TCP / IPv4 / Geneve の option (`tcp[mss.value == 1460]` や `ipv4[rr.pointer == 4]` など) も bracket で参照できます。parser が option 領域を走査して位置を決めるため、これらの bracket 条件は走査が終わった後に評価します。option が無いパケットでは条件は偽になり、`!=` も成り立ちません。TCP で 2 種類以上の option を参照するフィルタは、option の条件をすべて `==` で書いたときだけ受け付けます。条件は bracket に書いても、`where` 句に書いてもかまいません。詳しい条件は後の TCP option の節で説明します。IPv4 と Geneve の option にはこの制限がありません。bracket の中でも `where` 句と同じく `tcp[options.MSS.value == 1460]` と書けて、`tcp[mss.value == 1460]` と同じ条件になります。SACK の block のように option の中にある stack は `tcp[options.SACK.blocks[0].left == 5]` のように option を経由して書き、`tcp[blocks[0].left == 5]` は型エラーです。option の長さに収まらない index の entry は無いものとして扱います。

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

IPv6 アドレス (`Int<128>`) の算術は `+` と `-` だけです。2⁶⁴ 以上の定数は `int<128>(10 進の値)` で書きます (素の整数リテラルは 64 bit まで):

```
eth/ipv6/tcp where ipv6.src + int<128>(18446744073709551616) == ipv6.dst
eth/ipv6/srv6/tcp where srv6.segments[0].addr + 1 == srv6.segments[1].addr
eth/ipv6/srv6/tcp where srv6.segments[1].addr[64:128] == 2
```

segment のような 16 byte の aux field も、primary の `ipv6.dst[64:128]` と同じく `[0:64]` や `[64:128]` の slice で 64 bit の値として読めます。静的 index でも動的 index でも同じで、bracket predicate の中でも使えます。`srv6[segments[1].addr[0:64] == 0xfc00000000000000]` のように、64 bit までの値と比べられます。

IPv4 / IPv6 / MAC のアドレスリテラルと CIDR は slice 後の幅と比べます。`ipv6.dst[96:128] == 10.0.0.1` や `ipv6.dst[96:128] == 10.0.0.0/8` のように、IPv6 アドレスの下位 32 bit を IPv4 のリテラルと比較できます。逆に `ipv6.dst[64:128] == fc00::2` は 64 bit の slice と 128 bit のリテラルなので型エラーになります。アドレスリテラルと比べる slice は byte 境界で始まり byte 境界で終わる必要があります。

算術ネストは MVP では 16 段までです。それを超えると `ErrNotImplemented` になります。上限は `maxArithDepth` 定数で管理されています。比較の両辺がともに 16 段のときも、片方の値を退避する場所が無いので `ErrNotImplemented` です。`Bool == Bool` の内側では、外側の真偽値の退避に 1 段ずつ使うので、その分だけ浅くなります。`Bool == Bool` 自体の入れ子は 11 段までです。

#### 読めるのはパケットの先頭 512 byte まで

filter が読めるのはパケットの先頭 512 byte (`codegen.ScratchBufSize`) までです。fentry / fexit / tc ではこの分だけを scratch にコピーして読むので、そこから先にある layer や field は match しません。`--mode xdp` はパケットを直接読みますが、可変長の walk (IPv4 / TCP の option 領域、IPv6 拡張ヘッダ、SRv6 の segment list) の位置は host に関係なく 512 byte で打ち切られるので、walk が 512 byte を越えるパケットも、walk より後ろの layer や field が 512 byte を越えるパケットも reject されます。固定長の layer だけの chain なら XDP では 512 byte より先も読めます。Lean の仕様にはこの上限が無く、両者で結果が違う唯一の既知の例がこれです (vector `srv6-past-scratch-window`、DECISIONS D-029 追記 2)。

#### フィールド参照

| 形 | 例 | 用途 |
|---|---|---|
| `proto.field` | `tcp.dport` | primary header の field (チェーン内 1 個のとき) |
| `@label.field` | `outer.src` | 同 protocol が複数あるときラベルで識別 |
| `proto.aux.field` | `gtp.opt.next_ext` | 単発 auxiliary header の field |
| `proto.stack[N].field` | `srv6.segments[0].addr` | aux header stack の N 番目 (静的 index) |
| `proto.stack[expr].field` | `srv6.segments[srv6.last_entry].addr` | 動的 index (parent header field 由来) |
| `proto.options.NAME.field` | `tcp.options.MSS.value` | TCP/IPv4 option lookup |

stack の index は静的でも動的でも、抽出された要素数以上を指すとその要素は不在として扱われ、それを含む atom は `!=` でも false になります。要素数は protocol が宣言した count field (srv6 なら `last_entry + 1`)、option の中の配列 (`tcp.options.SACK.blocks[i]` など) ならその option の length byte、それ以外は parser が push した数です。bracket predicate の静的 index も同じ規則です。

量化された layer の field も参照できます。

- `?` / `{0,1}` の layer (`eth/vlan?/ipv4/tcp where vlan.tci == 100`): layer が無いパケットでは、その field を含む atom は **false** になります (`==` も `!=` も)。「無い、または 100 でない」は `not (vlan.tci == 100)` と書きます。
- `{n,m>1}` / `+` / `*` の layer は複数 header にマッチしうるので、素の proto 名では ambiguous エラーになります。`@label` を付けると**最後にマッチした header** を指します (`eth/mpls@m{1,8}/ipv4/tcp where m.label == 7`)。
- `{0,0}` の layer は header を 1 つも取りません。bracket の predicate は評価されず、label も束縛されないので、その `@label` を読む atom は false になります。`@label` を付けずに素の proto 名で読むとエラーになります。次の layer は `{0,0}` の手前の layer を親として dispatch します (`eth/mpls{0,0}/mpls/ipv4/tcp` は `eth/mpls/ipv4/tcp` と同じです)。`capture` の対象にすると、手前の layer までを capture します。
- 量化 layer の後ろの layer (`eth/vlan?/ipv4/tcp where ipv4.ttl == 64`) は普通に参照できます。offset は実行時に解決されます。実行時 offset を持てる layer の数に固定の上限はありません。ただし実行時 offset、aux の位置、alternation の member 番号、`options.valid` の結果を置く stack 上の領域は filter 全体で 36 slot なので、これに収まらない filter は `ErrNotImplemented` になります。
- alternation の member (`eth/(ipv4|ipv6)/tcp where ipv4.ttl == 64`、label なら `(ipv4@a|ipv6) where a.ttl == 64`): 別の member がマッチしたパケットでは、その field を含む atom は **false** になります (`?` の layer が無い場合と同じ扱い)。member ごとの条件は `or` で並べます (`where ipv4.ttl == 64 or ipv6.hop_limit == 64`)。
- `any` / `all` の対象 stack を持つ layer が無いときは、どちらも false です (空 stack の場合とは違います)。

あるプロトコルにどんな aux / stack / options が露出しているか調べたいときは、`bpf-ninja --dsl-help <proto>` で full reference を出せます。たとえば `--dsl-help srv6` では `segments[0..7]` stack の field と access pattern が、`--dsl-help gtp` では `opt` aux + `exts[0..7]` stack が、`--dsl-help tcp` では options walk の named entries が一覧されます。

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

1 つの filter で TCP の option を 2 種類以上見る場合は、option の field を読む条件をすべて `<option>.<field> == <定数>` の形にします。この条件は bracket に書くか、`where` 句の一番外側の `and` の項として書きます。`where` 句のほかの項、たとえば `tcp.dport == 80`、`ipv4.ttl == 64`、`options.valid` は、option を読まない限り自由に混ぜられます。`int<128>(n)` で field に収まらない定数を書くと、その filter はどの packet にも一致しません。option を `!=`、大小比較、`in`、`.exists` で読む条件や、`or` と `not` の内側で読む条件を混ぜると `ErrNotImplemented` になります。`tcp?` や alternation の member のように不在になりうる layer の bracket に option の `==` を書いた場合も compile できます。layer が不在の packet では、ほかの bracket と同じく条件は評価されません。

```
eth/ipv4/tcp where tcp.options.MSS.value == 1460 and tcp.options.WS.shift == 7                     # compile できる
eth/ipv4/tcp[mss.value == 1460, ws.shift == 7]                                                     # compile できる
eth/ipv4/tcp[mss.value == 1460] where tcp.options.WS.shift == 7 and tcp.dport == 80                 # compile できる
eth/ipv4/tcp[mss.value == 1460, ts.tsval > 5]                                                      # ErrNotImplemented
eth/ipv4/tcp[mss.value == 1460, ws.shift == 7]?                                                    # compile できる
eth/ipv4/(tcp[mss.value == 1460, ws.shift == 7]|udp)                                               # compile できる
```

見る TCP の option が 1 種類のときと、IPv4 や Geneve の option では、この制約はありません。仕組みは [`dsl-multi-option-accumulator.md`](./dsl-multi-option-accumulator.md) を参照してください。

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

stack の容量を超える要素は保持されません (srv6.segments は 8 個)。9 個以上の segment を持つ SRH も正当なので reject はせず、最初の 8 個だけを保持して、次の header は `(last_entry+1) × 16` の先から読みます。このとき `any` と `srv6.segments[i]` は保持した 8 個だけを見て、`all` は false になります (全部を確かめられないため)。

#### SRH の無い SRv6

`srv6` layer は SRH (Segment Routing Header、routing type 4 の Routing Header) を表します。SRv6 でも SRH を付けない packet があります。
- RFC 8986 の H.Encaps.Red (reduced encapsulation) で、segment が 1 つだけ、flag / tag / TLV も不要なとき。SRH を省き、SID は外側 IPv6 の宛先アドレスにだけ置きます。
- RFC 9800 の圧縮 SID (uSID / CSID)。複数の SID を 1 つの IPv6 アドレス (CSID container) に詰め、SRH 無しで複数 hop をたどれます。

この packet は header の並びとしては普通の IPv6 なので、`eth/ipv6/srv6/...` には match しません (`srv6` が無い)。宛先アドレスが SID (locator prefix) であることで書き分けます。

```
# SRH があってもなくても、SRv6 locator 宛て
eth/ipv6/srv6?/tcp where ipv6.dst == fc00:0:1::/48

# SRH の無い SRv6 だけ (SRH があるものは除く)
eth/ipv6/tcp where ipv6.dst == fc00:0:1::/48

# uSID: 宛先アドレスの中の個々の CSID を bit slice で読む (locator block 32 bit、uSID 16 bit の例)
eth/ipv6/tcp where ipv6.dst[0:32] == 0xfc000000 and ipv6.dst[32:48] == 0x0100
```

`srv6` layer があるときは SRH が実在し、RFC 8754 により segment list は 1 個以上あります。segment list が壊れた SRH は packet ごと reject されます (srv6.p4 は `@kunai_option_region[on_fault=fail]`、D-029)。

#### action atom

`action == <NAME>` は `--mode exit` (fexit) でのみ使えます。`entry` (fentry) では下流プログラムの戻り値がまだ存在せず、`--mode xdp` は bpf-ninja 自身が常に `XDP_PASS` を返す立場で観測対象がないため、いずれも resolver で reject されます。

| ターゲット (自動判別) | サポートされる定数 |
|---|---|
| XDP プログラム (fexit) | `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT` |
| TC clsact プログラム (fexit) | `TC_ACT_UNSPEC` (-1), `TC_ACT_OK`, `TC_ACT_RECLASSIFY`, `TC_ACT_SHOT`, `TC_ACT_PIPE`, `TC_ACT_STOLEN`, `TC_ACT_QUEUED`, `TC_ACT_REPEAT`, `TC_ACT_REDIRECT`, `TC_ACT_TRAP` |
| cgroup-skb プログラム (fexit) | `SK_DROP` (0), `SK_PASS` (1)。egress 専用の 2/3 (輻輳通知付き drop) は uapi 名が無いため atom は無く、pcap 側では `cgroup-skb:UNKNOWN(n)` interface に落ちます |
| netfilter プログラム (fexit) | `NF_DROP` (0), `NF_ACCEPT` (1) |

host adapter ごとの定数表は `pkg/kunai/host/xdp/xdp.go` / `pkg/kunai/host/tc/tc.go` / `pkg/kunai/host/cgroupskb/cgroupskb.go` / `pkg/kunai/host/netfilter/netfilter.go` の `FexitCapabilities()` を参照してください。新 host を足すときは `Capabilities.Lang` に同 shape の `Action map[string]int32` + `ActionFetcher` を提供します。

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
- `capture headers` の長さは各 layer の固定ヘッダ長の合計で、IPv4 option や TCP option、IPv6 の拡張ヘッダのように parser が歩いた可変部分は含みません。`eth/ipv6/tcp capture headers` に Hop-by-Hop 拡張ヘッダ 8 byte が付いたフレームでは 74 byte で切れるので、拡張ヘッダまで欲しいときは `headers+N` か `capture all` を使います。
- capture の長さは compile 時に決まる上限です。量化 layer (`?`/`+`/`*`/`{n,m}`) を含むフィルタでは、その layer が最大数マッチした場合の長さを取ります (`eth/vlan?/ipv4/tcp capture headers` は 58 byte、`eth/mpls+/ipv4/tcp capture headers` は MPLS_MAX_DEPTH 分の 32 byte を含み、`eth/ipv4+/tcp capture headers` は 8 個の IPv4 ヘッダ分の 194 byte)。layer が無い / 短いパケットでは、その分だけ余分に capture されます (`min(pkt_len, 上限)` で切られる)。`capture vlan` のように無いかもしれない layer を対象にすると、無いときも同じ上限が使われます。複数の capture 句を書いた場合も実装は句ごとの上限の最大値を 1 つ使うので、「vlan があれば vlan+8、無ければ ipv4+8」のような実行時の使い分けは (仕様上は句を落として表現できますが) 実装ではできません。
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

alternation は、親の dispatch が一致した最初の alt を採用し、その alt の predicate や bounds が失敗しても次の alt を試しません。この規則は [`spec/lean/DECISIONS.md`](../../spec/lean/DECISIONS.md) の D-004 で決めたもので、`dsl-types.md` の [E-Layer-Alt-First] にあたります。同じ protocol の alt はどの親の下でも同じ dispatch を使うので、`eth/ipv4/(tcp[dport == 80]|tcp[sport == 22])` のように同じ protocol を 2 つの alt に書くと、後ろの alt はどのパケットにも match しません。`eth/(ipv4@a|ipv4@b)/tcp where b.ttl == 64` のように後ろの alt の label を読む比較も、常に false になります。resolver はこの形に warning を出します。alt を 1 つにまとめ、条件は `eth/ipv4/tcp where tcp.dport == 80 or tcp.sport == 22` のように `where` の `or` でつなぎます。同じ field の値を並べるだけなら、`tcp[dport in [80, 443]]` とも書けます。

### Label

同じ protocol が 2 段以上出てくると `proto.field` では曖昧になります。`@name` で明示できます。

```
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.dst == 0xc0a80101 and inner.ttl == 64
```

ラベル名は英数字と `_` です。`XDP_*` 等の予約語は使えません。MVP では 1 つの protocol あたり最大 2 ラベルです。

## 実例

### 基本

```bash
# ICMP echo request だけ
sudo bpf-ninja -i veth0 "eth/ipv4/icmp[type==8]"

# IPv6 TCP に絞って snaplen 256
sudo bpf-ninja -i veth0 "eth/ipv6/tcp capture headers+128"

# fexit 観測で XDP が DROP したものだけ
sudo bpf-ninja -i veth0 --mode exit "eth/ipv4/tcp where action == XDP_DROP"
```

### encapsulation

```bash
# VLAN 任意 1 段の TCP/443
sudo bpf-ninja -i veth0 "eth/vlan?/ipv4/tcp[dport==443]"

# QinQ + VLAN いずれか
sudo bpf-ninja -i veth0 "eth/(vlan|qinq)/ipv4/tcp"

# MPLS スタック (s-bit で終端、IPv4 ペイロード)
sudo bpf-ninja -i veth0 "eth/mpls+/ipv4/tcp"

# VXLAN inner Ethernet/IP/TCP
sudo bpf-ninja -i veth0 "eth/ipv4/udp/vxlan/eth/ipv4/tcp"

# GTP-U inner IP, ラベル付き outer/inner
sudo bpf-ninja -i veth0 \
  "eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.src == 0xc0a80001"
```

### where と capture の組合せ

```bash
# total_length 100 byte 超の TCP のみ、ヘッダ + 64 byte 取得
sudo bpf-ninja -i veth0 \
  "eth/ipv4/tcp where ipv4.total_length > 100 capture headers+64"

# TCP/443 か TCP/80
sudo bpf-ninja -i veth0 \
  "eth/ipv4/tcp where tcp.dport == 443 or tcp.dport == 80"
```

## 型エラーの例

resolver / parser が出す主要なエラーパターンを示します。詳しくは [`dsl-types.md`](./dsl-types.md) を参照してください。

### 値が field 幅に収まらない

```
$ bpf-ninja -i eth0 'eth/ipv4/tcp where tcp.dport > 99999'
1:32: value 99999 does not fit in bit<16> (in arithmetic context)
```

`tcp.dport` は `bit<16>` field なので、99999 は narrow できません。`> 65535` に書き直すか、より広い field を使います。

### 整数リテラルが 64 bit を超える

```
$ bpf-ninja -i eth0 'eth/ipv6/tcp where ipv6.src == 18446744073709551616'
1:32: integer literal 18446744073709551616 exceeds 64 bits; write int<128>(18446744073709551616) for a wider value
```

素の整数リテラルは 64 bit までです。`int<128>(…)` で書くか、IPv6 リテラル (`::1:0:0:0:0`) を使います。

### CIDR の host bits が立っている

```
$ bpf-ninja -i eth0 'eth/ipv4[src==10.0.0.5/24]/tcp'
1:15: CIDR "10.0.0.5/24" has host bits set; network would be 10.0.0.0/24
  (suggestion: 10.0.0.0/24 for the subnet, or 10.0.0.5/32 for the single host)
```

CIDR は boundary 整列した network address を要求します。`10.0.0.0/24` で subnet match、`10.0.0.5/32` で host match の使い分けを明示します。

### division / modulo by zero (静的)

```
$ bpf-ninja -i eth0 'eth/ipv4/tcp where tcp.dport / 0 == 1'
1:30: division by zero
```

書き間違いを防ぐため resolver が reject します。runtime に divisor が 0 の場合は BPF の既定で `0` が返ります。

### Bool に対する ordered cmp

```
$ bpf-ninja -i eth0 'eth/ipv4/tcp where true < false'
1:25: ordered comparison < not allowed for Bool (Bool supports only == and !=)
```

Bool には自然順序がないので `<`、`>` 等は禁止です。`==` (iff) / `!=` (xor) を使います。

## Bool atom の使い方

`where` 直下に bool atom を書けます ([`dsl-types.md` §5.4](./dsl-types.md#54-intn--bool-coercion-bool-文脈))。

```
where true                              # 常に match (where 省略と等価)
where false                             # 常に no-match
where gtp.opt.exists                    # GTP-U の opt block が抽出されたか
where not tcp.options.valid             # TCP option 領域が壊れている packet だけ (D-029)
# bracket でも書ける (肯定形のみ): eth/ipv4/tcp[options.valid, dport == 443]
where tcp.dport                         # tcp.dport != 0 の縮約 (Int<N> -> Bool decay)
where (tcp.dport == 443) == gtp.opt.exists   # iff (両方真 or 両方偽)
where (tcp.dport == 443) != gtp.opt.exists   # xor (片方だけ真)
```

## `--mode xdp` で native XDP として直接 attach する

この節の操作説明は [capture guide](cli/capture.md) に移しました。

## 入口と出口の両方に一致した packet だけを取る (`--mode` を 2 回)

この節の操作説明は [capture guide](cli/capture.md) に移しました。

## 出力ファイルレイアウト (per-CPU sharded)

この節の操作説明は [output guide](cli/output.md) に移しました。

## 複数の (プログラム, 関数) に同時アタッチする

この節の操作説明は [capture guide](cli/capture.md) に移しました。

### `--list-progs` で到達可能プログラムを洗い出す

この節の操作説明は [capture guide](cli/capture.md) に移しました。

### ID の代わりに名前で選ぶ (`--prog-name`)

この節の操作説明は [capture guide](cli/capture.md) に移しました。

### list 出力を JSON で得る (`--json`)

この節の操作説明は [capture guide](cli/capture.md) に移しました。

## 集合マッチ (`--set` / `--arg-filter @NAME`)

この節の操作説明は [sets guide](cli/sets.md) に移しました。

### DSL `layer[field in @NAME]` でパケットフィールドを照合する

この節の操作説明は [sets guide](cli/sets.md) に移しました。

## 関数引数の値を覗く (`--arg-echo`)

この節の操作説明は [capture guide](cli/capture.md) に移しました。

## capture point の書き方 (`--arg-filter` が当たらないとき)

この節の操作説明は [capture guide](cli/capture.md) に移しました。

## Performance flags

現在の flag と既定値は `bpf-ninja --help`、測定と選び方は [tuning](tuning.md) を参照してください。
`--no-wakeup`、`--busy-poll`、`--rx-cores` は `--fast-reader` が前提です。
`--in-memory-buffer` は raw-dump、`--rx-hwts` は xdp mode 用です。
`--snaplen 0` は DSL の capture 長に従う指定で、0 byte を取得する指定ではありません。

## Hand-test として `--dump-asm` で eBPF asm を覗く

`--dump-asm` を付けると、フィルタをコンパイルした結果の eBPF 命令列を load せずに stdout に print して exit します。`-i` / `-p` は不要です。さまざまな式を試して codegen の挙動を確認したいときに便利です。

スコープは 2 段階あります。

| 値 | 範囲 |
|---|---|
| `--dump-asm filter` | kunai (DSL) または cbpfc (tcpdump) が出した filter Main + Callbacks + CaptureInfo だけを print する。target-agnostic ABI (R0=pkt_start, R1=pkt_end → R2=accept/reject @ filter_result) |
| `--dump-asm full` | 上記を `loadProbe` の wrapper (xdp_buff load + scratch コピー + bpf_xdp_output + return) で囲んだ完全な tracing program を print する。load しないので map FD は 0 placeholder のままで問題ない |

```bash
# DSL filter のみ
bpf-ninja --dump-asm filter "eth/ipv4/tcp where tcp.dport == 443"

# tcpdump filter のみ (cbpfc 出力、 --cbpf 必須)
bpf-ninja --cbpf --dump-asm filter "tcp port 443"

# 完全な tracing program (mode 別に shape が変わる)
bpf-ninja --dump-asm full --mode entry "eth/ipv4/tcp[dport==443]"
bpf-ninja --dump-asm full --mode exit "eth/ipv4/tcp where action == XDP_DROP"
```

DSL の parse error / type error も同じ経路を通るので、`--dump-asm filter` は構文/型のサニティチェックにも使えます。load 前に stderr に error を出して exit 1 します。

resolver が出す warning も、通常のキャプチャと同じく `warning:` で始まる行として stderr に出ます。たとえば `eth/ipv4/(tcp|tcp)` のように alternation に同じ protocol を 2 回書くと、後ろの member が match しないことを知らせる warning が asm より先に出ます。asm は stdout にだけ出るので、パイプや diff に warning が混ざることはありません。

## Hand-test として `set` map を手元で叩く

この節の操作説明は [sets guide](cli/sets.md) に移しました。

### ライフサイクルをひととおり流す

この節の操作説明は [sets guide](cli/sets.md) に移しました。

### value すなわち tag を出し入れする

この節の操作説明は [sets guide](cli/sets.md) に移しました。

### 複数の値を照合する

この節の操作説明は [sets guide](cli/sets.md) に移しました。

### bpftool で map を直接覗く

この節の操作説明は [sets guide](cli/sets.md) に移しました。

### 16 バイトの SID キーを確認する

この節の操作説明は [sets guide](cli/sets.md) に移しました。

## tag ごとに pcap を出し分ける (`--split-by-tag`)

この節の操作説明は [output guide](cli/output.md) に移しました。

### set del で tag の出力を完成させる (`--finalize-on-del`)

この節の操作説明は [output guide](cli/output.md) に移しました。

### entry ごとの出力サイズ上限 (`set add ... max-bytes=N`)

この節の操作説明は [output guide](cli/output.md) に移しました。

## 仕組みの概要

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
- vocab 一覧: `pkg/kunai/protocols/*.p4`

### 明示した関数のfexit戻り値

`--mode exit --func NAME` は、各対象関数のBTF prototypeから戻り値の位置を求めます。
異なる引数数の関数を複数指定しても、DSLの `action` とpcap metadataは同じ実戻り値を使います。
packet captureで対応するprototypeは、先頭がcontext pointer、引数が1〜5個の
scalar/pointer（各8byte以下）、戻り値が32bit integer/enumのものです。
void・pointer・64bit戻り値やaggregate引数は、誤った値に切り詰めず明示的にエラーにします。

`--func` を明示したexit出力では、interface名は `return:0x00000002` のような生の
32bit値になります。helperの戻り値が同じ数値でも、呼び出し元の最終XDP/TC verdictを
意味するとは限らないためです。DSLの `action == XDP_PASS` 等の定数は引き続き数値比較であり、
その関数の戻り値が当該定数と等しいことを検査します。`--func` を指定しないentrypointの
exit出力は従来のhook verdict名を使います。

`--dump-asm full` は対象未解決のため、1引数のreturn offset `+8` をplaceholderとして表示します。
実際のattachでは対象ごとのBTFから解決します。

P4-liteの1つのstate内では、`extract` → counter操作 → `advance` の順を基本とします。順序に依存しない定数の`decrement`は`advance`の後にも書けます。`lookahead`やheader fieldを読むcounter操作はcursor移動前に評価され、inline stateとloop callbackで共通です。`advance`やcounter操作の後に`extract`する記述、field依存counterを`advance`後に置く記述、field依存`advance`を他の`advance`と同じstateに置く記述は未対応として拒否します。必要な場合はstateを分けてください。1 stateだけのparserでも追加のcounter・advance操作は省略しません。
