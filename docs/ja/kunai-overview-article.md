# kunai: P4 vocabulary でやわらかく BPF パケットフィルタを書くライブラリ

> XDP / tracing / tc / userspace BPF の packet filter を、 tcpdump 構文より表現力の高い one-liner で書きたい。 そのために `eth/ipv4/udp/gtp/ipv4/tcp where any(srv6.segments.addr == fc00::1)` のような chain 構文の DSL を、 P4-16 の strict subset を vocabulary にして BPF 命令列にコンパイルする — それが kunai。

## なぜ kunai を作ったか

[xdp-ninja](https://github.com/takehaya/xdp-ninja) は既に load 済の XDP プログラムに BPF trampoline (fentry/fexit) で attach する観測ツール。 attach した先のパケットのうち「特定の条件を満たすもの」だけ pcap-ng で吐きたい。

最初は **cbpfc** ([cloudflare/cbpfc](https://github.com/cloudflare/cbpfc)) を使って tcpdump 構文 (cBPF) を eBPF に変換していた。 これは `tcp port 443` `host 10.0.0.1 and udp` のようなフラットな predicate を書けて素晴らしい。

しかし xdp-ninja の用途では tcpdump では足りない場面が出てくる。 たとえば:

- **Encapsulation の特定階層を狙いたい**: `eth/ipv4/udp/vxlan/eth/ipv4@inner/tcp[dport=80]` で「VXLAN トンネル内側の TCP/80 だけ」を表現したい。 tcpdump でこれを書くのは可能だが byte offset の計算を手で書くことになる
- **Variable-length extension headers を walk したい**: IPv6 ext-chain (HBH / DestOpt / Routing / Fragment) を任意深さで歩いて中の TCP を見たい。 tcpdump はそもそも対応していない
- **配列性のある field**: SRv6 segments / GTP extension headers / TCP options。 「any segment が `fc00::1` か?」を書きたい
- **セマンティックな match**: 「outer の total_length と inner の total_length に 36 byte 差があるパケット」みたいな同 chain 内 cross-layer の比較

これらを **declarative に書ける DSL** が欲しい、 というのが kunai の出発点。

## kunai の DSL で書けるもの

具体的にはこんな式を書ける:

```
# 基本: encapsulation 階層を chain で表現
eth/ipv4/udp/vxlan/eth/ipv4@inner/tcp[dport=80]

# chain quantifier (+ * ?) で「0 個以上」「1 個以上」を表現
eth/vlan?/ipv4/tcp                                   # VLAN tag は optional
eth/mpls+/ipv4/tcp                                   # MPLS stack は 1 段以上
eth/mpls{1,4}/ipv4/tcp                               # MPLS stack 1-4 段

# alternation
eth/(ipv4|ipv6)/tcp                                  # IPv4 でも IPv6 でも

# where 句で arithmetic / boolean / IP literal compare
eth/ipv4@outer/udp/gtp/ipv4@inner/tcp where outer.total_length == inner.total_length + 36
eth/ipv6/tcp where ipv6.dst == fc00::/16
eth/ipv4/tcp where (src == 10.0.0.0/8 or src == 192.168.0.0/16) and dport == 443

# capture: パケットの何バイトを userspace に渡すか
eth/ipv4/tcp[dport=443] capture headers+128                    # ヘッダ + 128B
eth/ipv6/srv6/tcp capture absolute 256                          # 先頭 256B 固定

# aux header: GTP opt / IPv6 ext / SRv6 segments / TCP options
eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.next_ext == 0           # GTP optional header の field
eth/ipv6/srv6/tcp where srv6.segments[0].addr == fc00::1        # SRv6 segments[N]
eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)      # ∃ 量化
eth/ipv4/tcp where tcp.options.MSS.value == 1460                # TCP option lookup

# action atom (fexit attach 時): XDP の return code で絞り込み
eth/ipv4/tcp where action == XDP_DROP
```

「pcap だと書けないけど、 やりたい」が DSL でほぼ自然に書ける。 これらが **静的に BPF 命令列にコンパイルされ、 verifier 通過、 そして実 kernel で走る**。 1 行の DSL が実プログラムとして load されるまでに何が起きているのかを、 以下で説明していく。

## アーキテクチャ overview

kunai の処理は以下の pipeline:

```
DSL one-liner ("eth/ipv4/tcp[dport=443]")
   │
   ├─ lexer: トークナイズ
   ├─ parser: AST 構築 (recursive descent)
   ├─ resolve: AST を vocabulary に bind して IR を作る
   └─ codegen: IR を asm.Instructions (cilium/ebpf 形式) に lower
   │
   ▼
asm.Instructions (BPF bytecode)
   │
   └─ host adapter (xdp-ninja は XDP fentry/fexit 用) でラップ
   │
   ▼
verifier 通過 → 実行
```

各段階を簡単に。

### Lexer / parser

DSL 構文は手書き再帰下降パーサで処理する。 構文の特徴は **value mode** という独自概念で、 `==` `!=` `<` `>` `in` の後に来る right-hand side を IP literal `192.168.1.1` や `fc00::1/16` のような **atomic token** として読む。 通常の identifier モードと value モードが lexer 状態として切り替わる。

これは「`192.168.1.1` を 1 つの value として扱いたいが、 通常の lexer ルールだと `192` `.` `168` `.` `1` `.` `1` に分割される」問題への対処。 P4-16 の lexer も同じ pattern を持つ (literal expr の type-aware parsing)。

### AST → IR (resolve 層)

AST は構文を木にしただけなので、 protocol 名が「文字列 `ipv4`」のままになっている。 これを resolver が **vocabulary** (= 後述の `.p4` ファイル) と照合して、 「ipv4_h header の field layout」 「親 protocol からの dispatch 条件」 「HDRLEN_* の header-length 形」 などを resolved IR に変える。

ここで **`@label` 重複検出** や **chain quantifier の妥当性** や **field 名のタイポ検出** などが行われる。 また「ipv4 が gtp の下に来たとき、 vocab に `IPV4_GTP_*` の dispatch const があるか?」のようなケースで、 const がなくても **ipv4 自身の parser block が `transition select(version) { 4: accept; default: reject; }` で自己検証していれば** allow する (=  parser-block self-validation)。 これは kunai の重要な設計で、 後述。

### IR → BPF (codegen 層)

resolved IR を `cilium/ebpf` の `asm.Instructions` (BPF assembly の Go 表現) に lower する。 codegen の出力は **target-agnostic** で、 「2 つのレジスタ間の連続したパケットウィンドウと数本のワーキングレジスタ」という ABI だけを仮定する。 host adapter (xdp-ninja の場合は XDP fentry/fexit 用) が context から packet pointer をロードしてここにつなぐ。

verifier 通過のために、 各 layer の境界で必ず bounds check (R0 + R4 + N ≤ R1) を出し、 chain quantifier は `bpf_loop` ヘルパを使って iteration を表現する (5.17+ floor)。 単純な fixed-size chain なら inline 命令だけで済むので older kernel でも動く。

## P4-16 strict subset を vocabulary にした設計

ここからが kunai の core idea。

### なぜ P4 を vocab に使うか

「IPv4 の header はどう layout されているか」「next protocol は ipv4 の `protocol` field の何の値か」 といったプロトコル知識をどこかに集約する必要がある。 選択肢:

1. **Go コードで hardcode**: 各 protocol を Go struct にして field offset を書く
2. **YAML / JSON で declarative**: 静的 declaration ファイル
3. **既存の packet-description language を借りる**

選んだのは 3 で、 **P4-16 の strict subset** (kunai は `p4lite` と呼ぶ)。 理由:

- **P4 はそのまま packet header 記述用に作られた言語**。 `header` block で field layout、 `parser` block で extract / transition select / variable extension headers を表現できる
- **公式 p4c がパースを検証してくれる**。 `make p4c-check` で `docker exec p4c --parse-only` を全 vocab に走らせる CI が組み込まれている。 kunai 側で P4 文法を勝手に拡張しないかぎり、 vocab ファイルは **本物の P4-16 として valid なまま**
- **dispatch / HDRLEN / option-walk といった declarative metadata は const family の命名規約で表現**: `<SELF>_<PARENT>_<FIELD> = <value>` (Field dispatch)、 `<SELF>_<PARENT>_NO_CHECK = true` (NoCheck)、 `<SELF>_HDRLEN_*` (variable trailer length 計算式) など。 const は P4 の標準構文で、 命名規約の方を kunai が解釈する

例: `pkg/kunai/protocols/ipv4.p4` の抜粋:

```p4
header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_length;
    /* ... */
}

// Ethernet / VLAN / QinQ から ipv4 への dispatch
const bit<16> IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> IPV4_VLAN_ETHERTYPE = 0x0800;
const bit<16> IPV4_QINQ_ETHERTYPE = 0x0800;

// IHL trailing は HDRLEN で表現
const bit<8> IPV4_HDRLEN_BYTE_OFFSET = 0;
const bit<8> IPV4_HDRLEN_MASK        = 0x0F;
const bit<8> IPV4_HDRLEN_SCALE       = 4;
const bit<8> IPV4_HDRLEN_BASE        = 20;

// 自己検証 — 親に Field dispatch がない場合 (MPLS / GTP-U の下) でも、
// version=4 を確認することで chain を許可
parser IPv4Fragment(packet_in pkt, out ipv4_h hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version) {
            4:       accept;
            default: reject;
        }
    }
}
```

vocabulary を **データとして** 管理することで、 新 protocol 追加が 1 ファイル drop で済む (kunai のコードを編集しない)。 17 プロトコル (eth, ipv4, ipv6, tcp, udp, icmp/6, vlan, qinq, cw, mpls, gre, vxlan, geneve, gtp, srv6, esp) が現在 bundle されている。

### parser-block 自己検証という発想

たとえば `eth/mpls+/ipv4/tcp` という chain では、 MPLS は payload type を示す field を持たないので、 MPLS の下にある ipv4 をどう識別するか?

最初は **SANITY const family** (`IPV4_MPLS_SANITY_NIBBLE = 4`、 「ipv4 の先頭 nibble が 4 であることを確認する」 を意味する) で表現していた。 これは codegen が boundary に「byte 0 を読んで 上位 4 bit が 4 か?」の BPF 命令を inject する仕組み。

ただし P4-16 の `parser` block は **`transition select` + `default: reject`** で同じ意味を表現できる。 ipv4 の parser block に `transition select(hdr.version) { 4: accept; default: reject; }` を入れれば、 version != 4 のパケットは parser machine 自身が reject する。 SANITY const family は不要になる。

この移行で、 vocabulary は **self-contained** になった (子の `.p4` が「自分が valid である条件」を持つ → 親の identity に依存しない)。 結果として bundle 全体が P4-16 の純粋な subset で記述された vocab になり、 kunai 独自の declarative metadata は dispatch / HDRLEN / OPT_TRIGGER などの命名規約に絞り込まれた。

## chain quantifier の codegen 戦略

`vlan+`, `mpls+`, `srv6` 等の **可変長 / 反復構造** を BPF にコンパイルするのは hot point。 BPF verifier はループを許さないので、 工夫が要る。

kunai は 3 つの戦略を併用している:

### 1. 静的 unroll

`mpls{1,4}` のような **上限が小さい (m ≤ 4) range quantifier** は、 各 iteration を inline 命令で展開する。 N 回繰り返しなら N 回 codegen が走り、 普通の fixed-size chain と同じになる。

この path は **5.17 より前の古い kernel でも動く**。 `bpf_loop` ヘルパが要らない。

### 2. bpf_loop callback (5.17+)

`mpls+`, `mpls{1,16}`, `mpls*` のような **上限が大きい / 無制限 quantifier** は、 1 回目の iteration を inline 命令、 2 回目以降を bpf2bpf callback subprogram に展開し、 main 命令列が `bpf_loop` ヘルパを呼ぶ。

```
[main 命令列]
  iter 0 inline
  bpf_loop(max_iter, &cb_func, &ctx, 0)
  // ctx から R4 を reload
  ...

[callback subprogram]
  parent dispatch peek
  if mismatch: return 1 (break)
  layer body inline
  R4 += hs
  return 0 (continue)
```

`bpf_loop` は kernel 5.17 以降の新ヘルパで、 verifier はこれを **bounded loop** として正しく扱える。 callback は bpf2bpf subprogram になるので、 main プログラムから `pseudo_func` ロードで参照する。

### 3. parser machine による variable-length header

`ipv6` の ext-header chain (HBH / Fragment / DestOpt が次々続く) や `srv6` の segment list (各 16 byte の IPv6 アドレスが N 個並ぶ) は、 **protocol 内部の可変長構造**。 これは chain quantifier (= 外側の繰り返し) ではなく、 protocol の `parser` block の state machine として表現する。

```p4
parser IPv6Fragment(packet_in pkt, out ipv6_h hdr, out ipv6_ext_h[8] exts) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version, hdr.next_header) {
            (6,  0): parse_ext;      // HBH
            (6, 44): parse_ext;      // Fragment
            (6, 60): parse_ext;      // DestOpt
            (6,  _): accept;
            default: reject;
        }
    }
    state parse_ext {
        pkt.extract(exts.next);
        transition select(exts.last.next_header) {
            0: parse_ext;
            44: parse_ext;
            60: parse_ext;
            default: accept;
        }
    }
}
```

codegen は `parser` block の state machine を IR に変換し (`vocab/parser_machine.go`)、 `parse_ext` の self-loop は再び `bpf_loop` で展開する (`MAX_DEPTH = 4` で iteration 上限)。 各 ext-header の `next_header` を見て次に進むか accept/reject を決定する transition select も BPF 命令列に lower される。

aux header model (例: GTP の optional header `gtp.opt`、 SRv6 の `srv6.segments[N]`、 TCP の `tcp.options.MSS`) も parser block の `out` 引数として宣言され、 DSL からは `<protocol>.<aux>[.index].<field>` で読める。 codegen が address を runtime で計算して LDX を出す。

## target-portable な設計

kunai の output は **XDP に固定しない**。 「2 レジスタの packet window と少数のワーキングレジスタ」しか仮定せず、 host adapter (= attach point 固有の prologue / epilogue) が context から R0 / R1 / R9 をセットアップする責務を持つ。

`pkg/kunai/host/xdp/` が xdp-ninja の fentry/fexit 用 adapter、 同じ paradigm で tc clsact / userspace `BPF_PROG_TEST_RUN` / 独自 tracing 等の host adapter を書ける。 fexit attach では `where action == XDP_DROP` のような **action atom** が使えるが、 fentry では使えない (return code がまだ無い) — これは `Capabilities.Action` map で host から kunai に declare する設計。

「kunai 自身は XDP を知らない、 XDP を知る adapter が wraps する」 が kunai のスタンスで、 結果として library として完全に独立して使える (`pkg/kunai/README.md` の Quick start 参照)。

## トレードオフと limitations

- **複雑なパケットでは tcpdump より overhead が大きい**: 各 layer で bounds check + dispatch check + advance の overhead が乗る。 単純な `tcp port 443` のようなフィルタなら tcpdump 構文 + cbpfc の方が短い BPF 命令列を生成する。 cbpfc-vs-DSL benchmark は `docs/ja/dsl-benchmark.md` 参照
- **kernel 5.17+ floor (chain quantifier 使用時)**: `+`, `*`, 大きい `{n,m}` が `bpf_loop` を要求する。 単純な fixed-size chain (eth/ipv4/tcp 等) はもっと古い kernel でも動く
- **vocab は P4-16 strict subset**: action / table / control / apply / extern は使えない。 これは「kunai が必要とする情報は header layout + parser logic だけ」という割り切り

## まとめ

kunai は packet filter の DSL を:

- **P4-16 strict subset で vocabulary を表現** (新 protocol は 1 ファイル drop で追加)
- **target-agnostic な BPF 命令列にコンパイル** (host adapter が attach point ごとの整形を担当)
- **chain quantifier は静的 unroll + bpf_loop の使い分け** (古い kernel との互換性 vs 表現力のバランス)
- **parser block の `transition select` で protocol が自己検証** (vocab が self-contained に)

という方針で設計したライブラリ。 122 commits の積み上げの結果、 17 protocol を bundle して、 GTP-U の 7 階層 encapsulation や SRv6 segments の `any()` 量化、 TCP options の kind 別 lookup まで 1 行の DSL で書けるようになった。

詳しい仕様は `pkg/kunai/README.md` (英) / `pkg/kunai/README.ja.md` (日本語)、 internal は `docs/ja/dsl-internals.md`、 文法 BNF は `docs/ja/dsl-grammar.md` を参照。 親リポジトリ `xdp-ninja` の default filter syntax として実 packet capture に使える。
