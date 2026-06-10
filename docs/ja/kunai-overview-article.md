# P4 vocabulary でやわらかく BPF パケットフィルタを書くライブラリ kunai

> kunai は、XDP / tracing / tc / userspace BPF の packet filter を、tcpdump 構文より表現力の高い one-liner で書くためのライブラリです。`eth/ipv4/udp/gtp/ipv4/tcp where any(srv6.segments.addr == fc00::1)` のような chain 構文の DSL を、P4-16 の strict subset を vocabulary にして BPF 命令列にコンパイルします。

## なぜ kunai を作ったか

[xdp-ninja](https://github.com/takehaya/xdp-ninja) は、既に load 済の XDP プログラムに BPF trampoline (fentry/fexit) で attach する観測ツールです。attach した先のパケットのうち、特定の条件を満たすものだけを pcap-ng で書き出したいと考えていました。

最初は cbpfc ([cloudflare/cbpfc](https://github.com/cloudflare/cbpfc)) を使って tcpdump 構文 (cBPF) を eBPF に変換していました。これは `tcp port 443` や `host 10.0.0.1 and udp` のようなフラットな predicate を書ける、優れたツールです。

しかし xdp-ninja の用途では、tcpdump では足りない場面が出てきます。たとえば次のような場面です。

- Encapsulation の特定階層を狙いたい場面です。`eth/ipv4/udp/vxlan/eth/ipv4@inner/tcp[dport=80]` で VXLAN トンネル内側の TCP/80 だけを表現したいとします。tcpdump でこれを書くことは可能ですが、byte offset の計算を手で書くことになります。
- Variable-length extension headers を walk したい場面です。IPv6 ext-chain (HBH / DestOpt / Routing / Fragment) を任意深さで歩いて中の TCP を見たいのですが、tcpdump はそもそも対応していません。
- 配列性のある field を見たい場面です。SRv6 segments / GTP extension headers / TCP options に対して、any segment が `fc00::1` か、という条件を書きたくなります。
- セマンティックな match を書きたい場面です。outer の total_length と inner の total_length に 36 byte 差があるパケット、のような同 chain 内 cross-layer の比較です。

これらを declarative に書ける DSL が欲しい、というのが kunai の出発点です。

## kunai の DSL で書けるもの

具体的には次のような式を書けます。

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

pcap では書けないがやりたい、という条件が DSL でほぼ自然に書けます。これらは静的に BPF 命令列にコンパイルされ、verifier を通過し、実 kernel で走ります。1 行の DSL が実プログラムとして load されるまでに何が起きているのかを、以下で説明していきます。

## アーキテクチャ overview

kunai の処理は次の pipeline で進みます。

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

各段階を簡単に説明します。

### Lexer / parser

DSL 構文は手書き再帰下降パーサで処理します。構文の特徴は value mode という独自概念で、`==` `!=` `<` `>` `in` の後に来る right-hand side を、IP literal `192.168.1.1` や `fc00::1/16` のような atomic token として読みます。通常の identifier モードと value モードが lexer 状態として切り替わります。

これは、`192.168.1.1` を 1 つの value として扱いたいのに、通常の lexer ルールでは `192` `.` `168` `.` `1` `.` `1` に分割されてしまう、という問題への対処です。P4-16 の lexer も、literal expr の type-aware parsing という同じ pattern を持ちます。

### AST → IR (resolve 層)

AST は構文を木にしただけなので、protocol 名が文字列 `ipv4` のままになっています。これを resolver が vocabulary、すなわち後述の `.p4` ファイルと照合して、ipv4_h header の field layout、親 protocol からの dispatch 条件、parser block の variable-trailer (`pkt.advance` template) や TLV walk の構造などを resolved IR に変えます。

ここで `@label` 重複検出、chain quantifier の妥当性、field 名のタイポ検出などが行われます。また、ipv4 が gtp の下に来たとき vocab に `IPV4_GTP_*` の dispatch const があるか、のようなケースでは、const がなくても ipv4 自身の parser block が `transition select(version) { 4: accept; default: reject; }` で自己検証していれば allow します。これが parser-block self-validation で、kunai の重要な設計です。詳しくは後述します。

### IR → BPF (codegen 層)

resolved IR を、`cilium/ebpf` の `asm.Instructions` (BPF assembly の Go 表現) に lower します。codegen の出力は target-agnostic で、2 つのレジスタ間の連続したパケットウィンドウと数本のワーキングレジスタ、という ABI だけを仮定します。host adapter (xdp-ninja の場合は XDP fentry/fexit 用) が context から packet pointer をロードしてここにつなぎます。

verifier 通過のために、各 layer の境界で必ず bounds check (R0 + R4 + N ≤ R1) を出し、chain quantifier は kernel 5.17 以降で使える `bpf_loop` ヘルパで iteration を表現します。単純な fixed-size chain なら inline 命令だけで済むので、より古い kernel でも動きます。

## P4-16 strict subset を vocabulary にした設計

ここからが kunai の core idea です。

### なぜ P4 を vocab に使うか

IPv4 の header はどう layout されているか、next protocol は ipv4 の `protocol` field のどの値か、といったプロトコル知識をどこかに集約する必要があります。選択肢は次のとおりです。

1. Go コードで hardcode する方法です。各 protocol を Go struct にして field offset を書きます。
2. YAML / JSON で declarative に書く方法です。静的 declaration ファイルを使います。
3. 既存の packet-description language を借りる方法です。

選んだのは 3 番目の、P4-16 の strict subset です。kunai はこれを `p4lite` と呼びます。理由は次のとおりです。

- P4 はそのまま packet header 記述用に作られた言語です。`header` block で field layout を、`parser` block で extract / transition select / variable extension headers を表現できます。
- 公式 p4c がパースを検証してくれます。`make p4c-check` で `docker exec p4c --parse-only` を全 vocab に走らせる CI が組み込まれています。kunai 側で P4 文法を勝手に拡張しないかぎり、vocab ファイルは本物の P4-16 として valid なままです。
- dispatch / variable-trailer / option-walk といった declarative metadata は、const family の命名規約と parser block で表現します。Field dispatch は `<SELF>_<PARENT>_<FIELD> = <value>`、NoCheck は `<SELF>_<PARENT>_NO_CHECK = true`、variable trailer は parser block の `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` template (mechanism 1) などです。const と parser block は P4-16 の標準構文で、命名規約や template 形状の方を kunai が解釈します。旧 `<SELF>_HDRLEN_*` const family は B-2 で `pkt.advance` の parser-block 表現に移行済で、loader は loud-reject します。

例として、`pkg/kunai/protocols/ipv4.p4` から抜粋します。

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

// IHL trailing は parser block の pkt.advance template A で表現
//   - 自己検証 (version == 4) — 親に Field dispatch がない場合 (MPLS / GTP-U
//     の下) でも、 version=4 を確認することで chain を許可
//   - skip_options state で IHL × 4 byte - 20 byte の trailer を advance
parser IPv4Parser(packet_in pkt, out ipv4_h hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version) {
            4:       skip_options;
            default: reject;
        }
    }
    state skip_options {
        pkt.advance(((bit<32>)(hdr.ihl - 5)) << 5);  // (ihl - 5) × 32 bit
        transition accept;
    }
}
```

vocabulary をデータとして管理することで、kunai のコードを編集することなく、新 protocol を 1 ファイル drop で追加できます。現在は eth, ipv4, ipv6, tcp, udp, icmp/6, vlan, qinq, cw, mpls, gre, vxlan, geneve, gtp, srv6, esp の 17 プロトコルが bundle されています。

### parser-block 自己検証という発想

たとえば `eth/mpls+/ipv4/tcp` という chain では、MPLS は payload type を示す field を持たないので、MPLS の下にある ipv4 をどう識別するかが問題になります。

最初は SANITY const family で表現していました。`IPV4_MPLS_SANITY_NIBBLE = 4` と書くと、ipv4 の先頭 nibble が 4 であることを確認する、という意味になります。これは、codegen が boundary に、byte 0 を読んで上位 4 bit が 4 かを確認する BPF 命令を inject する仕組みです。

ただし P4-16 の `parser` block は、`transition select` と `default: reject` で同じ意味を表現できます。ipv4 の parser block に `transition select(hdr.version) { 4: accept; default: reject; }` を入れれば、version != 4 のパケットは parser machine 自身が reject します。SANITY const family は不要になります。

この移行で、vocabulary は self-contained になりました。子の `.p4` が自分自身が valid である条件を持つため、親の identity に依存しません。結果として bundle 全体が P4-16 の純粋な subset で記述された vocab になり、kunai 独自の declarative metadata は dispatch / HDRLEN / OPT_TRIGGER などの命名規約に絞り込まれました。

## chain quantifier の codegen 戦略

`vlan+`, `mpls+`, `srv6` 等の可変長 / 反復構造を BPF にコンパイルするのは hot point です。BPF verifier はループを許さないので、工夫が要ります。

kunai は次の 3 つの戦略を併用しています。

### 1. 静的 unroll

`mpls{1,4}` のような、上限が小さい (m ≤ 4) range quantifier は、各 iteration を inline 命令で展開します。N 回繰り返しなら N 回 codegen が走り、普通の fixed-size chain と同じになります。

この path は 5.17 より前の古い kernel でも動きます。`bpf_loop` ヘルパが要らないためです。

### 2. bpf_loop callback (5.17+)

`mpls+`, `mpls{1,16}`, `mpls*` のような、上限が大きい / 無制限の quantifier は、1 回目の iteration を inline 命令に、2 回目以降を bpf2bpf callback subprogram に展開し、main 命令列が `bpf_loop` ヘルパを呼びます。

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

`bpf_loop` は kernel 5.17 以降の新ヘルパで、verifier はこれを bounded loop として正しく扱えます。callback は bpf2bpf subprogram になるので、main プログラムから `pseudo_func` ロードで参照します。

### 3. parser machine による variable-length header

`ipv6` の ext-header chain のように HBH / Fragment / DestOpt が次々続く構造や、`srv6` の segment list のように各 16 byte の IPv6 アドレスが N 個並ぶ構造は、protocol 内部の可変長構造です。これは外側の繰り返しである chain quantifier ではなく、protocol の `parser` block の state machine として表現します。

```p4
parser IPv6Parser(packet_in pkt, out ipv6_h hdr, out ipv6_ext_h[8] exts) {
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

codegen は `parser` block の state machine を IR に変換し (`vocab/parser_machine.go`)、`parse_ext` の self-loop は再び `bpf_loop` で展開します。iteration 上限は `MAX_DEPTH = 4` です。各 ext-header の `next_header` を見て次に進むか accept/reject を決定する transition select も、BPF 命令列に lower されます。

GTP の optional header `gtp.opt`、SRv6 の `srv6.segments[N]`、TCP の `tcp.options.MSS` のような aux header model も parser block の `out` 引数として宣言され、DSL からは `<protocol>.<aux>[.index].<field>` で読めます。codegen が address を runtime で計算して LDX を出します。

## target-portable な設計

kunai の output は XDP に固定されません。2 レジスタの packet window と少数のワーキングレジスタしか仮定せず、attach point 固有の prologue / epilogue である host adapter が、context から R0 / R1 / R9 をセットアップする責務を持ちます。

`pkg/kunai/host/xdp/` が xdp-ninja の fentry/fexit 用 adapter で、同じ paradigm で tc clsact / userspace `BPF_PROG_TEST_RUN` / 独自 tracing 等の host adapter を書けます。fexit attach では `where action == XDP_DROP` のような action atom が使えますが、fentry では return code がまだ無いため使えません。これは `Capabilities.Lang.Action` map で host から kunai に declare する設計です。

kunai 自身は XDP を知らず、XDP を知る adapter が wrap する、というのが kunai のスタンスです。結果として、library として完全に独立して使えます。使い方は `pkg/kunai/README.md` の Quick start を参照してください。

## トレードオフと limitations

- 複雑なパケットでは tcpdump より overhead が大きくなります。各 layer で bounds check + dispatch check + advance の overhead が乗るためです。単純な `tcp port 443` のようなフィルタなら、tcpdump 構文 + cbpfc の方が短い BPF 命令列を生成します。cbpfc-vs-DSL benchmark は `docs/ja/dsl-benchmark.md` を参照してください。
- chain quantifier 使用時は kernel 5.17 以降が必要です。`+`, `*`, 大きい `{n,m}` が `bpf_loop` を要求するためです。eth/ipv4/tcp のような単純な fixed-size chain は、もっと古い kernel でも動きます。
- vocab は P4-16 strict subset です。action / table / control / apply / extern は使えません。これは、kunai が必要とする情報は header layout + parser logic だけ、という割り切りです。

## まとめ

kunai は、packet filter の DSL を次の方針で設計したライブラリです。

- P4-16 strict subset で vocabulary を表現します。新 protocol は 1 ファイル drop で追加できます。
- target-agnostic な BPF 命令列にコンパイルします。host adapter が attach point ごとの整形を担当します。
- chain quantifier は静的 unroll と bpf_loop を使い分けます。古い kernel との互換性と表現力のバランスを取るためです。
- parser block の `transition select` で protocol が自己検証します。これにより vocab が self-contained になります。

122 commits の積み上げの結果、17 protocol を bundle して、GTP-U の 7 階層 encapsulation や SRv6 segments の `any()` 量化、TCP options の kind 別 lookup まで 1 行の DSL で書けるようになりました。

詳しい仕様は英語版 `pkg/kunai/README.md` と日本語版 `pkg/kunai/README.ja.md` を、internal は `docs/ja/dsl-internals.md` を、文法 BNF は `docs/ja/dsl-grammar.md` を参照してください。親リポジトリ `xdp-ninja` の default filter syntax として、実 packet capture に使えます。
