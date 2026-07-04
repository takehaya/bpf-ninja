# P4 で新しいプロトコルを追加する Vocab 開発ガイド

`pkg/kunai/protocols/*.p4` に P4-16 の strict subset である p4lite でプロトコル定義を 1 ファイル追加すると、DSL のレイヤ名として使えるようになります。このドキュメントは、ファイルの書き方、const / parser block / annotation の全規約、loader が reject するもの、テスト手順までを、`pkg/kunai/vocab/loader.go` と `pkg/kunai/vocab/parser_machine.go` の実装に基づいてまとめた hands-on ガイドです。

なぜこの形なのかという設計背景は [`dsl-internals.md` §3](./dsl-internals.md#3-vocab-開発ガイド) を、可変長構造 8 機構の分類と codegen 上の扱いは [同 §6](./dsl-internals.md#6-可変長構造の分類と表現) を、p4lite の formal EBNF は [`dsl-grammar.md`](./dsl-grammar.md) を参照してください。

## 目次

1. [クイックスタート](#1-クイックスタート)
2. [ファイル規約](#2-ファイル規約)
3. [p4lite で書けるもの・書けないもの](#3-p4lite-で書けるもの書けないもの)
4. [Header 宣言](#4-header-宣言)
5. [名前で意味が決まる Const 宣言](#5-名前で意味が決まる-const-宣言)
6. [実行コードに落ちる Parser block](#6-実行コードに落ちる-parser-block)
7. [可変長構造でどの機構を選ぶか](#7-可変長構造でどの機構を選ぶか)
8. [@kunai_* アノテーション](#8-kunai_-アノテーション)
9. [loader と codegen が reject するもの](#9-loader-と-codegen-が-reject-するもの)
10. [テストとチェックリスト](#10-テストとチェックリスト)
11. [WireGuard を追加する実例](#11-wireguard-を追加する実例)

## 1. クイックスタート

固定長ヘッダを持ち、親のフィールドで識別できるプロトコルであれば、次の 4 ステップで完了します。

```p4
// pkg/kunai/protocols/foo.p4
header foo_h {              // ← primary header 名は <ファイル名>_h 固定
    bit<8>  version;
    bit<8>  flags;
    bit<16> reserved;
}

// foo は UDP dport==4444 で識別 (Field dispatch)
const bit<16> KUNAI_FOO_UDP_DPORT = 4444;

parser FooParser(packet_in pkt, out foo_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

1. 上記を `pkg/kunai/protocols/foo.p4` に置きます。`//go:embed *.p4` が取り込むため、リビルドだけで読み込まれます。
2. `go test ./pkg/kunai/...` を実行し、vocab がロードでき、既存テストが緑のままであることを確認します。
3. `make p4c-check` を実行し、本物の p4c でも parse できることを確認します。CI でも同じ検査が走ります。
4. `internal/program/load_dsl_test.go` の `dslEntryExprs` に式を 1 本追加し、`make test-bpf` で実 verifier を通過することを確認します。

これで DSL から `eth/ipv4/udp/foo` と書けます。`dport==4444` のチェックは dispatch const から自動で emit されます。

## 2. ファイル規約

| 項目 | 規約 |
|---|---|
| 配置 | `pkg/kunai/protocols/<name>.p4`。1 プロトコル = 1 ファイルで、サブディレクトリは読まれない |
| プロトコル名 | ファイル名から `.p4` を除いた lowercase。これが DSL のレイヤ名になる。`mpls.p4` であれば `eth/mpls/ipv4` のように書く |
| primary header | `<name>_h` という名前の header 宣言が必須。無いと loader が reject する |
| 補助 header | option、拡張ヘッダ、スタック要素用に同ファイルへ何個でも書ける。名前の重複は reject される |
| const prefix | すべての const は self-prefix、つまり `<NAME の uppercase>_` で始まる。違反は reject される |
| 取り込み | `protocols/embed.go` の `//go:embed *.p4` で自動的にビルドへ入る |
| P4-16 互換 | `p4c --parse-only` で通ること。`make p4c-check` で検証でき、CI でもゲートされる。kunai 拡張は annotation と `extern ParserCounter` のみで、どちらも標準 P4-16 の範囲内にある |

## 3. p4lite で書けるもの・書けないもの

p4lite は `pkg/kunai/vocab/p4lite/` にある手書きの P4-16 strict subset parser です。次の構文を受け付けます。

- `header H { bit<N> f; ... }`。N は 1..2048
- `const bit<N> X = <int>;` と `const bool X = true;`
- `parser P(packet_in pkt, out H hdr, out H2[N] stack) { state ... }`。parser block は 1 ファイルに 1 個まで
- state 内の statement。`pkt.extract(<out>)`、`pkt.extract(<stack>.next)`、`pkt.advance(...)` の 3 テンプレート (§7.1)、ParserCounter の `set` と `decrement`
- `transition accept;`、`transition reject;`、`transition <state>;`、`transition select(...) { ... }`。select のタプルは最大 3 鍵
- `extern ParserCounter { ... }` の宣言と、parser 内の `ParserCounter() pc;` によるインスタンス化
- structured annotation `@name[k=v, ...]`。header、parser、parser パラメータに付与できる

P4-16 として valid でも、次の構文は reject されます。

- `action` / `table` / `control` / `apply`、および ParserCounter 以外の `extern`
- positional annotation `@name(arg, arg)`。構造化 KV 形式のみ受け付ける
- 任意の式、代入、`verify()`。statement は上記テンプレートに限る

詳細な互換性監査は [`dsl-internals.md` §5](./dsl-internals.md#5-p4-16-互換性) を参照してください。

## 4. Header 宣言

```p4
header mpls_h {
    bit<20> label;
    bit<3>  tc;
    bit<1>  s;
    bit<8>  ttl;
}
```

- フィールドは `bit<N> name;` の列で、名前には lowercase、underscore、数字を使います。
- 全フィールドの bit 合計は 8 の倍数、つまり byte-aligned でなければなりません。primary header だけでなく、extract やスタック要素になる補助 header も同様です。
- `mpls[label==100]` や `where ipv4.ttl < 5` のような DSL の predicate は、ここで宣言したフィールド名をそのまま使います。`bit<20> label` のような sub-byte フィールドの mask と shift は codegen が処理するので、wire layout どおりに素直に書きます。

補助 header の用途は、GTP の `gtp_opt_h` のような単発 aux、IPv6 の `ipv6_ext_h` や SRv6 の `srv6_seg_h` のようなスタック要素、TCP の `tcp_opt_mss_h` のような TLV option の 3 種です。各形の使い方は §7 で説明します。

## 5. 名前で意味が決まる Const 宣言

const は名前のパターンによって loader の `vocab/loader.go::classifyConsts` が分類します。`<SELF>` はファイル名の uppercase、`<PARENT>` は親プロトコル名の uppercase で underscore を含まない単一トークン、`<FIELD>` は親 primary header のフィールド名の uppercase で underscore を含められます。

`KUNAI_` は inter-layer dispatch のマーカです。親レイヤから自分へ遷移する dispatch const (Field / NoCheck / self-dispatch) には `KUNAI_` を付け、それ以外の value-only const と構造 const には付けません。value-only とは、select-match の値そのものを表す const のことで、routing_type や option kind、next-header 種別など、親が実在プロトコルでない phantom parent のものを指します。たとえば `SRV6_ROUTING_TYPE`、`IPV4_OPT_RR`、`IPV6_NH_FRAGMENT` がこれにあたります。これらは parser block の select arm に畳み込まれるだけで dispatch edge ではないので無印にします。`<SELF>_MAX_DEPTH` / `<SELF>_CHAIN_END_<FIELD>` / `<SELF>_OPT_*` のような構造 const も同様に無印です。loader はこの規約を強制します。dispatch の形 (実在親への Field / NO_CHECK) なのに `KUNAI_` が無いとエラーになり、逆に `KUNAI_` 付きで親が非プロトコルだとエラーになります。

| パターン | 型 | 意味 |
|---|---|---|
| `KUNAI_<SELF>_<PARENT>_<FIELD>` | `bit<N>` | Field dispatch。親の `field` がこの値のとき自分として展開する |
| `KUNAI_<SELF>_<PARENT>_NO_CHECK` | `bool`、true 固定 | NoCheck dispatch。検査せず blind cast する |
| `<SELF>_MAX_DEPTH` | `bit<N>`、1..64 | chain quantifier や parser self-loop など bpf_loop 系の反復上限。未宣言なら既定 8 |
| `<SELF>_CHAIN_END_<FIELD>` | `bit<N>` | chain 終了条件。1 プロトコル 1 個まで。`<FIELD>` は primary に存在すること |
| `<SELF>_OPT_FLAGS_BYTE_OFFSET` | `bit<N>` | flag-triggered optional (§7.6) の flag byte 位置。primary 内に限る |
| `<SELF>_OPT_TRIGGER_<NAME>` | `bit<N>`、範囲 (0, 0xFF] | flag bit mask。`OPT_LEN_<NAME>` と必ずペアにする |
| `<SELF>_OPT_LEN_<NAME>` | `bit<N>`、0 より大 | trigger 成立時に進める byte 数 |

次の family は撤廃済みで、宣言すると loader が error で reject します。

- `*_SANITY_*` family は、parser block の自己検証 `transition select(<field>) { ...; default: reject; }` に置き換えます (§6.2)。
- `<SELF>_HDRLEN_*` family は、parser block の `pkt.advance(((bit<N>)(hdr.<F> - K)) << S)` に置き換えます (§7.1)。

### 5.1 Field dispatch

```p4
// ipv4 は eth または vlan 経由で来るとき、親の ethertype が 0x0800
const bit<16> KUNAI_IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> KUNAI_IPV4_VLAN_ETHERTYPE = 0x0800;
const bit<16> KUNAI_IPV4_QINQ_ETHERTYPE = 0x0800;
```

- ビット幅は親フィールドの宣言幅と一致させます。`ethertype` であれば `bit<16>` です。
- 値は byte-swap せず直感どおりに書きます。network-order 化は codegen の仕事です。
- 親が複数あるなら、上記のように同じ値でも親ごとに別 const として 1 行ずつ宣言します。
- `(ipv4|ipv6)/tcp` のような alternation の直後に置くレイヤは、各 alt に対する dispatch const を 1 つずつ宣言しておく必要があります。const が alt 間で揃っていれば単一チェックに、field や値が異なる場合も全 alt が Field dispatch であれば alt ごとの diverged dispatch として codegen されます。

### 5.2 NoCheck dispatch

```p4
const bool KUNAI_ETH_VXLAN_NO_CHECK = true;   // VXLAN inner Ethernet
const bool KUNAI_MPLS_MPLS_NO_CHECK = true;   // MPLS label stack (区切り無し)
```

親との境界に識別フィールドが無いときの最終手段です。ユーザーの one-liner の記述順だけを信じて blind cast します。`= true` のみ valid で、`false` の宣言は禁止されています。

### 5.3 chain quantifier 用の self-dispatch

`KUNAI_<SELF>_<SELF>_*` は `+` / `*` / `{n,m}` の 2 周目以降で読まれます。self-dispatch も inter-layer dispatch edge なので `KUNAI_` を付けます。

```p4
const bit<16> KUNAI_VLAN_VLAN_ETHERTYPE = 0x8100;  // inner VLAN は ethertype 再一致で識別
const bool    KUNAI_MPLS_MPLS_NO_CHECK  = true;    // label に区切りが無いので blind
```

self-dispatch の無いプロトコルは quantifier で chain できません。chain の終了条件をフィールド値で示せる場合は、次のように `CHAIN_END` も併せて宣言します。

```p4
const bit<1> MPLS_CHAIN_END_S = 1;   // bottom-of-stack ビット
```

### 5.4 dispatch type の選び方

優先順位は Field > NoCheck > SelfValidating です。resolver は const ベースの形を parser block の自己検証より優先します。

1. 親に次プロトコルを示すフィールドがある場合は Field を使います。
2. 親に無くても、IPv4 / IPv6 の version、SRv6 の routing_type、WireGuard の msg_type のように自分の primary header に識別可能なフィールドがある場合は、parser block で自己検証します (§6.2)。const は不要です。
3. encapsulation の inner Ethernet のようにどちらも無い場合は NO_CHECK を使います。

どの形も無いと、resolver が `no dispatch constant for ...` で reject します。

## 6. 実行コードに落ちる Parser block

parser block は単なる宣言ではありません。loader の `vocab/parser_machine.go::buildParseStateMachine` が state machine に lower し、codegen が実際に実行される eBPF に落とします。例外は次の最小形だけです。

### 6.1 固定長で検証なしの trivial 形

```p4
parser FooParser(packet_in pkt, out foo_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

1 state で primary を extract して accept するだけの形は trivial と判定され、parser machine を作らず、bounds check と固定 advance のみの固定長高速経路を通ります。固定長プロトコルは必ずこの形で書きます。

### 6.2 自己検証

```p4
parser SRv6Parser(packet_in pkt, out srv6_h hdr, ...) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.routing_type) {
            SRV6_ROUTING_TYPE: walk;     // routing_type 4 で SRH 確定
            default:           reject;   // それ以外は不一致
        }
    }
    ...
}
```

start state の `transition select(<primary field>)` に `default: reject` を持たせると、resolver が `DispatchSelfValidating` を合成し、親側に dispatch const が無くても chain を許可します。実行時には reject 判定が走ります。複数値を許容する場合は `1: accept; 2: accept; ...` のように case を並べます。

なお、`transition select` に `default` を書かなかった場合も暗黙に reject になります。P4-16 spec はこのケースを未規定としていますが、codegen の決定性のため reject に固定しています。

### 6.3 state 本体に書ける statement

| statement | 意味 | 制約 |
|---|---|---|
| `pkt.extract(<out>)` | aux や primary を取り込み、R4 を進める | 対象 header は byte-aligned。同じ aux を複数 state で extract するのは不可 |
| `pkt.extract(<stack>.next)` | スタックに 1 要素 push する | 1 state に push は 1 回まで |
| `pkt.advance(...)` | byte 単位のスキップ。テンプレートは §7.1 の 3 種 | primary フィールド駆動の advance は extract と同じ state に同居できないため専用 state に分ける。aux 駆動、lookahead、literal は同居できる |
| `pc.set(...)` / `pc.decrement(...)` | ParserCounter 操作 (§7.8) | set の対象フィールドは primary 内 |

### 6.4 transition select の鍵

鍵は最大 3 本のタプルです。鍵にできるのは次の 3 種です。

- extract 済み header のフィールド `hdr.<field>` または `<stack>.last.<field>`。aux gating に使う場合は単一 byte 内に収める必要があります。
- `pkt.lookahead<bit<8>>()`。未消費の次 1 byte を覗きます。8 bit 限定です。
- `<counter>.is_zero()`。ParserCounter の残量を判定します。case 値は `true` または `false` です。

case 値は整数 literal、同一ファイルで宣言した named const、wildcard の `_`、bool のいずれかです。範囲 match は書けません。named const を使うと識別値に名前が付くので、srv6.p4 の `SRV6_ROUTING_TYPE: walk;` のように value-only const (§5) を立てて、コメントで RFC を引きながら書けます。整数 literal を inline で書く場合は、その値の出典をコメントで残します。

## 7. 可変長構造でどの機構を選ぶか

可変長や多態なプロトコルは、下表から機構を選びます。分類の設計議論と codegen 上の扱いは [`dsl-internals.md` §6.5](./dsl-internals.md#65-vocab-declaration-mechanism-8-種) の Mechanism 1～8 が正典です。ここでは vocab に何を書くかだけを示します。

| 構造 | 機構 | 実例 |
|---|---|---|
| 固定 header と、長さフィールド駆動の不透明な trailer | §7.1 variable trailer | tcp の data_offset、ipv4 の ihl。両者は option walk と併用 |
| 同一 header の連接。区切りが無く、ユーザーが `+` で明示する | §7.2 chain self-loop | mpls |
| next フィールドで自走する同一形の拡張ヘッダ連鎖 | §7.3 parser self-loop | ipv6 ext、gtp ext |
| ParserCounter で要素数を数えながら 1 個ずつ push する固定間隔の要素列 | §7.4 element-driven stack walk | srv6 segments |
| フラグで gate された単発 optional | §7.5 gated single aux | gtp opt |
| フラグの bit ごとに長さが決まる optional 列 | §7.6 flag-triggered | gre |
| kind byte で dispatch する TLV option 列 | §7.7 TLV options walk | tcp options |
| byte 数 counter で終端を判定する TLV walk | §7.8 ParserCounter walk | ipv4 options |

排他制約として、OPT_* const family (§7.6) と non-trivial parser block は同一ファイルで併用できません。loader の `validateLayoutExclusivity` が reject します。codegen は parser machine を優先するため、OPT_* が気付かれないまま無効になる事故を防ぐ目的です。

カーネル下限にも注意してください。§7.2 / §7.3 / §7.7 / §7.8 の self-loop と chain quantifier は `bpf_loop` に落ちるため、Linux 5.17 以降が必須です。trivial と §7.1 / §7.5 / §7.6 だけのチェインは、もっと古いカーネルでも動きます。

### 7.1 variable trailer に使う `pkt.advance` の 3 テンプレート

statement として書ける advance は次の 3 形のみで、任意の式は parse されません。

```p4
pkt.advance(64);                                            // (a) literal: 固定 bit 数 (8 の倍数、> 0)
pkt.advance(((bit<32>)(hdr.ihl - 5)) << 5);                 // (b) field 減算形: (F - K) * 2^(S-3) byte
pkt.advance(((bit<32>)(hdr.hdr_ext_len & 0x0F)) << 6);      // (b') field mask 形: (F & MASK) * 2^(S-3) byte
pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3); // (c) lookahead 形: 覗いた byte 値 * 2^(S-3) byte
```

制約は `parser_machine.go` の `buildAdvance*` にあります。

- (b) と (b') の `F` は 1 byte 内に収まるフィールドに限り、byte 境界は跨げません。`-K` と `&MASK` は併用できません。
- codegen は byte 単位でしか進められないため、shift は `S >= 3` が必要です。
- (c) の lookahead 幅 M は 8 の倍数で、slice `[hi:lo]` はちょうど 8 bit かつ byte 境界から始まる必要があります。
- mask は verifier 対策を兼ねます。`& 0x0F` のように上限を抑えておくと、verifier が静的上限を証明できます。同じ目的のキャップは ipv6.p4 の `@kunai_variable_tail[..., mask=0x03]` (§8) でも使われています。raw advance の実例は ipv4.p4 / tcp.p4 のコメントを参照してください。
- (b) で primary を対象にする advance は、R4 が primary 末尾に固定されている前提のため、extract と同じ state には書けません。専用 state に分離します。

### 7.2 MPLS 型の chain self-loop

vocab 側は const だけで済み、parser block は trivial のままにします。self-dispatch の `KUNAI_MPLS_MPLS_NO_CHECK`、構造 const の `MPLS_MAX_DEPTH`、`MPLS_CHAIN_END_S` を §5 のとおり宣言します。ユーザーが `mpls+` や `mpls{1,3}` と書いたときだけ bpf_loop に落ちます。

### 7.3 IPv6 ext 型の parser self-loop

`extract(<stack>.next)` で 1 要素 push し、`<stack>.last` で直前要素を参照して自走する形です。

```p4
parser IPv6Parser(packet_in pkt, out ipv6_h hdr, out ipv6_ext_h[8] exts) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.version, hdr.next_header) {
            (6,  0): parse_ext;
            (6, 44): parse_ext;
            (6, 60): parse_ext;
            (6,  _): accept;
            default: reject;
        }
    }
    state parse_ext {
        pkt.extract(exts.next);                  // push (1 state 1 push)
        transition select(exts.last.next_header) {
            0:  parse_ext;                       // self-loop
            44: parse_ext;
            60: parse_ext;
            default: accept;
        }
    }
}
```

- スタック容量 `[8]` が loop 上限を兼ねます。`<SELF>_MAX_DEPTH` でさらに絞れます。
- 要素 header が可変長 tail を持つ場合は、`@kunai_variable_tail` を header に付けます (§8)。
- 連鎖の最後の next_header を親の dispatch に反映したい場合は `@kunai_writeback` を使います (§8)。

### 7.4 SRv6 型の element-driven stack walk

SRv6 の segment list は、ParserCounter をセグメント数で seed して 1 要素ずつ push する element-driven walk で表現します。bundled srv6.p4 は `@kunai_layout` / `@kunai_stack_count` / `@kunai_variable_tail` を一切使いません。要素数も next-header 位置も、この walk の形から loader と codegen が導出します。

```p4
parser SRv6Parser(packet_in pkt,
                    out srv6_h        hdr,
                    out srv6_seg_h[8] segments) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        // セグメント数 = last_entry + 1 で counter を seed
        // (RFC 8754: last_entry は最後のセグメントの index)
        pc.set((bit<8>)(hdr.last_entry + 1));
        transition select(hdr.routing_type) {
            SRV6_ROUTING_TYPE: walk;     // routing_type 4 で SRH 確定
            default:           reject;
        }
    }
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume_seg;
        }
    }
    state consume_seg {
        pkt.extract(segments.next);      // 16 byte を 1 個 push
        pc.decrement(1);                 // 1 要素ぶん減らす
        transition walk;
    }
}
```

- `pc.set((bit<8>)(hdr.<F> + K))` の bare-cast add 形 (scale=1) が、walk を element-driven にします。1 セグメント push ごとに counter が 1 減るので、`any` / `all` の要素数を loader が seed フィールドの `last_entry` と addend の `+1` から導出します。`@kunai_stack_count` は不要です。
- 同じ count から next-header 位置も決まります。codegen は walk 収束後に R4 を `layer_entry + 8 + (last_entry+1)*16` へ再アンカーします。これは TLV を持たない SRH では segment list の末尾がそのまま next header になる (RFC 8754) という性質を使っています。
- `consume_seg` がスタックを push するので、`@kunai_layout` も不要です。スタックの base は push state の layer-entry offset (= `sizeof(srv6_h)` = 8) から自然に決まります。
- TLV 付き SRH を chain で越えるのは非対応です。R4 が segment list の末尾で止まるため、Padding や HMAC のような末尾 TLV を持つ SRH の後ろに `eth/ipv6/srv6/tcp` のように別レイヤを繋ぐと next header に届きません。TLV サポートは RFC 8754 Section 2 で optional なので、規約準拠の制限です。`srv6.segments[N]` や `any` / `all` といった segment 参照は末尾 TLV の有無に関わらず正しく動きます。
- `routing_type 4` は `SRV6_ROUTING_TYPE` という value-only const で名付けます。phantom parent の `ROUTING` なので `KUNAI_` は付けません。詳しくは §5 を参照してください。loader は select arm に畳み込むだけで dispatch edge とは扱いません。

### 7.5 GTP 型の gated single aux

```p4
state start {
    pkt.extract(gtp);
    transition select(gtp.e, gtp.s, gtp.pn) {
        (0, 0, 0): accept;        // 全 bit 0 → optional 無し
        default:   parse_opt;     // どれか立っていれば aux あり
    }
}
state parse_opt {
    pkt.extract(opt);
    ...
}
```

loader の `computeAuxLayouts` と `computeAuxGating` が認識する gating は、MVP では次の 2 形だけです。

1. default→aux 形。上記 GTP のように、明示 case がちょうど 1 個で全値が 0、default が aux state を指す形です。
2. explicit 形。aux state を指すのが唯一の明示 case で、鍵 1 本かつ具体値の形です。

gating の鍵は primary header のフィールドで、全鍵が同一 byte 内に収まる必要があります。これ以外の形は、常に存在する aux として黙って通すのではなく error にします。

### 7.6 GRE 型の flag-triggered optional

parser block は trivial のままにして、§5 の表の OPT_* const で宣言します。P4-16 の `select` は等値 match しかできず bit-test を表現できないため、この族だけ const 駆動になっています。gre.p4 のコメントも参照してください。

```p4
const bit<8> GRE_OPT_FLAGS_BYTE_OFFSET = 0;     // flag byte の位置 (primary 内)
const bit<8> GRE_OPT_TRIGGER_C         = 0x80;  // bit mask
const bit<8> GRE_OPT_LEN_C             = 4;     // 立っていたら 4 byte 進む
const bit<8> GRE_OPT_TRIGGER_K         = 0x20;
const bit<8> GRE_OPT_LEN_K             = 4;
```

宣言順が wire 上の出現順になり、codegen はこの順で advance します。TRIGGER と LEN は NAME で必ずペアにします。

### 7.7 TCP 型の TLV options walk

kind byte で dispatch する TLV 列です。形の要件は `IsMultiStateLoopEntry` が定義しており、次のとおりです。

- `parse_options` のような entry state は本体が空で、`transition select` だけを持ちます。
- select の鍵は、`pkt.lookahead<bit<8>>()` 単独、`<counter>.is_zero()` 単独、その 2 本のタプルのいずれかです。
- 各 case の行き先は accept / reject か、`transition parse_options;` で entry に戻るだけの sibling state です。

sibling の書き方は次の 3 パターンです。tcp.p4 と ipv4.p4 を参照してください。

```p4
state parse_mss { pkt.extract(mss); transition parse_options; }        // (1) extract 形
state parse_nop { pkt.advance(8);   transition parse_options; }        // (2) 固定スキップ形
state parse_sack {                                                     // (3) advance-only 形
    pkt.advance(((bit<32>)pkt.lookahead<bit<16>>()[7:0]) << 3);
    transition parse_options;
}
```

(3) は dispatched-but-not-extracted 形です。state 名を `parse_<aux名>` にしておくと、loader が dispatch case の kind 値と `out tcp_opt_sack_h sack` のような out param を関連付け、extract 無しでも DSL から `tcp.options.SACK.kind` などを参照できます。slot prelude が state 進入時の R3 を option base として記録する仕組みです。extract と field 駆動 advance の組よりも verifier に優しい形です。詳細は tcp.p4 の `parse_sack` コメントを参照してください。

SACK blocks や IPv4 RR addrs のように、option の後ろに固定長要素の配列がぶら下がる形では、`out tcp_sack_block_h[4] blocks` のように宣言だけのスタックを並べておきます。loader の `resolveOwnedStacks` が、extract 1 個とその aux 駆動の advance 1 個を持つ state、または `parse_<aux>` の advance-only state を owner として自動で束ねます。DSL からは `tcp.options.SACK.blocks[0].left` のような 5-part path で届きます。

DSL 上の参照名は `<proto>.options.<OUT_PARAM 名>.<field>` です。`options` セグメント名は `@kunai_option_segment` で変更できます。out param 名は case-insensitive に解決されるため、DSL では `MSS` や `SACK` のような大文字表記が使えます。

### 7.8 IPv4 型の ParserCounter walk

トレーラの残 byte 数で終端を判定する Tofino TNA 互換の形です。vocab には次の extern 宣言が必要です。

```p4
extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser IPv4Parser(packet_in pkt, out ipv4_h hdr, ...) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set(((bit<8>)(hdr.ihl - 5)) << 5);   // 残 trailer byte 数 (§7.1 と同じ cast-shift 形)
        transition select(hdr.version) {
            4:       walk;
            default: reject;
        }
    }
    state walk {
        transition select(pc.is_zero(), pkt.lookahead<bit<8>>()) {
            (true,  _):   accept;          // counter 枯渇 → 終了
            (false, 0):   accept;          // EOL
            (false, 1):   parse_nop;
            (false, 148): parse_router_alert;
            (false, _):   reject;
        }
    }
    state parse_nop { pkt.advance(8); pc.decrement(1); transition walk; }
    ...
}
```

`decrement` の引数は 3 形あります。literal の `pc.decrement(4)`、aux フィールドの `pc.decrement(opt.length)`、lookahead slice の `pc.decrement((bit<8>)pkt.lookahead<bit<16>>()[7:0])` です。aux フィールド形は byte-aligned な 8 bit フィールドに限り、primary は使えません。`set` の対象は primary のフィールドのみです。

## 8. @kunai_* アノテーション

すべて structured 形式 `@name[k=v, ...]` で書きます。未知の annotation 名は将来の予約として無視されますが、既知 annotation の未知キーは reject されます。typo が気付かれないまま no-op になるのを防ぐためです。定義は `vocab/header_annotations.go` にあります。

| annotation | 付く場所 | キー | 用途 |
|---|---|---|---|
| `@kunai_variable_tail` | header | `len_field` 必須、`scale` 必須かつ 2 冪、`mask`、`shift`、`base` | extract 後にさらに `(field値 [& mask] [>> shift]) * scale + base` byte 進む可変 tail。`len_field` は 1 byte 内のフィールド |
| `@kunai_writeback` | header | `source` 必須、`parent=proto.field` 必須 | スタック要素の `source` byte を親 header の field に書き戻し、ipv6 ext の next_header のように後続 dispatch へ連鎖の最終値を見せる。両 field とも byte-aligned な 8 bit |
| `@kunai_option_segment` | parser | `name` 必須 | DSL の option セグメント名を `options` から変更する |
| `@kunai_layout` | parser param の `out X[N]` | `after` 必須。値は `primary` または他 stack 名 | declare-only スタックの base offset を anchor する。push されない top-level スタックには必須。現在 bundled vocab では未使用 (SRv6 は §7.4 の element-driven walk に移行し、base が push state から決まるため) だが loader は引き続きサポートする |
| `@kunai_stack_count` | parser param の `out X[N]` | `field` 必須、`offset` | `any` / `all` quantifier 用の実行時要素数を primary の `field` 値 + `offset` で与える。`field` は byte-aligned な 8 bit。現在 bundled vocab では未使用 (SRv6 は parser counter から要素数を導出する方式に移行) だが loader は引き続きサポートし、明示宣言があれば counter 由来の導出より優先する |

使用例は、`variable_tail` と `writeback` を使う ipv6.p4 にあります。`@kunai_layout` / `@kunai_stack_count` は現在 bundled vocab には使用者がいませんが、loader は両 annotation を引き続き解釈します。

## 9. loader と codegen が reject するもの

vocab を書いたら、`go test ./pkg/kunai/vocab/...` が最初の関門です。典型エラーと対処を早見表として示します。まず `vocab/loader.go` の loader が出すエラーです。

| エラーの要旨 | 原因と対処 |
|---|---|
| `missing primary header "<name>_h"` | primary header 名がファイル名と不一致 |
| `const "X" must begin with "<SELF>_"` | self-prefix 漏れ |
| `const "X" does not match <SELF>_{...} or KUNAI_<SELF>_{...}` | 命名パターン不一致。`<PARENT>` に underscore を含めた、などが典型 |
| `... is an inter-layer dispatch edge — prefix it with KUNAI_` / `... is an inter-layer dispatch edge, prefix it with KUNAI_` | 無印の dispatch shape (実在親への Field / NO_CHECK)。`KUNAI_` を付ける (§5) |
| `KUNAI_ marks an inter-layer dispatch edge ... drop the KUNAI_ prefix for a value-only select-match const` | `KUNAI_` 付きで親が非プロトコル (routing_type / option kind 等)。`KUNAI_` を外す (§5) |
| `uses the SANITY family, which has been removed` | parser block の自己検証 (§6.2) に書き換える |
| `HDRLEN_* const family is no longer supported` | `pkt.advance` テンプレート (§7.1) に書き換える |
| `duplicate const "X"` / `duplicate header "X"` / `duplicate protocol "X"` | 重複宣言。p4c 無しの vendored 環境でも落ちるよう二重にゲートされている |
| `declares both a non-trivial parser block and OPT_TRIGGER_*` | §7.6 と parser machine は排他。どちらかに寄せる |
| `OPT_TRIGGER_X declared without matching OPT_LEN_X` | TRIGGER と LEN はペア必須。逆向きも同様 |
| `MAX_DEPTH ... exceeds cap 64` | 上限 64。verifier の命令数予算も考えて一桁を推奨 |
| `top-level declare-only aux stack "X" has no @kunai_layout` | push されない top-level スタックを使う場合に出る。`@kunai_layout[after=primary]` を付ける (§8)。SRv6 のように `consume_seg` で push する形 (§7.4) なら、そもそもこのエラーは出ない |
| `CHAIN_END const "X" references unknown field` | `<FIELD>` が primary に無い |

次に `vocab/parser_machine.go` の parser machine が出すエラーです。

| エラーの要旨 | 原因と対処 |
|---|---|
| `parser blocks declared; MVP supports at most one` | parser block は 1 個まで |
| `parser "P" has N states; MVP cap is 16` | state 数の上限 |
| `transition select has N keys; MVP cap is 3` | 鍵は 3 本まで。タプルを分解する |
| `lookahead<bit<N>>() select keys must be exactly 8 bits` | 覗き読みの鍵は 1 byte 限定 |
| `state "X" pushes N stack entries; MVP allows at most one` | push は 1 state に 1 回 |
| `state "X" mixes pkt.extract with primary-targeted pkt.advance` | primary 駆動の advance を専用 state に分離する |
| `aux "X" extracted by multiple states` | extract する state は一意にする |
| `state "X" is reachable at two distinct byte offsets` | 静的 offset が多義。state graph を見直す |
| `aux gating shape unsupported` / `keys span multiple bytes` | §7.5 の MVP 2 形に収める |
| `has no start state` | P4-16 必須の `state start` が無い |

最後に、DSL 式のコンパイル時に resolver と codegen が出すエラーです。

| エラーの要旨 | 原因と対処 |
|---|---|
| `no dispatch constant for "foo" under "udp"` | §5.4 のいずれかを宣言する。const なら `KUNAI_FOO_UDP_<FIELD\|NO_CHECK>` |
| `chained "foo" has no self-dispatch const` | `KUNAI_FOO_FOO_*` を宣言する (§5.3) |
| `alternation alts disagree on dispatch for "tcp"` | dispatch が alt 間で揃わないこと自体は可。Field dispatch でない alt が混ざったときに出るので、全 alt に Field const を宣言する |
| `parser machine self-loop depth N exceeds cap M` | `<SELF>_MAX_DEPTH` で調整する。既定 8、最大 64 |

## 10. テストとチェックリスト

```bash
# 1. vocab がロードでき、resolver / codegen の既存テストが緑のまま (root 不要)
go test ./pkg/kunai/...

# 2. packet-level の意味検証 (root 必要、BPF_PROG_TEST_RUN)
#    gopacket でフレームを組み、DSL が accept/reject を正しく出すかを実カーネルで確認
sudo env "PATH=$PATH" "HOME=$HOME" "GOPATH=$(go env GOPATH)" "GOMODCACHE=$(go env GOMODCACHE)" \
    go test -v ./pkg/kunai/dsltest/

# 3. 実 verifier 通過 (host 込み)。新プロトコルの式を
#    internal/program/load_dsl_test.go の dslEntryExprs に足してから:
make test-bpf

# 4. カーネル matrix (CI は 6.1 / 6.6 / 6.12 / 6.18 / 7.0)。特に bpf_loop を使う形
#    (§7.3 / §7.7 / §7.8) は古いカーネルの 1M insn 予算に当たりやすいので必須
vimto -kernel :6.6 exec -- go test -v -count 1 -timeout 5m ./internal/program/ -run TestBpf

# 5. 本物の p4c で parse できるか (docker 必要、CI ゲート)
make p4c-check
```

リリース前のチェックリストを示します。

- [ ] primary header 名が `<ファイル名>_h` であり、全 header が byte-aligned である
- [ ] dispatch const を親ごとに `KUNAI_` 付きで宣言した。自己検証 parser や NO_CHECK でもよいが、NO_CHECK は最終手段とする
- [ ] quantifier 対応が必要なら self-dispatch を宣言し、必要に応じて CHAIN_END と MAX_DEPTH も宣言した
- [ ] 可変長は §7 の 8 機構から選び、OPT_* と parser machine を混ぜていない
- [ ] `pkt.advance` の mask で verifier 向けの静的上限を確保している (§7.1)
- [ ] `dslEntryExprs` に式を追加し、dsltest に accept と reject 両方のケースを追加した
- [ ] `make p4c-check` が通る
- [ ] 既存 .p4 の流儀に合わせ、識別値や layout の出典である RFC や 3GPP 文書をコメントで引用した
- [ ] `docs/ja/dsl-usage.md` のプロトコル一覧に追記した

なお、`internal/program/filterset_test.go` の `WantInsns` は命令数の pin であり、codegen 本体を変えたときだけ更新します。vocab 追加だけで既存 pin が動いた場合は意図しない副作用なので、原因を調べてください。

## 11. WireGuard を追加する実例

UDP 上のプロトコルで、msg_type が 1..4 のいずれかであるという自己検証も効かせる例です。

```p4
// pkg/kunai/protocols/wg.p4
//
// WireGuard transport (https://www.wireguard.com/protocol/).
// 全 message type 共通の先頭 4 byte: type (1 byte) + reserved (3 byte)。
header wg_h {
    bit<8>  msg_type;
    bit<24> reserved;
}

// 慣習的な listen port で識別する Field dispatch。この検査は
// eth/ipv4/udp/wg と書いたとき必ず emit される点に注意。WireGuard の
// ように port が運用で変わるプロトコルでは、Field dispatch を宣言せず
// 自己検証 (下記 parser block) だけに頼る選択もある。
const bit<16> KUNAI_WG_UDP_DPORT = 51820;

// 自己検証: msg_type 1..4 (handshake init / response / cookie / data)
// 以外は reject。これにより資格のある親の下なら dispatch const 無し
// でも chain を許可される (DispatchSelfValidating)。
parser WgParser(packet_in pkt, out wg_h hdr) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.msg_type) {
            1:       accept;
            2:       accept;
            3:       accept;
            4:       accept;
            default: reject;
        }
    }
}
```

次のとおり確認します。

```bash
go test ./pkg/kunai/vocab/... ./pkg/kunai/resolve/...   # ロード + 解決
make p4c-check                                          # P4-16 互換
```

`internal/program/load_dsl_test.go` の `dslEntryExprs` に次を追加します。

```go
"eth/ipv4/udp/wg",
"eth/ipv4/udp/wg where wg.msg_type == 4",
```

`make test-bpf` で verifier を通し、`pkg/kunai/dsltest/` に gopacket でフレームを組む accept / reject テストを追加します。既存の `runner_test.go` のパターンを踏襲してください。これで `xdp-ninja -i eth0 'eth/ipv4/udp/wg where wg.msg_type == 1'` と書けるようになります。

## 関連ドキュメント

- [`dsl-internals.md` §3](./dsl-internals.md#3-vocab-開発ガイド)。dispatch type の設計判断など概念面をまとめています
- [`dsl-internals.md` §5](./dsl-internals.md#5-p4-16-互換性)。p4lite と P4-16 の互換性を監査しています
- [`dsl-internals.md` §6](./dsl-internals.md#6-可変長構造の分類と表現)。可変長 8 機構の分類、設計議論、codegen 上の扱いを説明しています
- [`dsl-grammar.md`](./dsl-grammar.md)。filter 式と p4lite の formal EBNF を定義しています
- [`dsl-usage.md`](./dsl-usage.md)。対応プロトコル一覧を含むユーザー向けの CLI ガイドです
