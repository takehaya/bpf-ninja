# DSL 内部仕様

xdp-ninja DSL の **設計動機 / 全体アーキテクチャ / codegen ABI / vocab 著者ガイド / P4-16 互換性** を 1 本にまとめた内部資料。CLI 利用者向けは [`dsl-usage.md`](./dsl-usage.md)、文法定義は [`dsl-grammar.md`](./dsl-grammar.md) を参照。

## 目次

1. [設計動機](#1-設計動機)
2. [全体アーキテクチャ](#2-全体アーキテクチャ)
3. [Vocab 著者ガイド](#3-vocab-著者ガイド)
4. [Codegen ABI](#4-codegen-abi)
5. [P4-16 互換性](#5-p4-16-互換性)
6. [可変長構造の分類と表現](#6-可変長構造の分類と表現)
7. [制限と将来拡張](#7-制限と将来拡張)

---

## 1. 設計動機

### 1.1 背景

xdp-ninja は **non-invasive な XDP 観測ツール**。BPF trampoline (fentry / fexit) で本番 XDP プログラムにアタッチし、target を改変せずに pcap 取得する。

既存のフィルタ実装は cbpfc (Cloudflare の cBPF→eBPF transpiler) で tcpdump 構文を解釈する。しかし:

- **多段カプセル化を書きづらい**: GTP-U の extension chain、SRv6 の segment list、MPLS label stack、QinQ、L2/L3 VPN を tcpdump で書くのは事実上不可能 (cbpfc が L2 + L3 の絶対 offset しか扱えない)
- **operator 視点の表現力不足**: 「VXLAN の inner で TCP/443」のような直感的記述ができない
- **観測ホストの target XDP は改変不可**: Cilium / Katran / 5G UPF などは "operationally-sealed"

### 1.2 ゴール

- **多段カプセル化を「プロトコルスタックの形」で記述**: `eth/ipv4/udp/gtp/ipv4/tcp` のように
- **verifier-safe な BPF を吐く**: 全ループに静的上限、bounds check を codegen が emit
- **SRE / operator が読める**: P4 expert 限定にしない
- **target XDP に手を入れない**: 既存 fentry / fexit wrapper にそのまま乗る

### 1.3 設計判断

| 判断 | 理由 |
|---|---|
| **薄い user-facing DSL + 厚い vocab** | プロトコル知識は再利用可能な `.p4` ファイルに切り出す |
| **kernel 5.17+ (quantifier / parser self-loop あり) / さらに古くても可 (fixed chain)** | `bpf_loop` が必須。predicate は BPF_END で済むので BSWAP (6.6+) は不要 |
| **`--dsl` フラグ** | 既存の cbpfc パスを破壊しない、opt-in |
| **baked-in vocab** | `//go:embed *.p4` で `.p4` ファイル群を binary に同梱、deploy 時に外部依存ゼロ |
| **vocab は p4lite (P4-16 strict subset)** | p4c で parse 可能な範囲に留める (互換性は §5 参照) |
| **MVP は ラベル 2 段まで** | `@outer` / `@inner` の 2 段で VXLAN / GTP-U の典型ケースをカバー |
| **codegen は純 Go** | cilium/ebpf の `asm.Instructions` を直接組む、外部 toolchain 不要 |

### 1.4 明示的な除外項目

- **map references**: `map["name"][key]` を filter 内に書く機能。per-packet lookup overhead と zero-config 原則に抵触
- **L7 semantic parsing**: DNS body / HTTP header / TLS 内部。cooperation Tier 3 (将来) に持ち越し
- **temporal conditions**: 「直前 SYN から N 秒以内」等の時間軸条件
- **blind protocol auto-detection**: encap 型の heuristic 推測。明示的な layer chain 指定が要件

---

## 2. 全体アーキテクチャ

### 2.1 三層構造

```
┌─────────────────────────────────────────────────────┐
│ One-liner DSL (user-facing)                         │
│   eth/ipv4/udp/gtp/ipv4/tcp[dport==443]              │
└───────────────┬─────────────────────────────────────┘
                │ parse  (pkg/kunai/parser/)
                ↓
┌─────────────────────────────────────────────────────┐
│ AST (pkg/kunai/ast/)                             │
│   Filter / Layer / Predicate / WhereExpr / Capture  │
└───────────────┬─────────────────────────────────────┘
                │ resolve  (pkg/kunai/resolve/)
                │   ↑ vocab 参照 (pkg/kunai/vocab/)
                ↓
┌─────────────────────────────────────────────────────┐
│ IR (pkg/kunai/ir/)                               │
│   Program / LayerInstance / Condition / FieldRef    │
│   ※ vocab 解決済 (DispatchChoice / Spec バインド)    │
└───────────────┬─────────────────────────────────────┘
                │ codegen  (pkg/kunai/codegen/)
                ↓
┌─────────────────────────────────────────────────────┐
│ Output{ Main, Callbacks, CaptureInfo }              │
│   asm.Instructions (cilium/ebpf)                    │
│   bpf2bpf subprogram (chain callback) + BTF func    │
└───────────────┬─────────────────────────────────────┘
                │ load  (internal/program/program.go::compileFilter)
                ↓
┌─────────────────────────────────────────────────────┐
│ kernel BPF verifier → fentry / fexit attach          │
└─────────────────────────────────────────────────────┘
```

### 2.2 各段の役割と主要ファイル

| 段 | パッケージ | 入口 | 役割 |
|---|---|---|---|
| Lex | `pkg/kunai/lexer/` | `Lexer.Next()` / `NextValue()` | structural / value の 2 モード切替トークナイザ |
| Parse | `pkg/kunai/parser/` | `Parse()` | AST 構築 (再帰下降、where のみ precedence climbing) |
| AST | `pkg/kunai/ast/` | (型定義) | Filter / Layer / Predicate / WhereExpr / Capture / Value 等 |
| Vocab load | `pkg/kunai/vocab/` | `Bundled()` | `.p4` → `ProtocolSpec` (cache 付き) |
| Resolve | `pkg/kunai/resolve/` | `Resolve()` | AST + vocab → IR、dispatch 選択、ラベル解決 |
| IR | `pkg/kunai/ir/` | (型定義) | 解決済みプログラム表現 |
| Codegen | `pkg/kunai/codegen/` | `Gen(p, mode)` | IR → `Output{Main, Callbacks, Capture}` |
| Compile | `pkg/kunai/compile.go` | `Compile(expr, mode)` | 全部束ねる薄い wrapper |
| Load 統合 | `internal/program/program.go` | `compileFilter(expr, useDSL)` | DSL or cbpfc を選び runFilter wrapper に乗せる |
| CLI | `cmd/xdp-ninja/main.go` | `--dsl` 分岐 | CLI 引数解釈 |

### 2.3 codegen 内ファイル分割

`pkg/kunai/codegen/` は機能別に分かれる:

- `codegen.go` — `Gen()` エントリ + 共通ヘルパ (offsetBase R4、loadFromOffset、emitBounds、landingNoop)
- `dispatch.go` — Field / Sanity / NoCheck dispatch 検査
- `predicate.go` — predicate codegen (整数 / IPv4 / IPv6 / MAC / CIDR、`==` / `!=` / ordered)
- `chain.go` — `{n,m}` 静的アンロール (m≤4)
- `bpfloop.go` — `+` / `*` / `{n,m>4}` の bpf_loop callback emit + BTF func_info
- `alternation.go` — `(a|b|c)` の sequence 展開
- `where.go` — where 節 (or / and / not / arith / action atom)
- `capture.go` — `capture` 節 (headers+N 静的長算出)

---

## 3. Vocab 著者ガイド

新プロトコルを DSL に追加する手順。`pkg/kunai/protocols/<name>.p4` を 1 ファイル足し、規約どおりの const を書けば codegen がそのまま走る。

### 3.1 ファイル配置

- 1 プロトコル = 1 ファイル: `pkg/kunai/protocols/<lowercase-name>.p4`
- ファイル名 (拡張子除く) が DSL でレイヤを書くときの protocol 名。例: `mpls.p4` → `eth/mpls/ipv4`
- バンドルは `embed.go` の `//go:embed *.p4` で取り込まれるので、ファイルを置けばリビルドだけで読み込まれる

### 3.2 ファイル構成 (3 セクション)

#### Header 宣言 (必須)

```p4
header mpls_h {
    bit<20> label;
    bit<3>  tc;
    bit<1>  s;
    bit<8>  ttl;
}
```

ルール:
- Primary header 名は `<protoname>_h` (上記なら `mpls_h`)。これがマッチしないと vocab loader が reject
- フィールドは `bit<N> name;` の繰り返し。`N` は 1..2048
- 全フィールドの bit 合計は **8 の倍数** (header total が byte-aligned)
- フィールド名は lowercase + underscore + 数字

補助 header (オプション解析用など) も同ファイルに書ける。codegen には primary だけが渡る。

#### Const 宣言 (dispatch + メタデータ)

const は **名前で意味が決まる** 。

| パターン | 意味 |
|---|---|
| `<SELF>_<PARENT>_<FIELD>` | 親 protocol の `field` がこの値のときに自分 (SELF) として展開 |
| `<SELF>_<PARENT>_SANITY_<TYPE>` | 親に dispatch field が無いとき、自分の最初の bit で sanity 検査 |
| `<SELF>_<PARENT>_NO_CHECK` | 検査せず blind cast (ユーザの記述順を信じる) |
| `<SELF>_MAX_DEPTH` | bpf_loop chain (`+`/`*`/`{n,m>4}`) のループ上限。未指定なら codegen 既定 (8) |
| `<SELF>_CHAIN_END_<FIELD>` | chain 終了条件 (例: MPLS s-bit が 1 で終端) |

`<SELF>` はファイル名 (uppercase)、`<PARENT>` は親 protocol 名 (uppercase)。

**Field dispatch (一番よく使う)**:

```p4
const bit<16> IPV4_ETH_ETHERTYPE  = 0x0800;
const bit<16> IPV4_VLAN_ETHERTYPE = 0x0800;
```

`ipv4` は eth または vlan 経由で来るとき、親の `ethertype` が `0x0800`。
- ビット幅は親フィールドの幅と一致 (`ethertype` は 16 bit なので `bit<16>`)
- 値は親フィールド幅に収まる整数
- field 名は親 header の field 名 (lowercase) と完全一致

**Sanity dispatch**:

```p4
const bit<4> IPV4_MPLS_SANITY_NIBBLE = 4;
```

親 (mpls) には次プロトコルを示す field が無い → 自分 (ipv4) の **先頭 4 bit** が `4` (= IPv4 version) であることで識別。
- サポートされている `<TYPE>` は **NIBBLE のみ** (MVP)。`MAGIC` / `LENGTH` / `RANGE` は宣言しても codegen がエラー

**NoCheck dispatch**:

```p4
const bool ETH_MPLS_NO_CHECK = true;
const bool MPLS_MPLS_NO_CHECK = true;
```

親と自分の境界に検査機構が無い (EoMPLS, VXLAN inner Ethernet など)。ユーザが one-liner で順序を明示することで境界を表現。
- `bool` 型必須。`= true` のみ有効。`false` は宣言禁止
- chain (`mpls+` 等) で iter 1+ の self-dispatch にも使える

**MAX_DEPTH**:

```p4
const bit<8> MPLS_MAX_DEPTH = 8;
```

bpf_loop で最大何回イテレーションするか。未宣言なら既定 8、上限 64。

**CHAIN_END**:

```p4
const bit<1> MPLS_CHAIN_END_S = 1;
```

chain 中、SELF の `s` field が `1` のとき chain を終了。MPLS の bottom-of-stack ビットがこの典型。

#### Parser 宣言 (シンタックスチェックのみ)

```p4
parser MplsFragment(packet_in pkt, out mpls_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

p4lite はこのセクションを **シンタックスチェックのみ** に使う (codegen は header だけを読む)。`extract` + `transition accept` の最小形を書いておけば良い。複雑な state マシンを書いても無視される。

### 3.3 どの dispatch type を選ぶか

優先順位は **Field > Sanity > NoCheck**。同じ親に対して複数の dispatch const があれば codegen / resolver は Field を優先する。

判断フロー:

1. 親 protocol に「次プロトコルを示すフィールド」があるか?
   - ある → **Field**: `<SELF>_<PARENT>_<FIELD> = <value>`
2. 自分の先頭 nibble 等で識別できるか? (例: IPv4 / IPv6 の version)
   - できる → **Sanity NIBBLE**: `<SELF>_<PARENT>_SANITY_NIBBLE = <value>`
3. どちらも無い (encapsulation の Ethernet inner など)
   - **NO_CHECK**: `<SELF>_<PARENT>_NO_CHECK = true`

### 3.4 Self-dispatch (chain 用)

`<SELF>_<SELF>_*` は chain (`+`/`*`/`{n,m}`) のときに iter 1+ で読まれる。

- VLAN: `VLAN_VLAN_ETHERTYPE = 0x8100` — inner VLAN は外側の ethertype が再び 0x8100 になることで識別
- MPLS: `MPLS_MPLS_NO_CHECK = true` — label 区切りは無いので blind chain

self-dispatch が無いプロトコルは `+` / `*` / `{n,m}` で chain できない (= 静的に固定回数しか展開できない)。

### 3.5 サンプル: 新しい encapsulation を追加する

仮想プロトコル `foo` (4 byte header, ipv4 を貫通する VXLAN-like) を足したい場合:

```p4
// pkg/kunai/protocols/foo.p4
header foo_h {
    bit<8>  version;
    bit<8>  flags;
    bit<16> reserved;
}

// foo は UDP の dport==4444 で識別
const bit<16> FOO_UDP_DPORT = 4444;

parser FooFragment(packet_in pkt, out foo_h hdr) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}
```

別ファイル `eth.p4` 側に:

```p4
const bool ETH_FOO_NO_CHECK = true;
```

を追加。これで DSL から `eth/ipv4/udp[dport==4444]/foo/eth/ipv4/tcp` が書ける。

### 3.6 テスト

```bash
# 1. 全 vocab がロードできる + 既存テストが緑
go test ./pkg/kunai/vocab/... ./pkg/kunai/resolve/...

# 2. DSL でコンパイルが通る
go test ./pkg/kunai/... -run TestCompile

# 3. 実 verifier 通過 (vimto 必要)
go test -c -o /tmp/test ./internal/program/
vimto exec -- /tmp/test -test.run TestBpfEntryWithDSLFilter -test.v
```

`internal/program/load_dsl_test.go` の `dslEntryExprs` に新プロトコルのケースを足すと、後の回帰防止になる。

### 3.7 デバッグ (典型エラー)

**vocab loader エラー**:
```
foo.p4: const "FOO_BAR_BAZ_QUX" does not match <SELF>_<PARENT>_{<FIELD>|SANITY_<TYPE>|NO_CHECK|MAX_DEPTH|CHAIN_END_<FIELD>}
```
const 名がパターンに一致していない。`<SELF>_` を抜かしている / parent 名のスペル違い、等が典型。

```
foo.p4: missing primary header "foo_h"
```
primary header の名前が `<filename>_h` になっていない。

**resolver エラー**:
```
no dispatch constant for "foo" under "udp" (declare FOO_UDP_<FIELD|SANITY_<TYPE>|NO_CHECK> in foo.p4)
```
DSL `eth/ipv4/udp/foo` を書いたが、`foo.p4` に `FOO_UDP_*` の const が無い。

```
alternation alts disagree on dispatch for "tcp": "TCP_IPV4_PROTOCOL" vs "TCP_IPV6_NEXT_HEADER"
```
alt group 後の layer に対して、各 alt の dispatch const が型/値/フィールドで揃わない。MVP では同じ field offset + value を要求する。

**codegen エラー**:
```
chained "foo" has no self-dispatch const (declare FOO_FOO_<FIELD|SANITY_<TYPE>|NO_CHECK> in foo.p4)
```
`foo+` / `foo*` / `foo{n,m>1}` を書いたが、`foo.p4` に `FOO_FOO_*` self-dispatch が無い。

### 3.8 設計上の心構え

1. **NO_CHECK は最後の手段**。Field/Sanity で識別できるなら必ずそれを使う。NO_CHECK は user の記述順だけが頼り = 間違うと誤読する
2. **MAX_DEPTH は実利用上限ではなく安全弁**。MPLS なら現実は 4-8 段だが、verifier に喰わせる loop 上限として一桁を選ぶ
3. **Field の値は byte-swap なし** で書く。codegen 側で network-order に直す。`ETHERTYPE = 0x0800` (IPv4) のように直感どおりに書ける
4. **Sanity NIBBLE のフィールド** は header 先頭 1 nibble (= 4 bit) を切り出した値を比較する。`bit<4>` 必須

---

## 4. Codegen ABI

DSL output が既存の runFilter wrapper にどう乗るか。**コードを読む前にここを抑える** こと。詳細実装は `pkg/kunai/codegen/codegen.go` のパッケージ doc。

### 4.1 レジスタ規約

| Register | 役割 |
|---|---|
| **R0** | scratch buffer 先頭 (in: wrapper が先読みしておいた packet bytes) |
| **R1** | scratch buffer 末尾 (in: bounds check 用) |
| **R2** | filter result (out: 1==accept / 0==reject) |
| **R3** / **R5** | 自由に clobber 可 (working) |
| **R4** | **offsetBase**: 現 layer の scratch buffer 内開始位置 (codegen 専用) |
| **R6-R8** | host 占有 (callee-saved from kunai's view、kunai は触らない)。xdp-ninja wrapper では xdp_buff / data / data_end を保持 |
| **R9** | packet length (in: wrapper が事前計算) |
| **R10** | stack pointer |

**Stack 占有**:
- kunai 占有: arith spill `[-56..-80]`、bpf_loop ctx `[-128..-104]`
- host 占有: `(KunaiStackTop, 0)` = `(-56, 0)` の任意の slot。xdp-ninja wrapper は `-48` で tracing args ptr、`-12..-8` で metadata
- 境界定数: `pkg/kunai/codegen.KunaiStackTop = int16(-56)` — kunai がここより浅いオフセットを書くことは無い (regression test `TestZeroCapsIsHostAgnostic` で守る)

### 4.2 制御フロー

成功時: R2==1 → `Ja filter_result` → wrapper の最終分岐に戻る
失敗時: `Ja dsl_reject` → R2==0 → fall through → `filter_result`

### 4.3 layer の emit 単位

各 layer は以下の 4 ステップ:

1. **bounds check**: `R3 = R0 + R4 + hs; R3 > R1 → dsl_reject`
2. **dispatch check**: 親の field を読んで const と比較 (Field) / 自分の先頭 nibble (Sanity) / なし (NoCheck)
3. **predicate emit**: layer のフィールド条件を AND で連鎖
4. **R4 進める**: `Add R4, hs`

### 4.4 chain (`+` / `*` / `{n,m}`)

`m≤4` は静的アンロール (chain.go)、それ以上は bpf_loop 経由 (bpfloop.go)。

bpf_loop callback は **bpf2bpf subprogram** として emit、BTF `func_info` を `internal/program` 側 wrapper で attach。callback 内では:
- R6-R9 禁忌 (verifier 制約)
- ABI: R1==index, R2==ctx
- ctx struct (stack 上): `{offset u32, count u32, min u32, pkt_end u64, scratch_start u64}`

### 4.5 alternation (`(a|b|c)`)

各 alt を sequence 展開、最初に match した alt の advance を取る。MVP 制約:
- alt 数 2-4
- 全 alt が同じ header size (uniform advance)
- ネスト不可
- 先頭 layer 不可
- alt 後の layer 全てが同一 dispatch を提供

### 4.6 where 節

短絡評価:
- AND の左辺 false → dsl_reject
- OR の左辺 true → `Ja or_done` (右辺スキップ)

NOT は inner success label を作って `Ja failLabel` で反転。

算術: tree walk で R3 に結果を残す契約、stack に左オペランドを退避。MVP は **3 段ネストまで**。

action atom (`action == NAME`): codegen は `caps.ActionFetcher.EmitFetch(R3)` を呼んで R3 に action u32 をロードする命令列を取得し、続けて `JNE R3, caps.Action[NAME], dsl_reject` を emit。**XDP fexit ABI** (`pkg/kunai/host/xdp.FexitFetcher`) は `stack[-48] → args[1]` の 2 段 LDX を返す既定実装。`caps.Action == nil` のときは resolver が atom を拒否 (host が action 値を提供できない)。tc clsact / userspace target は `pkg/kunai/host/<name>/` で独自の fetcher を実装すれば再利用可能 — kunai コアは host 知識を持たない。

### 4.7 capture 節

`headers+N` の N は静的計算 (chain を含む filter ではコンパイル時に長さ確定不能 → reject)。`captureWithXdpOutput(eventsFD, isFexit, maxCapLen)` の `maxCapLen` 引数として wrapper に渡す。per-capture `where` は filter 全体の `where` と AND 合成。

### 4.8 byte-swap trick

eBPF の LDX は x86 上 little-endian で読む。packet bytes は network order (BE)。runtime BSwap を avoid するため、**codegen 時に定数を byte-swap して LE 形式で immediate に埋める**。`==` / `!=` の単純比較が 1 命令で済む。ordered 比較 (`<`, `>` 等) は意味的に LE にできないので runtime BSwap を入れる。

---

## 5. P4-16 互換性

`pkg/kunai/vocab/p4lite/` は xdp-ninja の vocab loader が `.p4` ファイルを読むための **P4-16 の限定サブセット** パーサ。

実装ファイル:
- `lexer.go` (319 行) — トークナイザ + キーワード認識
- `parser.go` (589 行) — recursive descent
- `types.go` (136 行) — AST 型

**結論**: p4lite は P4-16 の **strict subset** (P4-16 仕様の範囲内に収まっている)。p4c が parse できる範囲だが、明示的な reject keyword (action / table / control / apply / extern) は p4lite で弾く。

### 5.1 サマリ表

| 領域 | P4-16 | p4lite | 評価 |
|---|---|---|---|
| Top-level decl | header / struct / header_union / enum / error / match_kind / typedef / type / extern / action / table / control / parser / package / instantiation / const | header / const / parser | strict subset |
| Header field 型 | bool / error / match_kind / `bit<N>` / `int<N>` / `varbit<N>` / typedef'd / struct nest / header stack | `bit<N>` のみ | strict subset |
| Const 型 | 任意 typeRef + 任意 expression | `bit<N>` (1..64) + `bool`、整数リテラルのみ | strict subset |
| Parser パラメータ direction | in / out / inout / 無指定 | `packet_in` / `out` のみ | strict subset (architecture 依存) |
| Parser local element | const / var / instantiation / value_set | 無し | strict subset |
| Parser statement | assignment / method call / direct application / block / conditional / const / var / empty | `obj.extract(target)` / `obj.extract(target.next)` のみ | strict subset |
| Transition | accept / reject / state name / select | 同左 | full ✓ |
| Select case keyset | 整数 / default / `_` / mask (`val &&& mask`) / range (`a..b`) / 名前参照 / tuple | 整数 / `_` / default / tuple | mask & range 未対応 |
| 整数リテラル | 10進 / 0x hex / 0o oct / 0b bin / sized (`4w0xff`, `8s10`) | 10進 / 0x hex のみ | bin / oct / sized 未対応 |
| Annotation (`@name`) | 全所に書ける | 一切受けない | strict subset |
| コメント | `//` / `/* */` | 同左 | full ✓ |

### 5.2 p4lite が拒否するもの

`vocab/p4lite/lexer.go:134` の `rejectedKeywords` で **明示的に reject**:
- `action`, `table`, `control`, `apply`, `extern`

これらが書かれた `.p4` ファイルを読むと `p4lite does not support "..."` エラー。

これ以外の P4-16 上位宣言 (`struct`, `header_union`, `enum`, `error`, `match_kind`, `typedef`, `type`, `package`) は明示 reject 対象ではないが、トップレベルで `header` / `const` / `parser` 以外のキーワードに遭遇すると `expected 'header', 'const', or 'parser'` エラーで弾かれる。

### 5.3 P4-16 で valid だが p4lite が reject するもの

すべて **vocab 用途で意味を持たない** と判断して除外:

- `action`, `table`, `control`, `apply` — match-action パイプライン定義。kernel verifier に通る eBPF を直接吐く xdp-ninja では使わない
- `extern` — 外部関数宣言。codegen は固定の eBPF パターンを emit するので呼び出す extern が無い
- `varbit<N>`, header stacks 内宣言 — 動的長 header / オプション解析。今は scratch 256B 内の静的フィールドアクセスのみ
- value_set — runtime に変動する match 集合
- `int<N>` / `bool` field — flag 系は `bit<1>` で書く慣習で代替
- 名前参照 const / 式 const (`const bit<8> A = B + 1;`) — vocab 内で計算は不要
- mask / range match — DSL の `where` で代替

### 5.4 P4-16 が reject するのに p4lite が通すケースの監査

確認結果: **無し**。

確認した観点:
1. `header` field 型は `bit<N>` のみ — P4 でも合法
2. `const` の bit 幅 1..64 — P4 では上限なし、p4lite で狭めただけ
3. `parser` パラメータ `packet_in` / `out` のみ — P4 の direction の subset
4. `extract` 引数 `obj.extract(target.next)` — P4 の header stack の `.next` プロパティと一致
5. `select` のキーに dotted path — P4 では expression なので `a.b.c` も許容、subset
6. `select` case の値は整数 or `_` — P4 の subset
7. キーワードの大小: P4 と同じ lowercase

### 5.5 動作確認

`pkg/kunai/protocols/*.p4` は **本物の p4c で `--parse-only` 通過**するように CI で検証している (`.github/workflows/p4c-check.yml`、ローカルは `make p4c-check` または `./scripts/p4c-check.sh`)。詳細は [`dsl-followups.md`](./dsl-followups.md) P0-4 を参照。

加えて `go test ./pkg/kunai/vocab/...` が `dslvocab.Bundled` 経由で全 `.p4` を 1 度パースしているので、Go test が緑 = 「全 vocab が p4lite subset (= P4-16 の strict subset) に収まる」の二重確認になる。

### 5.6 将来の拡張余地

| 拡張 | 動機 | 工数感 |
|---|---|---|
| Annotation `@name(...)` 受理 (無視) | 公式 P4 例が貼り付けやすい | 小 (lexer に `@` 追加) |
| `#include` / `#define` / `#pragma` skip | 既存 P4 hdr ファイルから流用 | 小 (lexer 拡張) |
| Sized integer literal `Nw0xVal` | 公式 P4 風の見た目 | 小 |
| `0b` バイナリリテラル | bit field の意図が読みやすい | 微小 |
| `varbit<N>` field | TCP options など可変 header | 中 (codegen 連動) |
| `match_kind`, `range`, `mask` | より柔軟な select | 中 |
| `typedef` / `type` | 型 alias で DRY | 小〜中 |
| `value_set` | 動的 vocab の上手な扱い | 大 |

### 5.7 参考

- [P4-16 公式仕様 v1.2.5](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html) (BNF: §G "Appendix: P4 grammar")
- [p4c parser grammar](https://github.com/p4lang/p4c/blob/main/frontends/parsers/p4/p4parser.ypp)

---

## 6. 可変長構造の分類と表現

ネットワークプロトコルの可変長部分は形が複数ある。kunai DSL では **どのパターンを chain として書かせ、どのパターンを wrapper の aux として表現するか** を設計判断として明確にしている。本節は分類とその表現指針を述べる。

### 6.1 4 パターンの分類

実 protocol の可変長構造は wire 形上 4 つの基本パターンに分類できる。

| # | パターン | 例 | 構造の特徴 |
|---|---|---|---|
| **A** | 全体繰り返し (層スタック) | VLAN, MPLS, QinQ | wire 上で同じ shape の header が back-to-back に並ぶ。各 entry が独立 |
| **B** | 拡張ヘッダ繰り返し | IPv6 ext, GTP-U ext header | wrapper の中に extension header が並ぶ。各 ext は次 type を field で持つ |
| **C** | wrapper + 内部項目列 | SRv6 segment list (16B 固定), TCP/IPv4 options (kind 依存可変) | 1 つの wrapper の中に items が並ぶ。entry 自体には dispatch 情報がない |
| **D** | wrapper + 条件付き単発 | GTP-U opt (E/S/PN flag gated) | wrapper の flag で有無が決まる、最大 1 回 |

これらの **判別基準は wire 構造**:
- 「外側に独立した header が並ぶ」(A) なら chain
- 「wrapper の内側に sub-header が入っている」(B/C/D) なら wrapper の aux

### 6.2 表現指針: chain vs aux

vocab 上の表現は 2 種類:

#### chain protocol (パターン A)

独立した protocol を vocab で 1 つ宣言、quantifier (`+` `*` `?` `{n,m}`) で repetition を表す。DSL 上は wire 順に並んだ別 layer として書く:

```
eth/vlan+/ipv4/tcp                ; VLAN tag (1 個以上)
eth/mpls+/ipv4/tcp                ; MPLS label stack
eth/qinq/vlan+/ipv4/tcp           ; QinQ (S-tag + C-tag stack)
```

vocab 側は `<SELF>_<PARENT>_<FIELD>` 系の dispatch const で「どこから始まるか / どこで終わるか」を declare する。

#### wrapper + aux header (パターン B/C/D)

1 個の protocol が **primary header + 0 個以上の aux header** を持つ形。aux は parser block の `out` 引数として宣言、parser の state machine が「いつ extract するか」を記述する。DSL 上は wrapper protocol の 1 layer として書き、内部の aux は dot path でアクセス:

```
; パターン B: 拡張ヘッダ繰り返し
eth/ipv4/udp/gtp/ipv4/tcp where any(gtp.exts.ext_type == 0xc0)
eth/ipv4/udp/gtp/ipv4/tcp where gtp.exts.count >= 1
eth/ipv6/tcp where any(ipv6.exts.next_header == 44)              ; Fragment ext あり

; パターン C: wrapper + 内部項目列
eth/ipv6/srv6/tcp where srv6.segments[0].addr == fc00::1         ; final dest
eth/ipv6/srv6/tcp where srv6.segments[srv6.last_entry].addr == X ; first hop
eth/ipv6/srv6/tcp where any(srv6.segments.addr == fc00::1)       ; ∃
eth/ipv4/tcp where tcp.mss.value == 1460                         ; TCP option (固定 size)
eth/ipv4/tcp where tcp.ts.val > 1000000

; パターン D: wrapper + 条件付き単発
eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.exists
eth/ipv4/udp/gtp/ipv4/tcp where gtp.opt.next_ext == 0
```

### 6.3 パターン C/D の判定基準: 「中身か外か」

「VLAN は eth の aux」「MPLS は eth の aux」と呼ぶことはしない。理由は VLAN/MPLS の wire 構造:

- VLAN tag は ethertype (0x8100) で type-of-next を持っている = 外側に「並ぶ」存在
- MPLS label は s-bit で stack 終端を持っている = 同上

これらは「eth の中身」ではない。「eth の後ろに並んだ別 protocol layer」なので chain (パターン A)。

一方、SRv6 の segment list は:

- SRH header の last_entry/segments_left field で長さが決まる
- 各 segment は IPv6 アドレスのみで type-of-next を持たない
- SRH header と segments は不可分の 1 セット (segments だけ抜き出して別解釈は不可能)

これは明確に「SRH の中身」=>aux (パターン C)。

GTP の opt も同じ: GTP header の E/S/PN flag で有無が決まる、独立 layer ではない。

### 6.4 過去の設計検討と現方針

開発初期に `srv6_seg` を独立 chain protocol として切り出す案 (`eth/ipv6/srv6/srv6_seg+/tcp`) を実装したが、aux model に切り替えた。判断理由:

1. **wire 構造に対して不誠実**: `srv6/srv6_seg+` は「srv6 → srv6_seg → srv6_seg → ...」と読める。実際は SRH 1 個 + その中の segment 列であり、構造が二段に分離して見えるのは misleading
2. **ネスト SRH (= SRH/SRH、Segment Routing over Segment Routing) と区別困難**: chain として書くと `srv6/srv6_seg+/srv6/srv6_seg+/...` と書ける一方、それが「ネスト SRH」なのか「外側 SRH の segment 列の続き」なのか visually 不明瞭
3. **概念の重複**: chain mechanism と aux mechanism が「リスト的なもの」を 2 系統で扱うことになり、user にとって学ぶ概念が増える

(Y) aux model 採用後は user が見える概念が:
- **chain protocol** (`+` quantifier、`vlan+` のような外側スタック)
- **wrapper + aux** (`protocol.aux_name`、`srv6.segments[N]` のような内側構造)

の 2 つに整理され、wire 構造との対応が一目瞭然になる。

### 6.5 vocab declaration の方法

aux header は parser block の `out` 引数で declare し、state machine で extract 条件を記述する。

#### 単発 aux (パターン D)

```p4
// gtp.p4
header gtp_h     { bit<3> version; ... bit<1> e; bit<1> s; bit<1> pn; ... }
header gtp_opt_h { bit<16> seq; bit<8> npdu; bit<8> next_ext; }

parser GtpFragment(packet_in pkt,
                   out gtp_h     gtp,
                   out gtp_opt_h opt) {
    state start {
        pkt.extract(gtp);
        transition select(gtp.e, gtp.s, gtp.pn) {
            (0,0,0): accept;            // opt 未抽出のまま
            default: parse_opt;
        }
    }
    state parse_opt {
        pkt.extract(opt);
        transition accept;
    }
}
```

DSL での `gtp.opt.exists` は「`parse_opt` state に到達したか」を runtime で確かめる。`gtp.opt.next_ext` は「opt が extract された場合のみ field 読み、未抽出なら predicate 不一致」。

#### aux header stack (パターン B/C)

P4 の header stack `H[N]` を使う:

```p4
// srv6.p4
header srv6_h     { bit<8> next_header; ... bit<8> last_entry; ... }
header srv6_seg_h { bit<128> addr; }

parser SRv6Fragment(packet_in pkt,
                    out srv6_h        hdr,
                    out srv6_seg_h[8] segments) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.routing_type) {
            4:       parse_segments;
            default: reject;
        }
    }
    state parse_segments {
        pkt.extract(segments.next);
        transition select(/* iter < hdr.last_entry+1 を表す */) {
            ...: parse_segments;
            ...: accept;
        }
    }
}
```

stack の reservation 数 (上の例では 8) は **verifier-safe な loop 上限** として codegen が利用する。実 packet では `hdr.last_entry+1` 個まで使われる。

#### option-style aux (パターン C 可変、TCP/IPv4 options)

各 option を kind ごとに独立 aux header として declare、parser block の state machine で kind dispatch + 条件付き extract:

```p4
// tcp.p4
header tcp_h               { ... bit<4> data_offset; ... }
header tcp_opt_mss_h       { bit<8> kind; bit<8> length; bit<16> value; }
header tcp_opt_ws_h        { bit<8> kind; bit<8> length; bit<8>  shift; }
header tcp_opt_sack_perm_h { bit<8> kind; bit<8> length; }
header tcp_opt_ts_h        { bit<8> kind; bit<8> length; bit<32> val; bit<32> ecr; }

parser TcpFragment(packet_in pkt,
                   out tcp_h               tcp,
                   out tcp_opt_mss_h       mss,
                   out tcp_opt_ws_h        ws,
                   out tcp_opt_sack_perm_h sack_perm,
                   out tcp_opt_ts_h        ts) {
    state start {
        pkt.extract(tcp);
        transition select(tcp.data_offset) {
            5:       accept;                    // options 領域なし
            default: parse_options;
        }
    }
    state parse_options {
        transition select(pkt.lookahead<bit<8>>()) {
            0:       accept;                    // EOL terminator
            1:       parse_nop;                 // NOP padding (1 byte)
            2:       parse_mss;
            3:       parse_ws;
            4:       parse_sack_perm;
            8:       parse_ts;
            default: parse_skip;                // unknown: length-byte advance
        }
    }
    state parse_mss        { pkt.extract(mss);       transition parse_options; }
    state parse_ws         { pkt.extract(ws);        transition parse_options; }
    state parse_sack_perm  { pkt.extract(sack_perm); transition parse_options; }
    state parse_ts         { pkt.extract(ts);        transition parse_options; }
    state parse_nop        { /* 1 byte 進めて parse_options に戻る */ }
    state parse_skip       { /* byte 1 (length) 分進めて parse_options に戻る */ }
}
```

各 option は wire 上 0 or 1 回出現する想定 (典型的な実 TCP frame と一致)。同 kind が複数現れる malformed packet は最後の値で上書き、または header stack 化 (Phase 2) で全件保持。

### 6.6 DSL access の体系

aux への access は **dot path で統一**。chain element も同じ accessor を共有する:

| 操作 | 構文 | 適用例 |
|---|---|---|
| 単発 aux のフィールド | `<proto>.<aux>.<field>` | `gtp.opt.next_ext == 0`, `tcp.mss.value == 1460` |
| 単発 aux の存在 | `<proto>.<aux>.exists` | `gtp.opt.exists`, `tcp.sack_perm.exists` |
| stack/chain の index | `<proto>.<aux>[N].<field>` | `srv6.segments[0].addr == fc00::1` |
| stack/chain の動的 index | `<proto>.<aux>[<expr>].<field>` | `srv6.segments[srv6.last_entry].addr` |
| 集合 ∃ | `any(<expr>)` | `any(srv6.segments.addr == X)`, `any(vlan.id == 100)` |
| 集合 ∀ | `all(<expr>)` | `all(srv6.segments.addr in fc00::/16)` |
| 件数 | `<proto>.<aux>.count` | `srv6.segments.count >= 3` |

`any` / `all` は関数形。bracket 形 `vlan+[id == 100]` は `all(vlan.id == 100)` の syntax sugar として残す (∀ デフォルト維持)。

### 6.7 codegen 上の扱い (概要)

| 表現 | 実装 mechanism |
|---|---|
| 単発 aux への field 読み | parser machine の state graph から「aux 抽出条件」を逆算し、gating check + offset 計算 + field load を emit |
| stack aux への [N] index (静的) | parse-time に `0 <= N < cap` を check、runtime は parser の state graph から算出した offset で field load |
| stack aux への [parent.field] (動的) | runtime に bound check (`<expr> < count`) + dynamic offset 計算 |
| `any(P)` / `all(P)` | bpf_loop 経由で per-iter P 評価。any: 1 個目の match で R0=1 早期 break、all: 1 個目の miss で reject |
| `count` | wrapper の field 由来 (SRv6 の last_entry+1 等) または stack walk 結果 |

implementation 詳細は `pkg/kunai/codegen/parser_machine.go` の state graph emit ロジックを参照。

---

## 7. 制限と将来拡張

詳細は [`dsl-followups.md`](./dsl-followups.md) を参照。本節は制約マップだけ簡潔に列挙。

### 7.1 現状の MVP 制限

| 領域 | 制限 |
|---|---|
| Predicate | `field in [...]` / `field has FLAG` parser は受理するが codegen は ErrNotImplemented |
| Where | 算術ネスト最大 3 段 / `flow.is_new` 等は dead syntax (codegen reject) |
| Capture | `capture f1, f2` フィールド列 不可 / chain 含む filter で `headers+N` 不可 |
| Alternation | alt 数 2-4 / 同サイズ only / ネスト不可 / 先頭不可 |
| Sanity dispatch | NIBBLE のみ (MAGIC / LENGTH / RANGE 未対応) / chain 内 sanity self-dispatch 不可 |
| Vocab | 1 protocol あたり最大 2 ラベル |
| Kernel | quantifier / parser self-loop あり: 5.17+ (`bpf_loop` 必須) / fixed chain のみ: さらに古くても可 |

### 7.2 アーキテクチャ上動かない要件

以下は本 DSL の design choice 上「動かない」もので、いずれも user 要望が出てから別 design check が必要:

- map references (`map["name"][key]`)
- L7 semantic parsing (DNS body / HTTP / TLS 内部)
- temporal conditions (時間軸条件)
- 自動 encap 推測

---

## 関連ドキュメント

- [`dsl-overview.md`](./dsl-overview.md) — index
- [`dsl-usage.md`](./dsl-usage.md) — ユーザー向け CLI ガイド
- [`dsl-grammar.md`](./dsl-grammar.md) — formal EBNF + 例文
- [`dsl-followups.md`](./dsl-followups.md) — 残作業
- [`dsl-benchmark.md`](./dsl-benchmark.md) — ベンチ方法論
